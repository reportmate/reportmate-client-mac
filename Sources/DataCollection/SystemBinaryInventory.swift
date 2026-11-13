import Darwin
import Foundation

/// A versioned command-line binary the System module looks for, such as a web server,
/// a language runtime or a TLS library, and how to read its version.
struct SystemBinaryTarget: Sendable {
    let name: String
    let category: String
    let arguments: [String]
    /// Regular expression whose first capture group is the version.
    let pattern: String
}

/// Inventory of system binaries: where each one is, its version, whether it was running when
/// collected, and the package or source it came from.
///
/// The collector runs as root, so it never executes a file a standard user could have replaced.
/// A binary runs for its version only when it and every directory above it are owned by root
/// and writable by nobody else. A Homebrew binary is owned by the user who installed Homebrew,
/// so its version comes from the Cellar path instead, and any other binary that fails the check
/// is reported with no version rather than run.
enum SystemBinaryInventory {

    static let targets: [SystemBinaryTarget] = [
        .init(name: "httpd", category: "server", arguments: ["-v"], pattern: #"Apache/([0-9][0-9A-Za-z.\-]*)"#),
        .init(name: "nginx", category: "server", arguments: ["-v"], pattern: #"nginx/([0-9][0-9A-Za-z.\-]*)"#),
        .init(name: "sshd", category: "server", arguments: ["-V"], pattern: #"OpenSSH_([0-9][0-9A-Za-z.\-]*)"#),
        .init(name: "named", category: "server", arguments: ["-v"], pattern: #"BIND ([0-9][0-9A-Za-z.\-]*)"#),
        .init(name: "mysqld", category: "database", arguments: ["--version"], pattern: #"Ver ([0-9][0-9A-Za-z.\-]*)"#),
        .init(name: "mariadbd", category: "database", arguments: ["--version"], pattern: #"Ver ([0-9][0-9A-Za-z.\-]*)"#),
        .init(name: "postgres", category: "database", arguments: ["--version"], pattern: #"\(PostgreSQL\) ([0-9][0-9A-Za-z.\-]*)"#),
        .init(name: "redis-server", category: "database", arguments: ["--version"], pattern: #"v=([0-9][0-9A-Za-z.\-]*)"#),
        .init(name: "openssl", category: "library", arguments: ["version"], pattern: #"(?:OpenSSL|LibreSSL) ([0-9][0-9A-Za-z.\-]*)"#),
        .init(name: "php", category: "runtime", arguments: ["-v"], pattern: #"PHP ([0-9][0-9A-Za-z.\-]*)"#),
        .init(name: "python3", category: "runtime", arguments: ["--version"], pattern: #"Python ([0-9][0-9A-Za-z.\-]*)"#),
        .init(name: "python", category: "runtime", arguments: ["--version"], pattern: #"Python ([0-9][0-9A-Za-z.\-]*)"#),
        .init(name: "node", category: "runtime", arguments: ["--version"], pattern: #"v?([0-9]+\.[0-9][0-9A-Za-z.\-]*)"#),
        .init(name: "java", category: "runtime", arguments: ["-version"], pattern: #"version "([^"]+)""#),
        .init(name: "ruby", category: "runtime", arguments: ["--version"], pattern: #"ruby ([0-9][0-9A-Za-z.\-]*)"#),
        .init(name: "perl", category: "runtime", arguments: ["-v"], pattern: #"\(v([0-9][0-9.]*)\)"#),
        .init(name: "curl", category: "tool", arguments: ["--version"], pattern: #"curl ([0-9][0-9A-Za-z.\-]*)"#),
        .init(name: "git", category: "tool", arguments: ["--version"], pattern: #"git version ([0-9][0-9A-Za-z.\-]*)"#),
        .init(name: "rsync", category: "tool", arguments: ["--version"], pattern: #"rsync +version ([0-9][0-9A-Za-z.\-]*)"#),
        .init(name: "sudo", category: "tool", arguments: ["-V"], pattern: #"Sudo version ([0-9][0-9A-Za-z.\-]*)"#),
    ]

    static let searchDirectories = [
        "/usr/sbin", "/usr/bin",
        "/usr/local/sbin", "/usr/local/bin",
        "/opt/homebrew/sbin", "/opt/homebrew/bin",
        "/opt/local/sbin", "/opt/local/bin",
        "/usr/local/mysql/bin",
        "/Library/Developer/CommandLineTools/usr/bin",
        "/Applications/Xcode.app/Contents/Developer/usr/bin",
    ]

    /// Directories with one level of wildcard: keg-only Homebrew formulas, python.org
    /// frameworks and installed JDKs.
    static let searchPatterns = [
        ("/opt/homebrew/opt", "bin"), ("/opt/homebrew/opt", "sbin"),
        ("/usr/local/opt", "bin"), ("/usr/local/opt", "sbin"),
        ("/Library/Frameworks/Python.framework/Versions", "bin"),
        ("/Library/Java/JavaVirtualMachines", "Contents/Home/bin"),
    ]

    /// Launchers in /usr/bin that hand off to the developer tools, or offer to install them,
    /// instead of reporting a version. The real binaries are found under the developer tools.
    static let launcherStubs: Set<String> = ["/usr/bin/python3", "/usr/bin/git", "/usr/bin/java"]

    static let versionTimeout: TimeInterval = 5

    // MARK: Pure helpers

    static func parseVersion(_ output: String, pattern: String) -> (version: String, line: String)? {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return nil }
        for raw in output.split(whereSeparator: \.isNewline) {
            let line = String(raw).trimmingCharacters(in: .whitespaces)
            let range = NSRange(line.startIndex..., in: line)
            if let match = regex.firstMatch(in: line, range: range), match.numberOfRanges > 1,
               let versionRange = Range(match.range(at: 1), in: line) {
                return (String(line[versionRange]), String(line.prefix(200)))
            }
        }
        return nil
    }

    /// Formula and version from a path inside a Homebrew Cellar, e.g.
    /// `/opt/homebrew/Cellar/httpd/2.4.62_1/bin/httpd` gives `httpd`, `2.4.62`, `2.4.62_1`.
    static func homebrewPackage(resolvedPath: String) -> (formula: String, version: String, packageVersion: String)? {
        let parts = resolvedPath.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        guard let cellar = parts.firstIndex(of: "Cellar"), parts.count > cellar + 2 else { return nil }
        let formula = parts[cellar + 1], packageVersion = parts[cellar + 2]
        var version = packageVersion
        if let underscore = version.lastIndex(of: "_"),
           version[version.index(after: underscore)...].allSatisfy(\.isNumber) {
            version = String(version[..<underscore])
        }
        return (formula, version, packageVersion)
    }

    /// Where a binary came from, judged by its resolved location.
    static func source(resolvedPath: String) -> String {
        if resolvedPath.contains("/Cellar/") { return "homebrew" }
        if resolvedPath.hasPrefix("/opt/local/") { return "macports" }
        if resolvedPath.hasPrefix("/Library/Developer/CommandLineTools/") ||
            resolvedPath.hasPrefix("/Applications/Xcode.app/") { return "developerTools" }
        if resolvedPath.hasPrefix("/System/") ||
            (resolvedPath.hasPrefix("/usr/") && !resolvedPath.hasPrefix("/usr/local/")) { return "os" }
        return "unknown"
    }

    /// Executable paths of running processes and how many of each, from `ps -axww -o comm=`.
    static func processPaths(psOutput: String) -> [String: Int] {
        var counts: [String: Int] = [:]
        for raw in psOutput.split(whereSeparator: \.isNewline) {
            let path = raw.trimmingCharacters(in: .whitespaces)
            if path.hasPrefix("/") { counts[path, default: 0] += 1 }
        }
        return counts
    }

    /// Processes that belong to a binary: the binary itself, or for a Python framework build the
    /// `Python.app` interpreter it hands off to, which is what `ps` shows for a running script.
    static func processCount(resolvedPath: String, name: String, processes: [String: Int]) -> Int {
        var count = processes[resolvedPath] ?? 0
        if name.hasPrefix("python"), let bin = resolvedPath.range(of: "/bin/", options: .backwards) {
            let appPrefix = String(resolvedPath[..<bin.lowerBound]) + "/Resources/Python.app/"
            count += processes.filter { $0.key.hasPrefix(appPrefix) }.reduce(0) { $0 + $1.value }
        }
        return count
    }

    /// Version from the bundle a Python framework build or a JDK lives in, read from its
    /// Info.plist without running anything. Other bundles are skipped: a `node` inside an app
    /// bundle carries the app's version, not its own.
    static func bundleVersionPlist(resolvedPath: String) -> (plist: String, keys: [String])? {
        for marker in ["/Python.framework/Versions/", "/Python3.framework/Versions/"] {
            if let range = resolvedPath.range(of: marker) {
                let rest = resolvedPath[range.upperBound...]
                guard let version = rest.split(separator: "/").first else { return nil }
                return (String(resolvedPath[..<range.upperBound]) + version + "/Resources/Info.plist", ["CFBundleVersion"])
            }
        }
        if let range = resolvedPath.range(of: ".jdk/Contents/Home/bin/") {
            return (String(resolvedPath[..<range.lowerBound]) + ".jdk/Contents/Info.plist", ["JavaVM.JVMVersion", "CFBundleShortVersionString"])
        }
        return nil
    }

    static func bundleVersion(resolvedPath: String) -> String? {
        guard let (plist, keys) = bundleVersionPlist(resolvedPath: resolvedPath),
              let info = NSDictionary(contentsOfFile: plist) else { return nil }
        for key in keys {
            let value = key.split(separator: ".").reduce(info as Any?) { ($0 as? NSDictionary)?[String($1)] }
            if let text = value as? String, let first = text.first, first.isNumber {
                return text.split(separator: ",").first.map { $0.trimmingCharacters(in: .whitespaces) }
            }
        }
        return nil
    }

    /// True when the file and every directory above it are owned by root and writable by nobody
    /// else, so running it as root cannot run code a standard user put there.
    static func isRootControlled(_ path: String) -> Bool {
        var current = path
        while true {
            var info = stat()
            guard lstat(current, &info) == 0, info.st_uid == 0,
                  info.st_mode & (S_IWGRP | S_IWOTH) == 0 else { return false }
            if current == "/" { return true }
            current = (current as NSString).deletingLastPathComponent
            if current.isEmpty { current = "/" }
        }
    }

    // MARK: Collection

    struct Candidate: Sendable {
        let target: SystemBinaryTarget
        let path: String
        let resolvedPath: String
    }

    static func candidates(runningPaths: [String]) -> [Candidate] {
        let fm = FileManager.default
        var directories = searchDirectories
        for (root, suffix) in searchPatterns {
            for entry in (try? fm.contentsOfDirectory(atPath: root))?.sorted() ?? [] where !entry.hasPrefix(".") {
                directories.append("\(root)/\(entry)/\(suffix)")
            }
        }
        var seen = Set<String>()
        var found: [Candidate] = []
        func consider(_ target: SystemBinaryTarget, _ path: String) {
            guard !launcherStubs.contains(path) else { return }
            let resolved = (path as NSString).resolvingSymlinksInPath
            var isDirectory: ObjCBool = false
            guard fm.fileExists(atPath: resolved, isDirectory: &isDirectory), !isDirectory.boolValue,
                  fm.isExecutableFile(atPath: resolved), seen.insert(resolved).inserted else { return }
            found.append(Candidate(target: target, path: path, resolvedPath: resolved))
        }
        for directory in directories {
            for target in targets { consider(target, "\(directory)/\(target.name)") }
        }
        // A running copy outside the usual locations, such as an app bundle's own httpd.
        let byName = Dictionary(targets.map { ($0.name, $0) }, uniquingKeysWith: { first, _ in first })
        for path in runningPaths.sorted() {
            if let target = byName[(path as NSString).lastPathComponent] { consider(target, path) }
        }
        return found
    }

    /// One reported binary. Optional fields are left out of the payload rather than sent empty.
    struct Record: Sendable {
        var name: String
        var category: String
        var path: String
        var resolvedPath: String?
        var source: String
        var package: String?
        var packageVersion: String?
        var version: String?
        var versionString: String?
        var versionSource: String?
        var running: Bool?
        var processCount: Int?

        var dictionary: [String: Any] {
            var item: [String: Any] = ["name": name, "category": category, "path": path, "source": source]
            let optional: [(String, Any?)] = [
                ("resolvedPath", resolvedPath), ("package", package), ("packageVersion", packageVersion),
                ("version", version), ("versionString", versionString), ("versionSource", versionSource),
                ("running", running), ("processCount", processCount),
            ]
            for (key, value) in optional { if let value { item[key] = value } }
            return item
        }
    }

    static func collect() async -> [[String: Any]] {
        let ps = try? await ProcessRunner.run(
            executable: "/bin/ps", arguments: ["-axww", "-o", "comm="], timeout: 30, label: "ps comm")
        var processes: [String: Int] = [:]
        for (path, count) in processPaths(psOutput: ps?.standardOutput ?? "") {
            processes[(path as NSString).resolvingSymlinksInPath, default: 0] += count
        }
        let psAvailable = ps.map { !$0.timedOut && $0.exitCode == 0 } ?? false
        let found = candidates(runningPaths: Array(processes.keys))
        let running = processes

        let records = await withTaskGroup(of: (Int, Record).self) { group in
            for (index, candidate) in found.enumerated() {
                group.addTask {
                    (index, await describe(candidate, processes: running, psAvailable: psAvailable))
                }
            }
            var results: [(Int, Record)] = []
            for await result in group { results.append(result) }
            return results.sorted { $0.0 < $1.0 }.map(\.1)
        }
        return records.map(\.dictionary)
    }

    private static func describe(_ candidate: Candidate, processes: [String: Int], psAvailable: Bool) async -> Record {
        let target = candidate.target
        var item = Record(
            name: target.name, category: target.category, path: candidate.path,
            resolvedPath: candidate.resolvedPath != candidate.path ? candidate.resolvedPath : nil,
            source: source(resolvedPath: candidate.resolvedPath))
        if psAvailable {
            let count = processCount(resolvedPath: candidate.resolvedPath, name: target.name, processes: processes)
            item.running = count > 0
            item.processCount = count
        }

        if let brew = homebrewPackage(resolvedPath: candidate.resolvedPath) {
            item.package = brew.formula
            item.packageVersion = brew.packageVersion
            item.version = brew.version
            item.versionSource = "package"
            return item
        }

        if item.source == "unknown", let receipt = await packageReceipt(candidate.resolvedPath) {
            item.source = "package"
            item.package = receipt.id
            item.packageVersion = receipt.version
        }

        guard isRootControlled(candidate.resolvedPath) else {
            if let version = bundleVersion(resolvedPath: candidate.resolvedPath) {
                item.version = version
                item.versionSource = "bundle"
            } else {
                item.versionSource = "notRun"
            }
            return item
        }
        if let result = try? await ProcessRunner.run(
            executable: candidate.resolvedPath, arguments: target.arguments,
            timeout: versionTimeout, label: "\(target.name) version"),
           !result.timedOut,
           let parsed = parseVersion(result.standardOutput + "\n" + result.standardError, pattern: target.pattern) {
            item.version = parsed.version
            item.versionString = parsed.line
            item.versionSource = "binary"
        }
        return item
    }

    private static func packageReceipt(_ path: String) async -> (id: String, version: String?)? {
        guard let result = try? await ProcessRunner.run(
            executable: "/usr/sbin/pkgutil", arguments: ["--file-info", path], timeout: 15, label: "pkgutil file-info"),
              !result.timedOut, result.exitCode == 0 else { return nil }
        var id: String?, version: String?
        for line in result.standardOutput.split(whereSeparator: \.isNewline) {
            let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            guard parts.count == 2, !parts[1].isEmpty else { continue }
            if parts[0] == "pkgid", id == nil { id = parts[1] }
            if parts[0] == "pkg-version", version == nil { version = parts[1] }
        }
        return id.map { ($0, version) }
    }
}
