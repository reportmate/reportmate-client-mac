import Foundation

/// Survey of the management tool log roots on the Mac, reported as the `logs`
/// section of the management module.
///
/// The convention puts each tool's logs under `/Library/Managed <Tool>/logs`
/// (Managed Installs for Munki, Managed Bootstrap for BootstrapMate, Managed Reports
/// for ReportMate, Managed State for Outset, ...). Two kinds of root live outside
/// it and are surveyed from a fixed table (`knownRoots`): the MDM agent's logs
/// (Intune's daemon under /Library/Logs/Microsoft/Intune, Jamf's /var/log/jamf.log)
/// reported as `mdm`, and the OS installer log /var/log/install.log reported as
/// `installer`. For each root this reports the
/// file inventory, the latest session summary when the tool writes Cimian-style
/// `YYYY-MM-DD/HHMM/session.json` directories, error and warning counts, and capped
/// tails of the most relevant logs. The Windows client does the same over
/// `C:\ProgramData\Managed*\logs`, with the same JSON shape under `management.logs`.
/// Pure file-system survey, kept free of the module plumbing so it can be run
/// against a temporary root in tests.
public enum ManagedLogSurvey {

    /// The management module's `logs` section: `{ platform, roots }` as plain
    /// JSON-compatible dictionaries.
    public static func managementSection(libraryPath: String = "/Library", systemRoot: String = "/") -> [String: Any] {
        let roots = surveyKnown(systemRoot: systemRoot) + surveyAll(libraryPath: libraryPath)
        ConsoleFormatter.writeDebug("Managed log survey found \(roots.count) roots")
        var encodedRoots: [Any] = []
        if let data = try? JSONEncoder().encode(roots),
           let array = (try? JSONSerialization.jsonObject(with: data)) as? [Any] {
            encodedRoots = array
        }
        return ["platform": "macOS", "roots": encodedRoots]
    }

    /// Roots reported per device.
    public static let maxRoots = 20
    /// Files listed per root (root-level files plus the latest session's files).
    public static let maxFiles = 50
    /// Logs tailed per root: the primary log plus the next most recent ones (session.json included).
    public static let maxTails = 6
    /// Entries visited while sizing a root. A logs directory can hold tens of
    /// thousands of per-run subdirectories when a tool's retention has failed;
    /// the walk stops here and marks the inventory as a floor.
    public static let walkBudget = 5_000
    /// Tail limits. The primary log is the run people read top to bottom, so its
    /// cap fits a whole ordinary run (a Munki or Cimian run.log is 400-600 lines,
    /// 35-40 KB); the other tails only need their most recent lines.
    public static let primaryTailLines = 2_000
    public static let primaryTailBytes = 256 * 1024
    public static let tailLines = 150
    public static let tailBytes = 32 * 1024

    static let dayPattern = try! NSRegularExpression(pattern: "^\\d{4}-\\d{2}-\\d{2}$")
    static let sessionPattern = try! NSRegularExpression(pattern: "^\\d{4}(_\\d)?$")
    static let errorPattern = try! NSRegularExpression(pattern: "\\b(ERROR|ERR|FAULT|CRITICAL|FATAL)\\b")
    static let warningPattern = try! NSRegularExpression(pattern: "\\b(WARN|WARNING|WRN)\\b")

    /// How a root's lines carry their severity. Generic logs are classified by
    /// the ERROR/WARN words; the Intune daemon writes a fixed pipe-separated
    /// record whose third field is I, W or E.
    public enum LineFormat: Sendable {
        case generic
        case intuneDaemon
    }

    /// A log root that lives outside `/Library/Managed *`: the MDM agent's logs and
    /// the OS installer log. Detection is by directory or file existence, so a
    /// device reports only the roots it actually has. `filePattern` selects the
    /// files inside `directory` that belong to the root, which lets several roots
    /// share `/var/log`.
    public struct KnownRoot: Sendable {
        public let tool: String
        public let name: String
        public let directory: String
        public let filePattern: NSRegularExpression
        public let primaryLog: String?
        public let lineFormat: LineFormat
    }

    /// Roots surveyed on every device, in report order: MDM agents first, then the
    /// installer log. One entry per MDM; the first whose files exist is the
    /// device's MDM (a Mac has one). Only paths verified on a real device belong
    /// here; add other MDMs once their log location is confirmed.
    public static let knownRoots: [KnownRoot] = [
        KnownRoot(tool: "mdm", name: "Intune",
                  directory: "Library/Logs/Microsoft/Intune",
                  filePattern: try! NSRegularExpression(pattern: "^IntuneMDMDaemon .*\\.log$"),
                  primaryLog: nil, lineFormat: .intuneDaemon),
        KnownRoot(tool: "mdm", name: "Jamf",
                  directory: "var/log",
                  filePattern: try! NSRegularExpression(pattern: "^jamf\\.log$"),
                  primaryLog: "jamf.log", lineFormat: .generic),
        KnownRoot(tool: "installer", name: "Installer",
                  directory: "var/log",
                  filePattern: try! NSRegularExpression(pattern: "^install\\.log(\\.\\d+\\.gz)?$"),
                  primaryLog: "install.log", lineFormat: .generic),
    ]

    /// The known roots present on this device. `systemRoot` is "/" in production
    /// and a temporary directory in tests.
    public static func surveyKnown(systemRoot: String) -> [LogRoot] {
        var roots: [LogRoot] = []
        var seenTools = Set<String>()
        for known in knownRoots where !seenTools.contains(known.tool) {
            let dir = (systemRoot as NSString).appendingPathComponent(known.directory)
            guard isDirectory(dir), let root = surveyKnown(known, directory: dir) else { continue }
            roots.append(root)
            seenTools.insert(known.tool)
        }
        return roots
    }

    /// Flat survey of one known root: the matching files in its directory, newest
    /// first, with tails of the text logs among them. Returns nil when no file
    /// matches, so an installed-then-removed agent drops out of the report.
    static func surveyKnown(_ known: KnownRoot, directory: String) -> LogRoot? {
        let entries = ((try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? [])
            .filter { matches(known.filePattern, $0) }
        var files: [LogFileEntry] = []
        for entry in entries {
            let full = (directory as NSString).appendingPathComponent(entry)
            if let file = fileEntry(fullPath: full, relativePath: entry) { files.append(file) }
        }
        guard !files.isEmpty else { return nil }
        files.sort { ($0.modified ?? "") > ($1.modified ?? "") }
        let totalBytes = files.reduce(Int64(0)) { $0 + $1.bytes }
        let newest = files.first?.modified
        let fileCount = files.count
        if files.count > maxFiles { files = Array(files.prefix(maxFiles)) }

        let primary: String?
        if let fixed = known.primaryLog, entries.contains(fixed) {
            primary = fixed
        } else {
            primary = newestLog(in: directory, entries: entries)
        }
        var tails: [LogTail] = []
        var errors = 0
        var warnings = 0
        for relative in tailCandidates(primary: primary, files: files) {
            let full = (directory as NSString).appendingPathComponent(relative)
            let t = readTail(fullPath: full, relativePath: relative, isPrimary: relative == primary)
            if t.lines.isEmpty && relative != primary { continue }
            tails.append(t)
            if tails.count >= maxTails { break }
        }
        if let first = tails.first, first.file == primary {
            for line in first.lines {
                switch classify(line, format: known.lineFormat) {
                case .error: errors += 1
                case .warning: warnings += 1
                case .plain: break
                }
            }
        }
        return LogRoot(
            tool: known.tool,
            name: known.name,
            path: directory,
            layout: "flat",
            fileCount: fileCount,
            totalBytes: totalBytes,
            newestModified: newest,
            inventoryTruncated: false,
            files: files,
            latestSession: nil,
            primaryLog: primary,
            errorCount: errors,
            warningCount: warnings,
            tails: tails
        )
    }

    enum Severity { case error, warning, plain }

    /// Severity of one log line under a root's line format.
    static func classify(_ line: String, format: LineFormat) -> Severity {
        switch format {
        case .generic:
            if matches(errorPattern, line) { return .error }
            if matches(warningPattern, line) { return .warning }
            return .plain
        case .intuneDaemon:
            // yyyy-MM-dd HH:mm:ss:SSS | IntuneMDM-Daemon | E | thread | logger | message
            let fields = line.split(separator: "|", maxSplits: 3, omittingEmptySubsequences: false)
            guard fields.count >= 3 else { return .plain }
            switch fields[2].trimmingCharacters(in: .whitespaces) {
            case "E": return .error
            case "W": return .warning
            default: return .plain
            }
        }
    }

    /// Every `Managed*` directory under `libraryPath` that has a `logs` subdirectory.
    public static func surveyAll(libraryPath: String) -> [LogRoot] {
        let fm = FileManager.default
        guard let entries = try? fm.contentsOfDirectory(atPath: libraryPath) else { return [] }
        var roots: [LogRoot] = []
        for entry in entries.sorted() where entry.hasPrefix("Managed") {
            let rootDir = (libraryPath as NSString).appendingPathComponent(entry)
            guard let logsDir = logsDirectory(in: rootDir) else { continue }
            if let root = survey(rootDir: rootDir, logsDir: logsDir) {
                roots.append(root)
            }
            if roots.count >= maxRoots { break }
        }
        return roots
    }

    /// `logs` is the convention; `Logs` is accepted for roots that predate it, and
    /// on a case-sensitive volume the two are different directories.
    static func logsDirectory(in rootDir: String) -> String? {
        for name in ["logs", "Logs"] {
            let candidate = (rootDir as NSString).appendingPathComponent(name)
            if isDirectory(candidate) { return candidate }
        }
        return nil
    }

    public static func survey(rootDir: String, logsDir: String) -> LogRoot? {
        let fm = FileManager.default
        let dirName = (rootDir as NSString).lastPathComponent
        let tool = toolKey(from: dirName)
        guard !tool.isEmpty else { return nil }

        // Session layout: logs/YYYY-MM-DD/HHMM/
        var latestSessionDir: String? = nil
        var latestSessionId: String? = nil
        let topEntries = (try? fm.contentsOfDirectory(atPath: logsDir)) ?? []
        let dayDirs = topEntries
            .filter { matches(dayPattern, $0) && isDirectory((logsDir as NSString).appendingPathComponent($0)) }
            .sorted(by: >)
        for day in dayDirs {
            let dayPath = (logsDir as NSString).appendingPathComponent(day)
            let sessions = ((try? fm.contentsOfDirectory(atPath: dayPath)) ?? [])
                .filter { matches(sessionPattern, $0) && isDirectory((dayPath as NSString).appendingPathComponent($0)) }
                .sorted(by: >)
            if let newest = sessions.first {
                latestSessionDir = (dayPath as NSString).appendingPathComponent(newest)
                latestSessionId = "\(day)-\(newest)"
                break
            }
        }
        let layout = latestSessionDir == nil ? "flat" : "sessions"

        // Inventory: root-level files plus the latest session's files, newest first.
        var files: [LogFileEntry] = []
        for entry in topEntries {
            let full = (logsDir as NSString).appendingPathComponent(entry)
            if let file = fileEntry(fullPath: full, relativePath: entry) { files.append(file) }
        }
        if let sessionDir = latestSessionDir {
            let rel = relativePath(of: sessionDir, under: logsDir)
            for entry in (try? fm.contentsOfDirectory(atPath: sessionDir)) ?? [] {
                let full = (sessionDir as NSString).appendingPathComponent(entry)
                if let file = fileEntry(fullPath: full, relativePath: rel + "/" + entry) { files.append(file) }
            }
        }
        files.sort { ($0.modified ?? "") > ($1.modified ?? "") }
        if files.count > maxFiles { files = Array(files.prefix(maxFiles)) }

        let sized = sizeTree(logsDir)

        // Latest session summary from session.json (Cimian, the Munki fork, StartSet).
        var latestSession: LogSessionSummary? = nil
        if let sessionDir = latestSessionDir {
            latestSession = readSession(at: (sessionDir as NSString).appendingPathComponent("session.json"), fallbackId: latestSessionId)
        }

        // Tails: the primary log first, then the next most recent logs in the root.
        let primary = primaryLog(logsDir: logsDir, sessionDir: latestSessionDir, topEntries: topEntries)
        var tails: [LogTail] = []
        var errors = 0
        var warnings = 0
        for relative in tailCandidates(primary: primary, files: files) {
            let full = (logsDir as NSString).appendingPathComponent(relative)
            let t = readTail(fullPath: full, relativePath: relative, isPrimary: relative == primary)
            if t.lines.isEmpty && relative != primary { continue }
            tails.append(t)
            if tails.count >= maxTails { break }
        }
        if let first = tails.first, first.file == primary {
            for line in first.lines {
                if matches(errorPattern, line) { errors += 1 } else if matches(warningPattern, line) { warnings += 1 }
            }
        }

        return LogRoot(
            tool: tool,
            name: dirName,
            path: logsDir,
            layout: layout,
            fileCount: sized.count,
            totalBytes: sized.bytes,
            newestModified: sized.newest,
            inventoryTruncated: sized.truncated,
            files: files,
            latestSession: latestSession,
            primaryLog: primary,
            errorCount: errors,
            warningCount: warnings,
            tails: tails
        )
    }

    /// "Managed Installs" -> "installs"; "ManagedInstalls" -> "installs"
    public static func toolKey(from directoryName: String) -> String {
        var name = directoryName
        if name.lowercased().hasPrefix("managed") { name = String(name.dropFirst("managed".count)) }
        return name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            .replacingOccurrences(of: " ", with: "")
    }

    /// Text logs worth tailing, primary first, then newest first. `files` is already
    /// sorted newest first and holds the root-level files plus the latest session's.
    static func tailCandidates(primary: String?, files: [LogFileEntry]) -> [String] {
        var ordered: [String] = []
        if let primary = primary { ordered.append(primary) }
        for file in files where isTextLog(file.name) && !ordered.contains(file.path) {
            ordered.append(file.path)
        }
        return ordered
    }

    static func isTextLog(_ name: String) -> Bool {
        let lower = name.lowercased()
        return lower.hasSuffix(".log") || lower.hasSuffix(".jsonl") || lower.hasSuffix(".json") || lower.hasSuffix(".txt")
    }

    static func relativePath(of path: String, under base: String) -> String {
        guard path.hasPrefix(base) else { return path }
        var rel = String(path.dropFirst(base.count))
        if rel.hasPrefix("/") { rel.removeFirst() }
        return rel
    }

    static func primaryLog(logsDir: String, sessionDir: String?, topEntries: [String]) -> String? {
        if let sessionDir = sessionDir {
            let rel = relativePath(of: sessionDir, under: logsDir)
            let entries = (try? FileManager.default.contentsOfDirectory(atPath: sessionDir)) ?? []
            for preferred in ["run.log", "install.log", "startset.log", "outset.log", "bootstrap.log"] where entries.contains(preferred) {
                return rel + "/" + preferred
            }
            if let newest = newestLog(in: sessionDir, entries: entries) { return rel + "/" + newest }
        }
        let logs = topEntries.filter { $0.lowercased().hasSuffix(".log") }
        let preferred = logs.filter { !$0.lowercased().hasSuffix(".error.log") }
        if let newest = newestLog(in: logsDir, entries: preferred.isEmpty ? logs : preferred) { return newest }
        return nil
    }

    static func newestLog(in dir: String, entries: [String]) -> String? {
        var best: (name: String, modified: Date)? = nil
        for entry in entries where entry.lowercased().hasSuffix(".log") {
            let full = (dir as NSString).appendingPathComponent(entry)
            guard let attrs = try? FileManager.default.attributesOfItem(atPath: full),
                  (attrs[.type] as? FileAttributeType) == .typeRegular else { continue }
            let modified = (attrs[.modificationDate] as? Date) ?? .distantPast
            if let current = best, current.modified >= modified { continue }
            best = (entry, modified)
        }
        return best?.name
    }

    static func fileEntry(fullPath: String, relativePath: String) -> LogFileEntry? {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: fullPath),
              (attrs[.type] as? FileAttributeType) == .typeRegular else { return nil }
        let size = (attrs[.size] as? NSNumber)?.int64Value ?? 0
        let modified = (attrs[.modificationDate] as? Date).map(iso8601)
        return LogFileEntry(name: (relativePath as NSString).lastPathComponent, path: relativePath, bytes: size, modified: modified)
    }

    /// Walks the whole logs tree with an entry budget.
    static func sizeTree(_ dir: String) -> (count: Int, bytes: Int64, newest: String?, truncated: Bool) {
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(atPath: dir) else { return (0, 0, nil, false) }
        var count = 0
        var bytes: Int64 = 0
        var visited = 0
        var newest: Date? = nil
        var truncated = false
        while enumerator.nextObject() != nil {
            visited += 1
            if visited > walkBudget { truncated = true; break }
            guard let attrs = enumerator.fileAttributes,
                  (attrs[.type] as? FileAttributeType) == .typeRegular else { continue }
            count += 1
            bytes += (attrs[.size] as? NSNumber)?.int64Value ?? 0
            if let m = attrs[.modificationDate] as? Date, newest == nil || m > newest! { newest = m }
        }
        return (count, bytes, newest.map(iso8601), truncated)
    }

    static func readSession(at path: String, fallbackId: String?) -> LogSessionSummary? {
        guard let data = FileManager.default.contents(atPath: path),
              let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            return fallbackId.map {
                LogSessionSummary(sessionId: $0, status: nil, startTime: nil, endTime: nil, durationSeconds: nil, runType: nil, errors: nil, warnings: nil)
            }
        }
        func str(_ keys: String...) -> String? {
            for k in keys {
                if let s = json[k] as? String { return s }
                if let n = json[k] as? NSNumber { return n.stringValue }
            }
            return nil
        }
        func num(_ keys: String...) -> Double? {
            for k in keys { if let n = json[k] as? NSNumber { return n.doubleValue } }
            return nil
        }
        let summary = json["summary"] as? [String: Any]
        // The Munki fork's summary carries errors and warnings; Cimian's and
        // StartSet's carry failures (and no warning count), so fall back to it.
        var errors = (summary?["errors"] as? NSNumber)?.intValue
            ?? (summary?["failures"] as? NSNumber)?.intValue
        var warnings = (summary?["warnings"] as? NSNumber)?.intValue
        if errors == nil, let items = json["error_items"] as? [Any] { errors = items.count }
        if warnings == nil, let items = json["warning_items"] as? [Any] { warnings = items.count }
        return LogSessionSummary(
            sessionId: str("session_id", "sessionId") ?? fallbackId,
            status: str("status"),
            startTime: str("start_time", "startTime"),
            endTime: str("end_time", "endTime"),
            durationSeconds: num("duration_seconds", "durationSeconds"),
            runType: str("run_type", "runType"),
            errors: errors,
            warnings: warnings
        )
    }

    /// Last `tailBytes` of the file, split into at most `tailLines` lines; the
    /// primary log gets the larger caps so a whole run is shown.
    static func readTail(fullPath: String, relativePath: String, isPrimary: Bool = false) -> LogTail {
        let maxBytes = isPrimary ? primaryTailBytes : tailBytes
        let maxLines = isPrimary ? primaryTailLines : tailLines
        guard let handle = FileHandle(forReadingAtPath: fullPath) else {
            return LogTail(file: relativePath, lines: [], truncated: false, bytes: 0)
        }
        defer { try? handle.close() }
        let size = (try? handle.seekToEnd()) ?? 0
        let start = size > UInt64(maxBytes) ? size - UInt64(maxBytes) : 0
        try? handle.seek(toOffset: start)
        let data = (try? handle.readToEnd()) ?? Data()
        var text = String(decoding: data, as: UTF8.self)
        var truncated = start > 0
        if start > 0, let firstNewline = text.firstIndex(of: "\n") {
            // Drop the partial first line of a mid-file read.
            text = String(text[text.index(after: firstNewline)...])
        }
        var lines = text
            .split(separator: "\n", omittingEmptySubsequences: false)
            .map { String($0).trimmingCharacters(in: CharacterSet(charactersIn: "\r")) }
        while let last = lines.last, last.isEmpty { lines.removeLast() }
        // A .json file is one document: keep every line within the byte cap so it still parses.
        let wholeDocument = relativePath.lowercased().hasSuffix(".json")
        if !wholeDocument && lines.count > maxLines {
            lines = Array(lines.suffix(maxLines))
            truncated = true
        }
        let bytes = lines.reduce(0) { $0 + $1.utf8.count + 1 }
        return LogTail(file: relativePath, lines: lines, truncated: truncated, bytes: bytes)
    }

    static func isDirectory(_ path: String) -> Bool {
        var isDir: ObjCBool = false
        return FileManager.default.fileExists(atPath: path, isDirectory: &isDir) && isDir.boolValue
    }

    static func matches(_ regex: NSRegularExpression, _ text: String) -> Bool {
        regex.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) != nil
    }

    static func iso8601(_ date: Date) -> String {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f.string(from: date)
    }
}
