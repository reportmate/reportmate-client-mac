import XCTest
@testable import ReportMate

final class SystemBinaryInventoryTests: XCTestCase {
    private func pattern(_ name: String) -> String {
        SystemBinaryInventory.targets.first { $0.name == name }!.pattern
    }

    func testVersionOutputsParse() {
        let cases: [(String, String, String)] = [
            ("httpd", "Server version: Apache/2.4.67 (Unix)\nServer built:   Oct  3 2026", "2.4.67"),
            ("sshd", "OpenSSH_10.5p1, LibreSSL 3.3.6", "10.5p1"),
            ("openssl", "LibreSSL 3.3.6", "3.3.6"),
            ("openssl", "OpenSSL 3.4.1 11 Feb 2025 (Library: OpenSSL 3.4.1 11 Feb 2025)", "3.4.1"),
            ("nginx", "nginx version: nginx/1.27.4", "1.27.4"),
            ("node", "v22.11.0", "22.11.0"),
            ("java", "openjdk version \"21.0.5\" 2024-10-15 LTS", "21.0.5"),
            ("perl", "This is perl 5, version 34, subversion 1 (v5.34.1) built for darwin", "5.34.1"),
            ("php", "PHP 8.3.14 (cli) (built: Nov 19 2024)", "8.3.14"),
            ("postgres", "postgres (PostgreSQL) 17.2", "17.2"),
            ("redis-server", "Redis server v=7.4.1 sha=00000000:0 malloc=libc", "7.4.1"),
            ("sudo", "Sudo version 1.9.13p2\nSudoers policy plugin version 1.9.13p2", "1.9.13p2"),
        ]
        for (name, output, expected) in cases {
            XCTAssertEqual(SystemBinaryInventory.parseVersion(output, pattern: pattern(name))?.version, expected, name)
        }
        XCTAssertNil(SystemBinaryInventory.parseVersion("usage: httpd [-D name]", pattern: pattern("httpd")))
    }

    func testHomebrewCellarPathGivesFormulaAndVersion() {
        let brew = SystemBinaryInventory.homebrewPackage(resolvedPath: "/opt/homebrew/Cellar/httpd/2.4.62_1/bin/httpd")
        XCTAssertEqual(brew?.formula, "httpd")
        XCTAssertEqual(brew?.version, "2.4.62")
        XCTAssertEqual(brew?.packageVersion, "2.4.62_1")
        XCTAssertEqual(SystemBinaryInventory.homebrewPackage(resolvedPath: "/opt/homebrew/Cellar/openssl@3/3.4.1/bin/openssl")?.version, "3.4.1")
        XCTAssertNil(SystemBinaryInventory.homebrewPackage(resolvedPath: "/usr/sbin/httpd"))
    }

    func testSourceFollowsLocation() {
        XCTAssertEqual(SystemBinaryInventory.source(resolvedPath: "/usr/sbin/httpd"), "os")
        XCTAssertEqual(SystemBinaryInventory.source(resolvedPath: "/usr/local/bin/node"), "unknown")
        XCTAssertEqual(SystemBinaryInventory.source(resolvedPath: "/usr/local/Cellar/node/22.1.0/bin/node"), "homebrew")
        XCTAssertEqual(SystemBinaryInventory.source(resolvedPath: "/opt/local/sbin/nginx"), "macports")
        XCTAssertEqual(SystemBinaryInventory.source(resolvedPath: "/Library/Developer/CommandLineTools/usr/bin/git"), "developerTools")
    }

    func testRunningCountsIncludeFrameworkPythonInterpreter() {
        let processes = SystemBinaryInventory.processPaths(psOutput: """
            /usr/sbin/httpd
            /usr/sbin/httpd
            /Library/Frameworks/Python.framework/Versions/3.12/Resources/Python.app/Contents/MacOS/Python
            launchd
            """)
        XCTAssertEqual(SystemBinaryInventory.processCount(resolvedPath: "/usr/sbin/httpd", name: "httpd", processes: processes), 2)
        XCTAssertEqual(SystemBinaryInventory.processCount(
            resolvedPath: "/Library/Frameworks/Python.framework/Versions/3.12/bin/python3.12", name: "python3", processes: processes), 1)
        XCTAssertEqual(SystemBinaryInventory.processCount(resolvedPath: "/usr/sbin/sshd", name: "sshd", processes: processes), 0)
    }

    func testBundleVersionComesOnlyFromPythonFrameworksAndJdks() {
        XCTAssertEqual(SystemBinaryInventory.bundleVersionPlist(
            resolvedPath: "/Library/Frameworks/Python.framework/Versions/3.11/bin/python3.11")?.plist,
            "/Library/Frameworks/Python.framework/Versions/3.11/Resources/Info.plist")
        XCTAssertEqual(SystemBinaryInventory.bundleVersionPlist(
            resolvedPath: "/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home/bin/java")?.plist,
            "/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Info.plist")
        XCTAssertNil(SystemBinaryInventory.bundleVersionPlist(resolvedPath: "/Applications/Example.app/Contents/Resources/node/bin/node"))
        XCTAssertNil(SystemBinaryInventory.parseVersion("openrsync: protocol version 29", pattern: pattern("rsync")))
        XCTAssertEqual(SystemBinaryInventory.parseVersion("rsync  version 3.1.1  protocol version 31", pattern: pattern("rsync"))?.version, "3.1.1")
    }

    func testOnlyRootControlledFilesAreRun() {
        XCTAssertTrue(SystemBinaryInventory.isRootControlled("/usr/sbin/httpd"))
        let temp = FileManager.default.temporaryDirectory.appendingPathComponent("rm-binary-\(UUID().uuidString)")
        FileManager.default.createFile(atPath: temp.path, contents: Data())
        defer { try? FileManager.default.removeItem(at: temp) }
        XCTAssertFalse(SystemBinaryInventory.isRootControlled(temp.path))
    }
}
