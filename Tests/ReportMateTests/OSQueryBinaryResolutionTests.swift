import Foundation
import XCTest
@testable import ReportMate

final class OSQueryBinaryResolutionTests: XCTestCase {
    private var dir: URL!

    /// The ownership and permission checks without the signature check, so shell-script
    /// stand-ins for osquery can be resolved.
    private let pathOnly: (String) -> String? = { BinaryTrust.trustedRealPath($0) }

    override func setUpWithError() throws {
        let created = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: created, withIntermediateDirectories: true)
        // The temporary directory sits behind the /var link; resolved paths come back real.
        let real = try XCTUnwrap(realpath(created.path, nil))
        dir = URL(fileURLWithPath: String(cString: real))
        free(real)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: dir)
    }

    private func executable(_ name: String, script: String = "#!/bin/sh\n") throws -> String {
        let path = dir.appendingPathComponent(name).path
        FileManager.default.createFile(atPath: path, contents: Data(script.utf8), attributes: [.posixPermissions: 0o755])
        return path
    }

    /// `osqueryi` still links into an osquery install that has since been removed.
    private func danglingLink(_ name: String) throws -> String {
        let path = dir.appendingPathComponent(name).path
        try FileManager.default.createSymbolicLink(atPath: path, withDestinationPath: "/opt/removed/osquery.app/Contents/MacOS/osqueryd")
        return path
    }

    private func configuration(osquery: String, extensionPath: String? = nil) -> ReportMateConfiguration {
        var configuration = ReportMateConfiguration()
        configuration.osqueryPath = osquery
        configuration.extensionEnabled = extensionPath != nil
        configuration.osqueryExtensionPath = extensionPath
        return configuration
    }

    // MARK: Resolution

    func testWorkingConfiguredPathIsUsedAsIs() throws {
        let configured = try executable("osqueryi")
        let resolved = OSQueryService.resolveOsqueryBinary(configured: configured, fallbacks: [], searchRoot: dir.path, trust: pathOnly)
        XCTAssertEqual(resolved.path, configured)
        XCTAssertEqual(resolved.shellArgs, [])
        XCTAssertTrue(resolved.trusted)
    }

    func testBrokenLinkFallsBackToAppBundleBinaryInShellMode() throws {
        let configured = try danglingLink("osqueryi")
        let osqueryd = try executable("osqueryd")
        let resolved = OSQueryService.resolveOsqueryBinary(configured: configured, fallbacks: [osqueryd], searchRoot: dir.path, trust: pathOnly)
        XCTAssertEqual(resolved.path, osqueryd)
        XCTAssertEqual(resolved.shellArgs, ["-S"])
    }

    func testBrokenLinkPrefersAnotherOsqueryiLink() throws {
        let configured = try danglingLink("broken-osqueryi")
        let other = try executable("osqueryi")
        let osqueryd = try executable("osqueryd")
        let resolved = OSQueryService.resolveOsqueryBinary(configured: configured, fallbacks: [other, osqueryd], searchRoot: dir.path, trust: pathOnly)
        XCTAssertEqual(resolved.path, other)
        XCTAssertEqual(resolved.shellArgs, [])
    }

    /// The standard `osqueryi` is a link to the bundle's `osqueryd`. The real path is what
    /// runs, and that binary only acts as a shell with `-S`.
    func testLinkResolvesToRealPathInShellMode() throws {
        let osqueryd = try executable("osqueryd")
        let link = dir.appendingPathComponent("osqueryi").path
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: osqueryd)
        let resolved = OSQueryService.resolveOsqueryBinary(configured: link, fallbacks: [], searchRoot: dir.path, trust: pathOnly)
        XCTAssertEqual(resolved.path, osqueryd)
        XCTAssertEqual(resolved.shellArgs, ["-S"])
    }

    /// A binary that never answers must not hold up the bash fallback past the probe budget.
    func testHungOsqueryReportsUnavailableWithinProbeBudget() async throws {
        let hung = try executable("osqueryi", script: "#!/bin/sh\nexec sleep 120\n")
        let service = OSQueryService(configuration: configuration(osquery: hung), osqueryTrust: pathOnly, extensionTrust: pathOnly)

        let start = Date()
        let available = await service.isAvailable()
        XCTAssertFalse(available)
        XCTAssertLessThan(Date().timeIntervalSince(start), OSQueryService.availabilityProbeTimeout + 5)
    }

    /// Installer relocated osquery.app onto an older copy elsewhere, so the link and the
    /// intended location are both empty and the binary has to be found.
    func testRelocatedInstallIsDiscovered() throws {
        let configured = try danglingLink("osqueryi")
        let macOS = dir.appendingPathComponent("vendor/bin/osqueryd/macos-app/stable/osquery.app/Contents/MacOS")
        try FileManager.default.createDirectory(at: macOS, withIntermediateDirectories: true)
        let relocated = macOS.appendingPathComponent("osqueryd").path
        FileManager.default.createFile(atPath: relocated, contents: Data("#!/bin/sh\n".utf8), attributes: [.posixPermissions: 0o755])

        let resolved = OSQueryService.resolveOsqueryBinary(
            configured: configured,
            fallbacks: [dir.appendingPathComponent("lib/osquery.app/Contents/MacOS/osqueryd").path],
            searchRoot: dir.path,
            trust: pathOnly
        )
        XCTAssertEqual(resolved.path, relocated)
        XCTAssertEqual(resolved.shellArgs, ["-S"])
    }

    func testNothingRunnableKeepsConfiguredPath() throws {
        let configured = try danglingLink("osqueryi")
        let resolved = OSQueryService.resolveOsqueryBinary(configured: configured, fallbacks: [dir.appendingPathComponent("absent").path], searchRoot: dir.path, trust: pathOnly)
        XCTAssertEqual(resolved.path, configured)
        XCTAssertFalse(resolved.trusted)
    }

    // MARK: Trust

    /// An osquery.app planted anywhere under the search root is only a candidate; without
    /// osquery's signature it is never chosen.
    func testUnsignedPlantedAppIsNeverChosen() throws {
        let macOS = dir.appendingPathComponent("planted/osquery.app/Contents/MacOS")
        try FileManager.default.createDirectory(at: macOS, withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: macOS.appendingPathComponent("osqueryd").path, contents: Data("#!/bin/sh\n".utf8), attributes: [.posixPermissions: 0o755])

        let resolved = OSQueryService.resolveOsqueryBinary(configured: try danglingLink("osqueryi"), fallbacks: [], searchRoot: dir.path)
        XCTAssertFalse(resolved.trusted)
    }

    func testWorldWritableDirectoryIsRejected() throws {
        let open = dir.appendingPathComponent("open")
        try FileManager.default.createDirectory(at: open, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o777])
        try FileManager.default.setAttributes([.posixPermissions: 0o777], ofItemAtPath: open.path)
        let binary = open.appendingPathComponent("osqueryi").path
        FileManager.default.createFile(atPath: binary, contents: Data("#!/bin/sh\n".utf8), attributes: [.posixPermissions: 0o755])
        XCTAssertNil(BinaryTrust.trustedRealPath(binary))
    }

    func testGroupWritableBinaryIsRejected() throws {
        let binary = try executable("osqueryi")
        try FileManager.default.setAttributes([.posixPermissions: 0o775], ofItemAtPath: binary)
        XCTAssertNil(BinaryTrust.trustedRealPath(binary))
    }

    func testBinaryOwnedBySomeoneElseIsRejected() throws {
        let binary = try executable("osqueryi")
        XCTAssertNotNil(BinaryTrust.trustedRealPath(binary))
        XCTAssertNil(BinaryTrust.trustedRealPath(binary, allowedOwners: [0]))
    }

    /// A link in a safe directory that points into an unsafe one is judged by its target.
    func testLinkIntoWritableDirectoryIsRejected() throws {
        let open = dir.appendingPathComponent("open")
        try FileManager.default.createDirectory(at: open, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o777], ofItemAtPath: open.path)
        let target = open.appendingPathComponent("osqueryd").path
        FileManager.default.createFile(atPath: target, contents: Data("#!/bin/sh\n".utf8), attributes: [.posixPermissions: 0o755])
        let link = dir.appendingPathComponent("osqueryi").path
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: target)
        XCTAssertNil(BinaryTrust.trustedRealPath(link))
    }

    func testInstalledOsqueryIsTrusted() throws {
        let installed = OSQueryService.bundledOsquerydPath
        try XCTSkipUnless(FileManager.default.isExecutableFile(atPath: installed), "osquery is not installed")
        XCTAssertEqual(BinaryTrust.trustedOsquery("/usr/local/bin/osqueryi"), installed)
    }

    /// An untrusted binary is never launched, not even for the availability probe.
    func testUntrustedBinaryIsNeverExecuted() async throws {
        let marker = dir.appendingPathComponent("ran").path
        let binary = try executable("osqueryi", script: "#!/bin/sh\ntouch '\(marker)'\necho '[]'\n")
        let service = OSQueryService(configuration: configuration(osquery: binary), osqueryTrust: { _ in nil }, extensionTrust: { _ in nil })

        let available = await service.isAvailable()
        XCTAssertFalse(available)
        do {
            _ = try await service.executeQuery("SELECT 1")
            XCTFail("an untrusted binary must not be queried")
        } catch {}
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker))
    }

    /// Extension queries reach osquery on stdin with no shell in between, so quotes and
    /// command substitutions in the query or the paths stay inert text.
    func testExtensionQueryIsPassedWithoutAShell() async throws {
        let marker = dir.appendingPathComponent("injected").path
        // A file name cannot hold a slash, so the extension's own substitution names a
        // relative marker; a shell would create it in the working directory it inherited.
        let relativeMarker = "injected-\(UUID().uuidString)"
        let relativeMarkerPaths = [dir.path, FileManager.default.currentDirectoryPath]
            .map { ($0 as NSString).appendingPathComponent(relativeMarker) }
        let received = dir.appendingPathComponent("received").path
        let arguments = dir.appendingPathComponent("arguments").path
        let binary = try executable(
            "osqueryi",
            script: "#!/bin/sh\nprintf '%s\\n' \"$@\" > '\(arguments)'\ncat > '\(received)'\necho '[{\"ok\":\"1\"}]'\n"
        )
        let extensionPath = try executable("ext $(touch \(relativeMarker)) `touch \(relativeMarker)`.ext")
        XCTAssertTrue(FileManager.default.isExecutableFile(atPath: extensionPath))
        let query = "SELECT * FROM mdm WHERE x = '$(touch \(marker))' OR y = '`touch \(marker)`'; touch \(marker)"

        var config = configuration(osquery: binary, extensionPath: extensionPath)
        config.extensionQueryTimeoutSeconds = 30
        let service = OSQueryService(configuration: config, osqueryTrust: pathOnly, extensionTrust: pathOnly)

        let rows = try await service.executeQuery(query)
        XCTAssertEqual(rows.first?["ok"] as? String, "1")
        // The configured extension, not one installed on the host, is what osquery was given.
        let passed = try String(contentsOfFile: arguments, encoding: .utf8).split(separator: "\n").map(String.init)
        XCTAssertEqual(passed.firstIndex(of: "--extension").map { passed[$0 + 1] }, extensionPath)
        XCTAssertEqual(try String(contentsOfFile: received, encoding: .utf8), "\(query)\n.exit\n")
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker))
        for path in relativeMarkerPaths {
            XCTAssertFalse(FileManager.default.fileExists(atPath: path))
        }
    }
}
