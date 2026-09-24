import Foundation
import XCTest
@testable import ReportMate

final class OSQueryBinaryResolutionTests: XCTestCase {
    private var dir: URL!

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: dir)
    }

    private func executable(_ name: String) throws -> String {
        let path = dir.appendingPathComponent(name).path
        FileManager.default.createFile(atPath: path, contents: Data("#!/bin/sh\n".utf8), attributes: [.posixPermissions: 0o755])
        return path
    }

    /// `osqueryi` still links into an osquery install that has since been removed.
    private func danglingLink(_ name: String) throws -> String {
        let path = dir.appendingPathComponent(name).path
        try FileManager.default.createSymbolicLink(atPath: path, withDestinationPath: "/opt/removed/osquery.app/Contents/MacOS/osqueryd")
        return path
    }

    func testWorkingConfiguredPathIsUsedAsIs() throws {
        let configured = try executable("osqueryi")
        let resolved = OSQueryService.resolveOsqueryBinary(configured: configured, fallbacks: [], searchRoot: dir.path)
        XCTAssertEqual(resolved.path, configured)
        XCTAssertEqual(resolved.shellArgs, [])
    }

    func testBrokenLinkFallsBackToAppBundleBinaryInShellMode() throws {
        let configured = try danglingLink("osqueryi")
        let osqueryd = try executable("osqueryd")
        let resolved = OSQueryService.resolveOsqueryBinary(configured: configured, fallbacks: [osqueryd], searchRoot: dir.path)
        XCTAssertEqual(resolved.path, osqueryd)
        XCTAssertEqual(resolved.shellArgs, ["-S"])
    }

    func testBrokenLinkPrefersAnotherOsqueryiLink() throws {
        let configured = try danglingLink("broken-osqueryi")
        let other = try executable("osqueryi")
        let osqueryd = try executable("osqueryd")
        let resolved = OSQueryService.resolveOsqueryBinary(configured: configured, fallbacks: [other, osqueryd], searchRoot: dir.path)
        XCTAssertEqual(resolved.path, other)
        XCTAssertEqual(resolved.shellArgs, [])
    }

    /// A binary that never answers must not hold up the bash fallback past the probe budget.
    func testHungOsqueryReportsUnavailableWithinProbeBudget() async throws {
        let hung = dir.appendingPathComponent("osqueryi").path
        FileManager.default.createFile(atPath: hung, contents: Data("#!/bin/sh\nexec sleep 120\n".utf8), attributes: [.posixPermissions: 0o755])
        var configuration = ReportMateConfiguration()
        configuration.osqueryPath = hung
        configuration.extensionEnabled = false

        let start = Date()
        let available = await OSQueryService(configuration: configuration).isAvailable()
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
            searchRoot: dir.path
        )
        XCTAssertEqual(URL(fileURLWithPath: resolved.path).resolvingSymlinksInPath(), URL(fileURLWithPath: relocated).resolvingSymlinksInPath())
        XCTAssertEqual(resolved.shellArgs, ["-S"])
    }

    func testNothingRunnableKeepsConfiguredPath() throws {
        let configured = try danglingLink("osqueryi")
        let resolved = OSQueryService.resolveOsqueryBinary(configured: configured, fallbacks: [dir.appendingPathComponent("absent").path], searchRoot: dir.path)
        XCTAssertEqual(resolved.path, configured)
    }
}
