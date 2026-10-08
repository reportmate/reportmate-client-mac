import XCTest
@testable import ReportMate

final class MunkiLivenessTests: XCTestCase {
    private let utc = TimeZone(identifier: "UTC")!

    private func date(_ iso: String) -> Date {
        ISO8601DateFormatter().date(from: iso)!
    }

    func testNoRunningMunkiReturnsNil() {
        let ps = """
        Wed Oct  7 01:00:00 2026     /sbin/launchd
        Wed Oct  7 01:05:00 2026     /usr/bin/tail -f /Library/Managed Installs/Logs/ManagedSoftwareUpdate.log
        Wed Oct  7 01:06:00 2026     grep managedsoftwareupdate
        """
        XCTAssertNil(InstallsModuleProcessor.oldestRunningMunkiStart(psOutput: ps, timeZone: utc))
    }

    func testOldestRunIsReportedAcrossLaunchForms() {
        let ps = """
        Tue Oct  6 23:15:02 2026     /usr/local/munki/supervisor --delayrandom 3600 --timeout 43200 -- /usr/local/munki/managedsoftwareupdate --auto
        Wed Oct  7 02:00:10 2026     /usr/local/munki/Python.framework/Versions/Current/Resources/Python.app/Contents/MacOS/Python /usr/local/munki/managedsoftwareupdate --auto
        Mon Sep 28 10:30:00 2026     /usr/local/munki/managedsoftwareupdate --version
        """
        XCTAssertEqual(
            InstallsModuleProcessor.oldestRunningMunkiStart(psOutput: ps, timeZone: utc),
            date("2026-10-06T23:15:02Z")
        )
    }

    func testBareArgvZeroFromSudoIsMatched() {
        let ps = """
        Wed Oct  7 03:00:00 2026     sudo managedsoftwareupdate -v
        Wed Oct  7 03:00:01 2026     managedsoftwareupdate -v
        Wed Oct  7 03:01:00 2026     less managedsoftwareupdate
        """
        XCTAssertEqual(
            InstallsModuleProcessor.oldestRunningMunkiStart(psOutput: ps, timeZone: utc),
            date("2026-10-07T03:00:01Z")
        )
    }

    func testSingleDigitAndDoubleDigitDaysParse() {
        let ps = """
        Sat Oct 17 09:41:00 2026     /usr/local/munki/managedsoftwareupdate --auto
        """
        XCTAssertEqual(
            InstallsModuleProcessor.oldestRunningMunkiStart(psOutput: ps, timeZone: utc),
            date("2026-10-17T09:41:00Z")
        )
    }

    func testReportModifiedTimeReadsFileMtime() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("ManagedInstallReport-\(UUID().uuidString).plist")
        try Data("<plist/>".utf8).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let stamp = date("2026-10-01T12:00:00Z")
        try FileManager.default.setAttributes([.modificationDate: stamp], ofItemAtPath: url.path)

        XCTAssertEqual(InstallsModuleProcessor.reportModifiedTime(atPath: url.path), stamp)
        XCTAssertNil(InstallsModuleProcessor.reportModifiedTime(atPath: url.path + ".missing"))
    }
}
