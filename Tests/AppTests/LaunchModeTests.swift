import XCTest
@testable import App

final class LaunchModeTests: XCTestCase {
    private let bundle = "/Applications/Utilities/Managed Reports Runner.app/Contents/MacOS"

    func testRunnerNameSelectsCollector() {
        XCTAssertTrue(LaunchMode.isCommandLine(["\(bundle)/managedreportsrunner"]))
        XCTAssertTrue(LaunchMode.isCommandLine(["/usr/local/bin/managedreportsrunner", "--hello"]))
    }

    func testPlainLaunchOpensWindow() {
        XCTAssertFalse(LaunchMode.isCommandLine(["\(bundle)/ReportMateApp"]))
        XCTAssertFalse(LaunchMode.isCommandLine(["\(bundle)/ReportMateApp", "-psn_0_12345"]))
        XCTAssertFalse(LaunchMode.isCommandLine(["\(bundle)/ReportMateApp", "-NSDocumentRevisionsDebugMode", "YES"]))
    }

    func testCollectorArgumentsSelectCollector() {
        XCTAssertTrue(LaunchMode.isCommandLine(["\(bundle)/ReportMateApp", "--run-modules", "hardware"]))
        XCTAssertTrue(LaunchMode.isCommandLine(["\(bundle)/ReportMateApp", "-vv"]))
    }
}
