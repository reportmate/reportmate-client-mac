import XCTest
@testable import App

final class LaunchModeTests: XCTestCase {
    private let executable = "/Applications/Utilities/Managed Reports Runner.app/Contents/MacOS/managedreportsrunner"

    func testNoArgumentsOpensWindow() {
        XCTAssertEqual(LaunchMode([executable]), .window)
        XCTAssertEqual(LaunchMode([executable, "-psn_0_12345"]), .window)
        XCTAssertEqual(LaunchMode([executable, "-NSDocumentRevisionsDebugMode", "YES"]), .window)
        XCTAssertEqual(LaunchMode([]), .window)
    }

    func testRoleFlags() {
        XCTAssertEqual(LaunchMode([executable, "--helper"]), .helper)
        XCTAssertEqual(LaunchMode([executable, "--appusage"]), .appUsage)
        XCTAssertEqual(LaunchMode([executable, "--appusage", "--stats"]), .appUsage)
        XCTAssertEqual(LaunchMode([executable, "--register-daemons"]), .registerDaemons)
        XCTAssertEqual(LaunchMode([executable, "--unregister-daemons"]), .unregisterDaemons)
    }

    func testAnythingElseIsTheCollector() {
        XCTAssertEqual(LaunchMode([executable, "--run-modules", "hardware"]), .collector)
        XCTAssertEqual(LaunchMode([executable, "-vv"]), .collector)
        XCTAssertEqual(LaunchMode([executable, "--random-delay", "7200"]), .collector)
        XCTAssertEqual(LaunchMode([executable, "--hello"]), .collector)
        XCTAssertEqual(LaunchMode([executable, "-vv", "--helper"]), .collector, "a role flag only counts in first position")
    }
}
