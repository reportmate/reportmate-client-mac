import XCTest
@testable import App

final class LaunchdServicesTests: XCTestCase {
    func testIntervalInPlainWords() {
        XCTAssertEqual(LaunchdServices.describeInterval(3_600), "Every hour")
        XCTAssertEqual(LaunchdServices.describeInterval(14_400), "Every 4 hours")
        XCTAssertEqual(LaunchdServices.describeInterval(86_400), "Every day")
        XCTAssertEqual(LaunchdServices.describeInterval(900), "Every 15 minutes")
        XCTAssertEqual(LaunchdServices.describeInterval(45), "Every 45 seconds")
    }

    func testRunAtLoadDependsOnKind() {
        XCTAssertEqual(LaunchdServices.describeSchedule(["RunAtLoad": true], kind: .daemon), "At startup")
        XCTAssertEqual(LaunchdServices.describeSchedule(["RunAtLoad": true], kind: .agent), "At login")
    }

    func testCombinedSchedule() {
        let plist: [String: Any] = ["RunAtLoad": true, "StartInterval": 3_600, "KeepAlive": true]
        XCTAssertEqual(LaunchdServices.describeSchedule(plist, kind: .daemon),
                       "At startup, every hour, kept running; restarted if it quits")
    }

    func testCalendarIntervals() {
        XCTAssertEqual(LaunchdServices.describeSchedule(["StartCalendarInterval": ["Hour": 9, "Minute": 30]], kind: .daemon),
                       "Daily at 09:30")
        XCTAssertEqual(LaunchdServices.describeSchedule(["StartCalendarInterval": ["Minute": 5]], kind: .daemon),
                       "Every hour at :05")
        XCTAssertEqual(LaunchdServices.describeSchedule(["StartCalendarInterval": ["Weekday": 1, "Hour": 8, "Minute": 0]], kind: .daemon),
                       "Mondays at 08:00")
        let twice: [[String: Any]] = [["Hour": 9, "Minute": 0], ["Hour": 13, "Minute": 15]]
        XCTAssertEqual(LaunchdServices.describeSchedule(["StartCalendarInterval": twice], kind: .daemon),
                       "Daily at 09:00, 13:15")
    }

    func testOnDemandJobs() {
        XCTAssertEqual(LaunchdServices.describeSchedule(["MachServices": ["x.helper": true]], kind: .daemon),
                       "On demand, when an app connects to it")
        XCTAssertEqual(LaunchdServices.describeSchedule([:], kind: .daemon), "On demand")
    }

    func testParsePrintRunning() {
        let output = """
        system/com.example.tool = {
        \tactive count = 1
        \tstate = running
        \tpid = 412
        \tlast exit code = (never exited)
        \tenvironment = {
        \t\tstate = ignored
        \t}
        }
        """
        let status = LaunchdServices.parsePrint(output)
        XCTAssertEqual(status.state, .running(pid: 412))
        XCTAssertNil(status.lastExitCode)
    }

    func testParsePrintIdle() {
        let output = "system/com.example.tool = {\n\tstate = not running\n\tlast exit code = 1\n}\n"
        let status = LaunchdServices.parsePrint(output)
        XCTAssertEqual(status.state, .loaded)
        XCTAssertEqual(status.lastExitCode, "1")
    }

    func testJobNeedsLabel() {
        XCTAssertNil(LaunchdServices.job(fromPlist: [:], path: "/x.plist", kind: .daemon))
        XCTAssertEqual(LaunchdServices.job(fromPlist: ["Label": "com.example.tool"], path: "/x.plist", kind: .agent)?.id,
                       "agent:com.example.tool")
    }

    func testServiceTarget() {
        let daemon = LaunchdJob(label: "com.example.d", kind: .daemon, plistPath: "", schedule: "")
        let agent = LaunchdJob(label: "com.example.a", kind: .agent, plistPath: "", schedule: "")
        XCTAssertEqual(LaunchdServices.serviceTarget(for: daemon, uid: 501), "system/com.example.d")
        XCTAssertEqual(LaunchdServices.serviceTarget(for: agent, uid: 501), "gui/501/com.example.a")
    }
}
