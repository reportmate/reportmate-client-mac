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
        XCTAssertEqual(LaunchdServices.describeRunAtLoad(["RunAtLoad": true], kind: .daemon), "Yes, at startup")
        XCTAssertEqual(LaunchdServices.describeRunAtLoad(["RunAtLoad": true], kind: .agent), "Yes, at login")
        XCTAssertEqual(LaunchdServices.describeRunAtLoad([:], kind: .daemon), "No")
        let loginWindow: [String: Any] = ["LimitLoadToSessionType": ["LoginWindow"], "OnDemand": false]
        XCTAssertEqual(LaunchdServices.describeRunAtLoad(loginWindow, kind: .agent), "Yes, at the login window")
    }

    func testKeepAliveInPlainWords() {
        XCTAssertEqual(LaunchdServices.describeKeepAlive([:]), "No")
        XCTAssertEqual(LaunchdServices.describeKeepAlive(["KeepAlive": true]), "Yes, restarted if it quits")
        XCTAssertEqual(LaunchdServices.describeKeepAlive(["OnDemand": false]), "Yes, restarted if it quits")
        XCTAssertEqual(LaunchdServices.describeKeepAlive(["KeepAlive": ["PathState": ["/private/tmp/.trigger": true]]]),
                       "While its trigger file exists")
        XCTAssertEqual(LaunchdServices.describeKeepAlive(["KeepAlive": ["SuccessfulExit": false]]), "Restarted if it fails")
        XCTAssertEqual(LaunchdServices.describeKeepAlive(["KeepAlive": ["SuccessfulExit": false, "Crashed": true]]),
                       "While its conditions hold")
    }

    func testCalendarIntervals() {
        XCTAssertEqual(LaunchdServices.describeCalendar([["Hour": 9, "Minute": 30]]), "Daily at 09:30")
        XCTAssertEqual(LaunchdServices.describeCalendar([["Minute": 5]]), "Every hour at :05")
        XCTAssertEqual(LaunchdServices.describeCalendar([["Weekday": 1, "Hour": 8, "Minute": 0]]), "Mondays at 08:00")
        XCTAssertEqual(LaunchdServices.describeCalendar([["Hour": 9, "Minute": 0], ["Hour": 13, "Minute": 15]]),
                       "Daily at 09:00, 13:15")
    }

    func testCombinedSchedule() {
        let plist: [String: Any] = ["RunAtLoad": true, "StartInterval": 3_600, "KeepAlive": true]
        XCTAssertEqual(LaunchdServices.describeSchedule(plist, kind: .daemon),
                       "At startup, every hour, kept running; restarted if it quits")
    }

    func testCalendarSchedule() {
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

    func testTriggerFileAndLoginWindow() {
        let trigger: [String: Any] = ["KeepAlive": ["PathState": ["/private/tmp/.trigger": true]], "OnDemand": true]
        XCTAssertEqual(LaunchdServices.describeSchedule(trigger, kind: .daemon), "When its trigger file is created")
        let loginWindow: [String: Any] = ["LimitLoadToSessionType": ["LoginWindow"], "OnDemand": false, "LaunchOnlyOnce": true]
        XCTAssertEqual(LaunchdServices.describeSchedule(loginWindow, kind: .agent), "At the login window")
    }

    func testOnDemandJobs() {
        XCTAssertEqual(LaunchdServices.describeSchedule(["MachServices": ["x.helper": true]], kind: .daemon),
                       "On demand, when an app connects to it")
        XCTAssertEqual(LaunchdServices.describeSchedule([:], kind: .daemon), "On demand")
    }

    func testSummaryLine() {
        var job = LaunchdJob(label: "com.example.tool", kind: .daemon, plistPath: "/x.plist", schedule: "Daily at 04:00")
        XCTAssertEqual(job.summary, "Launch daemon \u{00B7} Daily at 04:00 \u{00B7} Has not exited")
        job.lastExitCode = "0"
        XCTAssertEqual(job.summary, "Launch daemon \u{00B7} Daily at 04:00 \u{00B7} Last exit 0")
        XCTAssertEqual(LaunchdJob.State.running(pid: 75412).displayName, "Running (PID 75412)")
        XCTAssertEqual(LaunchdJob.State.loaded.displayName, "Loaded, not running")
        XCTAssertEqual(LaunchdJob.State.notLoaded.displayName, "Not loaded")
    }

    func testJobReadsPlistFields() throws {
        let plist: [String: Any] = [
            "Label": "com.example.tool",
            "ProgramArguments": ["/usr/local/bin/tool", "--run", "two words"],
            "RunAtLoad": true,
            "StartInterval": 3_600,
            "StartCalendarInterval": ["Hour": 9, "Minute": 30],
            "UserName": "nobody",
            "StandardOutPath": "/var/log/tool.log"
        ]
        let job = try XCTUnwrap(LaunchdServices.job(fromPlist: plist, path: "/Library/LaunchDaemons/com.example.tool.plist", kind: .daemon))
        XCTAssertEqual(job.program, "/usr/local/bin/tool")
        XCTAssertEqual(job.arguments, ["--run", "two words"])
        XCTAssertEqual(job.runAtLoad, "Yes, at startup")
        XCTAssertEqual(job.keepAlive, "No")
        XCTAssertEqual(job.startInterval, "Every hour")
        XCTAssertEqual(job.calendarInterval, "Daily at 09:30")
        XCTAssertEqual(job.schedule, "At startup, every hour, daily at 09:30")
        XCTAssertEqual(job.userName, "nobody")
        XCTAssertEqual(job.standardOutPath, "/var/log/tool.log")
        XCTAssertNil(job.standardErrorPath)
    }

    func testFieldOrderAndLabels() {
        let job = LaunchdJob(label: "com.example.tool", kind: .daemon, plistPath: "/x.plist",
                             state: .running(pid: 412), arguments: ["--run", "two words"])
        XCTAssertEqual(job.fields.map(\.name), [
            "Type", "Status", "PID", "Last exit status", "Program", "Arguments",
            "Run at load", "Keep alive", "Start interval", "Calendar interval",
            "User", "Group", "Standard out", "Standard error", "Plist"
        ])
        let values = Dictionary(uniqueKeysWithValues: job.fields.map { ($0.name, $0.value) })
        XCTAssertEqual(values["Type"], "Launch daemon")
        XCTAssertEqual(values["Status"], "Running (PID 412)")
        XCTAssertEqual(values["PID"], "412")
        XCTAssertEqual(values["Last exit status"], "Has not exited")
        XCTAssertEqual(values["Arguments"], "--run 'two words'")
        XCTAssertEqual(values["User"], "root (default)")
        XCTAssertEqual(values["Standard out"], "Not set")
    }

    func testParsePrintRunning() {
        let output = """
        system/com.example.tool = {
        \tactive count = 1
        \tstate = running
        \tprogram = /usr/local/bin/tool
        \targuments = {
        \t\t/usr/local/bin/tool
        \t\t--auto
        \t}
        \tstdout path = /var/log/tool.log
        \tpid = 412
        \tlast exit code = (never exited)
        \tenvironment = {
        \t\tstate = ignored
        \t}
        }
        """
        let info = LaunchdServices.parsePrint(output)
        XCTAssertEqual(info.state, .running(pid: 412))
        XCTAssertNil(info.lastExitCode)
        XCTAssertEqual(info.program, "/usr/local/bin/tool")
        XCTAssertEqual(info.arguments, ["/usr/local/bin/tool", "--auto"])
        XCTAssertEqual(info.standardOutPath, "/var/log/tool.log")
        XCTAssertNil(info.standardErrorPath)
    }

    func testParsePrintIdle() {
        let output = "system/com.example.tool = {\n\tstate = not running\n\tlast exit code = 1\n}\n"
        let info = LaunchdServices.parsePrint(output)
        XCTAssertEqual(info.state, .loaded)
        XCTAssertEqual(info.lastExitCode, "1")
    }

    func testDisabledOverride() {
        let output = "\tdisabled services = {\n\t\t\"com.example.tool\" => disabled\n\t\t\"com.example.other\" => enabled\n\t}\n"
        let disabled = LaunchdServices.parseDisabled(output)
        XCTAssertEqual(disabled, ["com.example.tool"])
        let job = LaunchdJob(label: "com.example.tool", kind: .daemon, plistPath: "/x.plist")
        XCTAssertEqual(LaunchdServices.apply(.init(state: .notLoaded), to: job, disabledLabels: disabled).state, .disabled)
        XCTAssertEqual(LaunchdServices.apply(.init(state: .running(pid: 9)), to: job, disabledLabels: disabled).state, .running(pid: 9))
    }

    func testPrintFillsGapsOnly() {
        let job = LaunchdJob(label: "com.example.tool", kind: .daemon, plistPath: "/x.plist",
                             program: "/plist/program", standardOutPath: "/plist/out.log")
        let info = LaunchdServices.PrintInfo(state: .loaded, lastExitCode: "0", program: "/print/program",
                                             arguments: ["/print/program", "--flag"],
                                             standardOutPath: "/print/out.log", standardErrorPath: "/print/err.log")
        let merged = LaunchdServices.apply(info, to: job)
        XCTAssertEqual(merged.program, "/plist/program")
        XCTAssertEqual(merged.arguments, ["--flag"])
        XCTAssertEqual(merged.standardOutPath, "/plist/out.log")
        XCTAssertEqual(merged.standardErrorPath, "/print/err.log")
        XCTAssertEqual(merged.lastExitCode, "0")
    }

    func testJobNeedsLabel() {
        XCTAssertNil(LaunchdServices.job(fromPlist: [:], path: "/x.plist", kind: .daemon))
        XCTAssertEqual(LaunchdServices.job(fromPlist: ["Label": "com.example.tool"], path: "/x.plist", kind: .agent)?.id,
                       "agent:com.example.tool")
    }

    func testServiceTarget() {
        let daemon = LaunchdJob(label: "com.example.d", kind: .daemon, plistPath: "")
        let agent = LaunchdJob(label: "com.example.a", kind: .agent, plistPath: "")
        XCTAssertEqual(LaunchdServices.serviceTarget(for: daemon, uid: 501), "system/com.example.d")
        XCTAssertEqual(LaunchdServices.serviceTarget(for: agent, uid: 501), "gui/501/com.example.a")
    }
}
