//
//  LaunchdServices.swift
//
//  Reads the launchd jobs this tool installs and reports them, read-only,
//  with the same fields ReportMate's System module collects for launchd
//  services: type, status and PID, last exit status, program and arguments,
//  Run at Load, Keep Alive, start interval and calendar interval, user and
//  group, standard out and error paths, and the plist path. Everything comes
//  from the job's plist and `launchctl print`, which answers for the system
//  domain without root, so there is no osquery dependency and no privileged
//  call. Nothing here starts, stops or reloads a job.
//

import Foundation

public struct LaunchdJob: Identifiable, Equatable, Sendable {
    public enum Kind: String, Sendable {
        case daemon
        case agent

        public var displayName: String {
            switch self {
            case .daemon: return "Launch daemon"
            case .agent: return "Launch agent"
            }
        }
    }

    public enum State: Equatable, Sendable {
        case running(pid: Int?)
        case loaded
        case disabled
        case notLoaded
        case unknown

        public var displayName: String {
            switch self {
            case .running(let pid?): return "Running (PID \(pid))"
            case .running(nil): return "Running"
            case .loaded: return "Loaded, not running"
            case .disabled: return "Disabled"
            case .notLoaded: return "Not loaded"
            case .unknown: return "Unknown"
            }
        }

        public var pid: Int? {
            if case .running(let pid) = self { return pid }
            return nil
        }
    }

    public let label: String
    public let kind: Kind
    public let plistPath: String
    /// When the job runs, in plain words, for the collapsed row's summary line.
    public let schedule: String
    public var state: State
    /// The last exit status as launchd reports it, or nil when the job has never exited.
    public var lastExitCode: String?
    public var program: String?
    /// Arguments after the program itself (ProgramArguments without argv[0]).
    public var arguments: [String]
    public var runAtLoad: String
    public var keepAlive: String
    public var startInterval: String?
    public var calendarInterval: String?
    public var userName: String?
    public var groupName: String?
    public var standardOutPath: String?
    public var standardErrorPath: String?
    /// The plist's own Disabled key; launchd's override database can also disable a job.
    public var disabledInPlist: Bool

    public var id: String { "\(kind.rawValue):\(label)" }

    public init(label: String, kind: Kind, plistPath: String, schedule: String = "On demand",
                state: State = .unknown, lastExitCode: String? = nil,
                program: String? = nil, arguments: [String] = [],
                runAtLoad: String = "No", keepAlive: String = "No",
                startInterval: String? = nil, calendarInterval: String? = nil,
                userName: String? = nil, groupName: String? = nil,
                standardOutPath: String? = nil, standardErrorPath: String? = nil,
                disabledInPlist: Bool = false) {
        self.label = label
        self.kind = kind
        self.plistPath = plistPath
        self.schedule = schedule
        self.state = state
        self.lastExitCode = lastExitCode
        self.program = program
        self.arguments = arguments
        self.runAtLoad = runAtLoad
        self.keepAlive = keepAlive
        self.startInterval = startInterval
        self.calendarInterval = calendarInterval
        self.userName = userName
        self.groupName = groupName
        self.standardOutPath = standardOutPath
        self.standardErrorPath = standardErrorPath
        self.disabledInPlist = disabledInPlist
    }

    /// The collapsed row's secondary line: "Launch daemon · Daily at 04:00 · Last exit 0".
    public var summary: String {
        let exit = lastExitCode.map { "Last exit \($0)" } ?? "Has not exited"
        return [kind.displayName, schedule, exit].joined(separator: " \u{00B7} ")
    }

    // MARK: - Detail rows

    public struct Field: Identifiable, Equatable, Sendable {
        public let name: String
        public let value: String
        /// False when the value is a placeholder such as "Not set".
        public let isSet: Bool
        /// Paths and command lines: shown in monospace and truncated in the middle.
        public let isPath: Bool

        public var id: String { name }
    }

    /// The expanded detail, in the same order and with the same labels in every app.
    public var fields: [Field] {
        func field(_ name: String, _ value: String?, placeholder: String = "Not set", path: Bool = false) -> Field {
            if let value, !value.isEmpty {
                return Field(name: name, value: value, isSet: true, isPath: path)
            }
            return Field(name: name, value: placeholder, isSet: false, isPath: false)
        }
        return [
            field("Type", kind.displayName),
            field("Status", state.displayName),
            field("PID", state.pid.map(String.init), placeholder: "None"),
            field("Last exit status", lastExitCode, placeholder: "Has not exited"),
            field("Program", program, path: true),
            field("Arguments", LaunchdServices.commandLine(arguments), placeholder: "None", path: true),
            field("Run at load", runAtLoad),
            field("Keep alive", keepAlive),
            field("Start interval", startInterval),
            field("Calendar interval", calendarInterval),
            field("User", userName ?? (kind == .daemon ? "root (default)" : "Logged-in user (default)")),
            field("Group", groupName, placeholder: "Default for the user"),
            field("Standard out", standardOutPath, path: true),
            field("Standard error", standardErrorPath, path: true),
            field("Plist", plistPath, path: true)
        ]
    }
}

public enum LaunchdServices {
    public static let daemonDirectory = "/Library/LaunchDaemons"
    public static let agentDirectory = "/Library/LaunchAgents"

    // MARK: - Discovery

    /// Reads every plist in the system launchd folders whose file name starts
    /// with one of `prefixes`, plus every plist in `extraDaemonDirectories`
    /// (for example a helper embedded in the app bundle). Jobs are de-duplicated
    /// by label, the system folders winning.
    public static func discover(
        prefixes: [String],
        extraDaemonDirectories: [String] = [],
        daemonDirectory: String = daemonDirectory,
        agentDirectory: String = agentDirectory
    ) -> [LaunchdJob] {
        var jobs: [LaunchdJob] = []
        var seen: Set<String> = []

        func scan(_ directory: String, kind: LaunchdJob.Kind, filter: Bool) {
            let names = (try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? []
            for name in names.sorted() where name.hasSuffix(".plist") {
                if filter, !prefixes.contains(where: { name.hasPrefix($0) }) { continue }
                let path = (directory as NSString).appendingPathComponent(name)
                guard let data = FileManager.default.contents(atPath: path),
                      let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                      let job = job(fromPlist: plist, path: path, kind: kind),
                      seen.insert(job.id).inserted
                else { continue }
                jobs.append(job)
            }
        }

        scan(daemonDirectory, kind: .daemon, filter: true)
        scan(agentDirectory, kind: .agent, filter: true)
        for directory in extraDaemonDirectories {
            scan(directory, kind: .daemon, filter: false)
        }
        return jobs
    }

    public static func job(fromPlist plist: [String: Any], path: String, kind: LaunchdJob.Kind) -> LaunchdJob? {
        guard let label = plist["Label"] as? String, !label.isEmpty else { return nil }

        let programArguments = (plist["ProgramArguments"] as? [String]) ?? []
        let program = (plist["Program"] as? String) ?? programArguments.first

        var startInterval: String?
        if let seconds = (plist["StartInterval"] as? NSNumber)?.intValue, seconds > 0 {
            startInterval = describeInterval(seconds)
        }
        var calendarInterval: String?
        if let calendar = plist["StartCalendarInterval"] {
            let entries: [[String: Any]]
            if let single = calendar as? [String: Any] {
                entries = [single]
            } else {
                entries = (calendar as? [[String: Any]]) ?? []
            }
            calendarInterval = describeCalendar(entries)
        }

        return LaunchdJob(
            label: label,
            kind: kind,
            plistPath: path,
            schedule: describeSchedule(plist, kind: kind),
            program: program,
            arguments: Array(programArguments.dropFirst()),
            runAtLoad: describeRunAtLoad(plist, kind: kind),
            keepAlive: describeKeepAlive(plist),
            startInterval: startInterval,
            calendarInterval: calendarInterval,
            userName: plist["UserName"] as? String,
            groupName: plist["GroupName"] as? String,
            standardOutPath: plist["StandardOutPath"] as? String,
            standardErrorPath: plist["StandardErrorPath"] as? String,
            disabledInPlist: (plist["Disabled"] as? Bool) == true
        )
    }

    // MARK: - Status

    /// Discovers the jobs and asks launchd for the state of each, off the main thread.
    public static func load(prefixes: [String], extraDaemonDirectories: [String] = []) async -> [LaunchdJob] {
        await Task.detached(priority: .utility) {
            let jobs = discover(prefixes: prefixes, extraDaemonDirectories: extraDaemonDirectories)
            var disabled: [String: Set<String>] = [:]
            return jobs.map { job in
                let domain = domainTarget(for: job.kind)
                if disabled[domain] == nil {
                    disabled[domain] = parseDisabled(run(["print-disabled", domain]).output)
                }
                return apply(status(of: job), to: job, disabledLabels: disabled[domain] ?? [])
            }
        }.value
    }

    public static func domainTarget(for kind: LaunchdJob.Kind, uid: uid_t = getuid()) -> String {
        switch kind {
        case .daemon: return "system"
        case .agent: return "gui/\(uid)"
        }
    }

    public static func serviceTarget(for job: LaunchdJob, uid: uid_t = getuid()) -> String {
        "\(domainTarget(for: job.kind, uid: uid))/\(job.label)"
    }

    /// What `launchctl print` says about one job.
    public struct PrintInfo: Equatable, Sendable {
        public var state: LaunchdJob.State
        public var lastExitCode: String?
        public var program: String?
        public var arguments: [String]
        public var standardOutPath: String?
        public var standardErrorPath: String?

        public init(state: LaunchdJob.State, lastExitCode: String? = nil, program: String? = nil,
                    arguments: [String] = [], standardOutPath: String? = nil, standardErrorPath: String? = nil) {
            self.state = state
            self.lastExitCode = lastExitCode
            self.program = program
            self.arguments = arguments
            self.standardOutPath = standardOutPath
            self.standardErrorPath = standardErrorPath
        }
    }

    public static func status(of job: LaunchdJob) -> PrintInfo {
        let result = run(["print", serviceTarget(for: job)])
        guard let status = result.status else { return PrintInfo(state: .unknown) }
        // launchctl exits non-zero ("Could not find service") when the job is not loaded.
        if status != 0 { return PrintInfo(state: .notLoaded) }
        return parsePrint(result.output)
    }

    /// Fills the live launchd view into a job read from its plist. The plist
    /// wins for program, arguments and log paths; launchd fills any gaps.
    public static func apply(_ info: PrintInfo, to job: LaunchdJob, disabledLabels: Set<String> = []) -> LaunchdJob {
        var job = job
        job.lastExitCode = info.lastExitCode
        if job.program == nil { job.program = info.program }
        if job.arguments.isEmpty, info.arguments.count > 1 { job.arguments = Array(info.arguments.dropFirst()) }
        if job.standardOutPath == nil { job.standardOutPath = info.standardOutPath }
        if job.standardErrorPath == nil { job.standardErrorPath = info.standardErrorPath }

        let isDisabled = disabledLabels.contains(job.label) || job.disabledInPlist
        switch info.state {
        case .running:
            job.state = info.state
        case .notLoaded, .loaded:
            job.state = isDisabled ? .disabled : info.state
        default:
            job.state = info.state
        }
        return job
    }

    /// Parses the top level of `launchctl print` output, plus the
    /// `arguments` block. Other nested blocks are indented further and ignored.
    public static func parsePrint(_ output: String) -> PrintInfo {
        var stateText: String?
        var pid: Int?
        var lastExit: String?
        var program: String?
        var arguments: [String] = []
        var stdout: String?
        var stderr: String?
        var inArguments = false

        for rawLine in output.components(separatedBy: .newlines) {
            if inArguments {
                if rawLine.hasPrefix("\t\t") {
                    arguments.append(rawLine.trimmingCharacters(in: .whitespaces))
                    continue
                }
                inArguments = false
            }
            guard rawLine.hasPrefix("\t"), !rawLine.hasPrefix("\t\t") else { continue }
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line == "arguments = {" {
                inArguments = true
                continue
            }
            guard let range = line.range(of: " = ") else { continue }
            let key = String(line[..<range.lowerBound])
            let value = String(line[range.upperBound...])
            switch key {
            case "state": stateText = value
            case "pid": pid = Int(value)
            case "last exit code": lastExit = value
            case "program": program = value
            case "stdout path": stdout = value
            case "stderr path": stderr = value
            default: break
            }
        }

        let state: LaunchdJob.State
        switch stateText {
        case "running": state = .running(pid: pid)
        case .some: state = pid != nil ? .running(pid: pid) : .loaded
        case nil: state = .unknown
        }
        let exit = (lastExit == nil || lastExit == "(never exited)") ? nil : lastExit
        return PrintInfo(state: state, lastExitCode: exit, program: program, arguments: arguments,
                         standardOutPath: stdout, standardErrorPath: stderr)
    }

    /// Labels `launchctl print-disabled` lists as disabled in a domain.
    public static func parseDisabled(_ output: String) -> Set<String> {
        var labels: Set<String> = []
        for line in output.components(separatedBy: .newlines) {
            let parts = line.trimmingCharacters(in: .whitespaces).components(separatedBy: " => ")
            guard parts.count == 2, parts[1] == "disabled" || parts[1] == "true" else { continue }
            labels.insert(parts[0].trimmingCharacters(in: CharacterSet(charactersIn: "\"")))
        }
        return labels
    }

    static func run(_ arguments: [String]) -> (status: Int32?, output: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return (nil, "")
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, String(data: data, encoding: .utf8) ?? "")
    }

    // MARK: - Plain words

    public static func describeSchedule(_ plist: [String: Any], kind: LaunchdJob.Kind) -> String {
        var parts: [String] = []

        let sessionTypes: [String]
        if let one = plist["LimitLoadToSessionType"] as? String {
            sessionTypes = [one]
        } else {
            sessionTypes = (plist["LimitLoadToSessionType"] as? [String]) ?? []
        }
        let loginWindowOnly = sessionTypes == ["LoginWindow"]
        // OnDemand false is the legacy spelling of "start at load and keep alive".
        let legacyAlwaysOn = (plist["OnDemand"] as? Bool) == false

        if (plist["RunAtLoad"] as? Bool) == true || legacyAlwaysOn || (loginWindowOnly && plist["StartInterval"] == nil) {
            if loginWindowOnly {
                parts.append("At the login window")
            } else {
                parts.append(kind == .daemon ? "At startup" : "At login")
            }
        }
        if let seconds = (plist["StartInterval"] as? NSNumber)?.intValue, seconds > 0 {
            parts.append(describeInterval(seconds))
        }
        if let calendar = plist["StartCalendarInterval"] {
            let entries: [[String: Any]]
            if let single = calendar as? [String: Any] {
                entries = [single]
            } else {
                entries = (calendar as? [[String: Any]]) ?? []
            }
            if let text = describeCalendar(entries) { parts.append(text) }
        }
        if let keepAlive = plist["KeepAlive"] {
            if (keepAlive as? Bool) == true {
                parts.append("Kept running; restarted if it quits")
            } else if let conditions = keepAlive as? [String: Any] {
                if let pathState = conditions["PathState"] as? [String: Bool], conditions.count == 1 {
                    parts.append(pathState.values.contains(true)
                                 ? "When its trigger file is created"
                                 : "When its trigger file is removed")
                } else {
                    parts.append("Kept running while its conditions hold")
                }
            }
        }
        if let paths = plist["WatchPaths"] as? [Any], !paths.isEmpty {
            parts.append("When a watched path changes")
        }
        if let queues = plist["QueueDirectories"] as? [Any], !queues.isEmpty {
            parts.append("When files arrive in a queue folder")
        }
        if (plist["StartOnMount"] as? Bool) == true {
            parts.append("When a volume mounts")
        }
        if let events = plist["LaunchEvents"] as? [String: Any], !events.isEmpty {
            parts.append("On system events")
        }
        if parts.isEmpty {
            if let mach = plist["MachServices"] as? [String: Any], !mach.isEmpty {
                return "On demand, when an app connects to it"
            }
            return "On demand"
        }
        return joinSentence(parts)
    }

    public static func describeRunAtLoad(_ plist: [String: Any], kind: LaunchdJob.Kind) -> String {
        let sessionTypes: [String]
        if let one = plist["LimitLoadToSessionType"] as? String {
            sessionTypes = [one]
        } else {
            sessionTypes = (plist["LimitLoadToSessionType"] as? [String]) ?? []
        }
        // OnDemand false is the legacy spelling of "start at load and keep alive".
        let legacyAlwaysOn = (plist["OnDemand"] as? Bool) == false
        guard (plist["RunAtLoad"] as? Bool) == true || legacyAlwaysOn else { return "No" }
        if sessionTypes == ["LoginWindow"] { return "Yes, at the login window" }
        return kind == .daemon ? "Yes, at startup" : "Yes, at login"
    }

    public static func describeKeepAlive(_ plist: [String: Any]) -> String {
        if (plist["OnDemand"] as? Bool) == false { return "Yes, restarted if it quits" }
        guard let keepAlive = plist["KeepAlive"] else { return "No" }
        if let flag = keepAlive as? Bool { return flag ? "Yes, restarted if it quits" : "No" }
        guard let conditions = keepAlive as? [String: Any], !conditions.isEmpty else { return "No" }
        if conditions.count == 1, let pathState = conditions["PathState"] as? [String: Bool] {
            return pathState.values.contains(true)
                ? "While its trigger file exists"
                : "While its trigger file is absent"
        }
        if conditions.count == 1, let successful = conditions["SuccessfulExit"] as? Bool {
            return successful ? "Restarted after a clean exit" : "Restarted if it fails"
        }
        if conditions.count == 1, conditions["Crashed"] as? Bool == true {
            return "Restarted if it crashes"
        }
        return "While its conditions hold"
    }

    public static func describeInterval(_ seconds: Int) -> String {
        func unit(_ count: Int, _ singular: String) -> String {
            count == 1 ? "Every \(singular)" : "Every \(count) \(singular)s"
        }
        if seconds % 86_400 == 0 { return unit(seconds / 86_400, "day") }
        if seconds % 3_600 == 0 { return unit(seconds / 3_600, "hour") }
        if seconds % 60 == 0 { return unit(seconds / 60, "minute") }
        return unit(seconds, "second")
    }

    static let weekdayNames = ["Sundays", "Mondays", "Tuesdays", "Wednesdays", "Thursdays", "Fridays", "Saturdays", "Sundays"]
    static let monthNames = ["January", "February", "March", "April", "May", "June",
                             "July", "August", "September", "October", "November", "December"]

    public static func describeCalendar(_ entries: [[String: Any]]) -> String? {
        guard !entries.isEmpty else { return nil }
        func int(_ entry: [String: Any], _ key: String) -> Int? { (entry[key] as? NSNumber)?.intValue }

        // Several daily times collapse into one line: "Daily at 09:00, 13:00".
        let onlyTimes = entries.allSatisfy { entry in
            Set(entry.keys).isSubset(of: ["Hour", "Minute"]) && int(entry, "Hour") != nil
        }
        if onlyTimes, entries.count > 1 {
            let times = entries.map { time(hour: int($0, "Hour")!, minute: int($0, "Minute") ?? 0) }
            return "Daily at " + times.joined(separator: ", ")
        }
        return entries.map { describeCalendarEntry($0) }.joined(separator: "; ")
    }

    static func describeCalendarEntry(_ entry: [String: Any]) -> String {
        func int(_ key: String) -> Int? { (entry[key] as? NSNumber)?.intValue }
        let minute = int("Minute")
        let hour = int("Hour")
        let day = int("Day")
        let weekday = int("Weekday")
        let month = int("Month")

        let when: String
        switch (hour, minute) {
        case let (h?, m):
            when = "at " + time(hour: h, minute: m ?? 0)
        case let (nil, m?):
            when = "every hour at :" + String(format: "%02d", m)
        case (nil, nil):
            when = "every minute"
        }

        var prefix: String
        if let weekday, (0...7).contains(weekday) {
            prefix = weekdayNames[weekday]
        } else if let day {
            prefix = "On day \(day) of the month"
        } else {
            prefix = hour == nil ? "" : "Daily"
        }
        if let month, (1...12).contains(month) {
            prefix = prefix.isEmpty ? "In \(monthNames[month - 1])" : "\(prefix) in \(monthNames[month - 1])"
        }
        if prefix.isEmpty {
            return when.prefix(1).uppercased() + when.dropFirst()
        }
        return "\(prefix) \(when)"
    }

    static func time(hour: Int, minute: Int) -> String {
        String(format: "%02d:%02d", hour, minute)
    }

    static func joinSentence(_ parts: [String]) -> String {
        guard let first = parts.first else { return "" }
        let rest = parts.dropFirst().map { part -> String in
            // Keep weekday and month names capitalised; lower-case the rest.
            if weekdayNames.contains(where: { part.hasPrefix($0) }) { return part }
            return part.prefix(1).lowercased() + part.dropFirst()
        }
        return ([first] + rest).joined(separator: ", ")
    }

    /// Joins arguments the way a shell would read them back, quoting any with spaces.
    public static func commandLine(_ arguments: [String]) -> String? {
        guard !arguments.isEmpty else { return nil }
        return arguments.map { argument in
            argument.contains(where: { $0 == " " || $0 == "\t" || $0 == "\"" })
                ? "'" + argument.replacingOccurrences(of: "'", with: "'\\''") + "'"
                : argument
        }.joined(separator: " ")
    }
}
