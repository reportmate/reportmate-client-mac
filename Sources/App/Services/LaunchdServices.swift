//
//  LaunchdServices.swift
//
//  Reads the launchd jobs this tool installs and reports, read-only, whether
//  each one is loaded or running, how it last exited, and when it runs.
//  `launchctl print` answers for the system domain without root, so no
//  privileged call is needed. Nothing here starts, stops or reloads a job.
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
        case notLoaded
        case unknown

        public var displayName: String {
            switch self {
            case .running(let pid?): return "Running (PID \(pid))"
            case .running(nil): return "Running"
            case .loaded: return "Loaded, not running"
            case .notLoaded: return "Not loaded"
            case .unknown: return "Unknown"
            }
        }
    }

    public let label: String
    public let kind: Kind
    public let plistPath: String
    public let schedule: String
    public var state: State
    /// The last exit code as launchd reports it, or nil when the job has never exited.
    public var lastExitCode: String?

    public var id: String { "\(kind.rawValue):\(label)" }

    public init(label: String, kind: Kind, plistPath: String, schedule: String,
                state: State = .unknown, lastExitCode: String? = nil) {
        self.label = label
        self.kind = kind
        self.plistPath = plistPath
        self.schedule = schedule
        self.state = state
        self.lastExitCode = lastExitCode
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
        return LaunchdJob(label: label, kind: kind, plistPath: path,
                          schedule: describeSchedule(plist, kind: kind))
    }

    // MARK: - Status

    /// Discovers the jobs and asks launchd for the state of each, off the main thread.
    public static func load(prefixes: [String], extraDaemonDirectories: [String] = []) async -> [LaunchdJob] {
        await Task.detached(priority: .utility) {
            discover(prefixes: prefixes, extraDaemonDirectories: extraDaemonDirectories).map { job in
                var job = job
                let status = status(of: job)
                job.state = status.state
                job.lastExitCode = status.lastExitCode
                return job
            }
        }.value
    }

    public static func serviceTarget(for job: LaunchdJob, uid: uid_t = getuid()) -> String {
        switch job.kind {
        case .daemon: return "system/\(job.label)"
        case .agent: return "gui/\(uid)/\(job.label)"
        }
    }

    public static func status(of job: LaunchdJob) -> (state: LaunchdJob.State, lastExitCode: String?) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["print", serviceTarget(for: job)]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return (.unknown, nil)
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        let output = String(data: data, encoding: .utf8) ?? ""
        if process.terminationStatus != 0 {
            // launchctl exits non-zero ("Could not find service") when the job is not loaded.
            return (.notLoaded, nil)
        }
        return parsePrint(output)
    }

    /// Parses the top level of `launchctl print` output. Nested blocks
    /// (environment, endpoints) are indented further and ignored.
    public static func parsePrint(_ output: String) -> (state: LaunchdJob.State, lastExitCode: String?) {
        var stateText: String?
        var pid: Int?
        var lastExit: String?

        for rawLine in output.components(separatedBy: .newlines) {
            guard rawLine.hasPrefix("\t"), !rawLine.hasPrefix("\t\t") else { continue }
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard let range = line.range(of: " = ") else { continue }
            let key = String(line[..<range.lowerBound])
            let value = String(line[range.upperBound...])
            switch key {
            case "state": stateText = value
            case "pid": pid = Int(value)
            case "last exit code": lastExit = value
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
        return (state, exit)
    }

    // MARK: - Schedule in plain words

    public static func describeSchedule(_ plist: [String: Any], kind: LaunchdJob.Kind) -> String {
        var parts: [String] = []

        if (plist["RunAtLoad"] as? Bool) == true {
            parts.append(kind == .daemon ? "At startup" : "At login")
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
            } else if keepAlive is [String: Any] {
                parts.append("Kept running while its conditions hold")
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
}
