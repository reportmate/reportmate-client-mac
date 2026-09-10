import Foundation

/// The management module's `logs` section. Port of `modules/logs.ts` and the
/// line helpers in `ManagementLogsSection.tsx`.
public struct LogsInfo: Sendable, Hashable {
    public struct FileEntry: Sendable, Hashable, Identifiable {
        public var id: String { path }
        public var name: String
        public var path: String
        public var bytes: Double
        public var modified: String?
    }

    public struct SessionSummary: Sendable, Hashable {
        public var sessionId: String?
        public var status: String?
        public var startTime: String?
        public var endTime: String?
        public var durationSeconds: Double?
        public var runType: String?
        public var errors: Int?
        public var warnings: Int?

        public enum Tone: Sendable { case success, running, warning, failure, neutral }
        public var tone: Tone {
            let s = (status ?? "").lowercased()
            if ["completed", "success", "succeeded"].contains(s) { return .success }
            if s == "running" || s == "in_progress" { return .running }
            if s.contains("partial") || s.contains("warn") { return .warning }
            if s.contains("fail") || s.contains("error") || s == "abandoned" { return .failure }
            return .neutral
        }
    }

    public struct Tail: Sendable, Hashable, Identifiable {
        public var id: String { file ?? "" }
        public var file: String?
        public var lines: [String]
        public var truncated: Bool
        public var bytes: Double?
    }

    public struct Root: Sendable, Hashable, Identifiable {
        public var id: String { tool }
        public var tool: String
        public var name: String
        public var path: String
        public var layout: String?
        public var fileCount: Int?
        public var totalBytes: Double?
        public var newestModified: String?
        /// Version of the tool that owns the root, as the client read it from the installed package or bundle.
        public var version: String?
        public var files: [FileEntry]
        public var latestSession: SessionSummary?
        public var primaryLog: String?
        public var errorCount: Int?
        public var warningCount: Int?
        public var tails: [Tail]

        /// `normalizeLogRoot`; nil when the record has no tool key.
        public init?(json r: JSONValue) {
            guard let t = r["tool"].string?.trimmingCharacters(in: .whitespaces), !t.isEmpty else { return nil }
            tool = t
            name = r["name"].nonEmptyString ?? t
            path = r["path"].string ?? ""
            layout = r["layout"].nonEmptyString
            fileCount = r.first("fileCount", "file_count").int
            totalBytes = r.first("totalBytes", "total_bytes").double
            newestModified = r.firstString("newestModified", "newest_modified")
            version = r.firstString("version", "toolVersion", "tool_version")
            files = r["files"].elements.compactMap { f in
                guard f.object != nil else { return nil }
                return FileEntry(name: f["name"].string ?? "", path: f["path"].nonEmptyString ?? f["name"].string ?? "", bytes: f["bytes"].double ?? 0, modified: f["modified"].nonEmptyString)
            }
            let s = r.first("latestSession", "latest_session")
            latestSession = s.object == nil ? nil : SessionSummary(
                sessionId: s.first("sessionId", "session_id").string, status: s["status"].nonEmptyString,
                startTime: s.firstString("startTime", "start_time"), endTime: s.firstString("endTime", "end_time"),
                durationSeconds: s.first("durationSeconds", "duration_seconds").double, runType: s.firstString("runType", "run_type"),
                errors: s["errors"].int, warnings: s["warnings"].int)
            primaryLog = r.firstString("primaryLog", "primary_log")
            errorCount = r.first("errorCount", "error_count").int
            warningCount = r.first("warningCount", "warning_count").int
            tails = r["tails"].elements.compactMap { t in
                guard t.object != nil else { return nil }
                return Tail(file: t["file"].nonEmptyString, lines: t["lines"].elements.map { $0.string ?? $0.prettyPrinted }, truncated: t["truncated"].boolish, bytes: t["bytes"].double)
            }
        }

        /// "Managed Installs" -> "Installs"; falls back to the tool key.
        public var label: String {
            let stripped = name.replacingOccurrences(of: #"^Managed\s*"#, with: "", options: [.regularExpression, .caseInsensitive]).trimmingCharacters(in: .whitespaces)
            return stripped.isEmpty ? tool.prefix(1).uppercased() + tool.dropFirst() : stripped
        }

        static let productNames: [String: (mac: String, windows: String)] = [
            "installs": ("Munki", "Cimian"), "bootstrap": ("BootstrapMate", "BootstrapMate"), "reports": ("ReportMate", "ReportMate"),
            "state": ("Outset", "StartSet"), "encryption": ("Crypt", "Crypt"), "users": ("ManageUsers", "ManageUsers"),
            "utilities": ("Utilities", "Utilities"), "notifications": ("swiftDialog", "csharpDialog"), "installer": ("Installer", "Installer"),
        ]

        /// The product behind a root: Munki or Cimian for installs, and so on.
        /// The MDM root is named after the agent the client found (Intune, Jamf, ...).
        public func productName(platform: String?) -> String {
            let key = tool.lowercased()
            if key == "mdm" {
                let trimmed = name.trimmingCharacters(in: .whitespaces)
                return trimmed.isEmpty ? "MDM" : trimmed
            }
            guard let names = Root.productNames[key] else { return label }
            return (platform ?? "").lowercased().hasPrefix("win") ? names.windows : names.mac
        }
    }

    public var platform: String?
    public var collectedAt: String?
    public var moduleVersion: String?
    public var roots: [Root]

    /// `extractLogs`; nil when the device never reported a logs section.
    public init?(modules: JSONValue) {
        let raw = modules["management"].unwrappingSingleton()["logs"]
        guard raw.object != nil else { return nil }
        platform = raw["platform"].nonEmptyString
        collectedAt = raw.firstString("collectedAt", "collected_at", "collectionTimestamp")
        moduleVersion = raw.firstString("moduleVersion", "module_version")
        roots = LogsInfo.orderRoots(raw["roots"].elements.compactMap(Root.init(json:)))
    }

    /// Tab order: the MDM root first, then the management tools in the order
    /// the client reported them, then the OS installer log last.
    public static func orderRoots(_ roots: [Root]) -> [Root] {
        func rank(_ root: Root) -> Int {
            switch root.tool.lowercased() {
            case "mdm": return 0
            case "installer": return 2
            default: return 1
            }
        }
        return roots.enumerated().sorted { a, b in
            let ra = rank(a.element), rb = rank(b.element)
            return ra != rb ? ra < rb : a.offset < b.offset
        }.map(\.element)
    }

    public var totalErrors: Int { roots.reduce(0) { $0 + ($1.errorCount ?? 0) } }
    public var totalWarnings: Int { roots.reduce(0) { $0 + ($1.warningCount ?? 0) } }
    public var totalFiles: Int { roots.reduce(0) { $0 + ($1.fileCount ?? $1.files.count) } }
    public var totalBytes: Double { roots.reduce(0) { $0 + ($1.totalBytes ?? 0) } }

    // MARK: Line levels

    /// Where a line sits in the level vocabulary the convention uses: ERROR, WARN, INFO, DEBUG.
    public enum LineLevel: Sendable, Hashable { case error, warning, debug, plain }
    public typealias LineTone = LineLevel

    /// `[yyyy-MM-dd HH:mm:ss] LEVEL  message`: the level token is authoritative,
    /// so an INFO line that mentions CRITICAL stays INFO.
    static let conventionLevel = try! NSRegularExpression(pattern: #"^\[[^\]]+\]\s+\[?(DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\]?\b"#, options: [.caseInsensitive])

    public static func lineTone(_ line: String) -> LineLevel {
        if let token = conventionLevel.firstCapture(in: line)?.uppercased() {
            if token == "ERROR" || token == "FATAL" || token == "CRITICAL" { return .error }
            if token == "WARN" || token == "WARNING" { return .warning }
            if token == "DEBUG" { return .debug }
            return .plain
        }
        if line.range(of: #"\b(ERROR|ERR|FAULT|CRITICAL|FATAL)\b"#, options: .regularExpression) != nil { return .error }
        if line.range(of: #"\b(WARN|WARNING|WRN)\b"#, options: .regularExpression) != nil { return .warning }
        if line.range(of: #"\b(DEBUG|DBG|VERBOSE|TRACE)\b"#, options: .regularExpression) != nil { return .debug }
        return .plain
    }

    public static func levelTone(_ level: String?) -> LineLevel {
        let l = (level ?? "").uppercased()
        if l.hasPrefix("ERR") || l == "FAULT" || l == "CRITICAL" || l == "FATAL" { return .error }
        if l.hasPrefix("WARN") || l == "WRN" { return .warning }
        if l.hasPrefix("DEBUG") || l == "DBG" || l == "VERBOSE" || l == "TRACE" { return .debug }
        return .plain
    }

    /// A level label for a line with no level field, from its words; nil when it reads as plain information.
    static func wordLevel(_ text: String) -> String? {
        switch lineTone(text) {
        case .error: return "ERROR"
        case .warning: return "WARN"
        case .debug: return "DEBUG"
        case .plain: return nil
        }
    }

    /// Level filter state. Errors and warnings narrow the view to those levels
    /// when either is on; debug lines are hidden unless asked for, so a verbose
    /// log reads as its INFO story by default.
    public struct LevelFilter: Sendable, Hashable {
        public var errors = false
        public var warnings = false
        public var debug = false
        public init() {}
        public var isActive: Bool { errors || warnings || debug }

        public func passes(_ level: LineLevel) -> Bool {
            if level == .debug { return debug && !errors && !warnings }
            if errors || warnings { return (level == .error && errors) || (level == .warning && warnings) }
            return true
        }
    }

    public struct LevelCounts: Sendable, Hashable {
        public var error = 0
        public var warning = 0
        public var debug = 0
    }

    // MARK: Structured lines

    /// One structured `events.jsonl` record, a recognised text-log line, or the
    /// raw line when it does not parse.
    public struct JsonlEvent: Sendable, Hashable, Identifiable {
        public var id: Int
        public var raw: String
        public var parsed: JSONValue?
        public var timestamp: String?
        public var level: String?
        /// A status tag the tool put at the start of the message, e.g. PROGRESS, SUCCESS, SKIPPED, or an agent subsystem.
        public var tag: String?
        public var eventType: String?
        public var item: String?
        public var version: String?
        public var message: String?

        public init(index: Int, raw: String) {
            id = index
            self.raw = raw
        }

        /// `parseJsonlLine`.
        public init(index: Int, line: String) {
            id = index
            raw = line
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("{"), let obj = JSONValue.parse(trimmed), obj.object != nil else { return }
            parsed = obj
            func first(_ keys: String...) -> String? {
                for k in keys {
                    if let s = obj[k].string, !s.trimmingCharacters(in: .whitespaces).isEmpty { return s }
                    if let d = obj[k].double { return d == d.rounded() ? String(Int(d)) : String(d) }
                }
                return nil
            }
            timestamp = first("timestamp", "time", "ts", "date")
            level = first("level", "severity")
            eventType = first("event_type", "eventType", "type", "event")
            item = first("package_name", "packageName", "item_name", "itemName", "name", "display_name")
            version = first("package_version", "packageVersion", "target_version", "version")
            message = first("message", "msg", "status_reason", "error")
        }

        /// Tools mark phases inside the message with a bracketed tag
        /// (`[PROGRESS] Processing: X`, `[SUCCESS] ...`) and agents name their
        /// subsystem the same way (`[Flighting] ...`). Whatever leads the message
        /// in brackets becomes its own pill and leaves the text.
        public func liftingTag() -> JsonlEvent {
            guard let message, let m = LogsInfo.messageTag.captures(in: message), let tag = m[0], let rest = m[1] else { return self }
            var out = self
            out.tag = tag
            out.message = rest
            return out
        }
    }

    static let messageTag = try! NSRegularExpression(pattern: #"^\[([A-Za-z][A-Za-z0-9 ._:-]{0,39})\]\s*(.*)$"#, options: [.dotMatchesLineSeparators])

    /// CMTrace (Intune Management Extension on Windows):
    /// `<![LOG[message]LOG]!><time="HH:mm:ss.fffffff" date="M-d-yyyy" component="X" context="" type="1|2|3" thread="n" file="">`
    static let cmTrace = try! NSRegularExpression(pattern: #"^<!\[LOG\[(.*?)\]LOG\]!><time="([^"]*)"\s+date="([^"]*)"\s+component="([^"]*)"(?:\s+context="[^"]*")?\s+type="(\d)"(?:\s+thread="([^"]*)")?(?:\s+file="[^"]*")?>\s*$"#, options: [.dotMatchesLineSeparators])
    /// Intune MDM daemon on the Mac: `yyyy-MM-dd HH:mm:ss:SSS | IntuneMDM-Daemon | I|W|E | thread | Logger | message`.
    static let intuneDaemon = try! NSRegularExpression(pattern: #"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}):(\d{3}) \| ([^|]+?) \| ([IWE]) \| ([^|]*?) \| ([^|]*?) \| (.*)$"#, options: [.dotMatchesLineSeparators])
    /// The convention's own line: `[yyyy-MM-dd HH:mm:ss] LEVEL  message`.
    static let convention = try! NSRegularExpression(pattern: #"^\[(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})\]\s+(DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\s+(.*)$"#, options: [.dotMatchesLineSeparators])
    /// A bracketed stamp with no level token, or with the level itself in brackets.
    static let bracketStamp = try! NSRegularExpression(pattern: #"^\[(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:[.,]\d+)?\]\s*(.*)$"#, options: [.dotMatchesLineSeparators])
    static let bracketLevel = try! NSRegularExpression(pattern: #"^\[(DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\]\s*(.*)$"#, options: [.caseInsensitive, .dotMatchesLineSeparators])
    /// Munki: `Sep 02 2026 14:27:03 -0700 message`.
    static let munki = try! NSRegularExpression(pattern: #"^([A-Z][a-z]{2}) (\d{2}) (\d{4}) (\d{2}:\d{2}:\d{2}) [+-]\d{4} (.*)$"#, options: [.dotMatchesLineSeparators])
    /// macOS install.log and other syslog-style lines: `2026-09-02 14:27:03-07 host process[pid]: message`.
    static let syslog = try! NSRegularExpression(pattern: #"^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})(?:[+-]\d{2})? (\S+) ([^\[:\s]+)(?:\[\d+\])?: (.*)$"#, options: [.dotMatchesLineSeparators])
    /// Anything that leads with a date and time, ISO-ish, with or without zone: the rest is the message.
    static let stamped = try! NSRegularExpression(pattern: #"^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:[.,:]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+(.*)$"#, options: [.dotMatchesLineSeparators])

    static let months: [String: String] = ["Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04", "May": "05", "Jun": "06", "Jul": "07", "Aug": "08", "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12"]
    static let cmTraceLevels: [String: String] = ["1": "INFO", "2": "WARN", "3": "ERROR"]
    static let daemonLevels: [String: String] = ["I": "INFO", "W": "WARN", "E": "ERROR"]

    /// `parseStructuredLine`: text-log lines with a recognised shape become
    /// events with a time, level and message; the rest keep their raw text.
    public static func parseStructured(index: Int, line raw: String) -> JsonlEvent {
        var out = JsonlEvent(index: index, raw: raw)
        if let m = convention.captures(in: raw), let day = m[0], let clock = m[1], let level = m[2] {
            let message = m[3] ?? ""
            out.parsed = .object(["timestamp": .string("\(day) \(clock)"), "level": .string(level), "message": .string(message)])
            out.timestamp = "\(day)T\(clock)"; out.level = level; out.message = message
            return out
        }
        if let m = bracketStamp.captures(in: raw), let day = m[0], let clock = m[1] {
            let rest = m[2] ?? ""
            let lv = bracketLevel.captures(in: rest)
            let level = lv?[0].map { $0.uppercased().replacingOccurrences(of: "WARNING", with: "WARN") } ?? wordLevel(rest)
            let message = lv?[1] ?? rest
            var obj: [String: JSONValue] = ["timestamp": .string("\(day) \(clock)"), "message": .string(message)]
            if let level { obj["level"] = .string(level) }
            out.parsed = .object(obj)
            out.timestamp = "\(day)T\(clock)"; out.level = level; out.message = message
            return out
        }
        if let m = cmTrace.captures(in: raw), let message = m[0], let time = m[1], let date = m[2] {
            let component = m[3] ?? "", type = m[4] ?? "", thread = m[5] ?? ""
            let parts = date.split(separator: "-").map(String.init)
            var iso: String? = nil
            if parts.count == 3 {
                let clock = time.replacingOccurrences(of: #"[+-]\d+$"#, with: "", options: .regularExpression)
                iso = "\(parts[2])-\(parts[0].leftPadded(2))-\(parts[1].leftPadded(2))T\(clock)"
            }
            out.parsed = .object(["time": .string(time), "date": .string(date), "component": .string(component), "type": .string(type), "thread": .string(thread), "message": .string(message)])
            out.timestamp = iso; out.level = cmTraceLevels[type] ?? type; out.eventType = component; out.message = message
            return out
        }
        if let m = intuneDaemon.captures(in: raw), let stamp = m[0], let millis = m[1] {
            let process = (m[2] ?? "").trimmingCharacters(in: .whitespaces), level = m[3] ?? ""
            let thread = (m[4] ?? "").trimmingCharacters(in: .whitespaces), logger = (m[5] ?? "").trimmingCharacters(in: .whitespaces)
            let message = m[6] ?? ""
            out.parsed = .object(["timestamp": .string("\(stamp).\(millis)"), "process": .string(process), "level": .string(level), "thread": .string(thread), "logger": .string(logger), "message": .string(message)])
            out.timestamp = "\(stamp.replacingOccurrences(of: " ", with: "T")).\(millis)"
            out.level = daemonLevels[level] ?? level; out.eventType = logger; out.message = message
            return out
        }
        if let m = munki.captures(in: raw), let mon = m[0], let day = m[1], let year = m[2], let clock = m[3] {
            let message = m[4] ?? ""
            let stamp = "\(year)-\(months[mon] ?? "01")-\(day)T\(clock)"
            out.parsed = .object(["timestamp": .string(stamp), "message": .string(message)])
            out.timestamp = stamp; out.level = wordLevel(message); out.message = message
            return out
        }
        if let m = syslog.captures(in: raw), let day = m[0], let clock = m[1] {
            let host = m[2] ?? "", process = m[3] ?? "", message = m[4] ?? ""
            out.parsed = .object(["timestamp": .string("\(day) \(clock)"), "host": .string(host), "process": .string(process), "message": .string(message)])
            out.timestamp = "\(day)T\(clock)"; out.level = wordLevel(message); out.eventType = process; out.message = message
            return out
        }
        if let m = stamped.captures(in: raw), let day = m[0], let clock = m[1] {
            let message = m[2] ?? ""
            out.parsed = .object(["timestamp": .string("\(day) \(clock)"), "message": .string(message)])
            out.timestamp = "\(day)T\(clock)"; out.level = wordLevel(message); out.message = message
            return out
        }
        return out
    }

    /// A CMTrace record can span several physical lines when its message holds
    /// newlines; the client tails by line, so stitch a record back together from
    /// its `<![LOG[` opener to the line that closes it.
    public static func stitchCmTrace(_ lines: [String]) -> [String] {
        var out: [String] = []
        var open: String? = nil
        func closes(_ line: String) -> Bool { line.range(of: #"\]LOG\]!>.*>\s*$"#, options: .regularExpression) != nil }
        for line in lines {
            if var current = open {
                current += "\n" + line
                if closes(line) { out.append(current); open = nil } else { open = current }
                continue
            }
            if line.hasPrefix("<![LOG["), !closes(line) { open = line; continue }
            out.append(line)
        }
        if let open { out.append(open) }
        return out
    }

    /// The pill tone for a message tag: outcomes carry a colour, phases stay neutral.
    public enum TagTone: Sendable { case success, retry, failure, neutral }
    public static func tagTone(_ tag: String) -> TagTone {
        switch tag.uppercased() {
        case "SUCCESS", "DONE", "COMPLETE", "COMPLETED", "INSTALLED", "OK": return .success
        case "RETRY", "RETRYING", "TIMEOUT": return .retry
        case "FAILED", "FAILURE", "FAIL": return .failure
        default: return .neutral
        }
    }

    /// One tail line parsed once with its level; the text and level filters
    /// then narrow the list and the event view reuses the parse.
    public struct ClassifiedLine: Sendable, Hashable, Identifiable {
        public var id: Int
        public var line: String
        public var event: JsonlEvent?
        public var level: LineLevel
    }

    /// Every text log is shown as rows: JSONL by its records, `.json` as one
    /// document (no rows), everything else through the structured parsers.
    public static func classify(lines: [String], file: String?) -> [ClassifiedLine] {
        let lower = (file ?? "").lowercased()
        let isJsonl = lower.hasSuffix(".jsonl")
        let isJson = lower.hasSuffix(".json")
        return lines.enumerated().map { i, line in
            let event: JsonlEvent? = isJsonl ? JsonlEvent(index: i, line: line).liftingTag() : isJson ? nil : parseStructured(index: i, line: line).liftingTag()
            let level: LineLevel = event?.parsed != nil ? levelTone(event?.level) : lineTone(line)
            return ClassifiedLine(id: i, line: line, event: event, level: level)
        }
    }

    public static func levelCounts(_ lines: [ClassifiedLine]) -> LevelCounts {
        var counts = LevelCounts()
        for entry in lines {
            switch entry.level {
            case .error: counts.error += 1
            case .warning: counts.warning += 1
            case .debug: counts.debug += 1
            case .plain: break
            }
        }
        return counts
    }

    /// Whether a tailed file holds error and warning lines, for the dots beside its name.
    public static func fileFlags(_ tail: Tail) -> (errors: Bool, warnings: Bool) {
        let jsonl = (tail.file ?? "").lowercased().hasSuffix(".jsonl")
        var errors = false, warnings = false
        for (i, line) in tail.lines.enumerated() {
            let event = jsonl ? JsonlEvent(index: i, line: line) : parseStructured(index: i, line: line)
            let level = event.parsed != nil ? levelTone(event.level) : lineTone(line)
            if level == .error { errors = true } else if level == .warning { warnings = true }
            if errors && warnings { break }
        }
        return (errors, warnings)
    }

    /// A component that is the same on every row of the file says nothing per
    /// row (IntuneManagementExtension.log is all IntuneManagementExtension).
    public static func uniformComponent(_ lines: [ClassifiedLine]) -> Bool {
        var seen: String? = nil
        for entry in lines {
            guard let type = entry.event?.eventType else { continue }
            if seen == nil { seen = type } else if seen != type { return false }
        }
        return seen != nil
    }

    // MARK: Tool versions

    /// The managed item that owns each log root, per platform, for the version
    /// fallback. Munki reports items under installs.managedInstalls[] (or
    /// munki.items[]) with installedVersion; Cimian under cimian.items[].
    static let toolItems: [String: (mac: [String], windows: [String])] = [
        "installs": (["MunkiTools", "munkitools"], ["CimianTools", "Cimian"]),
        "bootstrap": (["BootstrapMate"], ["BootstrapMate"]),
        "reports": (["ReportMate"], ["ReportMate"]),
        "state": (["Outset"], ["StartSet"]),
        "encryption": (["Crypt"], ["Crypt", "CryptEscrow"]),
        "users": (["ManageUsers"], ["ManageUsers"]),
        "utilities": (["DockUtil"], ["SbinInstaller", "TaskbarUtil"]),
        "notifications": (["SwiftDialog"], ["csharpdialog", "CSharpDialog"]),
    ]

    /// `installedVersionFor`: the tool's version from the installs module when the root carries none.
    public static func installedVersion(for tool: String, platform: String?, installs: JSONValue) -> String? {
        guard installs.object != nil, let names = toolItems[tool.lowercased()] else { return nil }
        let isWindows = (platform ?? "").lowercased().contains("win")
        let wanted = Set((isWindows ? names.windows : names.mac).map { $0.lowercased() })
        let items = installs["managedInstalls"].elements + installs["munki"]["items"].elements + installs["cimian"]["items"].elements
        for item in items {
            let name = (item.firstString("name", "itemName") ?? "").lowercased()
            guard wanted.contains(name) else { continue }
            if let installed = item["installedVersion"].string?.trimmingCharacters(in: .whitespaces), !installed.isEmpty { return installed }
            let status = (item.firstString("currentStatus", "status") ?? "").lowercased()
            if let latest = item["latestVersion"].string?.trimmingCharacters(in: .whitespaces), !latest.isEmpty, status == "installed" { return latest }
        }
        return nil
    }

    // MARK: Formatting

    public static func formatBytes(_ bytes: Double?) -> String {
        guard let bytes, bytes.isFinite else { return "" }
        if bytes < 1024 { return "\(Int(bytes)) B" }
        let units = ["KB", "MB", "GB"]
        var value = bytes / 1024
        var unit = 0
        while value >= 1024, unit < units.count - 1 { value /= 1024; unit += 1 }
        return (value < 10 ? String(format: "%.1f", value) : String(Int(value.rounded()))) + " " + units[unit]
    }

    public static func formatDuration(_ seconds: Double?) -> String {
        guard let seconds, seconds.isFinite else { return "" }
        if seconds < 60 { return "\(Int(seconds.rounded()))s" }
        let minutes = Int(seconds / 60)
        let rest = Int((seconds.truncatingRemainder(dividingBy: 60)).rounded())
        if minutes < 60 { return rest > 0 ? "\(minutes)m \(rest)s" : "\(minutes)m" }
        return "\(minutes / 60)h \(minutes % 60)m"
    }
}

extension NSRegularExpression {
    /// Capture groups of the first match, nil when the pattern does not match;
    /// a group that did not participate is nil.
    func captures(in text: String) -> [String?]? {
        let ns = text as NSString
        guard let m = firstMatch(in: text, range: NSRange(location: 0, length: ns.length)) else { return nil }
        return (1..<m.numberOfRanges).map { i in
            let r = m.range(at: i)
            return r.location == NSNotFound ? nil : ns.substring(with: r)
        }
    }

    func firstCapture(in text: String) -> String? {
        captures(in: text)?.first ?? nil
    }
}

private extension String {
    func leftPadded(_ width: Int) -> String {
        count >= width ? self : String(repeating: "0", count: width - count) + self
    }
}
