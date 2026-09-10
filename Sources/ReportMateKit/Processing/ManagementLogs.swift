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
            "state": ("Outset", "StartSet"), "encryption": ("Crypt", "Crypt Escrow"), "users": ("ManageUsers", "ManageUsers"),
            "utilities": ("Utilities", "Utilities"),
        ]

        /// The product behind a root: Munki or Cimian for installs, and so on.
        public func productName(platform: String?) -> String {
            guard let names = Root.productNames[tool.lowercased()] else { return label }
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
        roots = raw["roots"].elements.compactMap(Root.init(json:))
    }

    public var totalErrors: Int { roots.reduce(0) { $0 + ($1.errorCount ?? 0) } }
    public var totalWarnings: Int { roots.reduce(0) { $0 + ($1.warningCount ?? 0) } }

    // MARK: Line helpers

    public enum LineTone: Sendable { case error, warning, plain }

    public static func lineTone(_ line: String) -> LineTone {
        if line.range(of: #"\b(ERROR|ERR|FAULT|CRITICAL|FATAL)\b"#, options: .regularExpression) != nil { return .error }
        if line.range(of: #"\b(WARN|WARNING|WRN)\b"#, options: .regularExpression) != nil { return .warning }
        return .plain
    }

    public static func levelTone(_ level: String?) -> LineTone {
        let l = (level ?? "").uppercased()
        if l.hasPrefix("ERR") || l == "FAULT" || l == "CRITICAL" || l == "FATAL" { return .error }
        if l.hasPrefix("WARN") || l == "WRN" { return .warning }
        return .plain
    }

    /// One structured `events.jsonl` record, or the raw line when it does not parse.
    public struct JsonlEvent: Sendable, Hashable, Identifiable {
        public var id: Int
        public var raw: String
        public var parsed: JSONValue?
        public var timestamp: String?
        public var level: String?
        public var eventType: String?
        public var item: String?
        public var version: String?
        public var message: String?

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
    }

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
