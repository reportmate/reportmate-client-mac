import Foundation

/// Reads the structured session reports newer Munki builds write beside
/// ManagedInstallReport.plist:
///
///     /Library/Managed Installs/logs/YYYY-MM-DD/HHMM[_n]/{session.json, events.jsonl, run.log}
///     /Library/Managed Installs/reports/{sessions.json, events.json, items.json, run.log}
///
/// The layout and field names are the ones the Windows client reads from Cimian, so the
/// installs module can carry the same shape on both platforms. `read()` returns nil when
/// `reports/sessions.json` does not exist, and the caller keeps the legacy plist path.
struct MunkiSessionReports {
    /// Raw session records (snake_case, as written), newest first.
    let sessions: [[String: Any]]
    /// Raw item records from reports/items.json (snake_case).
    let items: [[String: Any]]
    /// The latest finished session's session.json (snake_case).
    let latestSession: [String: Any]?
    /// Directory of the latest finished session.
    let latestSessionDir: String?
    /// Raw events (snake_case) for the latest finished session.
    let events: [[String: Any]]
    /// reports/run.log contents (capped).
    let runLog: String
    /// Number of session directories on disk.
    let totalSessions: Int

    var sessionId: String? { latestSession?["session_id"] as? String }
    var runType: String? { latestSession?["run_type"] as? String }
    var status: String? { latestSession?["status"] as? String }
    var durationSeconds: Int? { latestSession?["duration_seconds"] as? Int }
    var environment: [String: Any] { latestSession?["environment"] as? [String: Any] ?? [:] }
    var warningItems: [[String: Any]] { latestSession?["warning_items"] as? [[String: Any]] ?? [] }
    var errorItems: [[String: Any]] { latestSession?["error_items"] as? [[String: Any]] ?? [] }
}

enum MunkiSessionReportReader {
    static let defaultBaseDir = "/Library/Managed Installs"
    static let runLogCap = 100_000

    static func read(baseDir: String = defaultBaseDir) -> MunkiSessionReports? {
        let reportsDir = (baseDir as NSString).appendingPathComponent("reports")
        let logsDir = (baseDir as NSString).appendingPathComponent("logs")
        guard let sessions = readArray(at: (reportsDir as NSString).appendingPathComponent("sessions.json")) else {
            return nil
        }
        let items = readArray(at: (reportsDir as NSString).appendingPathComponent("items.json")) ?? []

        let dirs = sessionDirectories(logsDir: logsDir)
        var latestSession: [String: Any]?
        var latestDir: String?
        for dir in dirs {
            guard let session = readObject(at: (dir as NSString).appendingPathComponent("session.json")) else { continue }
            // A session still marked running belongs to a managedsoftwareupdate that has not
            // finished; report the previous one rather than a half-written run.
            if (session["status"] as? String) == "running" { continue }
            latestSession = session
            latestDir = dir
            break
        }

        var events: [[String: Any]] = []
        if let latestDir {
            events = readJSONLines(at: (latestDir as NSString).appendingPathComponent("events.jsonl"))
        }
        if events.isEmpty, let sessionId = latestSession?["session_id"] as? String,
           let reportEvents = readArray(at: (reportsDir as NSString).appendingPathComponent("events.json"))
        {
            events = reportEvents.filter { ($0["session_id"] as? String) == sessionId }
        }

        var runLog = ""
        if let data = FileManager.default.contents(atPath: (reportsDir as NSString).appendingPathComponent("run.log")),
           let text = String(data: data, encoding: .utf8)
        {
            runLog = text.count > runLogCap ? String(text.suffix(runLogCap)) : text
        }

        return MunkiSessionReports(
            sessions: sessions,
            items: items,
            latestSession: latestSession,
            latestSessionDir: latestDir,
            events: events,
            runLog: runLog,
            totalSessions: dirs.count
        )
    }

    /// Every session directory under logs/, newest first. Day directories are
    /// `YYYY-MM-DD`; session directories are `HHMM` with an optional `_2`…`_9` suffix.
    static func sessionDirectories(logsDir: String) -> [String] {
        let fm = FileManager.default
        guard let days = try? fm.contentsOfDirectory(atPath: logsDir) else { return [] }
        var result: [String] = []
        for day in days.filter(isDayDirectory).sorted(by: >) {
            let dayPath = (logsDir as NSString).appendingPathComponent(day)
            guard let times = try? fm.contentsOfDirectory(atPath: dayPath) else { continue }
            for time in times.filter(isTimeDirectory).sorted(by: >) {
                result.append((dayPath as NSString).appendingPathComponent(time))
            }
        }
        return result
    }

    static func isDayDirectory(_ name: String) -> Bool {
        guard name.count == 10 else { return false }
        let parts = name.split(separator: "-")
        return parts.count == 3 && parts[0].count == 4 && parts[1].count == 2 && parts[2].count == 2
            && parts.allSatisfy { $0.allSatisfy(\.isNumber) }
    }

    static func isTimeDirectory(_ name: String) -> Bool {
        let parts = name.split(separator: "_", maxSplits: 1).map(String.init)
        guard let time = parts.first, time.count == 4, let value = Int(time), value >= 0, value <= 2359 else { return false }
        if parts.count == 2 { return parts[1].count == 1 && Int(parts[1]) != nil }
        return true
    }

    // MARK: - Key conversion

    /// snake_case → camelCase for the keys of one record, recursively. Sessions are sent
    /// as written (snake_case) because the dashboard already reads them that way from
    /// Cimian; events and items are camelCase there.
    static func camelCased(_ record: [String: Any]) -> [String: Any] {
        var out: [String: Any] = [:]
        for (key, value) in record {
            let newKey = camelCase(key)
            if let dict = value as? [String: Any] {
                out[newKey] = camelCased(dict)
            } else if let array = value as? [[String: Any]] {
                out[newKey] = array.map(camelCased)
            } else {
                out[newKey] = value
            }
        }
        return out
    }

    static func camelCase(_ key: String) -> String {
        guard key.contains("_") else { return key }
        let parts = key.split(separator: "_", omittingEmptySubsequences: true).map(String.init)
        guard let first = parts.first else { return key }
        return first + parts.dropFirst().map { $0.prefix(1).uppercased() + $0.dropFirst() }.joined()
    }

    // MARK: - File helpers

    private static func readArray(at path: String) -> [[String: Any]]? {
        guard let data = FileManager.default.contents(atPath: path),
              let json = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else { return nil }
        return json
    }

    private static func readObject(at path: String) -> [String: Any]? {
        guard let data = FileManager.default.contents(atPath: path),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        return json
    }

    private static func readJSONLines(at path: String) -> [[String: Any]] {
        guard let data = FileManager.default.contents(atPath: path),
              let text = String(data: data, encoding: .utf8) else { return [] }
        return text.split(separator: "\n").compactMap { line in
            guard let lineData = line.data(using: .utf8),
                  let object = try? JSONSerialization.jsonObject(with: lineData) as? [String: Any] else { return nil }
            return object
        }
    }
}
