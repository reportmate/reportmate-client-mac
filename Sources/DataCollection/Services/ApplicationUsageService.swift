import Foundation
import SQLite

/// SQLite.swift's `Expression` collides with `Foundation.Expression` on recent
/// SDKs, making bare `Expression<...>` ambiguous. Alias to the SQLite type so
/// the column declarations below stay unambiguous.
private typealias Expression<Datatype> = SQLite.Expression<Datatype>

// MARK: - Application Usage Models

/// Snapshot of application usage data - matches Windows ApplicationUsageSnapshot
public struct ApplicationUsageSnapshot: Sendable {
    public var isCaptureEnabled: Bool = false
    public var status: String = "uninitialized"
    public var captureMethod: String = "None"
    public var generatedAt: Date = Date()
    public var windowStart: Date = Date()
    public var windowEnd: Date = Date()
    public var totalLaunches: Int = 0
    public var totalUsageSeconds: Double = 0
    public var activeSessions: [ApplicationUsageSession] = []
    public var warnings: [String] = []
    
    /// Create an unavailable snapshot with warning message
    public static func createUnavailable(_ message: String? = nil) -> ApplicationUsageSnapshot {
        var snapshot = ApplicationUsageSnapshot()
        snapshot.isCaptureEnabled = false
        snapshot.status = "unavailable"
        snapshot.warnings = [message ?? "Application usage tracking is not available"]
        return snapshot
    }
    
    /// Convert to dictionary for JSON serialization
    public func toDictionary() -> [String: Any] {
        let formatter = ISO8601DateFormatter()
        return [
            "isCaptureEnabled": isCaptureEnabled,
            "status": status,
            "captureMethod": captureMethod,
            "generatedAt": formatter.string(from: generatedAt),
            "windowStart": formatter.string(from: windowStart),
            "windowEnd": formatter.string(from: windowEnd),
            "totalLaunches": totalLaunches,
            "totalUsageSeconds": totalUsageSeconds,
            "activeSessions": activeSessions.map { $0.toDictionary() },
            "warnings": warnings
        ]
    }
}

/// Individual usage session - matches Windows ApplicationUsageSession
public struct ApplicationUsageSession: Sendable {
    public var sessionId: String = ""
    public var name: String = ""
    public var path: String = ""
    public var processId: Int = 0
    public var user: String = ""
    public var startTime: Date = Date()
    public var endTime: Date? = nil
    public var durationSeconds: Double = 0
    // Idle-time split: foreground = time app held OS focus; active = foreground
    // AND user input within prior 300s. Populated by AppUsageWatcher's tick.
    public var foregroundSeconds: Double = 0
    public var activeSeconds: Double = 0
    public var isActive: Bool = false

    public func toDictionary() -> [String: Any] {
        let formatter = ISO8601DateFormatter()
        var dict: [String: Any] = [
            "sessionId": sessionId,
            "name": name,
            "path": path,
            "processId": processId,
            "user": user,
            "startTime": formatter.string(from: startTime),
            "durationSeconds": Int64(durationSeconds),
            "foregroundSeconds": Int64(foregroundSeconds),
            "activeSeconds": Int64(activeSeconds),
            "isActive": isActive
        ]
        if let end = endTime {
            dict["endTime"] = formatter.string(from: end)
        }
        return dict
    }
}

// MARK: - Application Usage Service

/// Service for collecting application usage data from SQLite database.
/// The database is populated by the reportmate-appusage watcher daemon.
/// Falls back to ps-based polling if database is unavailable.
public class ApplicationUsageService: @unchecked Sendable {
    
    private let dbPath: String
    private var transmittedSessionIds: [Int64] = []  // Track IDs for two-phase delete
    
    public init(dbPath: String = "/Library/Managed Reports/appusage.sqlite") {
        self.dbPath = dbPath
    }
    
    /// Collect application usage data
    /// Primary: Query SQLite database populated by watcher daemon
    /// Fallback: Use ps command for currently running processes
    public func collectUsageData(
        installedApps: [[String: Any]],
        lookbackHours: Int? = nil
    ) async -> ApplicationUsageSnapshot {
        let hours = lookbackHours ?? 4
        var snapshot = ApplicationUsageSnapshot()
        snapshot.generatedAt = Date()
        snapshot.windowStart = Date().addingTimeInterval(TimeInterval(-hours * 3600))
        snapshot.windowEnd = Date()
        
        // Try SQLite database first (populated by watcher daemon)
        if FileManager.default.fileExists(atPath: dbPath) {
            do {
                let result = try collectFromDatabase(installedApps: installedApps)
                snapshot.isCaptureEnabled = true
                snapshot.captureMethod = "SQLiteWatcher"
                snapshot.status = "complete"
                snapshot.activeSessions = result.sessions
                snapshot.totalLaunches = result.totalLaunches
                snapshot.totalUsageSeconds = result.totalUsageSeconds
                transmittedSessionIds = result.sessionIds
                return snapshot
            } catch {
                snapshot.warnings.append("Database error: \(error.localizedDescription), falling back to polling")
            }
        }
        
        // Fallback to ps-based polling (for when watcher is not installed)
        snapshot.captureMethod = "ProcessPolling"
        snapshot.isCaptureEnabled = true
        
        do {
            let sessions = try collectRunningSessions(installedApps: installedApps)
            snapshot.status = "complete"
            snapshot.activeSessions = sessions
            snapshot.totalLaunches = sessions.count
            snapshot.totalUsageSeconds = sessions.reduce(0) { $0 + $1.durationSeconds }
            
            if !FileManager.default.fileExists(atPath: dbPath) {
                snapshot.warnings.append("Watcher daemon not running. Install reportmate-appusage for accurate usage tracking.")
            }
        } catch {
            snapshot.status = "error"
            snapshot.warnings.append(error.localizedDescription)
        }
        
        return snapshot
    }
    
    /// Retire the sessions that were just delivered. Call only after the API has
    /// confirmed success — until this runs, the same sessions are collected again
    /// on the next cycle and the server adds their duration a second time.
    public func confirmTransmission() {
        guard !transmittedSessionIds.isEmpty else { return }

        do {
            let db = try Connection(dbPath)

            // Marking before deleting keeps this safe to interrupt: a crash
            // between the two statements leaves the batch flagged, which excludes
            // it from the next collection and lets the following call clear it.
            let sessions = Table("app_sessions")
            let id = Expression<Int64>("id")
            let transmitted = Expression<Bool>("transmitted")

            // The first confirmation after a long backlog can carry tens of
            // thousands of ids; a single IN-list that size exceeds SQLite's
            // bound-variable limit and would abort the whole batch. Mark in
            // chunks so the machines with the worst backlogs still converge.
            let chunkSize = 500
            var start = 0
            while start < transmittedSessionIds.count {
                let end = min(start + chunkSize, transmittedSessionIds.count)
                let chunk = Array(transmittedSessionIds[start..<end])
                try db.run(sessions.filter(chunk.contains(id)).update(transmitted <- true))
                start = end
            }

            let toDelete = sessions.filter(transmitted == true)
            try db.run(toDelete.delete())

            transmittedSessionIds = []
        } catch {
            print("Warning: Failed to mark sessions as transmitted: \(error)")
        }
    }
    
    // MARK: - SQLite Database Collection
    
    private func collectFromDatabase(installedApps: [[String: Any]]) throws -> (sessions: [ApplicationUsageSession], totalLaunches: Int, totalUsageSeconds: Double, sessionIds: [Int64]) {
        let db = try Connection(dbPath, readonly: true)
        
        let sessions = Table("app_sessions")
        let idCol = Expression<Int64>("id")
        let appNameCol = Expression<String>("app_name")
        let pathCol = Expression<String>("path")
        let userCol = Expression<String>("user")
        let pidCol = Expression<Int64>("pid")
        let startTimeCol = Expression<String>("start_time")
        let endTimeCol = Expression<String?>("end_time")
        let durationCol = Expression<Int64>("duration_seconds")
        let foregroundCol = Expression<Int64>("foreground_seconds")
        let activeCol = Expression<Int64>("active_seconds")
        let transmittedCol = Expression<Bool>("transmitted")
        
        // Query untransmitted completed sessions + active sessions
        let query = sessions
            .filter(transmittedCol == false)
            .order(startTimeCol.desc)
        
        var result: [ApplicationUsageSession] = []
        var sessionIds: [Int64] = []
        var totalLaunches = 0
        var totalUsageSeconds: Double = 0
        
        let formatter = ISO8601DateFormatter()
        
        for row in try db.prepare(query) {
            let rowId = row[idCol]
            let path = row[pathCol]
            let isActive = row[endTimeCol] == nil
            
            // Accept all tracked applications from the watcher database
            // The watcher already filters to trackable GUI apps in /Applications
            let startDate = formatter.date(from: row[startTimeCol]) ?? Date()
            var duration = Double(row[durationCol])
            
            // For active sessions, calculate current duration
            if isActive {
                duration = Date().timeIntervalSince(startDate)
            }
            
            // Skip unknown duration sessions in totals but include them
            if row[durationCol] != -1 {
                totalUsageSeconds += duration
            }
            
            var session = ApplicationUsageSession()
            session.sessionId = "\(row[pidCol])-\(Int(startDate.timeIntervalSince1970))"
            session.name = row[appNameCol]
            session.path = path
            session.processId = Int(row[pidCol])
            session.user = row[userCol]
            session.startTime = startDate
            session.endTime = row[endTimeCol].flatMap { formatter.date(from: $0) }
            session.durationSeconds = duration
            // Foreground/active counters are missing on rows written before the
            // schema migration; SQLite returns 0 in that case, which is the
            // correct neutral value.
            session.foregroundSeconds = Double((try? row.get(foregroundCol)) ?? 0)
            session.activeSeconds = Double((try? row.get(activeCol)) ?? 0)
            session.isActive = isActive
            
            result.append(session)
            // Only completed sessions are eligible for retirement. A running app
            // is still accruing time, so it stays in the database until it exits
            // and contributes its duration once, when it is final.
            if !isActive {
                sessionIds.append(rowId)
            }
            totalLaunches += 1
        }
        
        return (result, totalLaunches, totalUsageSeconds, sessionIds)
    }
    
    // MARK: - Fallback: Process Polling
    
    /// Collect running application sessions - fast ps-based polling (fallback)
    private func collectRunningSessions(installedApps: [[String: Any]]) throws -> [ApplicationUsageSession] {
        var sessions: [ApplicationUsageSession] = []
        
        // Use Process with bash -c - MUST read output before waitUntilExit to avoid pipe deadlock
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/bash")
        process.arguments = ["-c", "/bin/ps axo pid,lstart,user,comm 2>/dev/null"]
        
        let outputPipe = Pipe()
        process.standardOutput = outputPipe
        process.standardError = FileHandle.nullDevice
        
        let readHandle = outputPipe.fileHandleForReading
        
        try process.run()
        
        // CRITICAL: Read output BEFORE waitUntilExit to avoid pipe buffer deadlock
        let outputData = readHandle.readDataToEndOfFile()
        
        process.waitUntilExit()
        
        guard let output = String(data: outputData, encoding: .utf8) else {
            return sessions
        }
        
        // Parse output efficiently
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "EEE MMM d HH:mm:ss yyyy"
        dateFormatter.locale = Locale(identifier: "en_US_POSIX")
        
        let lines = output.split(separator: "\n").dropFirst() // Skip header
        
        for line in lines {
            guard let parsed = parsePsLine(String(line), dateFormatter: dateFormatter) else {
                continue
            }
            
            // Only track apps from /Applications or /System/Applications
            guard parsed.path.contains("/Applications/") else {
                continue
            }
            
            // Match to installed apps
            guard let appInfo = matchToInstalledApp(path: parsed.path, installedApps: installedApps) else {
                continue
            }
            
            let duration = Date().timeIntervalSince(parsed.startTime)
            
            var session = ApplicationUsageSession()
            session.sessionId = "\(parsed.pid)-\(Int(parsed.startTime.timeIntervalSince1970))"
            session.name = appInfo["name"] as? String ?? parsed.processName
            session.path = parsed.path
            session.processId = parsed.pid
            session.user = parsed.user
            session.startTime = parsed.startTime
            session.durationSeconds = duration
            session.isActive = true
            
            sessions.append(session)
        }
        
        return sessions
    }
    
    /// Parse a single ps output line
    private func parsePsLine(_ line: String, dateFormatter: DateFormatter) -> (pid: Int, startTime: Date, user: String, path: String, processName: String)? {
        // Format: "  545 Fri Dec 12 10:07:48 2025     rod    /Applications/..."
        // Use regex to handle variable spacing in date
        let pattern = #"^\s*(\d+)\s+(\w{3})\s+(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\d{4})\s+(\S+)\s+(.+)$"#
        
        guard let regex = try? NSRegularExpression(pattern: pattern),
              let match = regex.firstMatch(in: line, range: NSRange(line.startIndex..., in: line)) else {
            return nil
        }
        
        func extract(_ index: Int) -> String? {
            guard let range = Range(match.range(at: index), in: line) else { return nil }
            return String(line[range])
        }
        
        guard let pidStr = extract(1), let pid = Int(pidStr),
              let dayName = extract(2), let month = extract(3),
              let day = extract(4), let time = extract(5), let year = extract(6),
              let user = extract(7), let path = extract(8) else {
            return nil
        }
        
        let dateString = "\(dayName) \(month) \(day) \(time) \(year)"
        guard let startTime = dateFormatter.date(from: dateString) else {
            return nil
        }
        
        let processName = (path as NSString).lastPathComponent
        return (pid, startTime, user, path.trimmingCharacters(in: .whitespaces), processName)
    }
    
    /// Match process path to installed application
    private func matchToInstalledApp(path: String, installedApps: [[String: Any]]) -> [String: Any]? {
        let lowerPath = path.lowercased()
        
        for app in installedApps {
            if let installLoc = app["installLocation"] as? String,
               lowerPath.hasPrefix(installLoc.lowercased()) {
                return app
            }
            if let bundleId = app["bundleIdentifier"] as? String,
               !bundleId.isEmpty,
               lowerPath.contains(bundleId.lowercased()) {
                return app
            }
            if let name = app["name"] as? String {
                let appPath = "/applications/\(name.lowercased()).app"
                if lowerPath.hasPrefix(appPath) {
                    return app
                }
            }
        }
        return nil
    }

    /// Running totals for one (date, app name) pair while summaries are built.
    private struct DailyUsageBucket {
        var launches = 0
        var totalSeconds = 0.0
        var foregroundSeconds = 0.0
        var activeSeconds = 0.0
        var users: Set<String> = []
    }

    /// The calendar days a session covers, each with the fraction of the
    /// session's wall-clock span that fell on that day.
    ///
    /// A session is one continuous run of an application, so an app opened
    /// before midnight and closed after it was in use on both days. Attributing
    /// the whole run to the day it started — as this did previously — books a
    /// week of uptime onto a single date and leaves the days it actually
    /// covered empty, which makes any per-day or per-week series wrong.
    ///
    /// The foreground and active counters are accumulated across the whole
    /// session rather than per day, so they are apportioned by the same
    /// wall-clock share. That is an estimate; only per-day counters in the
    /// watcher itself could make it exact.
    private func daySpans(of session: ApplicationUsageSession,
                          formatter: DateFormatter) -> [(String, Double)] {
        let start = session.startTime
        guard let end = session.endTime, end > start else {
            return [(formatter.string(from: start), 1.0)]
        }

        let span = end.timeIntervalSince(start)
        let calendar = Calendar.current
        var spans: [(String, Double)] = []
        var cursor = start

        // Bounded by the watcher's 30-day retention; the cap only guards against
        // a corrupt end_time far in the future turning this into a long loop.
        while cursor < end, spans.count < 400 {
            let dayStart = calendar.startOfDay(for: cursor)
            guard let nextDay = calendar.date(byAdding: .day, value: 1, to: dayStart),
                  nextDay > cursor else { break }
            let segmentEnd = min(nextDay, end)
            let seconds = segmentEnd.timeIntervalSince(cursor)
            if seconds > 0 {
                spans.append((formatter.string(from: cursor), seconds / span))
            }
            cursor = segmentEnd
        }

        return spans.isEmpty ? [(formatter.string(from: start), 1.0)] : spans
    }

    /// Build daily per-application usage summaries from sessions.
    /// Groups by (date, app name). Cumulative: last collection of the day wins (UPSERT on API).
    public func buildDailySummaries(sessions: [ApplicationUsageSession]) -> [[String: Any]] {
        // The server accumulates these totals per (device, date, app), so every
        // session must appear here exactly once, in the cycle it completes.
        // Running apps are excluded: their duration grows between cycles, so
        // sending them repeatedly would add the same app-open several times over.
        // They are counted once they exit; `sessions` still carries them for the
        // snapshot's live view.
        let sessions = sessions.filter { !$0.isActive }
        guard !sessions.isEmpty else { return [] }

        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd"
        dateFormatter.locale = Locale(identifier: "en_US_POSIX")
        dateFormatter.timeZone = TimeZone.current

        // Accumulate by (date string, app name). A session that runs past
        // midnight belongs to every day it covers, not only the one it started
        // on, so each session is split across the days it spans first.
        var buckets: [String: DailyUsageBucket] = [:]
        for session in sessions {
            // A session interrupted by a watcher restart is stamped with the -1
            // unknown-duration sentinel (AppUsageDatabase.markOrphanedSessions).
            // It carries no measurable duration, so it contributes nothing here —
            // summing it raw would send a negative total to the server, which
            // reads these as real seconds and accumulates them.
            let total = max(0, session.durationSeconds)
            let foreground = max(0, session.foregroundSeconds)
            let active = max(0, session.activeSeconds)
            let startDate = dateFormatter.string(from: session.startTime)

            for (dateStr, share) in daySpans(of: session, formatter: dateFormatter) {
                let key = "\(dateStr)||\(session.name)"
                var bucket = buckets[key] ?? DailyUsageBucket()
                bucket.totalSeconds += total * share
                bucket.foregroundSeconds += foreground * share
                bucket.activeSeconds += active * share
                if !session.user.isEmpty {
                    bucket.users.insert(session.user)
                }
                // One app-open is one launch, counted on the day it happened —
                // apportioning it too would multiply launch counts by the number
                // of days a long-running app happened to stay open.
                if dateStr == startDate {
                    bucket.launches += 1
                }
                buckets[key] = bucket
            }
        }

        var summaries: [[String: Any]] = []
        for (key, bucket) in buckets {
            let parts = key.split(separator: "|", maxSplits: 2, omittingEmptySubsequences: false)
            guard parts.count >= 3 else { continue }

            summaries.append([
                "date": String(parts[0]),
                "appName": String(parts[2]),
                "publisher": "",
                "launches": bucket.launches,
                "totalSeconds": bucket.totalSeconds,
                "foregroundSeconds": bucket.foregroundSeconds,
                "activeSeconds": bucket.activeSeconds,
                "users": Array(bucket.users)
            ])
        }

        return summaries.sorted { a, b in
            let dateA = a["date"] as? String ?? ""
            let dateB = b["date"] as? String ?? ""
            if dateA != dateB { return dateA < dateB }
            return (a["totalSeconds"] as? Double ?? 0) > (b["totalSeconds"] as? Double ?? 0)
        }
    }
}
