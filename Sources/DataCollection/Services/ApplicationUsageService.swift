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

    // Reporting watermark: the counter values the server has already accepted,
    // and when. A session still running contributes only what it gained since
    // then, so it can be reported the same day it is used without its running
    // total being added again on every cycle.
    public var reportedTotalSeconds: Double = 0
    public var reportedForegroundSeconds: Double = 0
    public var reportedActiveSeconds: Double = 0
    public var reportedAt: Date? = nil

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
    private var transmittedSessionIds: [Int64] = []  // Completed rows, retired on confirmation
    // Counter values handed to the server this cycle, per row. On confirmation
    // these become the row's watermark, so the next cycle reports only what the
    // session gained after this point.
    private var pendingWatermarks: [(id: Int64, total: Int64, foreground: Int64, active: Int64)] = []
    private var collectedAt: Date?

    /// How far back a session's very first report may attribute usage.
    ///
    /// A session that has never been reported carries counters covering its
    /// whole life, and nothing records which days that time fell on. Spreading
    /// it evenly would invent a usage pattern — a Mac left up for three months
    /// would appear to have been used every one of those days, weekends and
    /// closures included. Beyond this window the counters are taken as a
    /// starting watermark instead and nothing is claimed for them; reporting
    /// begins from the next cycle, when the window is a real measurement.
    private static let maxFirstReportWindow: TimeInterval = 24 * 3600

    /// Capture method reported when sessions come from the watcher's database,
    /// which is the only source that can carry a watermark forward.
    private static let watcherCaptureMethod = "SQLiteWatcher"
    
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
                snapshot.captureMethod = Self.watcherCaptureMethod
                snapshot.status = "complete"
                snapshot.activeSessions = result.sessions
                snapshot.totalLaunches = result.totalLaunches
                snapshot.totalUsageSeconds = result.totalUsageSeconds
                transmittedSessionIds = result.sessionIds
                pendingWatermarks = result.watermarks
                return snapshot
            } catch {
                snapshot.warnings.append("Database error: \(error.localizedDescription), falling back to polling")
            }
        }
        
        // Fallback to ps-based polling (for when watcher is not installed)
        snapshot.captureMethod = "ProcessPolling"
        snapshot.isCaptureEnabled = true
        
        do {
            let sessions = try await collectRunningSessions(installedApps: installedApps)
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
    ///
    /// Two things happen here. Every session that was reported, running or not,
    /// has its watermark advanced to the counters the server accepted, so the
    /// next cycle sends only the increment on top. Sessions that have ended are
    /// then retired, because they can gain nothing further.
    public func confirmTransmission() {
        guard !transmittedSessionIds.isEmpty || !pendingWatermarks.isEmpty else { return }

        do {
            let db = try Connection(dbPath)

            // Marking before deleting keeps this safe to interrupt: a crash
            // between the two statements leaves the batch flagged, which excludes
            // it from the next collection and lets the following call clear it.
            let sessions = Table("app_sessions")
            let id = Expression<Int64>("id")
            let transmitted = Expression<Bool>("transmitted")

            advanceWatermarks(db: db, sessions: sessions, id: id)

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

    /// Record, per reported session, the counter values the server accepted.
    ///
    /// The columns are added here as well as by the watcher because the two run
    /// as separate processes: a client that collects before the upgraded watcher
    /// has restarted would otherwise have nowhere to write the watermark, and
    /// would resend the same seconds every cycle.
    private func advanceWatermarks(db: Connection, sessions: Table, id: Expression<Int64>) {
        guard !pendingWatermarks.isEmpty else { return }

        _ = try? db.execute("ALTER TABLE app_sessions ADD COLUMN reported_total_seconds INTEGER NOT NULL DEFAULT 0")
        _ = try? db.execute("ALTER TABLE app_sessions ADD COLUMN reported_foreground_seconds INTEGER NOT NULL DEFAULT 0")
        _ = try? db.execute("ALTER TABLE app_sessions ADD COLUMN reported_active_seconds INTEGER NOT NULL DEFAULT 0")
        _ = try? db.execute("ALTER TABLE app_sessions ADD COLUMN reported_at TEXT")

        let reportedTotal = Expression<Int64>("reported_total_seconds")
        let reportedForeground = Expression<Int64>("reported_foreground_seconds")
        let reportedActive = Expression<Int64>("reported_active_seconds")
        let reportedAt = Expression<String?>("reported_at")
        let stamp = ISO8601DateFormatter().string(from: collectedAt ?? Date())

        do {
            try db.transaction {
                for mark in pendingWatermarks {
                    try db.run(sessions.filter(id == mark.id).update(
                        reportedTotal <- mark.total,
                        reportedForeground <- mark.foreground,
                        reportedActive <- mark.active,
                        reportedAt <- stamp
                    ))
                }
            }
            pendingWatermarks = []
        } catch {
            // Leaving the watermarks unadvanced resends this cycle's seconds on
            // the next one. That is the same at-least-once behaviour the delete
            // path already has, and is preferable to losing the counters.
            print("Warning: Failed to advance usage watermarks: \(error)")
        }
    }
    
    // MARK: - SQLite Database Collection
    
    private func collectFromDatabase(installedApps: [[String: Any]]) throws -> (sessions: [ApplicationUsageSession], totalLaunches: Int, totalUsageSeconds: Double, sessionIds: [Int64], watermarks: [(id: Int64, total: Int64, foreground: Int64, active: Int64)]) {
        let db = try Connection(dbPath, readonly: true)

        // Every elapsed figure in this batch is measured from one instant, so
        // the watermark written on confirmation matches what was actually sent.
        let now = Date()
        collectedAt = now
        
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
        let reportedTotalCol = Expression<Int64>("reported_total_seconds")
        let reportedForegroundCol = Expression<Int64>("reported_foreground_seconds")
        let reportedActiveCol = Expression<Int64>("reported_active_seconds")
        let reportedAtCol = Expression<String?>("reported_at")
        let transmittedCol = Expression<Bool>("transmitted")
        
        // Query untransmitted completed sessions + active sessions
        let query = sessions
            .filter(transmittedCol == false)
            .order(startTimeCol.desc)
        
        var result: [ApplicationUsageSession] = []
        var sessionIds: [Int64] = []
        var watermarks: [(id: Int64, total: Int64, foreground: Int64, active: Int64)] = []
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
                duration = now.timeIntervalSince(startDate)
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
            // Watermark columns are absent on databases written before the
            // migration; SQLite has no value to return and 0 / never-reported
            // is the correct reading for a row that predates them.
            session.reportedTotalSeconds = Double((try? row.get(reportedTotalCol)) ?? 0)
            session.reportedForegroundSeconds = Double((try? row.get(reportedForegroundCol)) ?? 0)
            session.reportedActiveSeconds = Double((try? row.get(reportedActiveCol)) ?? 0)
            session.reportedAt = ((try? row.get(reportedAtCol)) ?? nil).flatMap { formatter.date(from: $0) }
            session.isActive = isActive

            watermarks.append((
                id: rowId,
                total: Int64(observedTotalSeconds(of: session).rounded()),
                foreground: Int64(session.foregroundSeconds.rounded()),
                active: Int64(session.activeSeconds.rounded())
            ))

            result.append(session)
            // Only completed sessions are eligible for retirement. A running app
            // is still accruing time, so it stays in the database until it exits
            // and contributes its duration once, when it is final.
            if !isActive {
                sessionIds.append(rowId)
            }
            totalLaunches += 1
        }
        
        return (result, totalLaunches, totalUsageSeconds, sessionIds, watermarks)
    }
    
    // MARK: - Fallback: Process Polling
    
    /// Collect running application sessions - fast ps-based polling (fallback)
    private func collectRunningSessions(installedApps: [[String: Any]]) async throws -> [ApplicationUsageSession] {
        var sessions: [ApplicationUsageSession] = []

        // Reading before waiting avoided the pipe-buffer deadlock, but left the read itself
        // unbounded — a wedged ps would hold usage collection open indefinitely. ProcessRunner
        // gives it a time budget without reintroducing that deadlock.
        let result = try await ProcessRunner.bash("/bin/ps axo pid,lstart,user,comm 2>/dev/null", timeout: 60)

        guard !result.timedOut else {
            ConsoleFormatter.writeDebug("ps exceeded its time budget while collecting running sessions")
            return sessions
        }

        let output = result.standardOutput
        guard !output.isEmpty else {
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

    /// The wall-clock seconds a session is known to cover.
    ///
    /// `durationSeconds` carries -1 when a watcher restart interrupted the
    /// session and its true end was never observed (see
    /// `AppUsageDatabase.markOrphanedSessions`). The row still records when the
    /// session began and when the watcher closed it, and the app cannot have run
    /// past that point, so the span between the two is the figure available.
    /// Treating the sentinel as zero instead would put a day's foreground
    /// seconds above its total, which is not a state the data can be in.
    private func observedTotalSeconds(of session: ApplicationUsageSession) -> Double {
        if session.durationSeconds >= 0 {
            return session.durationSeconds
        }
        guard let end = session.endTime else { return 0 }
        return max(0, end.timeIntervalSince(session.startTime))
    }

    /// Running totals for one (date, app name) pair while summaries are built.
    private struct DailyUsageBucket {
        var launches = 0
        var totalSeconds = 0.0
        var foregroundSeconds = 0.0
        var activeSeconds = 0.0
        var users: Set<String> = []
    }

    /// The calendar days an interval covers, each with the fraction of the
    /// interval's wall-clock span that fell on that day.
    ///
    /// An app opened before midnight and closed after it was in use on both
    /// days. Attributing everything to one date books a stretch of uptime onto
    /// a single day and leaves the days it actually covered empty, which makes
    /// any per-day or per-week series wrong.
    ///
    /// The counters accumulate across the interval rather than per day, so they
    /// are apportioned by wall-clock share. That is an estimate, but the
    /// interval here is one collection cycle rather than a whole session, so it
    /// only ever spreads a few hours across a midnight boundary. Only per-day
    /// counters in the watcher itself could make it exact.
    private func daySpans(from start: Date,
                          to end: Date,
                          formatter: DateFormatter) -> [(String, Double)] {
        guard end > start else {
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
    /// Groups by (date, app name). The API accumulates these per (device, date, app).
    ///
    /// Each session reports the seconds it has gained since the counters the
    /// server last accepted, apportioned across the days that increment covers.
    /// Reporting a running total instead would add an app's whole lifetime again
    /// on every cycle, and waiting for the process to exit — which is what this
    /// did previously — reports nothing at all for the applications that matter
    /// most: the ones people leave open all day, on machines that stay booted
    /// for weeks. Those sessions never end, so their usage was never sent.
    public func buildDailySummaries(snapshot: ApplicationUsageSnapshot) -> [[String: Any]] {
        // Only the watcher's database can carry a watermark forward. The polling
        // fallback re-derives the same running processes every cycle with nothing
        // to record against them, so anything it reported would be counted again
        // on the next run.
        guard snapshot.captureMethod == Self.watcherCaptureMethod else { return [] }

        let sessions = snapshot.activeSessions
        guard !sessions.isEmpty else { return [] }

        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd"
        dateFormatter.locale = Locale(identifier: "en_US_POSIX")
        dateFormatter.timeZone = TimeZone.current

        let now = collectedAt ?? Date()
        var buckets: [String: DailyUsageBucket] = [:]

        for session in sessions {
            let startDate = dateFormatter.string(from: session.startTime)

            // An app-open is one launch, counted once on the day it happened,
            // the first time the session is reported. Counting it on every cycle
            // would multiply launches by how long the app stayed open.
            if session.reportedAt == nil {
                let key = "\(startDate)||\(session.name)"
                var bucket = buckets[key] ?? DailyUsageBucket()
                bucket.launches += 1
                if !session.user.isEmpty {
                    bucket.users.insert(session.user)
                }
                buckets[key] = bucket
            }

            let windowStart = session.reportedAt ?? session.startTime
            let windowEnd = session.endTime ?? now
            guard windowEnd > windowStart else { continue }

            // A first report reaching further back than the cap covers days
            // nothing recorded. Its counters become the watermark without being
            // claimed for any date — see maxFirstReportWindow.
            if session.reportedAt == nil,
               windowEnd.timeIntervalSince(windowStart) > Self.maxFirstReportWindow {
                continue
            }

            // The counters are accumulated on different clocks, so the
            // increments have to be put back in order before they are sent.
            // Foreground is charged a whole tick at a time, and a tick that
            // straddles the watermark instant contributes all of its interval
            // to the window that reads it while only the part after the
            // watermark is inside that window's wall clock. Total is measured
            // as wall clock, so foreground can land above it — an application
            // on screen for longer than it existed, which the fleet showed once
            // in 1,375 rows, over by 16.7 s against a 30 s tick.
            //
            // Active is bounded by foreground for the same reason and by
            // construction: the watcher charges active seconds only for the tick
            // it also charged as foreground.
            //
            // The excess is dropped rather than deferred. The watermark advances
            // to the counters actually observed, not to the clamped figures, so
            // at most one tick per session per cycle goes unreported and nothing
            // compounds.
            let total = max(0, observedTotalSeconds(of: session) - session.reportedTotalSeconds)
            let foreground = min(total, max(0, session.foregroundSeconds - session.reportedForegroundSeconds))
            let active = min(foreground, max(0, session.activeSeconds - session.reportedActiveSeconds))
            guard total > 0 || foreground > 0 || active > 0 else { continue }

            for (dateStr, share) in daySpans(from: windowStart, to: windowEnd, formatter: dateFormatter) {
                let key = "\(dateStr)||\(session.name)"
                var bucket = buckets[key] ?? DailyUsageBucket()
                bucket.totalSeconds += total * share
                bucket.foregroundSeconds += foreground * share
                bucket.activeSeconds += active * share
                if !session.user.isEmpty {
                    bucket.users.insert(session.user)
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
