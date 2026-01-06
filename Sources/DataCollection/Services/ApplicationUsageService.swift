import Foundation
import SQLite

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
    
    /// Mark transmitted data for deletion (called after successful API transmission)
    public func confirmTransmission() {
        guard !transmittedSessionIds.isEmpty else { return }
        
        do {
            let db = try Connection(dbPath)
            
            // Two-phase delete: First mark as transmitted
            let sessions = Table("app_sessions")
            let id = Expression<Int64>("id")
            let transmitted = Expression<Bool>("transmitted")
            
            let toUpdate = sessions.filter(transmittedSessionIds.contains(id))
            try db.run(toUpdate.update(transmitted <- true))
            
            // Delete previously transmitted sessions (from last cycle)
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
            session.isActive = isActive
            
            result.append(session)
            sessionIds.append(rowId)
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
}
