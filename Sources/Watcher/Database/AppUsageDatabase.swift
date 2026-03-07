import Foundation
import SQLite

/// SQLite database for persisting application usage sessions
/// Location: /Library/Managed Reports/appusage.sqlite
public final class AppUsageDatabase: @unchecked Sendable {
    
    // MARK: - Table Definitions
    
    private let sessions = Table("app_sessions")
    
    // Columns
    private let id = Expression<Int64>("id")
    private let bundleId = Expression<String?>("bundle_id")
    private let appName = Expression<String>("app_name")
    private let path = Expression<String>("path")
    private let user = Expression<String>("user")
    private let pid = Expression<Int64>("pid")
    private let startTime = Expression<String>("start_time")  // ISO8601
    private let endTime = Expression<String?>("end_time")      // ISO8601, null if still running
    private let durationSeconds = Expression<Int64>("duration_seconds")
    private let transmitted = Expression<Bool>("transmitted")  // Mark as transmitted for two-phase delete
    
    // MARK: - Properties
    
    private var db: Connection?
    private let dbPath: String
    private let queue = DispatchQueue(label: "com.reportmate.appusage.db", qos: .utility)
    
    // MARK: - Initialization
    
    public init(path: String = "/Library/Managed Reports/appusage.sqlite") {
        self.dbPath = path
    }
    
    /// Initialize the database connection and create tables if needed
    public func initialize() throws {
        // Ensure directory exists
        let directory = (dbPath as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(
            atPath: directory,
            withIntermediateDirectories: true,
            attributes: nil
        )
        
        db = try Connection(dbPath)
        
        // Enable WAL mode for better concurrency
        try db?.execute("PRAGMA journal_mode = WAL")
        
        // Create sessions table
        try db?.run(sessions.create(ifNotExists: true) { t in
            t.column(id, primaryKey: .autoincrement)
            t.column(bundleId)
            t.column(appName)
            t.column(path)
            t.column(user)
            t.column(pid)
            t.column(startTime)
            t.column(endTime)
            t.column(durationSeconds, defaultValue: 0)
            t.column(transmitted, defaultValue: false)
        })
        
        // Create indexes for common queries
        try db?.run(sessions.createIndex(bundleId, ifNotExists: true))
        try db?.run(sessions.createIndex(startTime, ifNotExists: true))
        try db?.run(sessions.createIndex(transmitted, ifNotExists: true))
        try db?.run(sessions.createIndex(pid, endTime, ifNotExists: true))
    }
    
    // MARK: - Session Management
    
    /// Record an application launch (start of session)
    @discardableResult
    public func recordLaunch(
        bundleIdentifier: String?,
        appName: String,
        path: String,
        user: String,
        pid: Int
    ) throws -> Int64 {
        guard let db = db else {
            throw AppUsageDatabaseError.notInitialized
        }
        
        let formatter = ISO8601DateFormatter()
        let now = formatter.string(from: Date())
        
        let insert = sessions.insert(
            bundleId <- bundleIdentifier,
            self.appName <- appName,
            self.path <- path,
            self.user <- user,
            self.pid <- Int64(pid),
            startTime <- now,
            endTime <- nil as String?,
            durationSeconds <- 0,
            transmitted <- false
        )
        
        return try db.run(insert)
    }
    
    /// Record an application termination (end of session)
    public func recordTermination(pid: Int) throws {
        guard let db = db else {
            throw AppUsageDatabaseError.notInitialized
        }
        
        let formatter = ISO8601DateFormatter()
        let now = Date()
        let nowString = formatter.string(from: now)
        
        // Find the most recent active session for this PID
        let query = sessions
            .filter(self.pid == Int64(pid))
            .filter(endTime == nil)
            .order(startTime.desc)
            .limit(1)
        
        if let row = try db.pluck(query) {
            // Calculate duration
            if let startTimeStr = row[startTime] as String?,
               let startDate = formatter.date(from: startTimeStr) {
                let duration = Int64(now.timeIntervalSince(startDate))
                
                // Update the session
                let session = sessions.filter(id == row[id])
                try db.run(session.update(
                    endTime <- nowString,
                    durationSeconds <- duration
                ))
            }
        }
    }
    
    /// Mark orphaned sessions (no end time) with unknown duration
    /// Called at watcher startup to handle sessions from previous crashes
    public func markOrphanedSessions() throws {
        guard let db = db else {
            throw AppUsageDatabaseError.notInitialized
        }
        
        let formatter = ISO8601DateFormatter()
        let now = formatter.string(from: Date())
        
        // Find all sessions with no end time and mark them with -1 duration (unknown)
        let orphaned = sessions.filter(endTime == nil)
        try db.run(orphaned.update(
            endTime <- now,
            durationSeconds <- -1  // -1 indicates unknown/interrupted duration
        ))
    }
    
    /// Reconcile with currently running processes at startup
    /// Creates sessions for apps that were already running before watcher started
    public func reconcileWithRunningProcesses(_ runningApps: [(bundleId: String?, name: String, path: String, user: String, pid: Int, startTime: Date)]) throws {
        guard let db = db else {
            throw AppUsageDatabaseError.notInitialized
        }
        
        let formatter = ISO8601DateFormatter()
        
        for app in runningApps {
            // Check if we already have an active session for this PID
            let existing = sessions
                .filter(pid == Int64(app.pid))
                .filter(endTime == nil)
            
            if try db.pluck(existing) == nil {
                // No existing session, create one
                let insert = sessions.insert(
                    bundleId <- app.bundleId,
                    appName <- app.name,
                    path <- app.path,
                    user <- app.user,
                    self.pid <- Int64(app.pid),
                    startTime <- formatter.string(from: app.startTime),
                    endTime <- nil as String?,
                    durationSeconds <- 0,
                    transmitted <- false
                )
                _ = try db.run(insert)
            }
        }
    }
    
    // MARK: - Query Methods
    
    /// Get all untransmitted sessions (completed sessions not yet sent to server)
    public func getUntransmittedSessions() throws -> [AppUsageSessionRecord] {
        guard let db = db else {
            throw AppUsageDatabaseError.notInitialized
        }
        
        let query = sessions
            .filter(transmitted == false)
            .filter(endTime != nil)  // Only completed sessions
            .order(startTime.asc)
        
        var records: [AppUsageSessionRecord] = []
        let formatter = ISO8601DateFormatter()
        
        for row in try db.prepare(query) {
            let record = AppUsageSessionRecord(
                id: row[id],
                bundleId: row[bundleId],
                appName: row[appName],
                path: row[path],
                user: row[user],
                pid: Int(row[pid]),
                startTime: formatter.date(from: row[startTime]) ?? Date(),
                endTime: row[endTime].flatMap { formatter.date(from: $0) },
                durationSeconds: row[durationSeconds],
                transmitted: row[transmitted]
            )
            records.append(record)
        }
        
        return records
    }
    
    /// Get active sessions (currently running apps)
    public func getActiveSessions() throws -> [AppUsageSessionRecord] {
        guard let db = db else {
            throw AppUsageDatabaseError.notInitialized
        }
        
        let query = sessions
            .filter(endTime == nil)
            .order(startTime.desc)
        
        var records: [AppUsageSessionRecord] = []
        let formatter = ISO8601DateFormatter()
        
        for row in try db.prepare(query) {
            // Calculate current duration for active sessions
            let startDate = formatter.date(from: row[startTime]) ?? Date()
            let currentDuration = Int64(Date().timeIntervalSince(startDate))
            
            let record = AppUsageSessionRecord(
                id: row[id],
                bundleId: row[bundleId],
                appName: row[appName],
                path: row[path],
                user: row[user],
                pid: Int(row[pid]),
                startTime: startDate,
                endTime: nil,
                durationSeconds: currentDuration,
                transmitted: false
            )
            records.append(record)
        }
        
        return records
    }
    
    /// Get aggregated usage stats by app
    public func getUsageStats() throws -> [AppUsageStats] {
        guard let db = db else {
            throw AppUsageDatabaseError.notInitialized
        }
        
        // SQLite aggregation query
        let query = """
            SELECT 
                bundle_id,
                app_name,
                path,
                COUNT(*) as launch_count,
                SUM(CASE WHEN duration_seconds > 0 THEN duration_seconds ELSE 0 END) as total_seconds,
                MAX(start_time) as last_used,
                COUNT(DISTINCT user) as unique_users
            FROM app_sessions
            WHERE transmitted = 0
            GROUP BY COALESCE(bundle_id, path)
            ORDER BY total_seconds DESC
        """
        
        var stats: [AppUsageStats] = []
        let formatter = ISO8601DateFormatter()
        
        for row in try db.prepare(query) {
            let stat = AppUsageStats(
                bundleId: row[0] as? String,
                appName: row[1] as? String ?? "Unknown",
                path: row[2] as? String ?? "",
                launchCount: Int(row[3] as? Int64 ?? 0),
                totalSeconds: row[4] as? Int64 ?? 0,
                lastUsed: (row[5] as? String).flatMap { formatter.date(from: $0) } ?? Date(),
                uniqueUsers: Int(row[6] as? Int64 ?? 0)
            )
            stats.append(stat)
        }
        
        return stats
    }
    
    // MARK: - Transmission Management
    
    /// Mark sessions as transmitted (first phase of two-phase delete)
    public func markAsTransmitted(sessionIds: [Int64]) throws {
        guard let db = db else {
            throw AppUsageDatabaseError.notInitialized
        }
        
        let toUpdate = sessions.filter(sessionIds.contains(id))
        try db.run(toUpdate.update(transmitted <- true))
    }
    
    /// Delete previously transmitted sessions (second phase - called on next cycle)
    public func deleteTransmittedSessions() throws {
        guard let db = db else {
            throw AppUsageDatabaseError.notInitialized
        }
        
        let toDelete = sessions.filter(transmitted == true)
        try db.run(toDelete.delete())
    }
    
    /// Clear all transmitted data after successful transmission confirmation
    /// Two-phase approach: first marks as transmitted, then deletes on next cycle
    public func clearTransmittedData() throws {
        // Phase 1: Delete previously transmitted
        try deleteTransmittedSessions()
        
        // Phase 2 will happen on next collection cycle when we mark current batch
    }
    
    // MARK: - Maintenance
    
    /// Get database statistics
    public func getStats() throws -> (totalSessions: Int, activeSessions: Int, transmittedPending: Int) {
        guard let db = db else {
            throw AppUsageDatabaseError.notInitialized
        }
        
        let total = try db.scalar(sessions.count)
        let active = try db.scalar(sessions.filter(endTime == nil).count)
        let transmitted = try db.scalar(sessions.filter(self.transmitted == true).count)
        
        return (total, active, transmitted)
    }
    
    /// Vacuum database to reclaim space
    public func vacuum() throws {
        guard let db = db else {
            throw AppUsageDatabaseError.notInitialized
        }
        try db.execute("VACUUM")
    }
}

// MARK: - Supporting Types

public struct AppUsageSessionRecord: Sendable {
    public let id: Int64
    public let bundleId: String?
    public let appName: String
    public let path: String
    public let user: String
    public let pid: Int
    public let startTime: Date
    public let endTime: Date?
    public let durationSeconds: Int64
    public let transmitted: Bool
    
    public var isActive: Bool { endTime == nil }
    public var isUnknownDuration: Bool { durationSeconds == -1 }
}

public struct AppUsageStats: Sendable {
    public let bundleId: String?
    public let appName: String
    public let path: String
    public let launchCount: Int
    public let totalSeconds: Int64
    public let lastUsed: Date
    public let uniqueUsers: Int
}

public enum AppUsageDatabaseError: Error, LocalizedError {
    case notInitialized
    case queryFailed(String)
    
    public var errorDescription: String? {
        switch self {
        case .notInitialized:
            return "Database not initialized. Call initialize() first."
        case .queryFailed(let message):
            return "Database query failed: \(message)"
        }
    }
}
