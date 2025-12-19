import Foundation

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

/// Fast, simple service for collecting application usage data.
/// Uses `ps` to get currently running application processes.
/// Designed to complete in under 1 second.
public class ApplicationUsageService: @unchecked Sendable {
    
    public init() {}
    
    /// Collect application usage data - FAST synchronous implementation
    public func collectUsageData(
        installedApps: [[String: Any]],
        lookbackHours: Int? = nil
    ) async -> ApplicationUsageSnapshot {
        let hours = lookbackHours ?? 4
        var snapshot = ApplicationUsageSnapshot()
        snapshot.generatedAt = Date()
        snapshot.windowStart = Date().addingTimeInterval(TimeInterval(-hours * 3600))
        snapshot.windowEnd = Date()
        snapshot.captureMethod = "ProcessPolling"
        snapshot.isCaptureEnabled = true
        
        do {
            // Get running processes - completes in milliseconds
            let sessions = try collectRunningSessions(installedApps: installedApps)
            
            snapshot.status = "complete"
            snapshot.activeSessions = sessions
            snapshot.totalLaunches = sessions.count
            snapshot.totalUsageSeconds = sessions.reduce(0) { $0 + $1.durationSeconds }
            
        } catch {
            snapshot.status = "error"
            snapshot.warnings.append(error.localizedDescription)
        }
        
        return snapshot
    }
    
    /// Collect running application sessions - fast ps-based polling
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
