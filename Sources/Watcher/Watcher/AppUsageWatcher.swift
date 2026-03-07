import Foundation
import AppKit
import Logging

/// Application usage watcher that monitors app launches and terminations
/// Uses NSWorkspace notifications for real-time GUI app tracking
public final class AppUsageWatcher: @unchecked Sendable {
    
    // MARK: - Properties
    
    private let database: AppUsageDatabase
    private let logger: Logger
    private var isRunning = false
    private var observers: [NSObjectProtocol] = []
    
    // MARK: - Initialization
    
    public init(database: AppUsageDatabase, logger: Logger) {
        self.database = database
        self.logger = logger
    }
    
    deinit {
        stop()
    }
    
    // MARK: - Lifecycle
    
    /// Start watching for application events
    public func start() throws {
        guard !isRunning else {
            logger.info("Watcher already running")
            return
        }
        
        logger.info("Starting application usage watcher")
        
        // Initialize database
        try database.initialize()
        
        // Mark any orphaned sessions from previous run
        try database.markOrphanedSessions()
        logger.info("Marked orphaned sessions from previous run")
        
        // Reconcile with currently running apps
        try reconcileRunningApps()
        
        // Set up workspace notifications
        setupNotificationObservers()
        
        isRunning = true
        logger.info("Application usage watcher started successfully")
    }
    
    /// Stop watching for application events
    public func stop() {
        guard isRunning else { return }
        
        logger.info("Stopping application usage watcher")
        
        // Remove all observers
        let center = NSWorkspace.shared.notificationCenter
        for observer in observers {
            center.removeObserver(observer)
        }
        observers.removeAll()
        
        isRunning = false
        logger.info("Application usage watcher stopped")
    }
    
    // MARK: - Notification Setup
    
    private func setupNotificationObservers() {
        let center = NSWorkspace.shared.notificationCenter
        
        // Observe application launches
        let launchObserver = center.addObserver(
            forName: NSWorkspace.didLaunchApplicationNotification,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            self?.handleAppLaunch(notification)
        }
        observers.append(launchObserver)
        
        // Observe application terminations
        let terminateObserver = center.addObserver(
            forName: NSWorkspace.didTerminateApplicationNotification,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            self?.handleAppTermination(notification)
        }
        observers.append(terminateObserver)
        
        // Observe application activations (for tracking focus time in future)
        let activateObserver = center.addObserver(
            forName: NSWorkspace.didActivateApplicationNotification,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            self?.handleAppActivation(notification)
        }
        observers.append(activateObserver)
        
        logger.debug("Set up \(observers.count) notification observers")
    }
    
    // MARK: - Event Handlers
    
    private func handleAppLaunch(_ notification: Notification) {
        guard let app = notification.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication else {
            logger.warning("App launch notification missing application info")
            return
        }
        
        // Only track GUI applications in /Applications
        guard let bundleURL = app.bundleURL,
              isTrackableApplication(bundleURL: bundleURL) else {
            return
        }
        
        let bundleId = app.bundleIdentifier
        let appName = app.localizedName ?? bundleURL.deletingPathExtension().lastPathComponent
        let path = bundleURL.path
        let user = NSUserName()
        let pid = Int(app.processIdentifier)
        
        logger.info("App launched: \(appName) (PID: \(pid))")
        
        do {
            try database.recordLaunch(
                bundleIdentifier: bundleId,
                appName: appName,
                path: path,
                user: user,
                pid: pid
            )
        } catch {
            logger.error("Failed to record app launch: \(error.localizedDescription)")
        }
    }
    
    private func handleAppTermination(_ notification: Notification) {
        guard let app = notification.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication else {
            logger.warning("App termination notification missing application info")
            return
        }
        
        // Only track GUI applications in /Applications
        guard let bundleURL = app.bundleURL,
              isTrackableApplication(bundleURL: bundleURL) else {
            return
        }
        
        let appName = app.localizedName ?? bundleURL.deletingPathExtension().lastPathComponent
        let pid = Int(app.processIdentifier)
        
        logger.info("App terminated: \(appName) (PID: \(pid))")
        
        do {
            try database.recordTermination(pid: pid)
        } catch {
            logger.error("Failed to record app termination: \(error.localizedDescription)")
        }
    }
    
    private func handleAppActivation(_ notification: Notification) {
        // For future: track foreground/focus time
        // Currently just log for debugging
        guard let app = notification.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication,
              let bundleURL = app.bundleURL,
              isTrackableApplication(bundleURL: bundleURL) else {
            return
        }
        
        let appName = app.localizedName ?? bundleURL.deletingPathExtension().lastPathComponent
        logger.trace("App activated: \(appName)")
    }
    
    // MARK: - Reconciliation
    
    /// Reconcile database with currently running applications
    /// Called at startup to capture apps that were already running
    private func reconcileRunningApps() throws {
        let runningApps = NSWorkspace.shared.runningApplications
        var appsToReconcile: [(bundleId: String?, name: String, path: String, user: String, pid: Int, startTime: Date)] = []
        
        for app in runningApps {
            guard let bundleURL = app.bundleURL,
                  isTrackableApplication(bundleURL: bundleURL) else {
                continue
            }
            
            let bundleId = app.bundleIdentifier
            let appName = app.localizedName ?? bundleURL.deletingPathExtension().lastPathComponent
            let path = bundleURL.path
            let user = NSUserName()
            let pid = Int(app.processIdentifier)
            
            // Try to get actual start time from process info
            let startTime = getProcessStartTime(pid: pid) ?? Date()
            
            appsToReconcile.append((
                bundleId: bundleId,
                name: appName,
                path: path,
                user: user,
                pid: pid,
                startTime: startTime
            ))
        }
        
        try database.reconcileWithRunningProcesses(appsToReconcile)
        logger.info("Reconciled \(appsToReconcile.count) running applications")
    }
    
    /// Get process start time using ps command
    private func getProcessStartTime(pid: Int) -> Date? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/ps")
        process.arguments = ["-o", "lstart=", "-p", "\(pid)"]
        
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        
        do {
            try process.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            
            guard let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !output.isEmpty else {
                return nil
            }
            
            // Parse "Day Mon DD HH:MM:SS YYYY" format
            let formatter = DateFormatter()
            formatter.dateFormat = "EEE MMM d HH:mm:ss yyyy"
            formatter.locale = Locale(identifier: "en_US_POSIX")
            
            return formatter.date(from: output)
        } catch {
            return nil
        }
    }
    
    // MARK: - Helpers
    
    /// Check if an application should be tracked
    /// Only tracks GUI apps in /Applications or /System/Applications
    private func isTrackableApplication(bundleURL: URL) -> Bool {
        let path = bundleURL.path.lowercased()
        
        // Must be in Applications folder
        guard path.contains("/applications/") else {
            return false
        }
        
        // Must be a .app bundle
        guard path.hasSuffix(".app") || path.contains(".app/") else {
            return false
        }
        
        // Note: We don't have bundle ID here, so we check by path patterns
        // Skip certain system/helper apps by path patterns
        let skipPaths = [
            "/system/applications/utilities/",
            "helper",
            "agent",
            "daemon",
            "loginitems"
        ]
        
        for skipPath in skipPaths {
            if path.contains(skipPath) {
                return false
            }
        }
        
        return true
    }
    
    // MARK: - Status
    
    /// Get current watcher status
    public var status: WatcherStatus {
        do {
            let stats = try database.getStats()
            return WatcherStatus(
                isRunning: isRunning,
                totalSessions: stats.totalSessions,
                activeSessions: stats.activeSessions,
                pendingTransmission: stats.transmittedPending
            )
        } catch {
            return WatcherStatus(
                isRunning: isRunning,
                totalSessions: 0,
                activeSessions: 0,
                pendingTransmission: 0
            )
        }
    }
}

// MARK: - Supporting Types

public struct WatcherStatus: Sendable {
    public let isRunning: Bool
    public let totalSessions: Int
    public let activeSessions: Int
    public let pendingTransmission: Int
}
