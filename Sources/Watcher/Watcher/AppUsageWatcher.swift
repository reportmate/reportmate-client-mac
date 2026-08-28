import Foundation
import AppKit
import CoreGraphics
import Logging

/// Application usage watcher that monitors app launches and terminations
/// Uses NSWorkspace notifications for real-time GUI app tracking
public final class AppUsageWatcher: @unchecked Sendable {
    
    // MARK: - Properties
    
    private let database: AppUsageDatabase
    private let logger: Logger
    private var isRunning = false
    private var observers: [NSObjectProtocol] = []

    // Idle-time tracking: a periodic tick attributes elapsed seconds to the
    // currently-foreground app's session as foreground time, and additionally
    // as active time when system input has occurred within the prior 300s.
    private var tickTimer: DispatchSourceTimer?
    private var lastTickAt: Date?
    private static let tickInterval: TimeInterval = 30   // seconds between ticks
    private static let idleThreshold: TimeInterval = 300 // seconds without input -> inactive
    // Clamp on per-tick elapsed to defend against sleep/wake gaps (otherwise a
    // single tick after a 4-hour laptop sleep would charge 4 hours of fg time).
    private static let maxTickElapsed: TimeInterval = 90

    // Retention sweep: a coarse daily timer prunes completed sessions older
    // than the safety-net retention, independent of the transmit/confirm path.
    private var pruneTimer: DispatchSourceTimer?
    private static let pruneInterval: TimeInterval = 86_400

    // Time budget for a `ps` invocation. Nothing the watcher runs should be
    // able to block its startup indefinitely.
    private static let psTimeout: TimeInterval = 15
    
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
        
        // Reconcile before sweeping. An application still running is one
        // continuous app-open, so its session has to survive the sweep with its
        // launch and its reporting watermark intact; only the sessions with no
        // process behind them any more are orphans.
        let live = try reconcileRunningApps()
        try database.markOrphanedSessions(excluding: live)
        logger.info("Marked orphaned sessions from previous run")

        // Prune expired sessions once at startup, then daily via timer
        runRetentionSweep()
        startPruneTimer()
        
        // Set up workspace notifications
        setupNotificationObservers()

        // Start idle/foreground polling tick
        startTickTimer()

        isRunning = true
        logger.info("Application usage watcher started successfully")
    }

    /// Stop watching for application events
    public func stop() {
        guard isRunning else { return }

        logger.info("Stopping application usage watcher")

        // Cancel idle/foreground tick
        tickTimer?.cancel()
        tickTimer = nil
        lastTickAt = nil

        // Cancel retention sweep timer
        pruneTimer?.cancel()
        pruneTimer = nil

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
        let pid = Int(app.processIdentifier)
        let user = processOwner(pid: pid) ?? NSUserName()

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
        // Activation transitions are handled by the periodic tick reading
        // NSWorkspace.shared.frontmostApplication directly — that avoids any
        // race where a fast activate→deactivate pair could be missed.
        guard let app = notification.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication,
              let bundleURL = app.bundleURL,
              isTrackableApplication(bundleURL: bundleURL) else {
            return
        }

        let appName = app.localizedName ?? bundleURL.deletingPathExtension().lastPathComponent
        logger.trace("App activated: \(appName)")
    }

    // MARK: - Idle/Foreground Tick

    /// Start a periodic timer that attributes foreground + active seconds to
    /// the currently-foreground tracked app's session.
    private func startTickTimer() {
        let queue = DispatchQueue(label: "com.reportmate.appusage.tick", qos: .utility)
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + Self.tickInterval, repeating: Self.tickInterval)
        timer.setEventHandler { [weak self] in
            self?.handleTick()
        }
        tickTimer = timer
        lastTickAt = Date()
        timer.resume()
        logger.info("Idle/foreground tick timer started (interval=\(Self.tickInterval)s, idleThreshold=\(Self.idleThreshold)s)")
    }

    private func handleTick() {
        let now = Date()

        // Compute elapsed since last tick. Clamp to defend against sleep/wake
        // gaps — if the laptop slept for 4h, we don't want to charge 4h of fg
        // time. We also lose the time *during* sleep, which is correct (no
        // user was using the machine).
        let elapsedRaw = lastTickAt.map { now.timeIntervalSince($0) } ?? Self.tickInterval
        let elapsed = min(max(elapsedRaw, 0), Self.maxTickElapsed)
        lastTickAt = now

        // Identify the foreground app via NSWorkspace (more robust than
        // tracking activation events, no missed deactivations).
        guard let frontApp = NSWorkspace.shared.frontmostApplication,
              let bundleURL = frontApp.bundleURL,
              isTrackableApplication(bundleURL: bundleURL) else {
            return
        }
        let pid = Int(frontApp.processIdentifier)

        // System-wide idle seconds (kCGAnyInputEventType = rawValue UInt32.max).
        // CGEventSourceStateID.combinedSessionState merges HID + posted events.
        let anyInput = CGEventType(rawValue: ~UInt32(0)) ?? .null
        let idleSecs = CGEventSource.secondsSinceLastEventType(.combinedSessionState, eventType: anyInput)

        let foregroundDelta = Int64(elapsed.rounded())
        let activeDelta: Int64 = idleSecs < Self.idleThreshold ? foregroundDelta : 0

        do {
            try database.accumulateActiveTime(
                pid: pid,
                foregroundDelta: foregroundDelta,
                activeDelta: activeDelta
            )
        } catch {
            logger.error("Failed to accumulate active time for pid \(pid): \(error.localizedDescription)")
        }
    }
    
    // MARK: - Retention Sweep

    /// Start a coarse daily timer that prunes expired sessions. This is a
    /// safety net against unbounded database growth if the transmit/confirm
    /// path ever breaks again.
    private func startPruneTimer() {
        let queue = DispatchQueue(label: "com.reportmate.appusage.prune", qos: .utility)
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + Self.pruneInterval, repeating: Self.pruneInterval)
        timer.setEventHandler { [weak self] in
            self?.runRetentionSweep()
        }
        pruneTimer = timer
        timer.resume()
        logger.info("Retention sweep timer started (interval=\(Self.pruneInterval)s, retention=\(AppUsageDatabase.retentionDays)d)")
    }

    private func runRetentionSweep() {
        do {
            let pruned = try database.pruneExpiredSessions()
            if pruned > 0 {
                logger.info("Pruned \(pruned) completed sessions older than \(AppUsageDatabase.retentionDays) days")
            }
        } catch {
            logger.error("Failed to prune expired sessions: \(error.localizedDescription)")
        }
    }

    // MARK: - Reconciliation
    
    /// Reconcile the database with the applications running right now, and
    /// return the sessions that describe them so the orphan sweep can spare
    /// them. Called at startup to pick up apps that were already open.
    @discardableResult
    private func reconcileRunningApps() throws -> Set<Int64> {
        let trackable = NSWorkspace.shared.runningApplications.compactMap { app -> (NSRunningApplication, URL)? in
            guard let bundleURL = app.bundleURL,
                  isTrackableApplication(bundleURL: bundleURL) else {
                return nil
            }
            return (app, bundleURL)
        }
        
        // One `ps` for the whole set, before the loop, rather than two inside it.
        let details = processDetails(pids: trackable.map { Int($0.0.processIdentifier) })
        
        var appsToReconcile: [RunningApplication] = []
        for (app, bundleURL) in trackable {
            let pid = Int(app.processIdentifier)
            appsToReconcile.append(RunningApplication(
                bundleId: app.bundleIdentifier,
                name: app.localizedName ?? bundleURL.deletingPathExtension().lastPathComponent,
                path: bundleURL.path,
                user: details[pid]?.user ?? NSUserName(),
                pid: pid,
                startTime: details[pid]?.startTime
            ))
        }
        
        let live = try database.reconcileWithRunningProcesses(appsToReconcile)
        logger.info("Reconciled \(appsToReconcile.count) running applications")
        return live
    }
    
    /// Owner and start time for a set of PIDs, read in a single `ps` call.
    ///
    /// The watcher runs as a root LaunchDaemon, so `NSUserName()` reports the
    /// daemon's own identity rather than the person at the keyboard. Reading the
    /// owner from the observed process attributes each session to the right user
    /// and stays correct across fast user switching. The uid is read rather than
    /// `ps -o user=`, which truncates usernames past eight characters.
    ///
    /// One invocation, not two per application. Startup asked `ps` twice for
    /// every running app -- roughly 134 spawns for 67 applications, 29 seconds
    /// on a real machine -- and the watcher sees nothing at all until it
    /// finishes, so every app opened in that window lost its launch.
    private func processDetails(pids: [Int]) -> [Int: (user: String?, startTime: Date?)] {
        guard !pids.isEmpty else { return [:] }

        let list = pids.map(String.init).joined(separator: ",")
        guard let output = runPS(arguments: ["-o", "pid=,uid=,lstart=", "-p", list]) else {
            return [:]
        }

        // "Day Mon DD HH:MM:SS YYYY", with the day of month space-padded. The
        // padding collapses because the line is split on whitespace runs.
        let formatter = DateFormatter()
        formatter.dateFormat = "EEE MMM d HH:mm:ss yyyy"
        formatter.locale = Locale(identifier: "en_US_POSIX")

        var details: [Int: (user: String?, startTime: Date?)] = [:]
        for line in output.split(separator: "\n") {
            let fields = line.split(separator: " ", omittingEmptySubsequences: true)
            guard fields.count >= 3, let pid = Int(fields[0]) else { continue }

            var user: String? = nil
            if let uid = uid_t(fields[1]), let entry = getpwuid(uid) {
                let name = String(cString: entry.pointee.pw_name)
                user = name.isEmpty ? nil : name
            }

            let started = formatter.date(from: fields[2...].joined(separator: " "))
            details[pid] = (user: user, startTime: started)
        }

        return details
    }

    /// The user a running process belongs to, or nil if it can't be determined.
    private func processOwner(pid: Int) -> String? {
        processDetails(pids: [pid])[pid]?.user
    }

    /// Run `ps` under a time budget, returning nil if it does not finish.
    ///
    /// The collection path routes external commands through `ProcessRunner`,
    /// which carries a timeout; the Watcher is a separate executable target and
    /// cannot reach it without making Core a library, so the two properties
    /// that matter are reproduced here. Output drains on its own queue, and the
    /// deadline is a semaphore rather than a read reaching EOF -- a wedged `ps`
    /// used to hang watcher startup with nothing to stop it.
    private func runPS(arguments: [String], timeout: TimeInterval = AppUsageWatcher.psTimeout) -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/ps")
        process.arguments = arguments

        // `ps` formats lstart through LC_TIME, so an inherited locale changes
        // the field order -- en_CA prints "Tue 25 Aug", which the month-first
        // parser below reads as nothing at all. launchd starts the watcher with
        // no locale set, so the daemon already gets the C ordering; pinning it
        // keeps the same result when the binary is run by hand from a shell.
        var environment = ProcessInfo.processInfo.environment
        environment["LC_ALL"] = "C"
        environment["LANG"] = "C"
        process.environment = environment

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
        } catch {
            logger.debug("Could not run ps \(arguments.joined(separator: " ")): \(error)")
            return nil
        }

        let collected = OutputBox()
        let drained = DispatchSemaphore(value: 0)
        DispatchQueue.global(qos: .utility).async {
            collected.store(pipe.fileHandleForReading.readDataToEndOfFile())
            drained.signal()
        }

        if drained.wait(timeout: .now() + timeout) == .timedOut {
            logger.warning("ps exceeded its \(Int(timeout))s budget; continuing without it")
            process.terminate()
            if drained.wait(timeout: .now() + 2) == .timedOut, process.isRunning {
                kill(process.processIdentifier, SIGKILL)
            }
            return nil
        }

        process.waitUntilExit()
        return String(data: collected.value, encoding: .utf8)
    }

    /// Hands the drained output back from the reader queue. The read has to
    /// happen off the calling thread so the deadline below does not depend on
    /// it, which means the buffer crosses a concurrency boundary.
    private final class OutputBox: @unchecked Sendable {
        private let lock = NSLock()
        private var data = Data()

        func store(_ new: Data) {
            lock.lock()
            data = new
            lock.unlock()
        }

        var value: Data {
            lock.lock()
            defer { lock.unlock() }
            return data
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
