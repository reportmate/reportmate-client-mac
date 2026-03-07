import Foundation
import ArgumentParser
import Logging
import AppKit

/// ReportMate Application Usage Watcher command
struct ReportMateAppUsage: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "reportmate-appusage",
        abstract: "ReportMate Application Usage Watcher",
        discussion: """
            Monitors GUI application launches and terminations, persisting usage data
            to /Library/Managed Reports/appusage.sqlite for collection by the main
            ReportMate client.
            
            This daemon should be run via launchd for continuous monitoring.
            """,
        version: "1.0.0"
    )
    
    @Flag(name: .shortAndLong, help: "Enable verbose logging")
    var verbose: Bool = false
    
    @Flag(name: [.customShort("q"), .long], help: "Quiet mode - minimal output")
    var quiet: Bool = false
    
    @Option(name: .long, help: "Path to SQLite database")
    var dbPath: String = "/Library/Managed Reports/appusage.sqlite"
    
    @Flag(name: .long, help: "Run in foreground (don't daemonize)")
    var foreground: Bool = false
    
    @Flag(name: .long, help: "Print database stats and exit")
    var stats: Bool = false
    
    func run() throws {
        // Configure logging
        let logLevel: Logger.Level = verbose ? .debug : (quiet ? .warning : .info)
        LoggingSystem.bootstrap { label in
            var handler = StreamLogHandler.standardOutput(label: label)
            handler.logLevel = logLevel
            return handler
        }
        
        var logger = Logger(label: "com.reportmate.appusage")
        logger.logLevel = logLevel
        
        // Initialize database
        let database = AppUsageDatabase(path: dbPath)
        
        // Handle stats command
        if stats {
            try database.initialize()
            let dbStats = try database.getStats()
            print("Database: \(dbPath)")
            print("Total sessions: \(dbStats.totalSessions)")
            print("Active sessions: \(dbStats.activeSessions)")
            print("Pending transmission: \(dbStats.transmittedPending)")
            return
        }
        
        logger.info("ReportMate Application Usage Watcher starting")
        logger.info("Database path: \(dbPath)")
        
        // Create watcher
        let watcher = AppUsageWatcher(database: database, logger: logger)
        
        // Set up signal handlers
        setupSignalHandlers()
        
        // Start watching
        do {
            try watcher.start()
        } catch {
            logger.error("Failed to start watcher: \(error.localizedDescription)")
            throw ExitCode.failure
        }
        
        // Log initial status
        let status = watcher.status
        logger.info("Watcher started - Active sessions: \(status.activeSessions), Total: \(status.totalSessions)")
        
        // Use ProcessInfo activity for App Nap awareness
        // This tells macOS we're doing important background work
        ProcessInfo.processInfo.performActivity(
            options: [.suddenTerminationDisabled, .automaticTerminationDisabled],
            reason: "ReportMate application usage monitoring"
        ) {
            // Run the main loop
            // NSWorkspace notifications require a run loop
            logger.info("Entering main run loop")
            
            // Run forever until terminated
            runForever()
        }
    }
}

// MARK: - Helpers

private func setupSignalHandlers() {
    // Handle SIGTERM gracefully
    signal(SIGTERM) { _ in
        print("\nReceived SIGTERM, shutting down...")
        Darwin.exit(0)
    }
    
    // Handle SIGINT (Ctrl+C) gracefully  
    signal(SIGINT) { _ in
        print("\nReceived SIGINT, shutting down...")
        Darwin.exit(0)
    }
    
    // Handle SIGHUP to reload configuration
    signal(SIGHUP) { _ in
        print("Received SIGHUP, reloading configuration...")
        // Future: reload configuration
    }
}

private func runForever() {
    while true {
        autoreleasepool {
            _ = RunLoop.current.run(mode: .default, before: .distantFuture)
        }
    }
}

// Entry point
ReportMateAppUsage.main()
