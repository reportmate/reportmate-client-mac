import Foundation

/// OSQuery service for macOS
/// Manages osquery execution with macadmins extension support and fallbacks to bash and Python
public class OSQueryService {
    private let configuration: ReportMateConfiguration
    private let osqueryPath: String
    private let extensionPath: String?
    private var extensionAvailable: Bool = false
    private var extensionTablesChecked: Bool = false
    private var availableTables: Set<String> = []
    
    /// Known extension tables from macadmins osquery extension
    /// These tables require the extension to be loaded, which takes 3-4 seconds
    /// For performance, queries to these tables should use bash fallbacks
    private static let extensionTables: Set<String> = [
        "network_quality", "wifi_network", "mdm", "macos_profiles",
        "filevault_users", "pending_apple_updates", "munki_info", 
        "munki_installs", "sofa_security_release_info", "sofa_unpatched_cves",
        "authdb", "alt_system_info", "macadmins_unified_log", "macos_rsr",
        "crowdstrike_falcon", "puppet_info", "puppet_logs", "puppet_state",
        "puppet_facts", "google_chrome_profiles", "file_lines"
    ]
    
    public init(configuration: ReportMateConfiguration) {
        self.configuration = configuration
        self.osqueryPath = configuration.osqueryPath
        
        // Extension support - load macadmins extension for additional tables
        if configuration.extensionEnabled {
            self.extensionPath = Self.resolveExtensionPath(configured: configuration.osqueryExtensionPath)
            if let path = self.extensionPath {
                ConsoleFormatter.writeDebug("OSQuery extension enabled: \(path)")
            } else {
                ConsoleFormatter.writeDebug("OSQuery extension enabled but not found")
            }
        } else {
            self.extensionPath = nil
            ConsoleFormatter.writeDebug("OSQuery extension disabled")
        }
    }
    
    /// Check if a query uses extension tables
    /// Extension tables require 3-4 second startup overhead
    public static func queryUsesExtensionTables(_ query: String) -> Bool {
        let queryLower = query.lowercased()
        for table in extensionTables {
            // Check for "FROM table" or "JOIN table" patterns
            if queryLower.contains("from \(table)") || 
               queryLower.contains("join \(table)") ||
               queryLower.contains("from \(table);") {
                return true
            }
        }
        return false
    }
    
    /// Check if osquery is available
    public func isAvailable() async -> Bool {
        return await withCheckedContinuation { continuation in
            let task = Process()
            task.executableURL = URL(fileURLWithPath: osqueryPath)
            task.arguments = ["--version"]
            task.standardOutput = Pipe()
            task.standardError = Pipe()
            
            do {
                try task.run()
                task.waitUntilExit()
                continuation.resume(returning: task.terminationStatus == 0)
            } catch {
                continuation.resume(returning: false)
            }
        }
    }
    
    /// Check if a specific osquery extension table is available
    public func isTableAvailable(_ tableName: String) async -> Bool {
        // Check cache first
        if extensionTablesChecked && availableTables.contains(tableName) {
            return true
        }
        
        // Query to check table existence
        let checkQuery = ".tables \(tableName)"
        do {
            let result = try await executeQuery(checkQuery)
            let found = !result.isEmpty
            if found {
                availableTables.insert(tableName)
            }
            return found
        } catch {
            return false
        }
    }
    
    /// Resolve extension path from configuration or bundled location
    private static func resolveExtensionPath(configured: String?) -> String? {
        // 1. Try configured path (highest priority - user override)
        if let configured = configured, FileManager.default.fileExists(atPath: configured) {
            return configured
        }
        
        // 2. Try standard installation location FIRST (installed by .pkg)
        // This has proper root ownership which osquery requires for security
        let installedPath = "/usr/local/reportmate/macadmins_extension.ext"
        if FileManager.default.fileExists(atPath: installedPath) {
            return installedPath
        }
        
        // 3. Try bundled in Resources/extensions/ (SPM executable bundle)
        // Fallback for development - may have permission warnings
        // For SPM, the bundle is at .build/release/<Target>_<Target>.bundle/Resources/
        if let bundlePath = Bundle.main.resourcePath {
            let bundledExt = "\(bundlePath)/extensions/macadmins_extension.ext"
            if FileManager.default.fileExists(atPath: bundledExt) {
                return bundledExt
            }
        }
        
        // 4. Try relative to executable (for development builds)
        let executablePath = Bundle.main.executablePath ?? ""
        let executableDir = (executablePath as NSString).deletingLastPathComponent
        let relativeToExec = "\(executableDir)/ReportMate_ReportMate.bundle/Resources/extensions/macadmins_extension.ext"
        if FileManager.default.fileExists(atPath: relativeToExec) {
            return relativeToExec
        }

        // 5. Try development source paths (for local builds)
        let devSourcePaths = [
            // Relative to working directory
            "Sources/Resources/extensions/macadmins_extension.ext",
            "../Sources/Resources/extensions/macadmins_extension.ext"
        ]

        // Get current working directory to try relative paths
        let cwd = FileManager.default.currentDirectoryPath
        for devPath in devSourcePaths {
            let fullPath = "\(cwd)/\(devPath)"
            if FileManager.default.fileExists(atPath: fullPath) {
                return fullPath
            }
        }

        return nil
    }
    
    /// Execute an osquery SQL query
    /// For extension tables, uses the --extension flag which starts extension as a child process
    /// The extension takes ~3 seconds to register, so for extension tables we use a two-phase approach
    /// Built-in table queries always use the fast path (no extension loading)
    ///
    /// Both code paths are wrapped in a hard timeout: if osqueryi does not return
    /// within the configured budget, the child process is killed (SIGTERM, then
    /// SIGKILL after a 2s grace period) and `OSQueryError.timeout` is thrown. This
    /// prevents a single misbehaving table — most commonly extension tables that
    /// do online I/O like `sofa_unpatched_cves` fetching the SOFA feed — from
    /// blocking the rest of a module's collection indefinitely.
    public func executeQuery(_ query: String) async throws -> [[String: Any]] {
        let useExtension = extensionPath != nil && Self.queryUsesExtensionTables(query)
        let timeout = useExtension
            ? configuration.extensionQueryTimeoutSeconds
            : configuration.queryTimeoutSeconds

        // Snapshot the values the detached query runner needs so the task
        // closures don't capture `self` (avoids Swift 6 sending-closure data
        // race diagnostics for this non-Sendable class).
        let osqueryPath = self.osqueryPath
        let extensionPath = self.extensionPath

        return try await withThrowingTaskGroup(of: QueryRunResult.self) { group in
            let processBox = ProcessBox()

            group.addTask {
                let rows: [[String: Any]]
                if useExtension, let extensionPath = extensionPath {
                    rows = try await Self.runExtensionQuery(
                        query,
                        osqueryPath: osqueryPath,
                        extensionPath: extensionPath,
                        processBox: processBox
                    )
                } else {
                    rows = try await Self.runSimpleQuery(
                        query,
                        osqueryPath: osqueryPath,
                        processBox: processBox
                    )
                }
                return .completed(rows)
            }

            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                return .timedOut
            }

            defer { group.cancelAll() }

            while let outcome = try await group.next() {
                switch outcome {
                case .completed(let rows):
                    return rows
                case .timedOut:
                    processBox.terminate()
                    // Grace period, then SIGKILL if still alive.
                    try? await Task.sleep(nanoseconds: 2_000_000_000)
                    processBox.forceKill()
                    throw OSQueryError.timeout(timeout)
                }
            }
            return []
        }
    }

    /// Outcome of one query race participant.
    /// `@unchecked Sendable` is sound here because each case payload is
    /// produced inside a single Task and only read after that Task ends;
    /// there is no concurrent mutation of the dictionary contents.
    private enum QueryRunResult: @unchecked Sendable {
        case completed([[String: Any]])
        case timedOut
    }

    /// Sendable wrapper for the JSON rows crossing Task boundaries. Same
    /// soundness argument as `QueryRunResult`: the rows are produced in one
    /// Task, never shared concurrently.
    private struct QueryRows: @unchecked Sendable {
        let rows: [[String: Any]]
    }

    /// Shared handle to the running osqueryi/bash Process so the timeout watcher
    /// can kill it from outside the running Task. Process itself is not Sendable
    /// across Swift Concurrency boundaries; we wrap it in a small class with
    /// just terminate/kill so the timeout path is self-contained.
    private final class ProcessBox: @unchecked Sendable {
        private let lock = NSLock()
        private var process: Process?

        func attach(_ process: Process) {
            lock.lock(); defer { lock.unlock() }
            self.process = process
        }

        func terminate() {
            lock.lock(); defer { lock.unlock() }
            guard let process = process, process.isRunning else { return }
            process.terminate()
        }

        func forceKill() {
            lock.lock(); defer { lock.unlock() }
            guard let process = process, process.isRunning else { return }
            kill(process.processIdentifier, SIGKILL)
        }
    }
    
    /// Execute a simple osquery query without extension support.
    /// Runs on a detached Task so the blocking pipe reads release the cooperative
    /// thread pool; on timeout, the parent will terminate the Process and the
    /// pipe will EOF, unblocking the read here.
    private static func runSimpleQuery(_ query: String, osqueryPath: String, processBox: ProcessBox) async throws -> [[String: Any]] {
        let box = try await Task.detached(priority: .userInitiated) { () throws -> QueryRows in
            let task = Process()
            task.executableURL = URL(fileURLWithPath: osqueryPath)
            task.arguments = ["--json", query]

            let outputPipe = Pipe()
            let errorPipe = Pipe()
            task.standardOutput = outputPipe
            task.standardError = errorPipe

            do {
                try task.run()
            } catch {
                throw OSQueryError.processLaunchFailed(error)
            }
            processBox.attach(task)

            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()
            task.waitUntilExit()

            // If the process was killed (e.g. timeout), surface a clean error so
            // the parent's race resolution stays deterministic. The parent has
            // already thrown OSQueryError.timeout in that case; this throw just
            // unblocks the group cleanly.
            if task.terminationReason == .uncaughtSignal {
                throw OSQueryError.executionFailed("osqueryi terminated by signal")
            }

            if task.terminationStatus != 0 {
                let errorMessage = String(data: errorData, encoding: .utf8) ?? "Unknown error"
                throw OSQueryError.executionFailed(errorMessage)
            }

            guard let jsonString = String(data: outputData, encoding: .utf8),
                  let jsonData = jsonString.data(using: .utf8) else {
                throw OSQueryError.invalidOutput("Could not decode output as UTF-8")
            }

            do {
                if let jsonArray = try JSONSerialization.jsonObject(with: jsonData) as? [[String: Any]] {
                    return QueryRows(rows: jsonArray)
                } else {
                    throw OSQueryError.invalidOutput("Output is not a JSON array")
                }
            } catch let error as OSQueryError {
                throw error
            } catch {
                throw OSQueryError.jsonDecodingFailed(error)
            }
        }.value
        return box.rows
    }
    
    /// Execute an osquery query with extension support.
    /// Uses a bash subshell that sleeps 7s before sending the query, giving the
    /// macadmins extension time to register its tables. The bash process is the
    /// one we kill on timeout — terminating it brings down the osqueryi child
    /// and unblocks the pipe reads here.
    private static func runExtensionQuery(_ query: String, osqueryPath: String, extensionPath: String, processBox: ProcessBox) async throws -> [[String: Any]] {
        let box = try await Task.detached(priority: .userInitiated) { () throws -> QueryRows in
            let task = Process()
            task.executableURL = URL(fileURLWithPath: "/bin/bash")

            let escapedQuery = query.replacingOccurrences(of: "'", with: "'\"'\"'")

            let script = """
            (sleep 7 && echo '\(escapedQuery)' && echo '.exit') | "\(osqueryPath)" --json --extension "\(extensionPath)" --extensions_timeout 15
            """

            task.arguments = ["-c", script]

            let outputPipe = Pipe()
            let errorPipe = Pipe()
            task.standardOutput = outputPipe
            task.standardError = errorPipe

            do {
                try task.run()
            } catch {
                throw OSQueryError.processLaunchFailed(error)
            }
            processBox.attach(task)

            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()
            task.waitUntilExit()

            guard let outputString = String(data: outputData, encoding: .utf8) else {
                throw OSQueryError.invalidOutput("Could not decode output as UTF-8")
            }

            let errorString = String(data: errorData, encoding: .utf8) ?? ""

            if task.terminationReason == .uncaughtSignal {
                throw OSQueryError.executionFailed("osqueryi (extension) terminated by signal")
            }

            if ConsoleFormatter.verboseLevel >= 3 {
                if !errorString.isEmpty && (errorString.contains("error") || errorString.contains("Error")) {
                    ConsoleFormatter.writeDebug("OSQuery stderr: \(errorString.prefix(200))...")
                }
            }
            ConsoleFormatter.writeDebug("OSQuery output length: \(outputString.count) chars")

            if let jsonStart = outputString.firstIndex(of: "["),
               let jsonEnd = outputString.lastIndex(of: "]") {
                let jsonString = String(outputString[jsonStart...jsonEnd])

                if let jsonData = jsonString.data(using: .utf8),
                   let jsonArray = (try? JSONSerialization.jsonObject(with: jsonData)) as? [[String: Any]] {
                    return QueryRows(rows: jsonArray)
                }
            }

            if outputString.contains("no such table") || errorString.contains("no such table") {
                throw OSQueryError.executionFailed("no such table")
            }

            if task.terminationStatus != 0 {
                let errorMessage = errorString.isEmpty ? "osquery exited with code \(task.terminationStatus)" : errorString
                throw OSQueryError.executionFailed(errorMessage)
            }

            if outputString.isEmpty {
                let errorMessage = errorString.isEmpty ? "No output from osquery" : errorString
                throw OSQueryError.executionFailed(errorMessage)
            }

            return QueryRows(rows: [])
        }.value
        return box.rows
    }
    
    /// Execute multiple queries from a module configuration with progress display.
    /// Each query emits started / ok / timeout lines under -v so a hung table is
    /// self-diagnosing. A timed-out or failed query yields an empty result and
    /// the module continues with the remaining queries — never let one bad
    /// table take down the whole module's transmit.
    public func executeModuleQueries(_ queries: [String: String], showProgress: Bool = true) async -> [String: [[String: Any]]] {
        var results: [String: [[String: Any]]] = [:]

        let queryArray = Array(queries)
        let totalQueries = queryArray.count

        if showProgress && totalQueries > 0 && ConsoleFormatter.isVerbose {
            ConsoleFormatter.writeInfo("Executing \(totalQueries) osquery queries")
        }

        for (index, (key, query)) in queryArray.enumerated() {
            if showProgress {
                ConsoleFormatter.writeQueryProgress(queryName: key, current: index + 1, total: totalQueries)
            }

            ConsoleFormatter.writeInfo("query \(key) status=started")
            let start = Date()

            do {
                let result = try await executeQuery(query)
                let elapsed = Date().timeIntervalSince(start)
                ConsoleFormatter.writeInfo("query \(key) status=ok rows=\(result.count) elapsed=\(String(format: "%.1fs", elapsed))")
                results[key] = result
            } catch let OSQueryError.timeout(seconds) {
                let elapsed = Date().timeIntervalSince(start)
                ConsoleFormatter.writeWarning("query \(key) status=timeout budget=\(String(format: "%.0fs", seconds)) elapsed=\(String(format: "%.1fs", elapsed)) -- skipping")
                results[key] = []
            } catch {
                let elapsed = Date().timeIntervalSince(start)
                ConsoleFormatter.writeWarning("query \(key) status=failed elapsed=\(String(format: "%.1fs", elapsed)) error=\(error)")
                results[key] = []
            }
        }

        return results
    }
    
    /// Get osquery version
    public func getVersion() async throws -> String {
        return try await withCheckedThrowingContinuation { continuation in
            let task = Process()
            task.executableURL = URL(fileURLWithPath: osqueryPath)
            task.arguments = ["--version"]
            
            let outputPipe = Pipe()
            task.standardOutput = outputPipe
            task.standardError = Pipe()
            
            do {
                try task.run()
                
                let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
                task.waitUntilExit()
                
                if task.terminationStatus != 0 {
                    continuation.resume(throwing: OSQueryError.executionFailed("Failed to get version"))
                    return
                }
                
                let versionOutput = String(data: outputData, encoding: .utf8) ?? ""
                let version = versionOutput.trimmingCharacters(in: .whitespacesAndNewlines)
                continuation.resume(returning: version)
                
            } catch {
                continuation.resume(throwing: OSQueryError.processLaunchFailed(error))
            }
        }
    }
}

// MARK: - Error Types

public enum OSQueryError: Error, LocalizedError {
    case executionFailed(String)
    case processLaunchFailed(Error)
    case invalidOutput(String)
    case jsonDecodingFailed(Error)
    case timeout(TimeInterval)

    public var errorDescription: String? {
        switch self {
        case .executionFailed(let message):
            return "OSQuery execution failed: \(message)"
        case .processLaunchFailed(let error):
            return "Failed to launch osquery process: \(error.localizedDescription)"
        case .invalidOutput(let message):
            return "Invalid osquery output: \(message)"
        case .jsonDecodingFailed(let error):
            return "Failed to decode JSON output: \(error.localizedDescription)"
        case .timeout(let seconds):
            return "OSQuery exceeded timeout of \(String(format: "%.0fs", seconds))"
        }
    }
}
