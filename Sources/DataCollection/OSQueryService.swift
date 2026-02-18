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
    public func executeQuery(_ query: String) async throws -> [[String: Any]] {
        // Route built-in table queries to the fast path — no extension overhead
        if extensionPath == nil || !Self.queryUsesExtensionTables(query) {
            return try await executeSimpleQuery(query)
        }
        
        // Extension tables: use osqueryi's --extension flag with sleep delay
        return try await executeQueryWithExtension(query)
    }
    
    /// Execute a simple osquery query without extension support
    private func executeSimpleQuery(_ query: String) async throws -> [[String: Any]] {
        return try await withCheckedThrowingContinuation { continuation in
            let task = Process()
            task.executableURL = URL(fileURLWithPath: osqueryPath)
            task.arguments = ["--json", query]
            
            let outputPipe = Pipe()
            let errorPipe = Pipe()
            task.standardOutput = outputPipe
            task.standardError = errorPipe
            
            do {
                try task.run()
                
                let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
                let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()
                
                task.waitUntilExit()
                
                if task.terminationStatus != 0 {
                    let errorMessage = String(data: errorData, encoding: .utf8) ?? "Unknown error"
                    continuation.resume(throwing: OSQueryError.executionFailed(errorMessage))
                    return
                }
                
                guard let jsonString = String(data: outputData, encoding: .utf8),
                      let jsonData = jsonString.data(using: .utf8) else {
                    continuation.resume(throwing: OSQueryError.invalidOutput("Could not decode output as UTF-8"))
                    return
                }
                
                do {
                    if let jsonArray = try JSONSerialization.jsonObject(with: jsonData) as? [[String: Any]] {
                        continuation.resume(returning: jsonArray)
                    } else {
                        continuation.resume(throwing: OSQueryError.invalidOutput("Output is not a JSON array"))
                    }
                } catch {
                    continuation.resume(throwing: OSQueryError.jsonDecodingFailed(error))
                }
                
            } catch {
                continuation.resume(throwing: OSQueryError.processLaunchFailed(error))
            }
        }
    }
    
    /// Execute an osquery query with extension support
    /// Uses delayed stdin approach to ensure extension has time to register before query runs
    /// The extension takes ~6 seconds to fully register its tables
    private func executeQueryWithExtension(_ query: String) async throws -> [[String: Any]] {
        return try await withCheckedThrowingContinuation { continuation in
            // WORKAROUND: osquery extension loading is asynchronous.
            // When using --extension flag, the extension process starts but tables
            // aren't immediately available. If we send the query too soon, it fails
            // with "no such table" error.
            //
            // Solution: Use bash to delay query input until extension has registered.
            // We pipe the query via a subshell that sleeps first.
            
            let task = Process()
            task.executableURL = URL(fileURLWithPath: "/bin/bash")
            
            // Escape the query for shell
            let escapedQuery = query.replacingOccurrences(of: "'", with: "'\"'\"'")
            
            // Use bash -c with a subshell that:
            // 1. Sleeps 7 seconds to let extension register
            // 2. Sends the query
            // 3. Sends .exit to close osqueryi
            // The pipe to osqueryi waits for input, giving extension time to load
            let script = """
            (sleep 7 && echo '\(escapedQuery)' && echo '.exit') | "\(osqueryPath)" --json --extension "\(extensionPath!)" --extensions_timeout 15
            """
            
            task.arguments = ["-c", script]
            
            let outputPipe = Pipe()
            let errorPipe = Pipe()
            task.standardOutput = outputPipe
            task.standardError = errorPipe
            
            do {
                try task.run()
                
                let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
                let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()
                
                task.waitUntilExit()
                
                guard let outputString = String(data: outputData, encoding: .utf8) else {
                    continuation.resume(throwing: OSQueryError.invalidOutput("Could not decode output as UTF-8"))
                    return
                }
                
                // Debug: log output for extension debugging (only when verbose)
                let errorString = String(data: errorData, encoding: .utf8) ?? ""
                if ConsoleFormatter.verboseLevel >= 3 {
                    if !errorString.isEmpty && (errorString.contains("error") || errorString.contains("Error")) {
                        ConsoleFormatter.writeDebug("OSQuery stderr: \(errorString.prefix(200))...")
                    }
                }
                ConsoleFormatter.writeDebug("OSQuery output length: \(outputString.count) chars")
                
                // Find the JSON array in the output (starts with [ and ends with ])
                if let jsonStart = outputString.firstIndex(of: "["),
                   let jsonEnd = outputString.lastIndex(of: "]") {
                    let jsonString = String(outputString[jsonStart...jsonEnd])
                    
                    if let jsonData = jsonString.data(using: .utf8) {
                        do {
                            if let jsonArray = try JSONSerialization.jsonObject(with: jsonData) as? [[String: Any]] {
                                continuation.resume(returning: jsonArray)
                                return
                            }
                        } catch {
                            // JSON parsing failed, check if it's an error response
                        }
                    }
                }
                
                // Check for errors in stderr or output
                if outputString.contains("no such table") || errorString.contains("no such table") {
                    continuation.resume(throwing: OSQueryError.executionFailed("no such table"))
                    return
                }
                
                // If task failed with non-zero exit code
                if task.terminationStatus != 0 {
                    let errorMessage = errorString.isEmpty ? "osquery exited with code \(task.terminationStatus)" : errorString
                    continuation.resume(throwing: OSQueryError.executionFailed(errorMessage))
                    return
                }
                
                // If we got here with no JSON, return empty array
                if outputString.isEmpty {
                    let errorMessage = errorString.isEmpty ? "No output from osquery" : errorString
                    continuation.resume(throwing: OSQueryError.executionFailed(errorMessage))
                } else {
                    // No valid JSON found but also no error - might be an empty result
                    continuation.resume(returning: [])
                }
                
            } catch {
                continuation.resume(throwing: OSQueryError.processLaunchFailed(error))
            }
        }
    }
    
    /// Execute multiple queries from a module configuration with progress display
    public func executeModuleQueries(_ queries: [String: String], showProgress: Bool = true) async -> [String: [[String: Any]]] {
        var results: [String: [[String: Any]]] = [:]
        
        let queryArray = Array(queries)
        let totalQueries = queryArray.count
        
        // Show header for osquery execution
        if showProgress && totalQueries > 0 && ConsoleFormatter.isVerbose {
            ConsoleFormatter.writeInfo("Executing \(totalQueries) osquery queries")
        }
        
        // Execute queries sequentially with progress tracking
        for (index, (key, query)) in queryArray.enumerated() {
            // Show progress bar for each query
            if showProgress {
                ConsoleFormatter.writeQueryProgress(queryName: key, current: index + 1, total: totalQueries)
            }
            
            do {
                let result = try await executeQuery(query)
                results[key] = result
            } catch {
                if ConsoleFormatter.isVerbose {
                    ConsoleFormatter.writeWarning("Query '\(key)' failed: \(error)")
                }
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
        }
    }
}
