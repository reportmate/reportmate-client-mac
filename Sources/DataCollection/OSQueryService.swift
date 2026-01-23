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
    
    /// Persistent osquery session for extension support
    /// The extension takes ~3 seconds to register, so we keep a persistent session
    private var persistentProcess: Process?
    private var persistentInput: FileHandle?
    private var persistentOutput: FileHandle?
    private var sessionInitialized: Bool = false
    
    public init(configuration: ReportMateConfiguration) {
        self.configuration = configuration
        self.osqueryPath = configuration.osqueryPath
        
        // Enable extension support - the extension registers after 3 seconds
        // We use a persistent session approach to avoid waiting 3s for each query
        if configuration.extensionEnabled {
            self.extensionPath = Self.resolveExtensionPath(configured: configuration.osqueryExtensionPath)
        } else {
            self.extensionPath = nil
        }
    }
    
    deinit {
        cleanupPersistentSession()
    }
    
    /// Cleanup the persistent osquery session
    private func cleanupPersistentSession() {
        if let process = persistentProcess, process.isRunning {
            // Send .exit command
            if let input = persistentInput {
                let exitCmd = ".exit\n"
                input.write(exitCmd.data(using: .utf8)!)
                try? input.close()
            }
            process.terminate()
            persistentProcess = nil
        }
        persistentInput = nil
        persistentOutput = nil
        sessionInitialized = false
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
        // 1. Try configured path
        if let configured = configured, FileManager.default.fileExists(atPath: configured) {
            return configured
        }
        
        // 2. Try bundled in Resources/extensions/ (SPM executable bundle)
        // For SPM, the bundle is at .build/release/<Target>_<Target>.bundle/Resources/
        if let bundlePath = Bundle.main.resourcePath {
            let bundledExt = "\(bundlePath)/extensions/macadmins_extension.ext"
            if FileManager.default.fileExists(atPath: bundledExt) {
                return bundledExt
            }
        }
        
        // 3. Try relative to executable (for development builds)
        let executablePath = Bundle.main.executablePath ?? ""
        let executableDir = (executablePath as NSString).deletingLastPathComponent
        let relativeToExec = "\(executableDir)/ReportMate_ReportMate.bundle/Resources/extensions/macadmins_extension.ext"
        if FileManager.default.fileExists(atPath: relativeToExec) {
            return relativeToExec
        }
        
        // 4. Try standard installation location (installed by .pkg)
        let installedPath = "/usr/local/reportmate/macadmins_extension.ext"
        if FileManager.default.fileExists(atPath: installedPath) {
            return installedPath
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
    public func executeQuery(_ query: String) async throws -> [[String: Any]] {
        // Simple query execution without extension
        if extensionPath == nil {
            return try await executeSimpleQuery(query)
        }
        
        // With extension: use osqueryi's --extension flag
        // The extension takes 3 seconds to register, so we pass the query after waiting
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
    
    /// Execute an osquery query with extension support using interactive mode
    /// The extension takes ~3 seconds to register, so we:
    /// 1. Start osqueryi in interactive mode with --extension
    /// 2. Wait 4 seconds for extension to register
    /// 3. Send the query via stdin
    /// 4. Read the JSON output
    private func executeQueryWithExtension(_ query: String) async throws -> [[String: Any]] {
        return try await withCheckedThrowingContinuation { continuation in
            let task = Process()
            task.executableURL = URL(fileURLWithPath: osqueryPath)
            
            // Use interactive mode with extension
            // --json makes all SELECT output JSON formatted
            // --extension loads the macadmins extension as a child process
            // --extensions_timeout gives the extension time to register
            task.arguments = [
                "--json",
                "--extension", extensionPath!,
                "--extensions_timeout", "10"
            ]
            
            let inputPipe = Pipe()
            let outputPipe = Pipe()
            let errorPipe = Pipe()
            task.standardInput = inputPipe
            task.standardOutput = outputPipe
            task.standardError = errorPipe
            
            do {
                try task.run()
                
                // Wait 4 seconds for the extension to register its tables
                // The extension has a 3-second sleep on startup
                Thread.sleep(forTimeInterval: 4.0)
                
                // Send the query followed by .exit
                let commands = "\(query)\n.exit\n"
                inputPipe.fileHandleForWriting.write(commands.data(using: .utf8)!)
                try? inputPipe.fileHandleForWriting.close()
                
                // Read all output
                let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
                let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()
                
                task.waitUntilExit()
                
                // Parse the JSON output
                // The output will include the osqueryi prompt, so we need to extract just the JSON
                guard let outputString = String(data: outputData, encoding: .utf8) else {
                    continuation.resume(throwing: OSQueryError.invalidOutput("Could not decode output as UTF-8"))
                    return
                }
                
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
                let errorString = String(data: errorData, encoding: .utf8) ?? ""
                if outputString.contains("no such table") || errorString.contains("no such table") {
                    continuation.resume(throwing: OSQueryError.executionFailed("no such table"))
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
