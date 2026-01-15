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
    
    public init(configuration: ReportMateConfiguration) {
        self.configuration = configuration
        self.osqueryPath = configuration.osqueryPath
        
        // TEMPORARILY DISABLED: macadmins extension has compatibility issues with osquery 5.21.0
        // The extension fails to create its socket and osquery doesn't wait for extension tables
        // Bash fallbacks provide all necessary data for now
        // TODO: Investigate extension compatibility or upgrade osquery
        self.extensionPath = nil
        /*
        // Determine extension path (bundled or configured)
        if configuration.extensionEnabled {
            self.extensionPath = Self.resolveExtensionPath(configured: configuration.osqueryExtensionPath)
        } else {
            self.extensionPath = nil
        }
        */
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
    public func executeQuery(_ query: String) async throws -> [[String: Any]] {
        return try await withCheckedThrowingContinuation { continuation in
            var extensionProcess: Process? = nil
            var socketPath: String? = nil
            
            // Start extension daemon if available
            if let extPath = extensionPath {
                let uniqueId = UUID().uuidString.prefix(8)
                socketPath = "/tmp/osquery-rm-\(uniqueId).em"
                
                // Clean up any stale socket
                try? FileManager.default.removeItem(atPath: socketPath!)
                
                // Start extension as background process
                let extTask = Process()
                extTask.executableURL = URL(fileURLWithPath: extPath)
                extTask.arguments = ["--socket", socketPath!, "--verbose"]
                extTask.standardOutput = Pipe()  // Suppress output
                extTask.standardError = Pipe()
                
                do {
                    try extTask.run()
                    extensionProcess = extTask
                    
                    // Wait for socket to be created (extension startup)
                    var retries = 0
                    while retries < 30 {  // 3 seconds max
                        if FileManager.default.fileExists(atPath: socketPath!) {
                            break
                        }
                        Thread.sleep(forTimeInterval: 0.1)
                        retries += 1
                    }
                    
                    if !FileManager.default.fileExists(atPath: socketPath!) {
                        print("WARNING: Extension socket not created after 3 seconds, continuing without extension")
                        extensionProcess?.terminate()
                        extensionProcess = nil
                        socketPath = nil
                    }
                } catch {
                    print("WARNING: Failed to start extension: \(error), continuing without extension")
                    extensionProcess = nil
                    socketPath = nil
                }
            }
            
            // Now run osquery connecting to the extension socket
            let task = Process()
            task.executableURL = URL(fileURLWithPath: osqueryPath)
            
            // Build arguments
            var arguments = ["--json"]
            
            // Connect to extension socket if we started the extension daemon
            if let socket = socketPath, extensionProcess != nil {
                arguments.append(contentsOf: [
                    "--extensions_socket", socket,
                    "--extensions_timeout", "5"  // Quick timeout since extension is already running
                ])
            }
            
            arguments.append(query)
            task.arguments = arguments
            
            let outputPipe = Pipe()
            let errorPipe = Pipe()
            task.standardOutput = outputPipe
            task.standardError = errorPipe
            
            do {
                try task.run()
                
                let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
                let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()
                
                task.waitUntilExit()
                
                // Cleanup extension process
                defer {
                    if let extProcess = extensionProcess, extProcess.isRunning {
                        extProcess.terminate()
                    }
                    if let socket = socketPath {
                        try? FileManager.default.removeItem(atPath: socket)
                    }
                }
                
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
    
    /// Execute multiple queries from a module configuration
    public func executeModuleQueries(_ queries: [String: String]) async -> [String: [[String: Any]]] {
        var results: [String: [[String: Any]]] = [:]
        
        // Execute queries sequentially for now to avoid Sendable issues
        for (key, query) in queries {
            do {
                let result = try await executeQuery(query)
                results[key] = result
            } catch {
                print("Warning: Query '\(key)' failed: \(error)")
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
