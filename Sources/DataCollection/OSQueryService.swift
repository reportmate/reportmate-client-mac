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
        
        // Determine extension path (bundled or configured)
        if configuration.extensionEnabled {
            self.extensionPath = Self.resolveExtensionPath(configured: configuration.osqueryExtensionPath)
            if let path = extensionPath {
                print("✅ OSQuery extension found at: \(path)")
                print("   Extension will be loaded automatically with queries")
            } else {
                print("⚠️  OSQuery extension not found - will use bash fallbacks")
                print("   Searched: Bundle.main.resourcePath/extensions/, /usr/local/bin/, /opt/reportmate/extensions/")
            }
        } else {
            print("ℹ️  OSQuery extension disabled in configuration")
            self.extensionPath = nil
        }
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
        
        // 4. Try standard locations
        let standardPaths = [
            "/usr/local/bin/macadmins_extension.ext",
            "/opt/reportmate/extensions/macadmins_extension.ext"
        ]
        
        for path in standardPaths {
            if FileManager.default.fileExists(atPath: path) {
                return path
            }
        }
        
        return nil
    }
    
    /// Execute an osquery SQL query
    public func executeQuery(_ query: String) async throws -> [[String: Any]] {
        return try await withCheckedThrowingContinuation { continuation in
            let task = Process()
            task.executableURL = URL(fileURLWithPath: osqueryPath)
            
            // Build arguments with extension support
            var arguments = ["--json"]
            
            // Load extension if available
            if let extPath = extensionPath {
                // Create a unique socket path for this execution
                let socketPath = "/tmp/osquery-reportmate-\(ProcessInfo.processInfo.processIdentifier).em"
                
                arguments.append(contentsOf: [
                    "--extension", extPath,
                    "--allow_unsafe",  // Skip ownership check
                    "--disable_extensions=false",  // Explicitly enable extensions
                    "--extensions_socket", socketPath  // Use unique socket to avoid conflicts
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
