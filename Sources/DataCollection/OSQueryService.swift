import Foundation

/// OSQuery service for macOS
/// Manages osquery execution with fallbacks to bash and Python
public class OSQueryService {
    private let configuration: ReportMateConfiguration
    private let osqueryPath: String
    
    public init(configuration: ReportMateConfiguration) {
        self.configuration = configuration
        self.osqueryPath = configuration.osqueryPath
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
    
    /// Execute an osquery SQL query
    public func executeQuery(_ query: String) async throws -> [[String: Any]] {
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

// MARK: - Bash Fallback Service

/// Bash command execution service for fallback data collection
public class BashService {
    
    /// Execute a bash command and return output
    public static func execute(_ command: String) async throws -> String {
        return try await withCheckedThrowingContinuation { continuation in
            let task = Process()
            task.executableURL = URL(fileURLWithPath: "/bin/bash")
            task.arguments = ["-c", command]
            
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
                    continuation.resume(throwing: BashError.executionFailed(command, errorMessage))
                    return
                }
                
                let output = String(data: outputData, encoding: .utf8) ?? ""
                continuation.resume(returning: output)
                
            } catch {
                continuation.resume(throwing: BashError.processLaunchFailed(error))
            }
        }
    }
    
    /// Execute system_profiler command for hardware information
    public static func executeSystemProfiler(_ dataType: String) async throws -> [String: Any] {
        let output = try await execute("system_profiler \(dataType) -json")
        
        guard let jsonData = output.data(using: .utf8),
              let jsonObject = try JSONSerialization.jsonObject(with: jsonData) as? [String: Any] else {
            throw BashError.invalidOutput("system_profiler did not return valid JSON")
        }
        
        return jsonObject
    }
}

// MARK: - Python Fallback Service

/// Python script execution service for last-resort data collection
public class PythonService {
    
    /// Execute a Python script and return JSON output
    public static func executeScript(_ scriptContent: String) async throws -> [String: Any] {
        // Create temporary script file
        let tempDir = FileManager.default.temporaryDirectory
        let scriptURL = tempDir.appendingPathComponent("reportmate_script_\(UUID().uuidString).py")
        
        defer {
            try? FileManager.default.removeItem(at: scriptURL)
        }
        
        try scriptContent.write(to: scriptURL, atomically: true, encoding: .utf8)
        
        return try await withCheckedThrowingContinuation { continuation in
            let task = Process()
            task.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
            task.arguments = [scriptURL.path]
            
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
                    continuation.resume(throwing: PythonError.executionFailed(errorMessage))
                    return
                }
                
                guard let jsonString = String(data: outputData, encoding: .utf8),
                      let jsonData = jsonString.data(using: .utf8),
                      let jsonObject = try? JSONSerialization.jsonObject(with: jsonData) as? [String: Any] else {
                    continuation.resume(throwing: PythonError.invalidOutput("Script did not return valid JSON"))
                    return
                }
                
                continuation.resume(returning: jsonObject)
                
            } catch {
                continuation.resume(throwing: PythonError.processLaunchFailed(error))
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

public enum BashError: Error, LocalizedError {
    case executionFailed(String, String)
    case processLaunchFailed(Error)
    case invalidOutput(String)
    
    public var errorDescription: String? {
        switch self {
        case .executionFailed(let command, let error):
            return "Bash command failed '\(command)': \(error)"
        case .processLaunchFailed(let error):
            return "Failed to launch bash process: \(error.localizedDescription)"
        case .invalidOutput(let message):
            return "Invalid bash output: \(message)"
        }
    }
}

public enum PythonError: Error, LocalizedError {
    case executionFailed(String)
    case processLaunchFailed(Error)
    case invalidOutput(String)
    
    public var errorDescription: String? {
        switch self {
        case .executionFailed(let message):
            return "Python script failed: \(message)"
        case .processLaunchFailed(let error):
            return "Failed to launch Python process: \(error.localizedDescription)"
        case .invalidOutput(let message):
            return "Invalid Python output: \(message)"
        }
    }
}