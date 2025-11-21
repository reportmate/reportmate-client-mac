import Foundation

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
