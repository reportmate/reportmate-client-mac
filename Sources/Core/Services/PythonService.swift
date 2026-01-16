import Foundation

/// DEPRECATED: Python script execution service for last-resort data collection
///
/// ⚠️ WARNING: This service is DEPRECATED and should NOT be used.
///
/// ReportMate uses only native Swift, osquery (with macadmins extension), and bash for data collection.
/// Python is not permitted as per project architecture guidelines in CLAUDE.md.
///
/// This file is kept for historical reference only and will be removed in a future release.
/// All module processors now use only osquery and bash fallbacks.
///
/// - SeeAlso: CLAUDE.md for technology stack requirements
@available(*, deprecated, message: "Python is not allowed in ReportMate. Use osquery or bash instead.")
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
