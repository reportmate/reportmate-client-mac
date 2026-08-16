import Foundation

/// Bash command execution service for fallback data collection
public class BashService {
    
    /// Execute a bash command and return its standard output.
    ///
    /// Every command runs under a hard time budget. Without one, a single wedged external tool
    /// stalls the whole collection silently and indefinitely: the module never reports, the
    /// payload never ships, and the device simply goes quiet while the other daemons keep
    /// running normally. That is far harder to spot than a crash. Observed in the wild with
    /// `mdatp health` against a hung Defender daemon, which held two collection runs for
    /// thirty minutes and nearly six hours respectively.
    ///
    /// - Parameter timeout: seconds before the command is terminated. Raise it for commands
    ///   that are legitimately slow rather than removing the bound.
    public static func execute(
        _ command: String,
        timeout: TimeInterval = ProcessRunner.defaultTimeout
    ) async throws -> String {
        let result = try await ProcessRunner.bash(command, timeout: timeout)

        if result.timedOut {
            throw BashError.timedOut(command, timeout)
        }

        if result.exitCode != 0 {
            let message = result.standardError.isEmpty ? "Unknown error" : result.standardError
            throw BashError.executionFailed(command, message)
        }

        return result.standardOutput
    }

    /// Execute system_profiler command for hardware information
    public static func executeSystemProfiler(_ dataType: String) async throws -> [String: Any] {
        // system_profiler is legitimately slow on large data types, so it gets a wider budget
        // than the default - but still a bounded one.
        let output = try await execute("system_profiler \(dataType) -json", timeout: 300)
        
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
    case timedOut(String, TimeInterval)

    public var errorDescription: String? {
        switch self {
        case .executionFailed(let command, let error):
            return "Bash command failed '\(command)': \(error)"
        case .processLaunchFailed(let error):
            return "Failed to launch bash process: \(error.localizedDescription)"
        case .invalidOutput(let message):
            return "Invalid bash output: \(message)"
        case .timedOut(let command, let seconds):
            return "Bash command exceeded its \(Int(seconds))s budget and was terminated: '\(command)'"
        }
    }
}
