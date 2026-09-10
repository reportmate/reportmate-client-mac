import Foundation

/// Mints short-lived Entra access tokens for the ReportMate API audience off
/// the operator's own `az` login, so no shared secret is stored on the Mac.
/// The API validates the bearer and maps the operator's roles to scopes.
public actor AzTokenSource {
    public static let shared = AzTokenSource()

    private var cache: [String: (token: String, expiry: Date)] = [:]
    private let azPath: String

    public init(azPath: String? = nil) {
        self.azPath = azPath ?? AzTokenSource.locateAz()
    }

    /// A delegated access token for `resource` (an app id GUID or `api://…` URI).
    public func token(forResource resource: String) async throws -> String {
        if let c = cache[resource], Date() < c.expiry { return c.token }
        let result = try await ProcessRunner.run(azPath, ["account", "get-access-token", "--resource", resource, "--query", "accessToken", "-o", "tsv"])
        guard result.exitCode == 0 else {
            let msg = (result.stderr.isEmpty ? result.stdout : result.stderr).trimmingCharacters(in: .whitespacesAndNewlines)
            throw AzTokenError.acquisitionFailed(resource, msg)
        }
        let token = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !token.isEmpty else { throw AzTokenError.acquisitionFailed(resource, "az returned an empty token") }
        cache[resource] = (token, Date().addingTimeInterval(50 * 60))
        return token
    }

    public func invalidate() {
        cache.removeAll()
    }

    public static func locateAz() -> String {
        for c in ["/opt/homebrew/bin/az", "/usr/local/bin/az"] where FileManager.default.isExecutableFile(atPath: c) { return c }
        return "az"
    }

    public var isAzAvailable: Bool {
        azPath.hasPrefix("/") ? FileManager.default.isExecutableFile(atPath: azPath) : true
    }
}

public enum AzTokenError: LocalizedError {
    case acquisitionFailed(String, String)

    public var errorDescription: String? {
        switch self {
        case .acquisitionFailed(let resource, let msg):
            return "Could not acquire an Entra token for \(resource). Run `az login` in a terminal and try again. \(msg)"
        }
    }
}

/// Runs a subprocess and captures its output.
public enum ProcessRunner {
    public struct Result: Sendable {
        public var stdout: String
        public var stderr: String
        public var exitCode: Int32
    }

    public static func run(_ executable: String, _ arguments: [String]) async throws -> Result {
        try await withCheckedThrowingContinuation { continuation in
            let process = Process()
            if executable.hasPrefix("/") {
                process.executableURL = URL(fileURLWithPath: executable)
                process.arguments = arguments
            } else {
                process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
                process.arguments = [executable] + arguments
            }
            let out = Pipe()
            let err = Pipe()
            process.standardOutput = out
            process.standardError = err
            process.terminationHandler = { p in
                let o = String(data: out.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
                let e = String(data: err.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
                continuation.resume(returning: Result(stdout: o, stderr: e, exitCode: p.terminationStatus))
            }
            do {
                try process.run()
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }
}
