import Foundation

// Management module `logs` section - management tool log roots under /Library/Managed */logs
//
// Mirrors the Windows client's LogsModels.cs field for field. Keys are
// camelCase on both platforms so one reader serves both.

public struct LogFileEntry: Codable, Sendable {
    public let name: String
    /// Path relative to the root's logs directory, e.g. "2026-09-01/1315/run.log"
    public let path: String
    public let bytes: Int64
    public let modified: String?
}

public struct LogSessionSummary: Codable, Sendable {
    public let sessionId: String?
    public let status: String?
    public let startTime: String?
    public let endTime: String?
    public let durationSeconds: Double?
    public let runType: String?
    public let errors: Int?
    public let warnings: Int?
}

public struct LogTail: Codable, Sendable {
    public let file: String
    public let lines: [String]
    public let truncated: Bool
    public let bytes: Int
}

public struct LogRoot: Codable, Sendable {
    /// Stable key derived from the directory name: "Managed Installs" -> "installs"
    public let tool: String
    /// Directory display name, e.g. "Managed Installs"
    public let name: String
    public let path: String
    /// "sessions" when the root holds YYYY-MM-DD/HHMM session directories, else "flat"
    public let layout: String
    public let fileCount: Int
    public let totalBytes: Int64
    public let newestModified: String?
    /// True when the walk hit its entry budget and fileCount/totalBytes are a floor
    public let inventoryTruncated: Bool
    public let files: [LogFileEntry]
    public let latestSession: LogSessionSummary?
    /// Relative path of the log the tail viewer opens first
    public let primaryLog: String?
    /// ERROR and WARN lines counted across the primary log's tail
    public let errorCount: Int
    public let warningCount: Int
    /// Tails of the root's most relevant logs, primary first; capped per file and per root
    public let tails: [LogTail]
    /// Version of the tool that owns the root, read from its package receipt or
    /// app bundle after the survey; nil when the tool has no known source.
    public var version: String?
}
