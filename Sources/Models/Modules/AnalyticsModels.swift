import Foundation

/// Analytics module data models for macOS ReportMate client
/// These models represent usage statistics and performance metrics

public struct AnalyticsData: ModuleDataModel, Sendable {
    public var moduleId: String { "analytics" }
    public let collectionTimestamp: Date
    public let success: Bool
    public let errorMessage: String?
    
    public let systemUptime: TimeInterval
    public let loadAverage: [Double]
    public let processCount: Int
    public let threadCount: Int
    public let userSessions: [UserSession]
    public let networkStats: NetworkStatistics?
    public let diskIO: DiskIOStats?
    
    public init(
        collectionTimestamp: Date = Date(),
        success: Bool = true,
        errorMessage: String? = nil,
        systemUptime: TimeInterval = 0,
        loadAverage: [Double] = [],
        processCount: Int = 0,
        threadCount: Int = 0,
        userSessions: [UserSession] = [],
        networkStats: NetworkStatistics? = nil,
        diskIO: DiskIOStats? = nil
    ) {
        self.collectionTimestamp = collectionTimestamp
        self.success = success
        self.errorMessage = errorMessage
        self.systemUptime = systemUptime
        self.loadAverage = loadAverage
        self.processCount = processCount
        self.threadCount = threadCount
        self.userSessions = userSessions
        self.networkStats = networkStats
        self.diskIO = diskIO
    }
}

public struct UserSession: Codable, Sendable {
    public let username: String
    public let loginTime: Date
    public let terminal: String
    public let host: String
    
    public init(username: String, loginTime: Date, terminal: String, host: String) {
        self.username = username
        self.loginTime = loginTime
        self.terminal = terminal
        self.host = host
    }
}

public struct NetworkStatistics: Codable, Sendable {
    public let packetsIn: Int64
    public let packetsOut: Int64
    public let bytesIn: Int64
    public let bytesOut: Int64
    public let errorsIn: Int64
    public let errorsOut: Int64
    
    public init(packetsIn: Int64, packetsOut: Int64, bytesIn: Int64, bytesOut: Int64, errorsIn: Int64, errorsOut: Int64) {
        self.packetsIn = packetsIn
        self.packetsOut = packetsOut
        self.bytesIn = bytesIn
        self.bytesOut = bytesOut
        self.errorsIn = errorsIn
        self.errorsOut = errorsOut
    }
}

public struct DiskIOStats: Codable, Sendable {
    public let reads: Int64
    public let writes: Int64
    public let bytesRead: Int64
    public let bytesWritten: Int64
    
    public init(reads: Int64, writes: Int64, bytesRead: Int64, bytesWritten: Int64) {
        self.reads = reads
        self.writes = writes
        self.bytesRead = bytesRead
        self.bytesWritten = bytesWritten
    }
}
