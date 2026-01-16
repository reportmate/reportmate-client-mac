import Foundation

/// Base module models that provide common structure for all data collection modules
/// These models define the interface and common functionality used across all module processors

/// Basic interface for module data that can be used by collection services
public protocol ModuleData: Codable, Sendable {
    var moduleId: String { get }
    var collectionTimestamp: Date { get }
}

/// Protocol that all module-specific models must implement  
public protocol ModuleDataModel: ModuleData {
    var success: Bool { get }
    var errorMessage: String? { get }
}

/// Base implementation for all module data models that also conforms to ModuleData protocol
public struct BaseModuleData: ModuleDataModel {
    public let moduleId: String
    public let collectionTimestamp: Date
    public let success: Bool
    public let errorMessage: String?
    private let dataJson: String
    
    public var data: [String: Any] {
        guard let jsonData = dataJson.data(using: .utf8),
              let decoded = try? JSONSerialization.jsonObject(with: jsonData) as? [String: Any] else {
            return [:]
        }
        return decoded
    }
    
    public init(moduleId: String, data: [String: Any], success: Bool = true, errorMessage: String? = nil) {
        self.moduleId = moduleId
        self.collectionTimestamp = Date()
        self.success = success
        self.errorMessage = errorMessage
        
        // Convert data dictionary to JSON string for Sendable compliance
        do {
            let jsonData = try JSONSerialization.data(withJSONObject: data)
            self.dataJson = String(data: jsonData, encoding: .utf8) ?? "{}"
        } catch {
            self.dataJson = "{}"
        }
    }
    
    public init(moduleId: String, error: Error) {
        self.moduleId = moduleId
        self.collectionTimestamp = Date()
        self.success = false
        self.errorMessage = error.localizedDescription
        self.dataJson = "{}"
    }
    
    // Custom coding implementation
    enum CodingKeys: String, CodingKey {
        case moduleId, collectionTimestamp, success, errorMessage, dataJson
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        moduleId = try container.decode(String.self, forKey: .moduleId)
        collectionTimestamp = try container.decode(Date.self, forKey: .collectionTimestamp)
        success = try container.decode(Bool.self, forKey: .success)
        errorMessage = try container.decodeIfPresent(String.self, forKey: .errorMessage)
        dataJson = try container.decode(String.self, forKey: .dataJson)
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(moduleId, forKey: .moduleId)
        try container.encode(collectionTimestamp, forKey: .collectionTimestamp)
        try container.encode(success, forKey: .success)
        try container.encodeIfPresent(errorMessage, forKey: .errorMessage)
        try container.encode(dataJson, forKey: .dataJson)
    }
}

/// Module execution status and metadata
public struct ModuleExecutionStatus: Codable, Sendable {
    public let moduleId: String
    public let startTime: Date
    public let endTime: Date?
    public let duration: TimeInterval
    public let success: Bool
    public let errorMessage: String?
    public let dataCollectionMethod: DataCollectionMethod
    public let recordCount: Int
    
    public init(
        moduleId: String,
        startTime: Date,
        endTime: Date? = nil,
        success: Bool,
        errorMessage: String? = nil,
        dataCollectionMethod: DataCollectionMethod,
        recordCount: Int = 0
    ) {
        self.moduleId = moduleId
        self.startTime = startTime
        self.endTime = endTime
        self.duration = endTime?.timeIntervalSince(startTime) ?? 0
        self.success = success
        self.errorMessage = errorMessage
        self.dataCollectionMethod = dataCollectionMethod
        self.recordCount = recordCount
    }
}

/// Enumeration of data collection methods
public enum DataCollectionMethod: String, Codable, Sendable {
    case osquery = "osquery"
    case bash = "bash"
    case native = "native"
    case systemProfiler = "system_profiler"
    case iokit = "iokit"
    case configuration = "configuration"
    
    public var displayName: String {
        switch self {
        case .osquery: return "OSQuery"
        case .bash: return "Bash Scripts"
        case .native: return "Native macOS APIs"
        case .systemProfiler: return "System Profiler"
        case .iokit: return "IOKit Framework"
        case .configuration: return "Configuration Profiles"
        }
    }
}

/// Collection summary for all modules
public struct ModuleCollectionSummary: Codable, Sendable {
    public let totalModules: Int
    public let successfulModules: Int
    public let failedModules: Int
    public let totalRecords: Int
    public let collectionStartTime: Date
    public let collectionEndTime: Date
    public let totalDuration: TimeInterval
    public let moduleStatuses: [ModuleExecutionStatus]
    
    public init(moduleStatuses: [ModuleExecutionStatus]) {
        self.moduleStatuses = moduleStatuses
        self.totalModules = moduleStatuses.count
        self.successfulModules = moduleStatuses.filter { $0.success }.count
        self.failedModules = moduleStatuses.filter { !$0.success }.count
        self.totalRecords = moduleStatuses.reduce(0) { $0 + $1.recordCount }
        
        let startTimes = moduleStatuses.map { $0.startTime }
        let endTimes = moduleStatuses.compactMap { $0.endTime }
        
        self.collectionStartTime = startTimes.min() ?? Date()
        self.collectionEndTime = endTimes.max() ?? Date()
        self.totalDuration = collectionEndTime.timeIntervalSince(collectionStartTime)
    }
    
    public var successRate: Double {
        guard totalModules > 0 else { return 0.0 }
        return Double(successfulModules) / Double(totalModules)
    }
}

/// Error types for module operations
public enum ModuleError: Error, Sendable {
    case moduleNotFound(String)
    case configurationError(String)
    case dataCollectionFailed(String)
    case processingError(String)
    case osqueryUnavailable
    case bashExecutionFailed(String)
    case pythonExecutionFailed(String)
    case nativeAPIError(String)
    
    public var localizedDescription: String {
        switch self {
        case .moduleNotFound(let moduleId):
            return "Module not found: \(moduleId)"
        case .configurationError(let message):
            return "Module configuration error: \(message)"
        case .dataCollectionFailed(let message):
            return "Data collection failed: \(message)"
        case .processingError(let message):
            return "Data processing error: \(message)"
        case .osqueryUnavailable:
            return "OSQuery is not available on this system"
        case .bashExecutionFailed(let message):
            return "Bash execution failed: \(message)"
        case .pythonExecutionFailed(let message):
            return "Python execution failed: \(message)"
        case .nativeAPIError(let message):
            return "Native API error: \(message)"
        }
    }
}

/// Module configuration settings
public struct ModuleConfiguration: Codable, Sendable {
    public let moduleId: String
    public let enabled: Bool
    public let priority: ModulePriority
    public let timeout: TimeInterval
    public let retryCount: Int
    public let fallbackMethods: [DataCollectionMethod]
    public let customParameters: [String: String]
    
    public init(
        moduleId: String,
        enabled: Bool = true,
        priority: ModulePriority = .normal,
        timeout: TimeInterval = 30,
        retryCount: Int = 2,
        fallbackMethods: [DataCollectionMethod] = [.osquery, .bash, .native],
        customParameters: [String: String] = [:]
    ) {
        self.moduleId = moduleId
        self.enabled = enabled
        self.priority = priority
        self.timeout = timeout
        self.retryCount = retryCount
        self.fallbackMethods = fallbackMethods
        self.customParameters = customParameters
    }
}

/// Module execution priority
public enum ModulePriority: String, Codable, Sendable, CaseIterable {
    case low = "low"
    case normal = "normal"
    case high = "high"
    case critical = "critical"
    
    public var sortOrder: Int {
        switch self {
        case .critical: return 0
        case .high: return 1
        case .normal: return 2
        case .low: return 3
        }
    }
}