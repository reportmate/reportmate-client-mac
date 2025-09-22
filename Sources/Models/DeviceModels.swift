import Foundation

/// Core device models for ReportMate Mac client
/// These models represent the fundamental device information structure

/// Base device information structure
public struct DeviceInfo: Codable, Sendable {
    public let deviceId: String
    public let deviceName: String
    public let serialNumber: String
    public let manufacturer: String
    public let model: String
    public let osName: String
    public let osVersion: String
    public let architecture: String
    public let lastSeen: Date
    public let reportMateVersion: String
    
    public init(
        deviceId: String,
        deviceName: String,
        serialNumber: String,
        manufacturer: String,
        model: String,
        osName: String,
        osVersion: String,
        architecture: String,
        lastSeen: Date,
        reportMateVersion: String
    ) {
        self.deviceId = deviceId
        self.deviceName = deviceName
        self.serialNumber = serialNumber
        self.manufacturer = manufacturer
        self.model = model
        self.osName = osName
        self.osVersion = osVersion
        self.architecture = architecture
        self.lastSeen = lastSeen
        self.reportMateVersion = reportMateVersion
    }
}

/// Sendable wrapper for module data
public struct ModuleDataValue: Codable, Sendable {
    private let jsonData: Data
    
    public init(_ value: Any) {
        do {
            self.jsonData = try JSONSerialization.data(withJSONObject: value)
        } catch {
            self.jsonData = Data()
        }
    }
    
    public var value: Any {
        do {
            return try JSONSerialization.jsonObject(with: jsonData)
        } catch {
            return NSNull()
        }
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        let jsonString = String(data: jsonData, encoding: .utf8) ?? ""
        try container.encode(jsonString)
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let jsonString = try container.decode(String.self)
        
        if let data = jsonString.data(using: .utf8) {
            self.jsonData = data
        } else if let data = Data(base64Encoded: jsonString) {
            self.jsonData = data
        } else {
            self.jsonData = Data()
        }
    }
}

/// Complete data payload structure for API transmission
public struct DeviceDataPayload: Codable, Sendable {
    public let deviceInfo: DeviceInfo
    public let collectionTimestamp: Date
    public let modules: [String: ModuleDataValue]
    
    public init(deviceInfo: DeviceInfo, collectionTimestamp: Date, modules: [String: Any]) {
        self.deviceInfo = deviceInfo
        self.collectionTimestamp = collectionTimestamp
        self.modules = modules.mapValues { ModuleDataValue($0) }
    }
    
    public init(deviceInfo: DeviceInfo, collectionTimestamp: Date, moduleValues: [String: ModuleDataValue]) {
        self.deviceInfo = deviceInfo
        self.collectionTimestamp = collectionTimestamp
        self.modules = moduleValues
    }
    
    // Helper method to get raw module values
    public var rawModules: [String: Any] {
        modules.mapValues { $0.value }
    }
}

/// Dynamic coding key for flexible dictionary encoding/decoding
public struct DynamicCodingKey: CodingKey {
    public let stringValue: String
    public let intValue: Int?
    
    public init?(stringValue: String) {
        self.stringValue = stringValue
        self.intValue = nil
    }
    
    public init?(intValue: Int) {
        self.stringValue = String(intValue)
        self.intValue = intValue
    }
}

/// API response wrapper for device operations
public struct DeviceResponse: Codable, Sendable {
    public let success: Bool
    public let message: String?
    public let deviceId: String?
    public let timestamp: Date
    
    public init(success: Bool, message: String? = nil, deviceId: String? = nil, timestamp: Date = Date()) {
        self.success = success
        self.message = message
        self.deviceId = deviceId
        self.timestamp = timestamp
    }
}

/// Configuration model for device settings
public struct DeviceConfiguration: Codable, Sendable {
    public let deviceId: String
    public let collectionInterval: TimeInterval
    public let enabledModules: [String]
    public let apiEndpoint: String
    public let lastUpdated: Date
    
    public init(
        deviceId: String,
        collectionInterval: TimeInterval,
        enabledModules: [String],
        apiEndpoint: String,
        lastUpdated: Date = Date()
    ) {
        self.deviceId = deviceId
        self.collectionInterval = collectionInterval
        self.enabledModules = enabledModules
        self.apiEndpoint = apiEndpoint
        self.lastUpdated = lastUpdated
    }
}

/// Error types for device operations
public enum DeviceError: Error, Sendable {
    case invalidDeviceId(String)
    case serialNumberNotFound
    case configurationError(String)
    case apiCommunicationError(String)
    case dataCollectionError(String)
    
    public var localizedDescription: String {
        switch self {
        case .invalidDeviceId(let id):
            return "Invalid device ID: \(id)"
        case .serialNumberNotFound:
            return "Could not retrieve device serial number"
        case .configurationError(let message):
            return "Configuration error: \(message)"
        case .apiCommunicationError(let message):
            return "API communication error: \(message)"
        case .dataCollectionError(let message):
            return "Data collection error: \(message)"
        }
    }
}