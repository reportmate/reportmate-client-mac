import Foundation
import CryptoKit

/// Core device models for ReportMate Mac client
/// These models represent the fundamental device information structure

/// Extension to generate a stable UUID from a string (like serial number)
extension String {
    /// Generate a deterministic UUID from a string using SHA256
    /// This ensures the same serial number always produces the same UUID
    func sha256UUID() -> String {
        let data = Data(self.utf8)
        let hash = SHA256.hash(data: data)
        let hashBytes = Array(hash)
        
        // Use first 16 bytes of SHA256 to create a UUID
        // Set version 4 (random) and variant bits
        var uuidBytes = Array(hashBytes.prefix(16))
        uuidBytes[6] = (uuidBytes[6] & 0x0F) | 0x40  // Version 4
        uuidBytes[8] = (uuidBytes[8] & 0x3F) | 0x80  // Variant
        
        // Format as UUID string
        let uuid = uuidBytes.enumerated().map { (index, byte) -> String in
            let hex = String(format: "%02x", byte)
            switch index {
            case 3, 5, 7, 9:
                return hex + "-"
            default:
                return hex
            }
        }.joined().uppercased()
        
        return uuid
    }
}

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
            self.jsonData = try JSONSerialization.data(withJSONObject: value, options: [.fragmentsAllowed])
        } catch {
            self.jsonData = Data()
        }
    }
    
    public var value: Any {
        do {
            return try JSONSerialization.jsonObject(with: jsonData, options: [.fragmentsAllowed])
        } catch {
            return NSNull()
        }
    }
    
    public func encode(to encoder: Encoder) throws {
        let object = self.value
        
        if let dict = object as? [String: Any] {
            var container = encoder.container(keyedBy: DynamicCodingKey.self)
            for (key, value) in dict {
                if let codingKey = DynamicCodingKey(stringValue: key) {
                    try container.encode(ModuleDataValue(value), forKey: codingKey)
                }
            }
        } else if let array = object as? [Any] {
            var container = encoder.unkeyedContainer()
            for value in array {
                try container.encode(ModuleDataValue(value))
            }
        } else {
            var container = encoder.singleValueContainer()
            if let v = object as? String { try container.encode(v) }
            else if let v = object as? Int { try container.encode(v) }
            else if let v = object as? Double { try container.encode(v) }
            else if let v = object as? Bool { try container.encode(v) }
            else if object is NSNull { try container.encodeNil() }
            else {
                let stringVal = String(describing: object)
                try container.encode(stringVal)
            }
        }
    }
    
    public init(from decoder: Decoder) throws {
        func decodeToAny(_ decoder: Decoder) throws -> Any {
            if let container = try? decoder.container(keyedBy: DynamicCodingKey.self) {
                var dict = [String: Any]()
                for key in container.allKeys {
                    let value = try container.decode(ModuleDataValue.self, forKey: key)
                    dict[key.stringValue] = value.value
                }
                return dict
            } else if var container = try? decoder.unkeyedContainer() {
                var array = [Any]()
                while !container.isAtEnd {
                    let value = try container.decode(ModuleDataValue.self)
                    array.append(value.value)
                }
                return array
            } else {
                let container = try decoder.singleValueContainer()
                if let v = try? container.decode(String.self) { return v }
                if let v = try? container.decode(Int.self) { return v }
                if let v = try? container.decode(Double.self) { return v }
                if let v = try? container.decode(Bool.self) { return v }
                if container.decodeNil() { return NSNull() }
                throw DecodingError.dataCorruptedError(in: container, debugDescription: "Cannot decode value")
            }
        }
        
        let anyValue = try decodeToAny(decoder)
        self.jsonData = try JSONSerialization.data(withJSONObject: anyValue, options: [.fragmentsAllowed])
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

// MARK: - Windows-Compatible Unified Payload Structure

/// Metadata structure matching Windows EventMetadata
/// This appears at the top of the payload and contains all device identification
public struct EventMetadata: Codable, Sendable {
    public let deviceId: String        // UUID format required by API
    public let serialNumber: String
    public let collectedAt: Date
    public let clientVersion: String
    public let platform: String
    public let collectionType: String
    public let enabledModules: [String]
    
    public init(
        deviceId: String,
        serialNumber: String,
        collectedAt: Date = Date(),
        clientVersion: String = AppVersion.current,
        platform: String = "macOS",
        collectionType: String = "Full",
        enabledModules: [String] = []
    ) {
        self.deviceId = deviceId
        self.serialNumber = serialNumber
        self.collectedAt = collectedAt
        self.clientVersion = clientVersion
        self.platform = platform
        self.collectionType = collectionType
        self.enabledModules = enabledModules
    }
}

/// Unified payload structure matching Windows UnifiedDevicePayload
/// This is the format expected by the /api/events endpoint
public struct UnifiedDevicePayload: Codable, Sendable {
    public let metadata: EventMetadata
    public let events: [ReportMateEvent]
    
    // Module data sections - these map to the collected data
    public let inventory: ModuleDataValue?
    public let system: ModuleDataValue?
    public let hardware: ModuleDataValue?
    public let management: ModuleDataValue?
    public let installs: ModuleDataValue?
    public let profiles: ModuleDataValue?
    public let security: ModuleDataValue?
    public let network: ModuleDataValue?
    public let displays: ModuleDataValue?
    public let printers: ModuleDataValue?
    public let applications: ModuleDataValue?
    public let peripherals: ModuleDataValue?
    
    public init(
        metadata: EventMetadata,
        events: [ReportMateEvent] = [],
        modules: [String: Any]
    ) {
        self.metadata = metadata
        self.events = events
        
        // Map module data to specific fields
        self.inventory = modules["inventory"].map { ModuleDataValue($0) }
        self.system = modules["system"].map { ModuleDataValue($0) }
        self.hardware = modules["hardware"].map { ModuleDataValue($0) }
        self.management = modules["management"].map { ModuleDataValue($0) }
        self.installs = modules["installs"].map { ModuleDataValue($0) }
        self.profiles = modules["profiles"].map { ModuleDataValue($0) }
        self.security = modules["security"].map { ModuleDataValue($0) }
        self.network = modules["network"].map { ModuleDataValue($0) }
        self.displays = modules["displays"].map { ModuleDataValue($0) }
        self.printers = modules["printers"].map { ModuleDataValue($0) }
        self.applications = modules["applications"].map { ModuleDataValue($0) }
        self.peripherals = modules["peripherals"].map { ModuleDataValue($0) }
    }
}

/// ReportMate event structure for the events array
public struct ReportMateEvent: Codable, Sendable {
    public let moduleId: String
    public let eventType: String
    public let message: String
    public let timestamp: Date
    public let details: [String: String]
    
    public init(
        moduleId: String,
        eventType: String,
        message: String,
        timestamp: Date = Date(),
        details: [String: String] = [:]
    ) {
        self.moduleId = moduleId
        self.eventType = eventType
        self.message = message
        self.timestamp = timestamp
        self.details = details
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