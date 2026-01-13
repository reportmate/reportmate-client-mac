import Foundation

/// Main data collection service that coordinates module processors
public class DataCollectionService {
    private let configuration: ReportMateConfiguration
    private let osqueryService: OSQueryService
    private let moduleProcessors: [String: ModuleProcessor]
    private let applicationUsageService: ApplicationUsageService
    
    public init(configuration: ReportMateConfiguration) {
        self.configuration = configuration
        self.osqueryService = OSQueryService(configuration: configuration)
        self.applicationUsageService = ApplicationUsageService()
        
        // Initialize module processors
        self.moduleProcessors = [
            "hardware": HardwareModuleProcessor(configuration: configuration),
            "system": SystemModuleProcessor(configuration: configuration),
            "network": NetworkModuleProcessor(configuration: configuration),
            "security": SecurityModuleProcessor(configuration: configuration),
            "applications": ApplicationsModuleProcessor(configuration: configuration, applicationUsageService: applicationUsageService),
            "management": ManagementModuleProcessor(configuration: configuration),
            "inventory": InventoryModuleProcessor(configuration: configuration),
            "profiles": ProfilesModuleProcessor(configuration: configuration)
        ]
    }
    
    /// Collect data from all enabled modules
    public func collectAllModules() async throws -> [String: Any] {
        var moduleResults: [String: ModuleData] = [:]
        
        // Execute data collection concurrently across all enabled modules
        await withTaskGroup(of: (String, ModuleData?).self) { group in
            for moduleId in configuration.enabledModules {
                guard let processor = moduleProcessors[moduleId] else {
                    print("Warning: No processor found for module '\(moduleId)'")
                    continue
                }
                
                group.addTask { @Sendable [processor] in
                    do {
                        let data = try await processor.collectData()
                        return (moduleId, data)
                    } catch {
                        print("Error collecting data from module '\(moduleId)': \(error)")
                        return (moduleId, nil)
                    }
                }
            }
            
            for await (moduleId, moduleData) in group {
                if let moduleData = moduleData {
                    moduleResults[moduleId] = moduleData
                }
            }
        }
        
        // Create device identification
        let deviceInfo = try await collectDeviceInfo()
        
        // Build unified payload structure matching Windows client format
        return buildUnifiedPayload(deviceInfo: deviceInfo, moduleResults: moduleResults)
    }
    
    /// Collect data from specific modules
    public func collectSpecificModules(_ moduleIds: [String]) async throws -> [String: Any] {
        var moduleResults: [String: ModuleData] = [:]
        
        for moduleId in moduleIds {
            guard let processor = moduleProcessors[moduleId] else {
                print("Warning: Module '\(moduleId)' not found, skipping...")
                continue
            }
            
            do {
                let moduleData = try await processor.collectData()
                moduleResults[moduleId] = moduleData
            } catch {
                print("Warning: Failed to collect data from module '\(moduleId)': \(error.localizedDescription)")
                // Continue with other modules instead of failing completely
            }
        }
        
        // Create device identification
        let deviceInfo = try await collectDeviceInfo()
        
        // Build unified payload structure matching Windows client format
        return buildUnifiedPayload(deviceInfo: deviceInfo, moduleResults: moduleResults)
    }

    /// Collect data from a specific module
    public func collectModule(_ moduleId: String) async throws -> ModuleData? {
        guard let processor = moduleProcessors[moduleId] else {
            throw DataCollectionError.moduleNotFound(moduleId)
        }
        
        return try await processor.collectData()
    }
    
    // MARK: - Private Methods
    
    private func collectDeviceInfo() async throws -> DeviceInfo {
        // Use system_profiler to get basic device information
        let hardwareInfo = try await BashService.executeSystemProfiler("SPHardwareDataType")
        
        // Extract device information from system_profiler output
        let deviceName = ProcessInfo.processInfo.hostName
        let osVersion = ProcessInfo.processInfo.operatingSystemVersionString
        
        // Get serial number and model
        var serialNumber = "Unknown"
        var modelIdentifier = "Unknown"
        
        if let hardwareArray = hardwareInfo["SPHardwareDataType"] as? [[String: Any]],
           let hardware = hardwareArray.first {
            serialNumber = hardware["serial_number"] as? String ?? "Unknown"
            modelIdentifier = hardware["machine_model"] as? String ?? "Unknown"
        }
        
        return DeviceInfo(
            deviceId: configuration.deviceId ?? generateDeviceId(),
            deviceName: deviceName,
            serialNumber: serialNumber,
            manufacturer: "Apple",
            model: modelIdentifier,
            osName: "macOS",
            osVersion: osVersion,
            architecture: ProcessInfo.processInfo.machineArchitecture,
            lastSeen: Date(),
            reportMateVersion: AppVersion.current
        )
    }
    
    private func generateDeviceId() -> String {
        // Generate a unique device ID based on hardware characteristics
        let hostname = ProcessInfo.processInfo.hostName
        let timestamp = Date().timeIntervalSince1970
        return "mac-\(hostname)-\(Int(timestamp))"
    }
    
    /// Build unified payload structure matching Windows client format
    /// This ensures the Mac API output structure matches what the dashboard expects
    private func buildUnifiedPayload(deviceInfo: DeviceInfo, moduleResults: [String: ModuleData]) -> [String: Any] {
        // Create ISO8601 date formatter for consistent timestamp formatting
        let isoFormatter = ISO8601DateFormatter()
        isoFormatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        
        // Build metadata section (matches Windows EventMetadata)
        let metadata: [String: Any] = [
            "deviceId": deviceInfo.deviceId,
            "serialNumber": deviceInfo.serialNumber,
            "collectedAt": isoFormatter.string(from: Date()),
            "clientVersion": AppVersion.current,
            "platform": "macOS",
            "collectionType": "Full",
            "enabledModules": configuration.enabledModules,
            "additional": [
                "deviceName": deviceInfo.deviceName,
                "manufacturer": deviceInfo.manufacturer,
                "model": deviceInfo.model,
                "osName": deviceInfo.osName,
                "osVersion": deviceInfo.osVersion,
                "architecture": deviceInfo.architecture
            ]
        ]
        
        // Start building the unified payload with metadata and empty events
        var payload: [String: Any] = [
            "metadata": metadata,
            "events": [] as [[String: Any]],
            // Also include modules dict for backwards compatibility
            "modules": moduleResults.mapValues { convertModuleDataToDict($0) }
        ]
        
        // Assign module data to top-level fields (mirrors Windows AssignModuleDataToPayload)
        for (moduleId, moduleData) in moduleResults {
            let moduleDict = convertModuleDataToDict(moduleData)
            
            // Map module IDs to top-level payload keys (matching Windows structure)
            switch moduleId.lowercased() {
            case "system":
                payload["system"] = moduleDict
            case "hardware":
                payload["hardware"] = moduleDict
            case "security":
                payload["security"] = moduleDict
            case "network":
                payload["network"] = moduleDict
            case "applications":
                payload["applications"] = moduleDict
            case "management":
                payload["management"] = moduleDict
            case "inventory":
                payload["inventory"] = moduleDict
            case "profiles":
                payload["profiles"] = moduleDict
            case "installs":
                payload["installs"] = moduleDict
            case "displays":
                payload["displays"] = moduleDict
            case "printers":
                payload["printers"] = moduleDict
            default:
                // For any unknown modules, add them under their original key
                payload[moduleId] = moduleDict
            }
        }
        
        return payload
    }
    
    /// Convert ModuleData to dictionary for JSON serialization
    /// Extracts the actual data from the module, not the wrapper
    private func convertModuleDataToDict(_ moduleData: ModuleData) -> [String: Any] {
        // If it's a BaseModuleData, extract the data property directly
        if let baseData = moduleData as? BaseModuleData {
            return baseData.data
        }
        
        // Fallback: Use JSONEncoder to convert the Codable ModuleData to Data, then to dictionary
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        
        do {
            let data = try encoder.encode(moduleData)
            if let dict = try JSONSerialization.jsonObject(with: data) as? [String: Any] {
                // If the result has a "dataJson" key, parse and return that instead
                if let dataJsonString = dict["dataJson"] as? String,
                   let jsonData = dataJsonString.data(using: .utf8),
                   let actualData = try? JSONSerialization.jsonObject(with: jsonData) as? [String: Any] {
                    return actualData
                }
                return dict
            }
        } catch {
            print("Warning: Failed to convert module data to dictionary: \(error)")
        }
        
        // Fallback: return empty dict
        return [:]
    }
}

// MARK: - Error Types

public enum DataCollectionError: Error, LocalizedError {
    case moduleNotFound(String)
    case collectionFailed(String, Error)
    case invalidData(String)
    
    public var errorDescription: String? {
        switch self {
        case .moduleNotFound(let moduleId):
            return "Module not found: \(moduleId)"
        case .collectionFailed(let moduleId, let error):
            return "Data collection failed for module \(moduleId): \(error.localizedDescription)"
        case .invalidData(let message):
            return "Invalid data: \(message)"
        }
    }
}

// MARK: - ProcessInfo Extension

private extension ProcessInfo {
    var machineArchitecture: String {
        var size = 0
        sysctlbyname("hw.machine", nil, &size, nil, 0)
        
        var machine = [CChar](repeating: 0, count: size)
        sysctlbyname("hw.machine", &machine, &size, nil, 0)
        
        let machineBytes: [UInt8] = machine.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        return String(decoding: machineBytes, as: UTF8.self)
    }
}