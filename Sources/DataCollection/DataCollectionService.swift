import Foundation

/// Main data collection service that coordinates module processors
public class DataCollectionService {
    private let configuration: ReportMateConfiguration
    private let osqueryService: OSQueryService
    private let moduleProcessors: [String: ModuleProcessor]
    
    public init(configuration: ReportMateConfiguration) {
        self.configuration = configuration
        self.osqueryService = OSQueryService(configuration: configuration)
        
        // Initialize module processors
        self.moduleProcessors = [
            "hardware": HardwareModuleProcessor(configuration: configuration),
            "system": SystemModuleProcessor(configuration: configuration),
            "network": NetworkModuleProcessor(configuration: configuration),
            "security": SecurityModuleProcessor(configuration: configuration),
            "applications": ApplicationsModuleProcessor(configuration: configuration),
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
        
        return [
            "deviceInfo": deviceInfo,
            "modules": moduleResults,
            "collectionTimestamp": Date(),
            "reportMateVersion": AppVersion.current
        ]
    }
    
    /// Collect data from specific modules
    public func collectSpecificModules(_ moduleIds: [String]) async throws -> [String: Any] {
        var moduleResults: [String: Any] = [:]
        
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
        
        return [
            "deviceInfo": deviceInfo,
            "modules": moduleResults,
            "collectionTimestamp": Date(),
            "reportMateVersion": AppVersion.current
        ]
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