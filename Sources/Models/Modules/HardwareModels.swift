import Foundation

/// Hardware module data models for macOS ReportMate client
/// These models represent hardware information collected from the system

// MARK: - Hardware Models

/// Main hardware information structure
public struct HardwareInfo: Codable, Sendable {
    public let systemInfo: SystemHardwareInfo
    public let cpuInfo: CPUInfo
    public let memoryInfo: MemoryInfo
    public let storageInfo: [StorageDevice]
    public let batteryInfo: BatteryInfo?
    public let platformInfo: PlatformInfo
    public let thermalInfo: ThermalInfo?
    
    public init(
        systemInfo: SystemHardwareInfo,
        cpuInfo: CPUInfo,
        memoryInfo: MemoryInfo,
        storageInfo: [StorageDevice],
        batteryInfo: BatteryInfo? = nil,
        platformInfo: PlatformInfo,
        thermalInfo: ThermalInfo? = nil
    ) {
        self.systemInfo = systemInfo
        self.cpuInfo = cpuInfo
        self.memoryInfo = memoryInfo
        self.storageInfo = storageInfo
        self.batteryInfo = batteryInfo
        self.platformInfo = platformInfo
        self.thermalInfo = thermalInfo
    }
}

/// System hardware information
public struct SystemHardwareInfo: Codable, Sendable {
    public let modelName: String
    public let modelIdentifier: String
    public let serialNumber: String
    public let hardwareUUID: String
    public let bootROMVersion: String
    public let smc_version: String?
    public let activationLockStatus: String?
    
    public init(
        modelName: String,
        modelIdentifier: String,
        serialNumber: String,
        hardwareUUID: String,
        bootROMVersion: String,
        smc_version: String? = nil,
        activationLockStatus: String? = nil
    ) {
        self.modelName = modelName
        self.modelIdentifier = modelIdentifier
        self.serialNumber = serialNumber
        self.hardwareUUID = hardwareUUID
        self.bootROMVersion = bootROMVersion
        self.smc_version = smc_version
        self.activationLockStatus = activationLockStatus
    }
}

/// CPU information structure
public struct CPUInfo: Codable, Sendable {
    public let brand: String
    public let model: String
    public let family: String
    public let manufacturer: String
    public let architecture: String
    public let physicalCores: Int
    public let logicalCores: Int
    public let maxSpeed: Double // in GHz
    public let currentSpeed: Double? // in GHz
    public let cacheL1: Int? // in KB
    public let cacheL2: Int? // in KB
    public let cacheL3: Int? // in KB
    public let features: [String]
    
    public init(
        brand: String,
        model: String,
        family: String,
        manufacturer: String,
        architecture: String,
        physicalCores: Int,
        logicalCores: Int,
        maxSpeed: Double,
        currentSpeed: Double? = nil,
        cacheL1: Int? = nil,
        cacheL2: Int? = nil,
        cacheL3: Int? = nil,
        features: [String] = []
    ) {
        self.brand = brand
        self.model = model
        self.family = family
        self.manufacturer = manufacturer
        self.architecture = architecture
        self.physicalCores = physicalCores
        self.logicalCores = logicalCores
        self.maxSpeed = maxSpeed
        self.currentSpeed = currentSpeed
        self.cacheL1 = cacheL1
        self.cacheL2 = cacheL2
        self.cacheL3 = cacheL3
        self.features = features
    }
}

/// Memory information structure
public struct MemoryInfo: Codable, Sendable {
    public let totalPhysical: Int64 // in bytes
    public let totalUsable: Int64 // in bytes
    public let totalUsed: Int64 // in bytes
    public let totalFree: Int64 // in bytes
    public let memoryModules: [MemoryModule]
    public let swapTotal: Int64 // in bytes
    public let swapUsed: Int64 // in bytes
    public let swapFree: Int64 // in bytes
    
    public init(
        totalPhysical: Int64,
        totalUsable: Int64,
        totalUsed: Int64,
        totalFree: Int64,
        memoryModules: [MemoryModule] = [],
        swapTotal: Int64 = 0,
        swapUsed: Int64 = 0,
        swapFree: Int64 = 0
    ) {
        self.totalPhysical = totalPhysical
        self.totalUsable = totalUsable
        self.totalUsed = totalUsed
        self.totalFree = totalFree
        self.memoryModules = memoryModules
        self.swapTotal = swapTotal
        self.swapUsed = swapUsed
        self.swapFree = swapFree
    }
    
    public var utilizationPercentage: Double {
        guard totalUsable > 0 else { return 0.0 }
        return (Double(totalUsed) / Double(totalUsable)) * 100.0
    }
}

/// Individual memory module information
public struct MemoryModule: Codable, Sendable {
    public let slot: String
    public let size: Int64 // in bytes
    public let speed: Int? // in MHz
    public let type: String
    public let manufacturer: String?
    public let partNumber: String?
    public let serialNumber: String?
    
    public init(
        slot: String,
        size: Int64,
        speed: Int? = nil,
        type: String,
        manufacturer: String? = nil,
        partNumber: String? = nil,
        serialNumber: String? = nil
    ) {
        self.slot = slot
        self.size = size
        self.speed = speed
        self.type = type
        self.manufacturer = manufacturer
        self.partNumber = partNumber
        self.serialNumber = serialNumber
    }
}

/// Storage device information
public struct StorageDevice: Codable, Sendable {
    public let name: String
    public let deviceId: String
    public let size: Int64 // in bytes
    public let type: StorageType
    public let interface: String
    public let model: String?
    public let manufacturer: String?
    public let serialNumber: String?
    public let firmwareVersion: String?
    public let isEncrypted: Bool
    public let encryptionType: String?
    public let healthStatus: String?
    public let temperature: Double? // in Celsius
    public let partitions: [StoragePartition]
    
    public init(
        name: String,
        deviceId: String,
        size: Int64,
        type: StorageType,
        interface: String,
        model: String? = nil,
        manufacturer: String? = nil,
        serialNumber: String? = nil,
        firmwareVersion: String? = nil,
        isEncrypted: Bool = false,
        encryptionType: String? = nil,
        healthStatus: String? = nil,
        temperature: Double? = nil,
        partitions: [StoragePartition] = []
    ) {
        self.name = name
        self.deviceId = deviceId
        self.size = size
        self.type = type
        self.interface = interface
        self.model = model
        self.manufacturer = manufacturer
        self.serialNumber = serialNumber
        self.firmwareVersion = firmwareVersion
        self.isEncrypted = isEncrypted
        self.encryptionType = encryptionType
        self.healthStatus = healthStatus
        self.temperature = temperature
        self.partitions = partitions
    }
}

/// Storage device type enumeration
public enum StorageType: String, Codable, Sendable {
    case ssd = "SSD"
    case hdd = "HDD"
    case hybrid = "Hybrid"
    case nvme = "NVMe"
    case external = "External"
    case network = "Network"
    case optical = "Optical"
    case unknown = "Unknown"
}

/// Storage partition information
public struct StoragePartition: Codable, Sendable {
    public let name: String
    public let mountPoint: String?
    public let size: Int64 // in bytes
    public let used: Int64 // in bytes
    public let available: Int64 // in bytes
    public let filesystem: String
    public let label: String?
    public let uuid: String?
    
    public init(
        name: String,
        mountPoint: String? = nil,
        size: Int64,
        used: Int64,
        available: Int64,
        filesystem: String,
        label: String? = nil,
        uuid: String? = nil
    ) {
        self.name = name
        self.mountPoint = mountPoint
        self.size = size
        self.used = used
        self.available = available
        self.filesystem = filesystem
        self.label = label
        self.uuid = uuid
    }
    
    public var utilizationPercentage: Double {
        guard size > 0 else { return 0.0 }
        return (Double(used) / Double(size)) * 100.0
    }
}

/// Battery information (for laptops)
public struct BatteryInfo: Codable, Sendable {
    public let isPresent: Bool
    public let manufacturer: String?
    public let model: String?
    public let serialNumber: String?
    public let health: String
    public let condition: String
    public let state: BatteryState
    public let maxCapacity: Int // in mAh
    public let currentCapacity: Int // in mAh
    public let designCapacity: Int // in mAh
    public let cycleCount: Int
    public let percentRemaining: Double
    public let isCharging: Bool
    public let timeRemaining: Int? // in minutes
    public let temperature: Double? // in Celsius
    
    public init(
        isPresent: Bool = false,
        manufacturer: String? = nil,
        model: String? = nil,
        serialNumber: String? = nil,
        health: String,
        condition: String,
        state: BatteryState,
        maxCapacity: Int,
        currentCapacity: Int,
        designCapacity: Int,
        cycleCount: Int,
        percentRemaining: Double,
        isCharging: Bool,
        timeRemaining: Int? = nil,
        temperature: Double? = nil
    ) {
        self.isPresent = isPresent
        self.manufacturer = manufacturer
        self.model = model
        self.serialNumber = serialNumber
        self.health = health
        self.condition = condition
        self.state = state
        self.maxCapacity = maxCapacity
        self.currentCapacity = currentCapacity
        self.designCapacity = designCapacity
        self.cycleCount = cycleCount
        self.percentRemaining = percentRemaining
        self.isCharging = isCharging
        self.timeRemaining = timeRemaining
        self.temperature = temperature
    }
}

/// Battery state enumeration
public enum BatteryState: String, Codable, Sendable {
    case unknown = "Unknown"
    case charging = "Charging"
    case discharging = "Discharging"
    case notCharging = "Not Charging"
    case full = "Full"
}

/// Platform information
public struct PlatformInfo: Codable, Sendable {
    public let vendor: String
    public let version: String
    public let date: String
    public let revision: String?
    public let biosVersion: String?
    public let firmwareFeatures: [String]
    
    public init(
        vendor: String,
        version: String,
        date: String,
        revision: String? = nil,
        biosVersion: String? = nil,
        firmwareFeatures: [String] = []
    ) {
        self.vendor = vendor
        self.version = version
        self.date = date
        self.revision = revision
        self.biosVersion = biosVersion
        self.firmwareFeatures = firmwareFeatures
    }
}

/// Thermal information
public struct ThermalInfo: Codable, Sendable {
    public let cpuTemperature: Double? // in Celsius
    public let gpuTemperature: Double? // in Celsius
    public let systemTemperature: Double? // in Celsius
    public let fanSpeeds: [FanInfo] // RPM
    public let thermalState: ThermalState
    
    public init(
        cpuTemperature: Double? = nil,
        gpuTemperature: Double? = nil,
        systemTemperature: Double? = nil,
        fanSpeeds: [FanInfo] = [],
        thermalState: ThermalState = .normal
    ) {
        self.cpuTemperature = cpuTemperature
        self.gpuTemperature = gpuTemperature
        self.systemTemperature = systemTemperature
        self.fanSpeeds = fanSpeeds
        self.thermalState = thermalState
    }
}

/// Fan information
public struct FanInfo: Codable, Sendable {
    public let id: String
    public let name: String
    public let currentSpeed: Int // in RPM
    public let minSpeed: Int // in RPM
    public let maxSpeed: Int // in RPM
    
    public init(id: String, name: String, currentSpeed: Int, minSpeed: Int, maxSpeed: Int) {
        self.id = id
        self.name = name
        self.currentSpeed = currentSpeed
        self.minSpeed = minSpeed
        self.maxSpeed = maxSpeed
    }
}

/// Thermal state enumeration
public enum ThermalState: String, Codable, Sendable {
    case normal = "Normal"
    case fair = "Fair"
    case serious = "Serious"
    case critical = "Critical"
}