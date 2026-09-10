import Foundation

/// Hardware facts as the Info widget and the Hardware tab show them.
/// Port of the web app's `Hardware.tsx` widget and `HardwareTab.tsx` extraction.
public struct HardwareInfo: Sendable, Hashable {
    public var manufacturer: String?
    public var model: String?
    public var modelIdentifier: String?
    public var formFactor: String?
    public var chipName: String?
    public var processorName: String?
    public var processorSpeed: String?
    public var processorMaxSpeed: Double?
    public var cpuCores: Int
    public var performanceCores: Int
    public var efficiencyCores: Int
    public var logicalProcessors: Int?
    public var graphicsName: String?
    public var graphicsManufacturer: String?
    public var graphicsMemoryGB: Double
    public var graphicsDriverVersion: String?
    public var graphicsMetalSupport: String?
    public var gpuCores: Int
    public var vram: String?
    public var npuName: String?
    public var npuManufacturer: String?
    public var npuCores: Int
    public var npuComputeUnits: Int
    public var npuTops: String?
    public var npuAvailable: Bool
    public var totalMemoryBytes: Double
    public var availableMemoryBytes: Double?
    public var memoryType: String?
    public var memoryManufacturer: String?
    public var memoryModules: [MemoryModule]
    public var unifiedMemoryFlag: Bool
    public var storageDevices: [StorageDevice]
    public var displays: [Display]
    public var battery: Battery?
    public var wireless: Radio?
    public var bluetooth: Radio?
    public var architecture: String?
    public var bootTime: String?
    public var isMac: Bool
    public var raw: JSONValue

    public struct MemoryModule: Sendable, Hashable, Identifiable {
        public var id: String { location + type + manufacturer }
        public var location: String
        public var type: String
        public var capacityMB: Double
        public var speed: String?
        public var manufacturer: String
    }

    public struct StorageDevice: Sendable, Hashable, Identifiable {
        public var id: String { name + (mountPoint ?? "") + (serialNumber ?? "") }
        public var name: String
        public var model: String?
        public var serialNumber: String?
        public var type: String?
        public var interface: String?
        public var capacityBytes: Double
        public var freeBytes: Double
        public var isInternal: Bool
        public var mountPoint: String?
        public var fileSystem: String?
        public var health: String?
        public var isEncrypted: Bool?
        public var rootDirectories: [StorageDirectory]

        public var usedPercent: Int {
            guard capacityBytes > 0 else { return 0 }
            return min(100, max(0, Int(((capacityBytes - freeBytes) / capacityBytes * 100).rounded())))
        }
    }

    public struct StorageDirectory: Sendable, Hashable, Identifiable {
        public var id: String { path }
        public var name: String
        public var path: String
        public var size: Double
        public var category: String
        public var fileCount: Int
        public var percentageOfDrive: Double
        public var subdirectories: [StorageDirectory]
    }

    public struct Display: Sendable, Hashable, Identifiable {
        public var id: String { name + (serialNumber ?? "") }
        public var name: String
        public var serialNumber: String?
        public var resolution: String?
        public var scaledResolution: String?
        public var displayType: String?
        public var isInternal: Bool
        public var firmwareVersion: String?
        public var isMainDisplay: Bool
        public var online: Bool
        public var diagonalInches: Double?
        public var ppi: Int?
        public var colorGamut: String?
        public var brightnessNits: Int?
        public var trueTone: Bool
        public var refreshRate: String?
        public var connectionType: String?
    }

    public struct Battery: Sendable, Hashable {
        public var cycleCount: Int
        public var chargePercent: Double
        public var health: String?
        public var condition: String?
        public var isCharging: Bool
        public var estimatedRuntime: String?
        public var designCapacity: Double?
        public var currentCapacity: Double?
        public var maxCapacity: Double?
    }

    public struct Radio: Sendable, Hashable {
        public var name: String?
        public var generation: String?
        public var version: String?
        public var status: String?
        public var protocolName: String?
        public var supportedBands: String?
        public var isAvailable: Bool
    }

    public var hasData: Bool { !raw.isNull && !raw.isEmptyContainer && (model != nil || processorName != nil || chipName != nil || totalMemoryBytes > 0) }

    /// Apple Silicon: both performance and efficiency cores reported.
    public var hasAppleSilicon: Bool { performanceCores > 0 && efficiencyCores > 0 }

    /// Unified memory: client flag, Apple Silicon, or CPU and GPU share a name.
    public var isUnifiedMemory: Bool {
        unifiedMemoryFlag || hasAppleSilicon || (processorName != nil && processorName == graphicsName)
    }

    /// Drives that count toward the totals: capacity and free space known, internal.
    public var internalDrives: [StorageDevice] {
        storageDevices.filter { $0.capacityBytes > 0 && $0.freeBytes > 0 && $0.isInternal }
    }
    public var totalStorageBytes: Double { internalDrives.reduce(0) { $0 + $1.capacityBytes } }
    public var freeStorageBytes: Double { internalDrives.reduce(0) { $0 + $1.freeBytes } }

    public var memoryFormatted: String { totalMemoryBytes > 0 ? ByteFormatting.bytes(totalMemoryBytes) : "Unknown" }
    public var storageFormatted: String {
        guard totalStorageBytes > 0 else { return "Unknown" }
        return "\(ByteFormatting.bytes(totalStorageBytes)) • \(ByteFormatting.bytes(freeStorageBytes)) free"
    }

    public var hasBattery: Bool {
        guard formFactor != "desktop", let b = battery else { return false }
        return b.cycleCount > 0 || b.chargePercent > 0
    }

    public var hasNpu: Bool {
        npuAvailable && (npuName ?? "").isEmpty == false && (npuComputeUnits > 0 || npuCores > 0)
    }

    /// GPU name without the vendor prefix.
    public var cleanGraphicsName: String {
        guard var name = graphicsName else { return "Unknown" }
        if let mfg = graphicsManufacturer?.uppercased(), !mfg.isEmpty, name.uppercased().hasPrefix(mfg) {
            name = String(name.dropFirst(mfg.count)).trimmingCharacters(in: .whitespaces)
        }
        for prefix in ["NVIDIA ", "AMD ", "INTEL "] where name.uppercased().hasPrefix(prefix) {
            name = String(name.dropFirst(prefix.count)).trimmingCharacters(in: .whitespaces)
        }
        return name.isEmpty ? (graphicsName ?? "Unknown") : name
    }

    /// GPU name with the processor prefix stripped on unified-memory machines.
    public var displayGraphicsName: String {
        let clean = cleanGraphicsName
        if isUnifiedMemory, let p = processorName, clean.hasPrefix(p) {
            let rest = String(clean.dropFirst(p.count)).trimmingCharacters(in: .whitespaces)
            return rest.isEmpty ? "Integrated Graphics" : rest
        }
        return clean
    }

    public init(modules: JSONValue, platform: Platform) {
        let rawHW = modules["hardware"].unwrappingSingleton()
        raw = rawHW
        let hw = rawHW.normalizedKeys()
        let system = modules["system"].normalizedKeys()
        let os = system["operatingSystem"]

        manufacturer = hw["manufacturer"].nonEmptyString ?? hw["system"]["hardwareVendor"].nonEmptyString
        model = hw["model"].nonEmptyString ?? hw["system"]["modelName"].nonEmptyString
        modelIdentifier = hw["modelIdentifier"].nonEmptyString ?? hw["system"]["hardwareModel"].nonEmptyString
        formFactor = hw["formFactor"].nonEmptyString

        let processor = hw["processor"]
        if let s = processor.string, processor.object == nil {
            processorName = s
            chipName = s
        } else {
            processorName = processor.firstString("name", "value", "brand")
            chipName = processor.firstString("chip", "name")
        }
        processorSpeed = processor.firstString("speed", "baseSpeed")
        processorMaxSpeed = processor["maxSpeed"].double
        cpuCores = [processor["cores"].int, processor["cpuCores"].int, processor["logicalCores"].int, processor["logicalProcessors"].int].compactMap { $0 }.first { $0 > 0 } ?? 0
        performanceCores = processor["performanceCores"].int ?? 0
        efficiencyCores = processor["efficiencyCores"].int ?? 0
        logicalProcessors = processor["logicalProcessors"].int ?? processor["logicalCores"].int

        let graphics = hw["graphics"].unwrappingSingleton()
        graphicsName = graphics["name"].nonEmptyString
        graphicsManufacturer = graphics["manufacturer"].nonEmptyString
        graphicsMemoryGB = graphics["memorySize"].double ?? 0
        graphicsDriverVersion = graphics["driverVersion"].nonEmptyString
        graphicsMetalSupport = graphics["metalSupport"].nonEmptyString
        gpuCores = graphics["cores"].int ?? graphics["gpuCores"].int ?? 0
        vram = graphics["vram"].nonEmptyString ?? graphics["memory"].nonEmptyString

        let npu = hw["npu"]
        npuName = npu["name"].nonEmptyString
        npuManufacturer = npu["manufacturer"].nonEmptyString
        npuCores = processor["npuCores"].int ?? npu["cores"].int ?? 0
        npuComputeUnits = npu["computeUnits"].int ?? 0
        npuTops = npu.firstString("performanceTops", "tops")
        npuAvailable = npu["isAvailable"].boolish || npu["hasNpu"].boolish

        let memory = hw["memory"]
        totalMemoryBytes = memory.firstDouble("physicalMemory", "totalPhysical", "total", "totalBytes") ?? 0
        availableMemoryBytes = memory.firstDouble("availablePhysical", "available")
        unifiedMemoryFlag = memory["unifiedMemory"].boolish
        let modules = memory["modules"].elements.enumerated().map { i, m in
            MemoryModule(location: m["location"].nonEmptyString ?? "Slot \(i + 1)", type: m["type"].nonEmptyString ?? "",
                         capacityMB: m["capacity"].double ?? 0, speed: m["speed"].nonEmptyString, manufacturer: m["manufacturer"].nonEmptyString ?? "")
        }
        memoryModules = modules
        memoryType = memory["type"].nonEmptyString ?? modules.first?.type
        memoryManufacturer = memory["manufacturer"].nonEmptyString ?? modules.first?.manufacturer

        func directory(_ d: JSONValue) -> StorageDirectory {
            StorageDirectory(name: d["name"].string ?? "", path: d["path"].string ?? d["name"].string ?? "", size: d["size"].double ?? 0,
                             category: d["category"].string ?? "Other", fileCount: d["fileCount"].int ?? 0,
                             percentageOfDrive: d["percentageOfDrive"].double ?? 0, subdirectories: d["subdirectories"].elements.map(directory))
        }
        storageDevices = hw["storage"].elements.map { drive in
            let capacity = drive.firstDouble("size", "capacity", "totalSize") ?? 0
            let free = drive.firstDouble("freeSpace", "free", "availableSpace") ?? 0
            let removable = (drive["type"].string ?? "").lowercased().contains("removable") || (drive["interface"].string ?? "").lowercased().contains("usb")
            let isInternal = drive["isInternal"].isNull ? !removable : drive["isInternal"].boolish
            return StorageDevice(name: drive.firstString("name", "volumeName", "mountPoint") ?? "Drive",
                                 model: drive.firstString("model", "deviceName"), serialNumber: drive["serialNumber"].nonEmptyString,
                                 type: drive.firstString("type", "mediaType", "driveType"), interface: drive["interface"].nonEmptyString,
                                 capacityBytes: capacity, freeBytes: free, isInternal: isInternal,
                                 mountPoint: drive.firstString("mountPoint", "mount"), fileSystem: drive.firstString("fileSystem", "filesystem", "format"),
                                 health: drive.firstString("health", "smartStatus"),
                                 isEncrypted: drive["encrypted"].boolishIfPresent ?? drive["isEncrypted"].boolishIfPresent,
                                 rootDirectories: drive["rootDirectories"].elements.map(directory))
        }

        displays = hw["displays"].elements.map { d in
            Display(name: d["name"].nonEmptyString ?? "Unknown Display", serialNumber: d["serialNumber"].nonEmptyString,
                    resolution: d["resolution"].nonEmptyString, scaledResolution: d["scaledResolution"].nonEmptyString,
                    displayType: d["displayType"].nonEmptyString, isInternal: d["type"].string == "internal",
                    firmwareVersion: d["firmwareVersion"].nonEmptyString, isMainDisplay: d["isMainDisplay"].boolish, online: d["online"].boolish,
                    diagonalInches: d["diagonalInches"].double, ppi: d["ppi"].int, colorGamut: d["colorGamut"].nonEmptyString,
                    brightnessNits: d["brightnessNits"].int, trueTone: d["trueTone"].boolish, refreshRate: d["refreshRate"].nonEmptyString,
                    connectionType: d["connectionType"].nonEmptyString)
        }

        let bat = hw["battery"]
        if !bat.isNull, bat.object != nil {
            let minutes = bat["minutesUntilEmpty"].double ?? 0
            battery = Battery(cycleCount: bat["cycleCount"].int ?? 0,
                              chargePercent: bat.firstDouble("percentRemaining", "chargePercent", "percent") ?? 0,
                              health: bat["health"].nonEmptyString, condition: bat.firstString("condition", "state"),
                              isCharging: bat["charging"].boolish || bat["isCharging"].boolish,
                              estimatedRuntime: minutes > 0 ? "\(Int(minutes)) min" : bat["estimatedRuntime"].nonEmptyString,
                              designCapacity: bat.firstDouble("designedCapacity", "designCapacity"), currentCapacity: bat["currentCapacity"].double,
                              maxCapacity: bat["maxCapacity"].double)
        } else {
            battery = nil
        }

        func radio(_ r: JSONValue) -> Radio? {
            guard !r.isNull, r.object != nil else { return nil }
            return Radio(name: r["name"].nonEmptyString, generation: r["wifiGeneration"].nonEmptyString, version: r.firstString("wifiVersion", "bluetoothVersion"),
                         status: r["status"].nonEmptyString, protocolName: r["protocol"].nonEmptyString, supportedBands: r["supportedBands"].nonEmptyString,
                         isAvailable: r["isAvailable"].boolish)
        }
        wireless = radio(hw["wireless"])
        bluetooth = radio(hw["bluetooth"])

        architecture = processor["architecture"].nonEmptyString ?? os["architecture"].nonEmptyString
        bootTime = os["bootTime"].nonEmptyString ?? system["bootTime"].nonEmptyString

        let modelLower = (model ?? "").lowercased()
        let vendorLower = (manufacturer ?? "").lowercased()
        isMac = platform == .macOS || modelLower.contains("mac") || vendorLower.contains("apple")
    }
}
