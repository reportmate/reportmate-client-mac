import Foundation

/// The module names the API serves per device.
public enum ModuleName: String, Sendable, CaseIterable, Codable, Identifiable {
    case inventory, system, hardware, network, security, management, applications, installs, peripherals, identity, profiles, displays, printers

    public var id: String { rawValue }

    /// Modules the device endpoints can serve on demand.
    public static let fetchable: [ModuleName] = [.applications, .hardware, .identity, .installs, .inventory, .management, .network, .peripherals, .security, .system]

    public var displayName: String {
        rawValue.prefix(1).uppercased() + rawValue.dropFirst()
    }
}

/// A device with its module payloads, from `/api/v1/device/{serial}` or the
/// fast `/info` endpoint plus progressively loaded `/modules/{name}` calls.
public struct DeviceDetail: Sendable, Hashable {
    public var serialNumber: String
    public var deviceId: String
    public var name: String
    public var platform: Platform
    public var rawPlatform: String?
    public var clientVersion: String?
    public var lastSeen: Date?
    public var createdAt: Date?
    public var archived: Bool
    public var archivedAt: Date?
    public var status: DeviceStatus
    public var modules: [String: JSONValue]
    /// Which modules have been fetched (a module can be present but empty).
    public var loadedModules: Set<String>

    public init(json deviceJSON: JSONValue, now: Date = Date()) {
        // Accept either the `{ success, device: {...} }` envelope or the bare device.
        let device = deviceJSON["device"].isNull ? deviceJSON : deviceJSON["device"]
        serialNumber = device["serialNumber"].nonEmptyString ?? device["deviceId"].nonEmptyString ?? ""
        deviceId = device["deviceId"].nonEmptyString ?? serialNumber
        var mods: [String: JSONValue] = [:]
        if let obj = device["modules"].object {
            for (k, v) in obj { mods[k] = v.unwrappingSingleton() }
        }
        modules = mods
        loadedModules = Set(mods.keys)
        lastSeen = FlexibleDate.parse(device["lastSeen"])
        createdAt = FlexibleDate.parse(device.first("createdAt", "registrationDate"))
        archived = device["archived"].boolish
        archivedAt = FlexibleDate.parse(device["archivedAt"])
        clientVersion = device["clientVersion"].nonEmptyString
        rawPlatform = device["platform"].nonEmptyString
        platform = Platform.detect(device: device)
        name = DeviceDetail.resolveName(device: device, modules: mods)
        status = DeviceStatus.calculate(lastSeen: lastSeen, archived: archived, now: now)
    }

    /// Display name fallback chain: inventory.deviceName, API name, hardware
    /// computer name or hostname, network hostname, serial.
    static func resolveName(device: JSONValue, modules: [String: JSONValue]) -> String {
        let inv = (modules["inventory"] ?? .null).normalizedKeys()
        let hwSystem = (modules["hardware"] ?? .null)["system"]
        let candidates: [String?] = [
            inv.firstString("deviceName", "computerName"),
            device["name"].nonEmptyString,
            hwSystem.firstString("computer_name", "computerName", "hostname"),
            (modules["network"] ?? .null)["hostname"].nonEmptyString,
            device["serialNumber"].nonEmptyString,
        ]
        for c in candidates {
            if let c, c.lowercased() != "unknown" { return c }
        }
        return "Unknown Device"
    }

    public subscript(module: ModuleName) -> JSONValue {
        modules[module.rawValue] ?? .null
    }

    public func module(_ name: String) -> JSONValue {
        modules[name] ?? .null
    }

    public func hasModule(_ name: ModuleName) -> Bool {
        loadedModules.contains(name.rawValue) && !(modules[name.rawValue]?.isEmptyContainer ?? true)
    }

    /// Merge a module fetched on demand.
    public mutating func setModule(_ module: ModuleName, _ value: JSONValue) {
        modules[module.rawValue] = value.unwrappingSingleton()
        loadedModules.insert(module.rawValue)
        if module == .inventory || module == .network || module == .hardware {
            self.name = DeviceDetail.resolveName(device: .object(["serialNumber": .string(serialNumber)]), modules: modules)
        }
        if module == .system || module == .inventory || module == .hardware {
            let synthetic: JSONValue = .object([
                "platform": rawPlatform.map(JSONValue.string) ?? .null,
                "modules": .object(modules),
            ])
            platform = Platform.detect(device: synthetic)
        }
    }

    /// The device as a raw record, for code that reads `device.modules.x.y`.
    public var asJSON: JSONValue {
        .object([
            "serialNumber": .string(serialNumber),
            "deviceId": .string(deviceId),
            "name": .string(name),
            "platform": rawPlatform.map(JSONValue.string) ?? .string(platform.rawValue),
            "archived": .bool(archived),
            "modules": .object(modules),
        ])
    }

    public var inventory: InventorySummary {
        InventorySummary(json: self[.inventory])
    }

    /// Identifier for the header: `ASSET · SERIAL` style pieces.
    public var assetTag: String? { inventory.assetTag }
}
