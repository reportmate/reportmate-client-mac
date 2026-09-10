import Foundation

/// Inventory fields the list endpoints carry alongside each device.
public struct InventorySummary: Sendable, Hashable, Codable {
    public var deviceName: String?
    public var assetTag: String?
    public var serialNumber: String?
    public var location: String?
    public var department: String?
    public var area: String?
    public var usage: String?
    public var catalog: String?
    public var owner: String?
    public var fleet: String?

    public init() {}

    public init(json: JSONValue) {
        let inv = json.normalizedKeys()
        deviceName = inv.firstString("deviceName", "computerName")
        assetTag = inv["assetTag"].nonEmptyString
        serialNumber = inv["serialNumber"].nonEmptyString
        location = inv["location"].nonEmptyString
        department = inv["department"].nonEmptyString
        area = inv["area"].nonEmptyString
        usage = inv["usage"].nonEmptyString
        catalog = inv["catalog"].nonEmptyString
        owner = inv["owner"].nonEmptyString
        fleet = inv["fleet"].nonEmptyString
    }

    public var isEmpty: Bool {
        deviceName == nil && assetTag == nil && location == nil && department == nil && area == nil
            && usage == nil && catalog == nil && owner == nil && fleet == nil
    }
}

/// One row of `/api/v1/devices` or `/api/v1/dashboard`.
///
/// Both endpoints return the same lightweight shape: identity, timestamps,
/// archive state, an OS summary under `modules.system.operatingSystem` and an
/// inventory summary. The full module payloads come from `DeviceDetail`.
public struct DeviceSummary: Sendable, Hashable, Identifiable {
    public var id: String { serialNumber }

    public var serialNumber: String
    public var deviceId: String
    /// Resolved display name: inventory name, then hardware computer name, then serial.
    public var name: String
    public var hostname: String?
    public var lastSeen: Date?
    public var createdAt: Date?
    public var archived: Bool
    public var archivedAt: Date?
    public var platform: Platform
    public var rawPlatform: String?
    public var osName: String?
    public var osVersion: String?
    public var osDisplayVersion: String?
    public var osBuild: String?
    public var osFeatureUpdate: String?
    public var osArchitecture: String?
    public var inventory: InventorySummary
    public var status: DeviceStatus
    public var clientVersion: String?
    /// The raw record, kept for filters that read fields we did not model.
    public var raw: JSONValue

    public init(json: JSONValue, now: Date = Date()) {
        raw = json
        let modules = json["modules"]
        serialNumber = json["serialNumber"].nonEmptyString ?? json["deviceId"].nonEmptyString ?? json["id"].string ?? ""
        deviceId = json["deviceId"].nonEmptyString ?? serialNumber

        let invJSON: JSONValue = !json["inventory"].isNull ? json["inventory"] : modules["inventory"]
        var inv = InventorySummary(json: invJSON)
        // Top-level convenience fields win when the inventory block is missing them.
        inv.assetTag = inv.assetTag ?? json["assetTag"].nonEmptyString
        inv.location = inv.location ?? json["location"].nonEmptyString
        inv.department = inv.department ?? json["department"].nonEmptyString
        inv.usage = inv.usage ?? json["usage"].nonEmptyString
        inv.catalog = inv.catalog ?? json["catalog"].nonEmptyString
        inv.owner = inv.owner ?? json["owner"].nonEmptyString
        inventory = inv

        let hardwareSystem = modules["hardware"]["system"]
        let candidateName = inv.deviceName
            ?? json["name"].nonEmptyString
            ?? json["deviceName"].nonEmptyString
            ?? hardwareSystem.firstString("computer_name", "computerName", "hostname")
        if let candidateName, candidateName.lowercased() != "unknown" {
            name = candidateName
        } else {
            name = serialNumber
        }

        hostname = json["hostname"].nonEmptyString ?? modules["network"]["hostname"].nonEmptyString
        lastSeen = FlexibleDate.parse(json["lastSeen"])
        createdAt = FlexibleDate.parse(json.first("createdAt", "registrationDate"))
        archived = json["archived"].boolish
        archivedAt = FlexibleDate.parse(json["archivedAt"])
        rawPlatform = json["platform"].nonEmptyString
        platform = Platform.detect(device: json)

        let os = modules["system"].first("operatingSystem", "operating_system")
        osName = os["name"].nonEmptyString ?? json.firstString("osName", "os")
        osVersion = os["version"].nonEmptyString ?? json["osVersion"].nonEmptyString
        osDisplayVersion = os.firstString("displayVersion", "display_version")
        osBuild = os.firstString("build", "buildNumber", "build_number")
        osFeatureUpdate = os.firstString("featureUpdate", "feature_update")
        osArchitecture = os["architecture"].nonEmptyString
        clientVersion = json["clientVersion"].nonEmptyString

        status = DeviceStatus.calculate(lastSeen: lastSeen, archived: archived, now: now)
    }

    /// The OS version string the dashboard shows: display version, then version.
    public var osVersionLabel: String {
        osDisplayVersion ?? osVersion ?? "Unknown"
    }

    /// Identifier line used in lists: `ASSET | SERIAL`, avoiding duplication
    /// when the name is the serial.
    public var identifierLine: String {
        let isNameSerial = name == serialNumber
        if let tag = inventory.assetTag, !isNameSerial { return "\(tag) | \(serialNumber)" }
        if let tag = inventory.assetTag { return tag }
        if !isNameSerial { return serialNumber }
        return ""
    }

    /// Area falls back to department everywhere in the web reports.
    public var areaOrDepartment: String? { inventory.area ?? inventory.department }

    /// Recompute status against a new clock (the dashboard refreshes relative
    /// status every couple of minutes without refetching).
    public mutating func refreshStatus(now: Date = Date()) {
        status = DeviceStatus.calculate(lastSeen: lastSeen, archived: archived, now: now)
    }
}

/// Envelope of `/api/v1/devices`.
public struct DevicesPage: Sendable {
    public var devices: [DeviceSummary]
    public var total: Int
    public var page: Int
    public var pageSize: Int
    public var hasMore: Bool

    public init(json: JSONValue) {
        let list = json["devices"].elements
        let now = Date()
        devices = list.map { DeviceSummary(json: $0, now: now) }.filter { !$0.serialNumber.isEmpty }
        total = json["total"].int ?? devices.count
        page = json["page"].int ?? 1
        pageSize = json["pageSize"].int ?? devices.count
        hasMore = json["hasMore"].boolish
    }
}
