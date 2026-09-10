import Foundation

/// Event severity, as the API stores it.
public enum EventKind: String, Sendable, Hashable, CaseIterable, Codable {
    case success, warning, error, info, system

    public init(raw: String?) {
        self = EventKind(rawValue: (raw ?? "info").lowercased()) ?? .info
    }

    public var displayName: String {
        switch self {
        case .success: return "Success"
        case .warning: return "Warnings"
        case .error: return "Errors"
        case .info: return "Info"
        case .system: return "System"
        }
    }

    /// Filter order used by the events feed (Info last, hidden by default).
    public static let filterOrder: [EventKind] = [.success, .warning, .error, .system, .info]
}

/// A fleet-wide event row from `/api/v1/events` or the dashboard envelope.
public struct FleetEvent: Sendable, Hashable, Identifiable {
    public var id: String
    /// Serial number of the reporting device.
    public var device: String
    public var deviceName: String?
    public var assetTag: String?
    public var platform: Platform
    public var kind: EventKind
    public var rawKind: String
    public var message: String
    public var ts: Date?
    public var rawTimestamp: String?
    /// Present on per-device events (`raw`) and on payload fetches.
    public var payload: JSONValue?

    public init(json: JSONValue) {
        id = json["id"].string ?? UUID().uuidString
        device = json.firstString("device", "serialNumber", "deviceId") ?? ""
        let name = json["deviceName"].nonEmptyString
        deviceName = (name?.lowercased() == "unknown") ? nil : name
        assetTag = json["assetTag"].nonEmptyString
        platform = Platform.normalize(json["platform"].nonEmptyString)
        rawKind = json.firstString("kind", "eventType", "event_type") ?? "info"
        kind = EventKind(raw: rawKind)
        rawTimestamp = json.firstString("ts", "timestamp")
        ts = FlexibleDate.parse(rawTimestamp)
        let payloadJSON = json.first("payload", "raw", "details")
        payload = payloadJSON.isNull ? nil : payloadJSON
        message = json["message"].nonEmptyString ?? EventBundling.payloadPreview(payloadJSON)
    }

    public init(id: String, device: String, deviceName: String? = nil, assetTag: String? = nil, platform: Platform = .unknown,
                kind: EventKind, message: String, ts: Date?, payload: JSONValue? = nil) {
        self.id = id
        self.device = device
        self.deviceName = deviceName
        self.assetTag = assetTag
        self.platform = platform
        self.kind = kind
        self.rawKind = kind.rawValue
        self.message = message
        self.ts = ts
        self.rawTimestamp = nil
        self.payload = payload
    }

    /// Name for the Device column: friendly name when known, else the serial.
    public var displayDeviceName: String {
        if let n = deviceName, n != device, n.lowercased() != "unknown" { return n }
        return device.isEmpty ? "Unknown Device" : device
    }
}

/// Envelope of `/api/v1/events`.
public struct EventsPage: Sendable {
    public var events: [FleetEvent]
    public var total: Int
    public var count: Int
    public var limit: Int
    public var offset: Int

    public init(json: JSONValue) {
        events = json["events"].elements.map(FleetEvent.init(json:))
        total = json.first("total", "totalEvents").int ?? events.count
        count = json["count"].int ?? events.count
        limit = json["limit"].int ?? events.count
        offset = json["offset"].int ?? 0
    }
}

/// Install-error counters returned by `/api/v1/dashboard`.
public struct InstallStats: Sendable, Hashable, Codable {
    public var devicesWithErrors = 0
    public var devicesWithWarnings = 0
    public var winDevicesWithErrors = 0
    public var winDevicesWithWarnings = 0
    public var macDevicesWithErrors = 0
    public var macDevicesWithWarnings = 0
    public var totalErrorItems = 0
    public var totalWarningItems = 0
    public var winErrorItems = 0
    public var winWarningItems = 0
    public var macErrorItems = 0
    public var macWarningItems = 0
    public var hasInstallData = false

    public init() {}

    public init(json: JSONValue) {
        devicesWithErrors = json["devicesWithErrors"].int ?? 0
        devicesWithWarnings = json["devicesWithWarnings"].int ?? 0
        winDevicesWithErrors = json["winDevicesWithErrors"].int ?? 0
        winDevicesWithWarnings = json["winDevicesWithWarnings"].int ?? 0
        macDevicesWithErrors = json["macDevicesWithErrors"].int ?? 0
        macDevicesWithWarnings = json["macDevicesWithWarnings"].int ?? 0
        totalErrorItems = json["totalErrorItems"].int ?? 0
        totalWarningItems = json["totalWarningItems"].int ?? 0
        winErrorItems = json["winErrorItems"].int ?? 0
        winWarningItems = json["winWarningItems"].int ?? 0
        macErrorItems = json["macErrorItems"].int ?? 0
        macWarningItems = json["macWarningItems"].int ?? 0
        hasInstallData = json["hasInstallData"].boolish
    }

    /// Device-with-errors count scoped to the active platform filter.
    public func devicesWithErrors(for filter: PlatformFilter) -> Int? {
        guard hasInstallData else { return nil }
        switch filter {
        case .all: return devicesWithErrors
        case .macOS: return macDevicesWithErrors
        case .windows: return winDevicesWithErrors
        }
    }

    public func devicesWithWarnings(for filter: PlatformFilter) -> Int? {
        guard hasInstallData else { return nil }
        switch filter {
        case .all: return devicesWithWarnings
        case .macOS: return macDevicesWithWarnings
        case .windows: return winDevicesWithWarnings
        }
    }
}

/// The consolidated `/api/v1/dashboard` payload.
public struct DashboardData: Sendable {
    public var devices: [DeviceSummary]
    public var totalDevices: Int
    public var installStats: InstallStats
    public var events: [FleetEvent]
    public var lastUpdated: Date?

    public init(json: JSONValue) {
        let now = Date()
        devices = json["devices"].elements.map { DeviceSummary(json: $0, now: now) }.filter { !$0.serialNumber.isEmpty }
        totalDevices = json["totalDevices"].int ?? devices.count
        installStats = InstallStats(json: json["installStats"])
        events = json["events"].elements.map(FleetEvent.init(json:))
        lastUpdated = FlexibleDate.parse(json["lastUpdated"])
    }

    public init(devices: [DeviceSummary] = [], installStats: InstallStats = InstallStats(), events: [FleetEvent] = []) {
        self.devices = devices
        self.totalDevices = devices.count
        self.installStats = installStats
        self.events = events
        self.lastUpdated = Date()
    }
}

/// One rejected or repaired check-in from `/api/v1/events/failures`.
public struct IngestFailure: Sendable, Hashable, Identifiable {
    public var id: String
    public var ts: Date?
    public var failureType: String
    public var reason: String
    public var detail: String?
    public var statusCode: Int?
    public var outcome: String
    public var endpoint: String?
    public var clientIp: String?
    public var userAgent: String?
    public var serialNumber: String?
    public var deviceUuid: String?
    public var deviceName: String?
    public var platform: String?
    public var clientVersion: String?

    public init(json: JSONValue) {
        id = json["id"].string ?? UUID().uuidString
        ts = FlexibleDate.parse(json["ts"])
        failureType = json["failureType"].string ?? ""
        reason = json["reason"].string ?? ""
        detail = json["detail"].nonEmptyString
        statusCode = json["statusCode"].int
        outcome = json["outcome"].string ?? ""
        endpoint = json["endpoint"].nonEmptyString
        clientIp = json["clientIp"].nonEmptyString
        userAgent = json["userAgent"].nonEmptyString
        serialNumber = json["serialNumber"].nonEmptyString
        deviceUuid = json["deviceUuid"].nonEmptyString
        deviceName = json["deviceName"].nonEmptyString
        platform = json["platform"].nonEmptyString
        clientVersion = json["clientVersion"].nonEmptyString
    }
}

public struct IngestFailuresPage: Sendable {
    public struct ReasonSummary: Sendable, Hashable, Identifiable {
        public var id: String { reason }
        public var reason: String
        public var count: Int
        public var devices: Int
        public var lastSeen: Date?
    }

    public var failures: [IngestFailure]
    public var summary: [ReasonSummary]
    public var total: Int
    public var hours: Int
    public var outcome: String
    public var rejected: Int
    public var retried: Int
    public var accepted: Int

    public init(json: JSONValue) {
        failures = json["failures"].elements.map(IngestFailure.init(json:))
        summary = json["summary"].elements.map {
            ReasonSummary(reason: $0["reason"].string ?? "", count: $0["count"].int ?? 0,
                          devices: $0["devices"].int ?? 0, lastSeen: FlexibleDate.parse($0["lastSeen"]))
        }
        total = json["total"].int ?? failures.count
        hours = json["hours"].int ?? 168
        outcome = json["outcome"].string ?? "rejected"
        rejected = json["counts"]["rejected"].int ?? 0
        retried = json["counts"]["retried"].int ?? 0
        accepted = json["counts"]["accepted"].int ?? 0
    }
}

/// A day of application usage for one device.
public struct UsageHistoryEntry: Sendable, Hashable, Identifiable {
    public var id: String { "\(date)|\(appName)" }
    public var date: String
    public var appName: String
    public var launches: Int
    public var totalSeconds: Double
    public var activeSeconds: Double
    public var foregroundSeconds: Double
    public var users: [String]

    public init(json: JSONValue) {
        date = json["date"].string ?? ""
        appName = json["appName"].string ?? ""
        launches = json["launches"].int ?? 0
        totalSeconds = json["totalSeconds"].double ?? 0
        activeSeconds = json["activeSeconds"].double ?? 0
        foregroundSeconds = json["foregroundSeconds"].double ?? 0
        users = json["users"].elements.compactMap(\.string)
    }
}
