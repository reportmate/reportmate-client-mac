import Foundation

/// Device freshness, derived from `lastSeen` exactly as the web dashboard's
/// `device-status.ts` does: active under 24 h, stale under 7 days, else missing.
public enum DeviceStatus: String, Sendable, Hashable, CaseIterable, Codable, Comparable {
    case active
    case stale
    case warning
    case error
    case missing
    case archived

    public static let activeThresholdHours: Double = 24
    public static let staleThresholdHours: Double = 168

    public static func calculate(lastSeen: Date?, archived: Bool = false, now: Date = Date()) -> DeviceStatus {
        if archived { return .archived }
        guard let lastSeen else { return .missing }
        let hours = now.timeIntervalSince(lastSeen) / 3600
        if hours < activeThresholdHours { return .active }
        if hours < staleThresholdHours { return .stale }
        return .missing
    }

    public static func calculate(lastSeen text: String?, archived: Bool = false, now: Date = Date()) -> DeviceStatus {
        // normalizeLastSeen treats an unparseable timestamp as "now" (active).
        if archived { return .archived }
        guard let text, !text.isEmpty else { return .missing }
        guard let date = FlexibleDate.parse(text) else { return .active }
        return calculate(lastSeen: date, archived: false, now: now)
    }

    public var displayName: String {
        rawValue.prefix(1).uppercased() + rawValue.dropFirst()
    }

    /// Order used by the fleet-status donut: active, stale, missing, then the rest.
    public var sortOrder: Int {
        switch self {
        case .active: return 0
        case .stale: return 1
        case .missing: return 2
        case .warning: return 3
        case .error: return 4
        case .archived: return 5
        }
    }

    public static func < (lhs: DeviceStatus, rhs: DeviceStatus) -> Bool {
        lhs.sortOrder < rhs.sortOrder
    }

    /// Hex colour used by the web charts for this status.
    public var chartColorHex: String {
        switch self {
        case .active: return "#10b981"
        case .stale: return "#f59e0b"
        case .missing: return "#6b7280"
        case .warning: return "#f97316"
        case .error: return "#ef4444"
        case .archived: return "#64748b"
        }
    }
}
