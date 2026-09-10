import Foundation

/// Device platform, normalised from the many spellings the fleet reports.
public enum Platform: String, Sendable, Hashable, CaseIterable, Codable {
    case macOS
    case windows = "Windows"
    case unknown

    public var displayName: String {
        switch self {
        case .macOS: return "macOS"
        case .windows: return "Windows"
        case .unknown: return "Unknown"
        }
    }

    /// Chart label: the web app labels Macs "Macintosh" in distribution charts.
    public var chartLabel: String {
        switch self {
        case .macOS: return "Macintosh"
        case .windows: return "Windows"
        case .unknown: return "Other"
        }
    }

    public var systemImage: String {
        switch self {
        case .macOS: return "apple.logo"
        case .windows: return "square.grid.2x2.fill"
        case .unknown: return "questionmark.circle"
        }
    }

    /// `normalizePlatform` from the web app.
    public static func normalize(_ raw: String?) -> Platform {
        guard let raw, !raw.isEmpty else { return .unknown }
        let lower = raw.lowercased()
        if ["macos", "mac", "macintosh", "darwin", "munki"].contains(lower) { return .macOS }
        if lower == "windows" || lower.hasPrefix("win") || lower == "cimian" { return .windows }
        if lower.contains("mac") || lower.contains("darwin") { return .macOS }
        if lower.contains("windows") { return .windows }
        return .unknown
    }

    /// `getDevicePlatform`: the full detection chain over a raw device record.
    ///
    /// Priority: system.operatingSystem.name (kernel), then the device's own
    /// `platform`, inventory.platform, configType (Cimian/Munki), legacy
    /// osName/os, and finally hardware model/vendor hints.
    public static func detect(device: JSONValue) -> Platform {
        let modules = device["modules"]
        if let osName = modules["system"].first("operatingSystem", "operating_system")["name"].nonEmptyString {
            let p = normalize(osName)
            if p != .unknown { return p }
        }
        if let p = device["platform"].nonEmptyString {
            let n = normalize(p)
            if n != .unknown { return n }
        }
        if let p = modules["inventory"]["platform"].nonEmptyString {
            let n = normalize(p)
            if n != .unknown { return n }
        }
        if let configType = device["configType"].nonEmptyString {
            if configType == "Cimian" { return .windows }
            if configType == "Munki" { return .macOS }
        }
        if let legacy = device.firstString("osName", "os") {
            let n = normalize(legacy)
            if n != .unknown { return n }
        }
        let hardware = modules["hardware"]
        let modelName = (hardware["system"].firstString("model_name", "modelName") ?? hardware["model"].nonEmptyString ?? "").lowercased()
        if modelName.contains("mac") || modelName.contains("imac") { return .macOS }
        if ["surface", "thinkpad", "latitude", "optiplex"].contains(where: { modelName.contains($0) }) { return .windows }
        let vendor = (hardware["system"].firstString("hardware_vendor", "hardwareVendor") ?? hardware["manufacturer"].nonEmptyString ?? "").lowercased()
        if vendor.contains("apple") { return .macOS }
        return .unknown
    }
}

/// The global Mac / Windows / All toggle.
public enum PlatformFilter: String, Sendable, Hashable, CaseIterable, Codable {
    case all
    case macOS
    case windows

    public var platform: Platform? {
        switch self {
        case .all: return nil
        case .macOS: return .macOS
        case .windows: return .windows
        }
    }

    /// `isPlatformVisible`: unknown platforms are hidden while a filter is active.
    public func includes(_ platform: Platform) -> Bool {
        switch self {
        case .all: return true
        case .macOS: return platform == .macOS
        case .windows: return platform == .windows
        }
    }

    public func includes(_ raw: String?) -> Bool {
        includes(Platform.normalize(raw))
    }

    /// URL query value used by the web app (`?platform=mac|win`).
    public var queryValue: String? {
        switch self {
        case .all: return nil
        case .macOS: return "mac"
        case .windows: return "win"
        }
    }
}
