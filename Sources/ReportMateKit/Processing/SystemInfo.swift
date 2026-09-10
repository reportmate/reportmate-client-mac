import Foundation

/// Operating system facts and the per-platform lists the System tab shows.
/// Port of `data-processing/modules/system.ts` and the System widget.
public struct SystemInfo: Sendable, Hashable {
    public struct OperatingSystem: Sendable, Hashable {
        public var name: String?
        public var version: String?
        public var displayVersion: String?
        public var edition: String?
        public var build: String?
        public var architecture: String?
        public var locale: String?
        public var timeZone: String?
        public var keyboardLayout: String?
        public var featureUpdate: String?
        public var platform: String?
        public var kernelVersion: String?
        public var activation: Activation?
    }

    public struct Activation: Sendable, Hashable {
        public var isActivated: Bool?
        public var status: String?
        public var statusCode: Int?
        public var partialProductKey: String?
        public var licenseType: String?
    }

    public struct PendingUpdate: Sendable, Hashable, Identifiable {
        public var id: String { name + (version ?? "") }
        public var name: String
        public var version: String?
        public var buildVersion: String?
        public var size: String?
        public var recommended: Bool
        public var isSecurity: Bool
        public var restartRequired: Bool
        public var deferred: Bool
        public var deferredUntil: String?
        public var firstOfferedAt: String?
        public var updateType: String?
        // Windows-only
        public var kbNumber: String?
        public var category: String?
        public var severity: String?
        public var description: String?
        public var cves: [String]
        public var isMandatory: Bool
        public var isDownloaded: Bool
        public var releaseDate: String?
    }

    public var isMac: Bool
    public var operatingSystem: OperatingSystem
    public var uptime: String?
    public var bootTime: String?
    public var pendingAppleUpdates: [PendingUpdate]
    public var pendingWindowsUpdates: [PendingUpdate]
    public var pendingWindowsUpdatesCount: Int
    /// Raw lists kept as JSON: services, environment, updates history,
    /// scheduled tasks, login items, extensions. The System tab renders them
    /// with per-row fallbacks.
    public var services: [JSONValue]
    public var environment: [(name: String, value: String)]
    public var installedUpdates: [JSONValue]
    public var scheduledTasks: [JSONValue]
    public var installHistory: [JSONValue]
    public var loginItems: [JSONValue]
    public var systemExtensions: [JSONValue]
    public var kernelExtensions: [JSONValue]
    public var privilegedHelperTools: [JSONValue]
    public var raw: JSONValue

    public static func == (lhs: SystemInfo, rhs: SystemInfo) -> Bool { lhs.raw == rhs.raw }
    public func hash(into hasher: inout Hasher) { hasher.combine(raw) }

    public var hasData: Bool { operatingSystem.name != nil || operatingSystem.version != nil }

    public var deferredUpdates: [PendingUpdate] { pendingAppleUpdates.filter { $0.deferred || $0.deferredUntil != nil } }
    public var activeAppleUpdates: [PendingUpdate] { pendingAppleUpdates.filter { !$0.deferred && $0.deferredUntil == nil } }

    public var soonestDeferral: PendingUpdate? {
        deferredUpdates.filter { $0.deferredUntil != nil }
            .sorted { (FlexibleDate.parse($0.deferredUntil) ?? .distantFuture) < (FlexibleDate.parse($1.deferredUntil) ?? .distantFuture) }
            .first
    }

    /// Software-update status line for the Info widget.
    public enum UpdateStatus: Sendable, Hashable {
        case upToDate
        case pending(count: Int, deferred: Int, soonest: String?)
        case deferredOnly(count: Int, soonest: String?)
    }

    public var updateStatus: UpdateStatus {
        if isMac {
            let active = activeAppleUpdates.count
            let deferred = deferredUpdates.count
            let soonest = soonestDeferral?.deferredUntil
            if active > 0 { return .pending(count: active, deferred: deferred, soonest: soonest) }
            if deferred > 0 { return .deferredOnly(count: deferred, soonest: soonest) }
            return .upToDate
        }
        if pendingWindowsUpdatesCount > 0 { return .pending(count: pendingWindowsUpdatesCount, deferred: 0, soonest: nil) }
        return .upToDate
    }

    public init(modules: JSONValue, platform: Platform) {
        let system = modules["system"].unwrappingSingleton()
        raw = system
        let n = system.normalizedKeys()
        let os = n["operatingSystem"]
        let details = n["systemDetails"]
        let platformName = os["platform"].nonEmptyString ?? details["platform"].nonEmptyString ?? ""
        isMac = platform == .macOS || platformName.lowercased() == "darwin" || (os["name"].string ?? "").lowercased().contains("macos")

        var info = OperatingSystem()
        info.name = os.firstString("name", "productName")
        info.version = os["version"].nonEmptyString
        if let dv = os["displayVersion"].nonEmptyString {
            info.displayVersion = dv
        } else if let major = os["majorVersion"].int {
            info.displayVersion = "\(major).\(os["minorVersion"].int ?? 0).\(os["patchVersion"].int ?? 0)"
        } else if let major = os["major"].int {
            info.displayVersion = "\(major).\(os["minor"].int ?? 0).\(os["patch"].int ?? 0)"
        }
        info.edition = os.firstString("edition", "platform")
        info.build = os.firstString("build", "buildNumber")
        info.architecture = os.firstString("architecture", "arch")
        info.locale = os["locale"].nonEmptyString ?? details["locale"].nonEmptyString
        info.timeZone = os.firstString("timeZone", "timezone") ?? details["timeZone"].nonEmptyString
        if let kb = os["activeKeyboardLayout"].nonEmptyString {
            info.keyboardLayout = kb
        } else if let layouts = os["keyboardLayouts"].array, !layouts.isEmpty {
            info.keyboardLayout = layouts.compactMap(\.string).joined(separator: ", ")
        } else if let layouts = details["keyboardLayouts"].array, !layouts.isEmpty {
            info.keyboardLayout = layouts.compactMap(\.string).joined(separator: ", ")
        }
        info.featureUpdate = os["featureUpdate"].nonEmptyString
        info.platform = os["platform"].nonEmptyString
        info.kernelVersion = os["kernelVersion"].nonEmptyString
        let act = os["activation"]
        if !act.isNull {
            info.activation = Activation(isActivated: act["isActivated"].boolishIfPresent, status: act["status"].nonEmptyString,
                                         statusCode: act["statusCode"].int, partialProductKey: act["partialProductKey"].nonEmptyString,
                                         licenseType: act["licenseType"].nonEmptyString)
        }
        operatingSystem = info

        uptime = n.firstString("uptimeString", "uptime") ?? details["uptimeString"].nonEmptyString
        bootTime = n.firstString("lastBootTime", "bootTime") ?? details["bootTime"].nonEmptyString

        func update(_ u: JSONValue) -> PendingUpdate {
            PendingUpdate(
                name: u.firstString("name", "displayName", "title") ?? "",
                version: u["version"].nonEmptyString, buildVersion: u["buildVersion"].nonEmptyString,
                size: u["size"].nonEmptyString,
                recommended: u["recommended"].boolish || u["isRecommended"].boolish,
                isSecurity: u["isSecurity"].boolish,
                restartRequired: u["restartRequired"].boolish || u["rebootRequired"].boolish,
                deferred: u["deferred"].boolish, deferredUntil: u["deferredUntil"].nonEmptyString,
                firstOfferedAt: u["firstOfferedAt"].nonEmptyString, updateType: u["updateType"].nonEmptyString,
                kbNumber: u["kbNumber"].nonEmptyString, category: u["category"].nonEmptyString,
                severity: u["severity"].nonEmptyString, description: u["description"].nonEmptyString,
                cves: u["cves"].elements.compactMap(\.string),
                isMandatory: u["isMandatory"].boolish, isDownloaded: u["isDownloaded"].boolish,
                releaseDate: u["releaseDate"].nonEmptyString)
        }
        pendingAppleUpdates = n["pendingAppleUpdates"].elements.map(update)
        pendingWindowsUpdates = n["pendingWindowsUpdates"].elements.map(update)
        pendingWindowsUpdatesCount = n["pendingWindowsUpdatesCount"].int ?? pendingWindowsUpdates.count

        services = n["services"].elements
        if let arr = n["environment"].array {
            environment = arr.map { (name: $0.firstString("name", "key") ?? "", value: $0["value"].string ?? "") }
        } else if let obj = n["environment"].object {
            environment = obj.sorted { $0.key < $1.key }.map { (name: $0.key, value: $0.value.string ?? "") }
        } else {
            environment = []
        }
        installedUpdates = n["updates"].elements
        scheduledTasks = n["scheduledTasks"].elements
        installHistory = n["installHistory"].elements
        loginItems = n["loginItems"].elements
        systemExtensions = n["systemExtensions"].elements
        kernelExtensions = n["kernelExtensions"].elements
        privilegedHelperTools = n["privilegedHelperTools"].elements
    }
}

/// OS naming helpers shared by the System widget, charts and reports.
public enum OSNames {
    /// `getMacOSMarketingName`
    public static func macOSMarketingName(version: String?) -> String {
        guard let version, let major = Int(version.split(separator: ".").first ?? "") else { return "macOS" }
        let names: [Int: String] = [27: "macOS 27", 26: "Tahoe", 15: "Sequoia", 14: "Sonoma", 13: "Ventura", 12: "Monterey", 11: "Big Sur", 10: "Catalina"]
        if major == 10 {
            let minor = Int(version.split(separator: ".").dropFirst().first ?? "") ?? 0
            let old: [Int: String] = [15: "Catalina", 14: "Mojave", 13: "High Sierra", 12: "Sierra"]
            return old[minor] ?? "macOS"
        }
        return names[major] ?? "macOS"
    }

    /// `getOSLabel`: "macOS", "Windows 11", "Windows 10" or "Windows".
    public static func osLabel(name: String?, isMac: Bool) -> String {
        if isMac { return "macOS" }
        let n = name ?? ""
        if n.contains("Windows 11") { return "Windows 11" }
        if n.contains("Windows 10") { return "Windows 10" }
        return "Windows"
    }

    /// Mac: `major.minor.patch`; Windows: the build segment of `10.0.26200`.
    public static func formattedVersion(_ version: String?, isMac: Bool) -> String {
        guard let version, !version.isEmpty else { return "Unknown" }
        let parts = version.split(separator: ".").map(String.init)
        if isMac {
            return "\(parts.first ?? "0").\(parts.count > 1 ? parts[1] : "0").\(parts.count > 2 ? parts[2] : "0")"
        }
        return parts.count >= 3 ? parts[2] : version
    }
}
