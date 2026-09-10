import Foundation

// MARK: - Name normalisation

/// `normalizeAppName` and `shouldIncludeApplication` from the web
/// Applications page. Every JavaScript `replace` there runs without the `g`
/// flag, so each pattern here replaces its first match only.
public enum AppNameNormalizer {
    public static func normalize(_ appName: String) -> String {
        var n = appName.trimmingCharacters(in: .whitespacesAndNewlines)
        if n.isEmpty { return "" }
        if n.contains("${{") || n.contains("}}") { return "" }
        if n == "Unknown" || n == "N/A" { return "" }

        if matches(n, #"Microsoft Visual C\+\+ \d{4}"#) { return "Microsoft Visual C++ Redistributable" }
        if n.hasPrefix("Microsoft.NET") || n.contains("Microsoft ASP.NET Core") {
            if n.contains("Workload") { return "Microsoft .NET Workload" }
            if n.contains("Sdk") || n.contains("SDK") { return "Microsoft .NET SDK" }
            if n.contains("ASP.NET Core") { return "Microsoft ASP.NET Core" }
            if n.contains("Runtime") || n.contains("AppHost") || n.contains("Targeting Pack") || n.contains("Host FX Resolver") {
                return "Microsoft .NET Runtime"
            }
            return "Microsoft .NET"
        }
        if n.contains("Microsoft Visual Studio Tools") { return "Microsoft Visual Studio Tools" }
        if matches(n, #"Microsoft (365|Office 365)"#) { return "Microsoft 365" }
        if matches(n, "Kinect for Windows Speech Recognition Language Pack") { return "Kinect for Windows Speech Recognition Language Pack" }
        if matches(n, "Microsoft.*Language Pack") { return "Microsoft Language Pack" }
        if matches(n, "Kits Configuration Installer") { return "Kits Configuration Installer" }
        if matches(n, "Kofax VRS") { return "Kofax VRS" }
        if n.hasPrefix("Adobe "), let group = firstCapture(n, #"Adobe ([A-Za-z\s]+)"#) {
            let product = group.first?.isWhitespace == true ? "" : String(group.split(whereSeparator: \.isWhitespace).first ?? "")
            if !product.isEmpty, product != "AIR" { return "Adobe \(product)" }
        }
        if matches(n, "^7-Zip") { return "7-Zip" }
        if matches(n, "Google Chrome|Chrome") { return "Google Chrome" }
        if matches(n, "Mozilla Firefox|Firefox") { return "Mozilla Firefox" }
        if n.hasPrefix("AMD "), n.contains("Driver") || n.contains("Chipset") {
            return n.contains("Chipset") ? "AMD Chipset Software" : "AMD Drivers"
        }
        if n.contains("SOLIDWORKS") { return n.contains("3DEXPERIENCE") ? "3DEXPERIENCE for SOLIDWORKS" : "SOLIDWORKS" }
        if n.hasPrefix("HP ") || n.contains("HP ") { return "HP Software" }

        // Trailing version numbers.
        n = replaceFirst(n, #"\s+v?\d+(\.\d+)*(\.\d+)*(\.\d+)*$"#)
        n = replaceFirst(n, #"\s+\d{4}(\.\d+)*$"#)
        n = replaceFirst(n, #"\s+-\s+\d+(\.\d+)*$"#)
        n = replaceFirst(n, #"\s+\(\d+(\.\d+)*(\.\d+)*\)$"#)
        n = replaceFirst(n, #"\s+build\s+\d+"#)
        n = replaceFirst(n, #"\s+\d+(\.\d+)*(\.\d+)*(\.\d+)*$"#)
        // Versions in the middle.
        n = replaceFirst(n, #"\s+\d{4}\.\d{2}-\d+"#)
        n = replaceFirst(n, #"\s+\d{1,2}\.\d+\.\d+"#)
        n = replaceFirst(n, #"\s+\d{4}"#)
        n = replaceFirst(n, #"\s+v\d+(\.\d+)*"#)
        // Architecture and platform.
        n = replaceFirst(n, #"\s+(x64|x86|64-bit|32-bit|amd64|i386)$"#)
        n = replaceFirst(n, #"\s+\((x64|x86|64-bit|32-bit|amd64|i386)\)$"#)
        n = replaceFirst(n, #"\s+\(Python\s+[\d\.]+\s+(64-bit|32-bit)\)$"#)
        n = replaceFirst(n, #"\s+\(git\s+[a-f0-9]+\)$"#)
        n = replaceFirst(n, #"\s+\([^)]*bit[^)]*\)"#)
        n = replaceFirst(n, #"\s+\([^)]*\d+\.\d+\.\d+[^)]*\)"#)
        // Microsoft runtime suffixes.
        n = replaceFirst(n, #"\s+(Additional Runtime|Minimum Runtime|Redistributable|Shared Framework|Targeting Pack|AppHost Pack|Host FX Resolver|Hosting Support)$"#)
        n = replaceFirst(n, #"\s+-\s+(en-us|x64|x86|\d+(\.\d+)*)$"#)
        // Common application suffixes.
        n = replaceFirst(n, #"\s+(Desktop|App|Application|Software|Program|Tool|Suite|Client|Server)$"#)
        n = replaceFirst(n, #"\s+(Pro|Professional|Standard|Basic|Free|Premium|Enterprise|Business|Personal|Home|Student|Education)$"#)
        n = replaceFirst(n, #"\s+(Trial|Beta|Alpha|RC|Release|Final|Portable|Standalone)$"#)
        // Update and patch markers.
        n = replaceFirst(n, #"\s+Update\s+\d+"#)
        n = replaceFirst(n, #"\s+SP\d+"#)
        n = replaceFirst(n, #"\s+Patch\s+\d+"#)
        // Language and platform words.
        n = replaceFirst(n, #"\s+-\s+en-us$"#)
        n = replaceFirst(n, #"\s+for\s+Windows$"#)
        n = replaceFirst(n, #"\s+for\s+Microsoft\s+Windows$"#)
        n = replaceFirst(n, #"\s+Windows\s+Edition$"#)
        // Final cleanup.
        n = n.replacingOccurrences(of: #"\s+"#, with: " ", options: .regularExpression)
        n = replaceFirst(n, #"\s*-\s*$"#, caseInsensitive: false)
        n = replaceFirst(n, #"^\s*-\s*"#, caseInsensitive: false)
        n = n.trimmingCharacters(in: .whitespaces)
        if n.count < 2 { return "" }
        return n
    }

    private static let excludePatterns: [String] = [
        #"^Microsoft\.NET\.Workload\."#,
        #"^Microsoft\.NET\.Sdk\."#,
        #"^Windows Software Development Kit"#,
        #"^Microsoft Visual Studio Installer$"#,
        #"Update for Windows"#,
        #"Security Update for Microsoft"#,
        #"^KB\d+"#,
        #"^64 Bit HP CIO Components Installer"#,
        #"^1394 OHCI Compliant Host Controller"#,
        #"^AVG.*Helper$"#,
        #"^AVG.*Browser$"#,
        #"^AVerMedia.*HD Series"#,
        #"^AVerMedia RECentral$"#,
        #"Microsoft Visual C\+\+ \d{4} x\d{2} (Additional|Minimum) Runtime"#,
        #"Microsoft .NET (Runtime|AppHost Pack|Targeting Pack|Host FX Resolver) - [\d\.]+ \(x\d+"#,
        #"Microsoft ASP.NET Core [\d\.]+ (Shared Framework|Targeting Pack) \(x\d+"#,
        #"^\$\{\{.*\}\}$"#,
        #"^Unknown$"#,
        #"^N\/A$"#,
        #"^\s*$"#,
    ]

    /// Drops installer, runtime and placeholder rows the report never shows.
    public static func shouldInclude(_ appName: String) -> Bool {
        let trimmed = appName.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return false }
        if trimmed.contains("${{") || trimmed.contains("}}") { return false }
        if trimmed == "Unknown" || trimmed == "N/A" { return false }
        return !excludePatterns.contains { matches(trimmed, $0) }
    }

    static func matches(_ s: String, _ pattern: String) -> Bool {
        s.range(of: pattern, options: [.regularExpression, .caseInsensitive]) != nil
    }

    static func firstCapture(_ s: String, _ pattern: String) -> String? {
        guard let re = try? NSRegularExpression(pattern: pattern),
              let m = re.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)),
              m.numberOfRanges > 1, let r = Range(m.range(at: 1), in: s) else { return nil }
        return String(s[r])
    }

    static func replaceFirst(_ s: String, _ pattern: String, caseInsensitive: Bool = true) -> String {
        guard let re = try? NSRegularExpression(pattern: pattern, options: caseInsensitive ? [.caseInsensitive] : []),
              let m = re.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)),
              let r = Range(m.range, in: s) else { return s }
        var out = s
        out.removeSubrange(r)
        return out
    }
}

// MARK: - Filter options (`/applications/filters`)

/// A device known to the applications filter endpoint; the Missing report
/// subtracts devices that have an application from this list.
public struct ApplicationFilterDevice: Sendable, Hashable, Identifiable {
    public let serialNumber: String
    public let name: String
    public let usage: String?
    public let catalog: String?
    public let location: String?
    public let room: String?
    public var id: String { serialNumber }

    public init(json: JSONValue) {
        let j = json.normalizedKeys()
        serialNumber = j["serialNumber"].nonEmptyString ?? ""
        name = j["name"].nonEmptyString ?? j["deviceName"].nonEmptyString ?? serialNumber
        usage = j["usage"].nonEmptyString
        catalog = j["catalog"].nonEmptyString
        location = j["location"].nonEmptyString
        room = j["room"].nonEmptyString ?? j["location"].nonEmptyString
    }
}

public struct ApplicationFilterOptions: Sendable, Hashable {
    public var applicationNames: [String] = []
    public var windowsApplicationNames: [String] = []
    public var macApplicationNames: [String] = []
    public var usages: [String] = []
    public var catalogs: [String] = []
    public var rooms: [String] = []
    public var fleets: [String] = []
    public var areas: [String] = []
    public var locations: [String] = []
    public var devices: [ApplicationFilterDevice] = []

    public var devicesWithData: Int { devices.count }

    public init() {}

    public init(json: JSONValue) {
        let j = json.normalizedKeys()
        func list(_ key: String) -> [String] { j[key].elements.compactMap(\.nonEmptyString) }
        applicationNames = list("applicationNames")
        windowsApplicationNames = list("windowsApplicationNames")
        macApplicationNames = list("macApplicationNames")
        usages = list("usages")
        catalogs = list("catalogs")
        rooms = list("rooms")
        fleets = list("fleets")
        areas = list("areas")
        locations = list("locations")
        devices = j["devices"].elements.map(ApplicationFilterDevice.init(json:))
    }

    /// The chip cloud shows only the names collected on the toggled platform.
    public func applicationNames(for filter: PlatformFilter) -> [String] {
        switch filter {
        case .windows where !windowsApplicationNames.isEmpty: return windowsApplicationNames
        case .macOS where !macApplicationNames.isEmpty: return macApplicationNames
        default: return applicationNames
        }
    }

    /// Devices per room, used to size the location pills.
    public var roomCounts: [String: Int] {
        var counts: [String: Int] = [:]
        for d in devices { if let r = d.room { counts[r, default: 0] += 1 } }
        return counts
    }
}

// MARK: - Installed application rows (`/applications`)

/// One installed-application record from the bulk endpoint: the app plus the
/// device and inventory fields the Versions report filters on.
public struct FleetApplicationRow: Sendable, Hashable, Identifiable {
    public let id: String
    public let deviceName: String
    public let serialNumber: String
    public let lastSeen: String?
    public let name: String
    public let version: String
    public let vendor: String
    public let publisher: String
    public let category: String
    public let installDate: String?
    public let path: String?
    public let bundleId: String?
    public let architecture: String
    public let usage: String?
    public let catalog: String?
    public let location: String?
    public let room: String?
    public let fleet: String?
    public let department: String?
    public let area: String?
    public let assetTag: String?
    public let platform: String?

    public init(json: JSONValue) {
        let j = json.normalizedKeys()
        serialNumber = j["serialNumber"].nonEmptyString ?? j["deviceId"].nonEmptyString ?? ""
        deviceName = j["deviceName"].nonEmptyString ?? serialNumber
        lastSeen = j["lastSeen"].nonEmptyString ?? j["collectedAt"].nonEmptyString
        name = j["name"].nonEmptyString ?? ""
        version = j["version"].nonEmptyString ?? ""
        vendor = j["vendor"].nonEmptyString ?? j["publisher"].nonEmptyString ?? ""
        publisher = j["publisher"].nonEmptyString ?? ""
        category = j["category"].nonEmptyString ?? ""
        installDate = j["installDate"].nonEmptyString
        path = j["path"].nonEmptyString
        bundleId = j["bundleId"].nonEmptyString
        architecture = j["architecture"].nonEmptyString ?? ""
        usage = j["usage"].nonEmptyString
        catalog = j["catalog"].nonEmptyString
        location = j["location"].nonEmptyString
        room = j["room"].nonEmptyString
        fleet = j["fleet"].nonEmptyString
        department = j["department"].nonEmptyString
        area = j["area"].nonEmptyString
        assetTag = j["assetTag"].nonEmptyString
        platform = j["platform"].nonEmptyString
        id = j["id"].nonEmptyString ?? "\(serialNumber)|\(name)|\(version)"
    }

    /// The web shows `department || area`.
    public var areaOrDepartment: String? { department ?? area }
    public var displayDevice: String { deviceName.isEmpty ? serialNumber : deviceName }
}

// MARK: - Usage report (`/applications/usage`)

public struct UtilizationApp: Sendable, Hashable, Identifiable {
    public let name: String
    public let totalSeconds: Double
    public let totalHours: Double
    public let activeSeconds: Double?
    public let activeHours: Double?
    public let foregroundSeconds: Double?
    public let foregroundHours: Double?
    public let activeRatio: Double?
    public let launchCount: Int
    public let deviceCount: Int
    public let userCount: Int
    public let activeDeviceCount: Int?
    /// Devices whose applications inventory lists the app, folded by the same
    /// alias rules as the usage row. This is the install figure; deviceCount
    /// bottoms out at the last baseline reset and, on macOS, only sees GUI sessions.
    public let installedDeviceCount: Int?
    public let activeUserCount: Int?
    public let lastUsed: String?
    public let firstUsed: String?
    public let devices: [String]
    public let users: [String]
    public let isSingleUser: Bool
    public var id: String { name }

    public init(json: JSONValue) {
        let j = json.normalizedKeys()
        name = j["name"].nonEmptyString ?? ""
        totalSeconds = j["totalSeconds"].double ?? 0
        totalHours = j["totalHours"].double ?? totalSeconds / 3600
        activeSeconds = j["activeSeconds"].double
        activeHours = j["activeHours"].double
        foregroundSeconds = j["foregroundSeconds"].double
        foregroundHours = j["foregroundHours"].double
        activeRatio = j["activeRatio"].double
        launchCount = j["launchCount"].int ?? 0
        deviceCount = j["deviceCount"].int ?? 0
        userCount = j["userCount"].int ?? 0
        activeDeviceCount = j["activeDeviceCount"].int
        installedDeviceCount = j["installedDeviceCount"].int
        activeUserCount = j["activeUserCount"].int
        lastUsed = j["lastUsed"].nonEmptyString
        firstUsed = j["firstUsed"].nonEmptyString
        devices = j["devices"].elements.compactMap(\.nonEmptyString)
        users = j["users"].elements.compactMap(\.nonEmptyString)
        isSingleUser = j["isSingleUser"].boolish
    }

    /// No usage records in the window.
    public var hasNoData: Bool { deviceCount == 0 && launchCount == 0 && totalSeconds == 0 }

    public var statusLabel: String {
        if hasNoData { return "No data" }
        if isSingleUser { return "Single User" }
        return userCount > 5 ? "Popular" : "Normal"
    }

    /// Devices that contributed attention, falling back to the footprint.
    public var shownDeviceCount: Int { activeDeviceCount ?? deviceCount }
    public var shownUserCount: Int { activeUserCount ?? userCount }
}

public struct UtilizationSummary: Sendable, Hashable {
    public let totalAppsTracked: Int
    public let totalActiveHours: Double?
    public let totalUsageHours: Double
    public let totalLaunches: Int
    public let uniqueUsers: Int
    public let uniqueDevices: Int
    public let singleUserAppCount: Int
    public let unusedAppCount: Int
    public let noActiveUseAppCount: Int?

    public init(json: JSONValue) {
        let j = json.normalizedKeys()
        totalAppsTracked = j["totalAppsTracked"].int ?? 0
        totalActiveHours = j["totalActiveHours"].double
        totalUsageHours = j["totalUsageHours"].double ?? 0
        totalLaunches = j["totalLaunches"].int ?? 0
        uniqueUsers = j["uniqueUsers"].int ?? 0
        uniqueDevices = j["uniqueDevices"].int ?? 0
        singleUserAppCount = j["singleUserAppCount"].int ?? 0
        unusedAppCount = j["unusedAppCount"].int ?? 0
        noActiveUseAppCount = j["noActiveUseAppCount"].int
    }

    /// The header line under "Applications Usage Report".
    public var headline: String {
        var parts = ["\(totalAppsTracked.formatted()) apps", "\(uniqueDevices.formatted()) devices"]
        if let active = totalActiveHours { parts.append("\(Int(active.rounded()).formatted()) active hours") }
        parts.append("\(totalLaunches.formatted()) launches")
        parts.append("\(uniqueUsers.formatted()) unique users")
        if let none = noActiveUseAppCount, none > 0 { parts.append("\(none.formatted()) with no active use") }
        return parts.joined(separator: " · ")
    }
}

public struct VersionDevice: Sendable, Hashable {
    public let serialNumber: String
    public let deviceName: String
    public let location: String?
    public let catalog: String?
    public let lastSeen: String?

    public init(json: JSONValue) {
        let j = json.normalizedKeys()
        serialNumber = j["serialNumber"].nonEmptyString ?? ""
        deviceName = j["deviceName"].nonEmptyString ?? serialNumber
        location = j["location"].nonEmptyString
        catalog = j["catalog"].nonEmptyString
        lastSeen = j["lastSeen"].nonEmptyString
    }
}

public struct VersionInfo: Sendable, Hashable {
    public let count: Int
    public let devices: [VersionDevice]
    public init(json: JSONValue) {
        count = json["count"].int ?? json["devices"].elements.count
        devices = json["devices"].elements.map(VersionDevice.init(json:))
    }
}

public struct AppVersionDistribution: Sendable, Hashable {
    public let totalDevices: Int
    public let versions: [String: VersionInfo]
    public init(json: JSONValue) {
        var versions: [String: VersionInfo] = [:]
        for (v, info) in json["versions"].object ?? [:] { versions[v] = VersionInfo(json: info) }
        self.versions = versions
        totalDevices = json.normalizedKeys()["totalDevices"].int ?? versions.values.reduce(0) { $0 + $1.count }
    }
}

/// A device in the usage report's device-level aggregate.
public struct DeviceAggregate: Sendable, Hashable, UsageAggregatable {
    public let serialNumber: String
    public let deviceName: String
    public let usage: String?
    public let catalog: String?
    public let location: String?
    public let department: String?
    public let area: String?
    public let fleet: String?
    public let totalSeconds: Double
    public let totalHours: Double
    public let launchCount: Int

    public init(json: JSONValue) {
        let j = json.normalizedKeys()
        serialNumber = j["serialNumber"].nonEmptyString ?? ""
        deviceName = j["deviceName"].nonEmptyString ?? serialNumber
        usage = j["usage"].nonEmptyString
        catalog = j["catalog"].nonEmptyString
        location = j["location"].nonEmptyString
        department = j["department"].nonEmptyString
        area = j["area"].nonEmptyString
        fleet = j["fleet"].nonEmptyString
        totalSeconds = j["totalSeconds"].double ?? 0
        totalHours = j["totalHours"].double ?? totalSeconds / 3600
        launchCount = j["launchCount"].int ?? 0
    }
}

public struct UtilizationData: Sendable {
    public let status: String
    public let message: String?
    public let applications: [UtilizationApp]
    public let devicesAggregate: [DeviceAggregate]
    public let versionDistribution: [String: AppVersionDistribution]
    public let summary: UtilizationSummary
    public let lastUpdated: String?

    public init(json: JSONValue) {
        let j = json.normalizedKeys()
        status = j["status"].string ?? ""
        message = j["message"].nonEmptyString ?? j["error"].nonEmptyString
        applications = j["applications"].elements.map(UtilizationApp.init(json:))
        devicesAggregate = j["devicesAggregate"].elements.map(DeviceAggregate.init(json:))
        var dist: [String: AppVersionDistribution] = [:]
        for (app, bucket) in j["versionDistribution"].object ?? [:] { dist[app] = AppVersionDistribution(json: bucket) }
        versionDistribution = dist
        summary = UtilizationSummary(json: j["summary"])
        lastUpdated = j["lastUpdated"].nonEmptyString
    }

    public var isUnavailable: Bool { status == "unavailable" }
}

// MARK: - Version distribution (`/applications/distribution`)

public struct ServerDistributionBucket: Sendable, Hashable {
    public let totalDevices: Int
    public let versions: [String: Int]
}

public enum ApplicationsReport {
    /// Validates the distribution endpoint's `{app: {totalDevices, versions: {v: n}}}`
    /// shape; `nil` means fall back to folding the installed rows client-side.
    public static func parseServerDistribution(_ json: JSONValue) -> [String: ServerDistributionBucket]? {
        guard let object = json.object, json["error"].isNull else { return nil }
        var out: [String: ServerDistributionBucket] = [:]
        for (app, raw) in object {
            guard let versionsRaw = raw["versions"].object else { continue }
            var versions: [String: Int] = [:]
            for (v, c) in versionsRaw { if let n = c.int { versions[v] = n } }
            let total = raw.normalizedKeys()["totalDevices"].int ?? versions.values.reduce(0, +)
            out[app] = ServerDistributionBucket(totalDevices: total, versions: versions)
        }
        return out.isEmpty ? nil : out
    }

    /// `versionAnalysis`: normalised app → version → device count.
    public static func versionAnalysis(server: [String: ServerDistributionBucket]?, apps: [FleetApplicationRow]) -> [String: [String: Int]] {
        var analysis: [String: [String: Int]] = [:]
        if let server, !server.isEmpty {
            for (app, bucket) in server {
                let key = AppNameNormalizer.normalize(app).isEmpty ? app : AppNameNormalizer.normalize(app)
                for (v, c) in bucket.versions { analysis[key, default: [:]][v, default: 0] += c }
            }
            return analysis
        }
        for app in apps {
            let key = AppNameNormalizer.normalize(app.name)
            if key.isEmpty { continue }
            let version = app.version.isEmpty ? "Unknown" : app.version
            analysis[key, default: [:]][version, default: 0] += 1
        }
        return analysis
    }

    /// Versions newest first, the way `localeCompare` with `numeric` sorts them.
    public static func sortVersionsDescending<S: Sequence>(_ versions: S) -> [String] where S.Element == String {
        versions.sorted { compareVersions($0, $1) == .orderedDescending }
    }

    public static func compareVersions(_ a: String, _ b: String) -> ComparisonResult {
        a.compare(b, options: [.numeric, .caseInsensitive, .diacriticInsensitive])
    }

    /// Devices matching the selection dimensions that do not have the app.
    public static func missingDevices(all: [ApplicationFilterDevice], devicesWithApp: Set<String>,
                                      usages: Set<String>, catalogs: Set<String>, locations: Set<String>, rooms: Set<String>) -> [ApplicationFilterDevice] {
        let usages = Set(usages.map { $0.lowercased() }), catalogs = Set(catalogs.map { $0.lowercased() })
        let locations = Set(locations.map { $0.lowercased() }), rooms = rooms.map { $0.lowercased() }
        return all.filter { d in
            if devicesWithApp.contains(d.serialNumber) { return false }
            if !usages.isEmpty, !usages.contains(d.usage?.lowercased() ?? "") { return false }
            if !catalogs.isEmpty, !catalogs.contains(d.catalog?.lowercased() ?? "") { return false }
            if !locations.isEmpty, !locations.contains(d.location?.lowercased() ?? "") { return false }
            if !rooms.isEmpty {
                let loc = d.location?.lowercased() ?? "", room = d.room?.lowercased() ?? ""
                if !rooms.contains(where: { loc.contains($0) || room.contains($0) }) { return false }
            }
            return true
        }
    }

    /// `formatDuration`: `0m`, `45m`, `3h`, `3h 20m`.
    public static func duration(seconds: Double) -> String {
        guard seconds > 0 else { return "0m" }
        let h = Int(seconds / 3600), m = Int(seconds.truncatingRemainder(dividingBy: 3600) / 60)
        if h == 0 { return "\(m)m" }
        if m == 0 { return "\(h)h" }
        return "\(h)h \(m)m"
    }

    /// Selected versions are stored as `app:version` filter strings.
    public static func versionFilter(app: String, version: String) -> String { "\(app):\(version)" }

    public static func splitVersionFilter(_ filter: String) -> (app: String, version: String)? {
        guard let colon = filter.firstIndex(of: ":") else { return nil }
        return (String(filter[..<colon]), String(filter[filter.index(after: colon)...]))
    }
}

// MARK: - Usage widget aggregates

public enum UsageMetric: String, Sendable, CaseIterable, Identifiable {
    case launches, hours
    public var id: String { rawValue }
    public var label: String { self == .hours ? "Hours" : "Launches" }
    public func format(_ value: Double) -> String {
        self == .hours ? "\(Int(value.rounded()))h" : Int(value.rounded()).formatted()
    }
}

/// A device row the Widgets accordion can roll up by inventory dimension.
public protocol UsageAggregatable {
    var usage: String? { get }
    var catalog: String? { get }
    var location: String? { get }
    var department: String? { get }
    var area: String? { get }
    var fleet: String? { get }
    var totalHours: Double { get }
    var launchCount: Int { get }
}

/// The six usage widgets: sums by usage, catalog, fleet, area and location,
/// plus a histogram of devices by hours or launches.
public struct UsageAggregates: Sendable {
    public struct Bin: Sendable, Hashable {
        public let label: String
        public let min: Double
        public let max: Double
        public var count = 0
    }

    public let grandTotal: Double
    public let byLocation: [(label: String, value: Double)]
    public let byCatalog: [(label: String, value: Double)]
    public let byUsage: [(label: String, value: Double)]
    public let byArea: [(label: String, value: Double)]
    public let byFleet: [(label: String, value: Double)]
    public let bins: [Bin]
    public let deviceCount: Int

    public init<D: UsageAggregatable>(devices: [D], metric: UsageMetric) {
        func value(_ d: D) -> Double { metric == .hours ? d.totalHours : Double(d.launchCount) }
        let total = devices.reduce(0) { $0 + value($1) }
        grandTotal = total == 0 ? 1 : total
        func isUnknown(_ k: String?) -> Bool {
            guard let k else { return true }
            let v = k.trimmingCharacters(in: .whitespaces).lowercased()
            return v.isEmpty || v == "unknown" || v == "null" || v == "n/a"
        }
        func sum(_ key: (D) -> String?) -> [(label: String, value: Double)] {
            var m: [String: Double] = [:]
            for d in devices {
                let raw = key(d)
                if isUnknown(raw) { continue }
                m[raw!, default: 0] += value(d)
            }
            return m.filter { $0.value > 0 }.sorted { $0.value != $1.value ? $0.value > $1.value : $0.key < $1.key }.map { ($0.key, $0.value) }
        }
        byLocation = Array(sum { $0.location }.prefix(10))
        byCatalog = sum { $0.catalog }
        byUsage = sum { $0.usage }
        byArea = Array(sum { $0.area ?? $0.department }.prefix(10))
        byFleet = sum { $0.fleet }
        var bins: [Bin] = metric == .hours
            ? [Bin(label: "0–10h", min: 0, max: 10), Bin(label: "10–50h", min: 10, max: 50), Bin(label: "50–100h", min: 50, max: 100),
               Bin(label: "100–250h", min: 100, max: 250), Bin(label: "250h+", min: 250, max: .infinity)]
            : [Bin(label: "0–10", min: 0, max: 10), Bin(label: "10–50", min: 10, max: 50), Bin(label: "50–250", min: 50, max: 250),
               Bin(label: "250–1000", min: 250, max: 1000), Bin(label: "1000+", min: 1000, max: .infinity)]
        for d in devices {
            let v = value(d)
            if let i = bins.firstIndex(where: { v >= $0.min && v < $0.max }) { bins[i].count += 1 }
        }
        self.bins = bins
        deviceCount = devices.count
    }

    public var hasBins: Bool { bins.contains { $0.count > 0 } }
}

// MARK: - Per-app usage by device (`/applications/usage/by-device`)

public struct UsageDeviceRow: Sendable, Hashable, Identifiable, UsageAggregatable {
    public let serialNumber: String
    public let deviceName: String
    public let usage: String?
    public let catalog: String?
    public let location: String?
    public let room: String?
    public let department: String?
    public let area: String?
    public let fleet: String?
    public let assetTag: String?
    public let totalSeconds: Double
    public let totalHours: Double
    public let launchCount: Int
    public let userCount: Int
    public let users: [String]
    public let appVariants: [String]
    public let appVariantCount: Int
    public let firstUsed: String?
    public let lastUsed: String?
    public var id: String { serialNumber }

    public init(json: JSONValue) {
        let j = json.normalizedKeys()
        serialNumber = j["serialNumber"].nonEmptyString ?? ""
        deviceName = j["deviceName"].nonEmptyString ?? serialNumber
        usage = j["usage"].nonEmptyString
        catalog = j["catalog"].nonEmptyString
        location = j["location"].nonEmptyString
        room = j["room"].nonEmptyString
        department = j["department"].nonEmptyString
        area = j["area"].nonEmptyString
        fleet = j["fleet"].nonEmptyString
        assetTag = j["assetTag"].nonEmptyString
        totalSeconds = j["totalSeconds"].double ?? 0
        totalHours = j["totalHours"].double ?? totalSeconds / 3600
        launchCount = j["launchCount"].int ?? 0
        userCount = j["userCount"].int ?? 0
        users = j["users"].elements.compactMap(\.nonEmptyString)
        appVariants = j["appVariants"].elements.compactMap(\.nonEmptyString)
        appVariantCount = j["appVariantCount"].int ?? appVariants.count
        firstUsed = j["firstUsed"].nonEmptyString
        lastUsed = j["lastUsed"].nonEmptyString
    }

    public var areaOrDepartment: String? { area ?? department }
}

public struct UsageByDeviceReport: Sendable {
    public struct Summary: Sendable, Hashable {
        public let deviceCount: Int
        public let totalUsageHours: Double
        public let totalLaunches: Int
        public let uniqueUsers: Int
    }
    public let status: String
    public let appPattern: String
    public let days: Int
    public let devices: [UsageDeviceRow]
    public let summary: Summary
    public let lastUpdated: String?

    public init(json: JSONValue) {
        let j = json.normalizedKeys()
        status = j["status"].string ?? ""
        appPattern = j["appPattern"].string ?? ""
        days = j["days"].int ?? 0
        devices = j["devices"].elements.map(UsageDeviceRow.init(json:))
        let s = j["summary"].normalizedKeys()
        summary = Summary(deviceCount: s["deviceCount"].int ?? devices.count,
                          totalUsageHours: s["totalUsageHours"].double ?? devices.reduce(0) { $0 + $1.totalHours },
                          totalLaunches: s["totalLaunches"].int ?? devices.reduce(0) { $0 + $1.launchCount },
                          uniqueUsers: s["uniqueUsers"].int ?? Set(devices.flatMap(\.users)).count)
        lastUpdated = j["lastUpdated"].nonEmptyString
    }

    public var headline: String {
        "\(summary.deviceCount) devices · \(Int(summary.totalUsageHours.rounded()).formatted()) hours · \(summary.totalLaunches.formatted()) launches · \(summary.uniqueUsers) unique users"
    }
}

// MARK: - Usage data coverage (`/applications/collection-health`)

public struct CollectionHealth: Sendable {
    public struct Summary: Sendable, Hashable {
        public let totalDevices: Int
        public let healthy: Int
        public let stale: Int
        public let dark: Int
        public let never: Int
        public let freshDays: Int
        public let staleDays: Int
    }

    public struct PlatformCounts: Sendable, Hashable {
        public let healthy: Int
        public let stale: Int
        public let dark: Int
        public let never: Int
        public let total: Int
    }

    public enum Bucket: String, Sendable, Hashable { case dark, never }

    public struct DarkDevice: Sendable, Hashable, Identifiable {
        public let serialNumber: String
        public let deviceName: String
        public let platform: String?
        public let osName: String?
        public let lastSeen: String?
        public let usage: String?
        public let catalog: String?
        public let location: String?
        public let lastUsageDate: String?
        public let daysSinceUsage: Int?
        public let totalHoursEver: Double
        public let rowCount: Int
        public let bucket: Bucket
        public var id: String { serialNumber }

        public init(json: JSONValue) {
            let j = json.normalizedKeys()
            serialNumber = j["serialNumber"].nonEmptyString ?? ""
            deviceName = j["deviceName"].nonEmptyString ?? serialNumber
            platform = j["platform"].nonEmptyString
            osName = j["osName"].nonEmptyString
            lastSeen = j["lastSeen"].nonEmptyString
            usage = j["usage"].nonEmptyString
            catalog = j["catalog"].nonEmptyString
            location = j["location"].nonEmptyString
            lastUsageDate = j["lastUsageDate"].nonEmptyString
            daysSinceUsage = j["daysSinceUsage"].int
            totalHoursEver = j["totalHoursEver"].double ?? 0
            rowCount = j["rowCount"].int ?? 0
            bucket = Bucket(rawValue: j["bucket"].string ?? "") ?? .dark
        }
    }

    public let summary: Summary
    public let byPlatform: [String: PlatformCounts]
    public let darkDevices: [DarkDevice]
    public let error: String?

    public init(json: JSONValue) {
        let j = json.normalizedKeys()
        let s = j["summary"].normalizedKeys()
        summary = Summary(totalDevices: s["totalDevices"].int ?? 0, healthy: s["healthy"].int ?? 0, stale: s["stale"].int ?? 0,
                          dark: s["dark"].int ?? 0, never: s["never"].int ?? 0, freshDays: s["freshDays"].int ?? 7, staleDays: s["staleDays"].int ?? 30)
        var platforms: [String: PlatformCounts] = [:]
        for (name, c) in j["byPlatform"].object ?? [:] {
            platforms[name] = PlatformCounts(healthy: c["healthy"].int ?? 0, stale: c["stale"].int ?? 0, dark: c["dark"].int ?? 0,
                                             never: c["never"].int ?? 0, total: c["total"].int ?? 0)
        }
        byPlatform = platforms
        darkDevices = j["darkDevices"].elements.map(DarkDevice.init(json:))
        error = j["error"].nonEmptyString
    }

    public var platformNames: [String] { byPlatform.keys.sorted() }
}
