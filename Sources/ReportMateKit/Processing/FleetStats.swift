import Foundation

/// Aggregations behind the dashboard charts.
public enum FleetStats {
    // MARK: Status donut

    public struct StatusSlice: Sendable, Hashable, Identifiable {
        public var id: DeviceStatus { status }
        public var status: DeviceStatus
        public var count: Int
        public var percentage: Int
    }

    public static func statusDistribution(_ devices: [DeviceSummary]) -> [StatusSlice] {
        guard !devices.isEmpty else { return [] }
        var counts: [DeviceStatus: Int] = [:]
        for d in devices { counts[d.status, default: 0] += 1 }
        return counts.map { StatusSlice(status: $0.key, count: $0.value, percentage: Int((Double($0.value) / Double(devices.count) * 100).rounded())) }
            .sorted { a, b in
                if a.status.sortOrder != b.status.sortOrder { return a.status.sortOrder < b.status.sortOrder }
                return a.count > b.count
            }
    }

    // MARK: New clients

    public static func newClients(_ devices: [DeviceSummary], days: Int = 7, now: Date = Date()) -> [DeviceSummary] {
        let cutoff = now.addingTimeInterval(-Double(days) * 86400)
        return devices.filter { ($0.createdAt ?? .distantPast) >= cutoff }
            .sorted { ($0.createdAt ?? .distantPast) > ($1.createdAt ?? .distantPast) }
    }

    // MARK: OS versions

    public struct VersionNode: Sendable, Hashable, Identifiable {
        public var id: String { name }
        public var name: String
        public var displayName: String
        public var sortKey: Double
        public var count: Int
        public var children: [VersionNode]
        public var parentName: String?
        /// Position among siblings, newest first, for the temperature palette.
        public var index: Int
        public var siblingCount: Int
    }

    /// `processVersionsHierarchical`: Macs group by major.minor and drill to
    /// patch; Windows groups by marketing major + build and drills to feature.
    public static func osVersions(_ devices: [DeviceSummary], platform: Platform) -> [VersionNode] {
        struct Group { var count = 0; var sortKey = 0.0; var displayName = ""; var children: [String: (count: Int, sortKey: Double)] = [:]; var order: [String] = [] }
        var groups: [String: Group] = [:]
        var order: [String] = []
        for d in devices where d.platform == platform {
            guard let version = d.osVersion, !version.isEmpty else { continue }
            let parts = version.split(separator: ".").map { Int($0.prefix { $0.isNumber }) ?? 0 }
            if platform == .macOS {
                let major = parts.first ?? 0
                let minor = parts.count > 1 ? parts[1] : 0
                let patch = parts.count > 2 ? parts[2] : 0
                let groupKey = "\(major).\(minor)"
                let childKey = "\(major).\(minor).\(patch)"
                if groups[groupKey] == nil { groups[groupKey] = Group(sortKey: Double(major * 10000 + minor * 100), displayName: groupKey); order.append(groupKey) }
                groups[groupKey]!.count += 1
                if groups[groupKey]!.children[childKey] == nil { groups[groupKey]!.order.append(childKey) }
                groups[groupKey]!.children[childKey, default: (0, Double(major * 10000 + minor * 100 + patch))].count += 1
            } else {
                let name = d.osName ?? ""
                let winMajor = name.range(of: #"Windows\s+(\d+)"#, options: .regularExpression).map { String(name[$0]).split(separator: " ").last.map(String.init) ?? "11" } ?? "11"
                let majorNum = Int(winMajor) ?? 11
                let build = parts.count > 2 ? String(parts[2]) : (d.osBuild ?? "0")
                let buildNum = Int(build) ?? 0
                let feature = Int(d.osFeatureUpdate ?? "0") ?? 0
                let groupKey = "\(winMajor).\(build)"
                let childKey = "\(winMajor).\(build).\(feature > 0 ? feature : 0)"
                if groups[groupKey] == nil { groups[groupKey] = Group(sortKey: Double(majorNum * 100000 + buildNum), displayName: groupKey); order.append(groupKey) }
                groups[groupKey]!.count += 1
                if groups[groupKey]!.children[childKey] == nil { groups[groupKey]!.order.append(childKey) }
                groups[groupKey]!.children[childKey, default: (0, Double(majorNum) * 100_000_000 + Double(buildNum) * 1000 + Double(feature))].count += 1
            }
        }
        let sortedGroups = groups.sorted { $0.value.sortKey > $1.value.sortKey }
        return sortedGroups.enumerated().map { index, entry in
            let (key, g) = entry
            let sortedChildren = g.children.sorted { $0.value.sortKey > $1.value.sortKey }
            let children = sortedChildren.enumerated().map { ci, c in
                VersionNode(name: c.key, displayName: c.key, sortKey: c.value.sortKey, count: c.value.count, children: [], parentName: g.displayName, index: ci, siblingCount: sortedChildren.count)
            }
            return VersionNode(name: key, displayName: g.displayName, sortKey: g.sortKey, count: g.count, children: children, parentName: nil, index: index, siblingCount: sortedGroups.count)
        }
    }

    // MARK: Platform distribution

    public struct AgeStats: Sendable, Hashable {
        public var averageAgeDays: Double = 0
        public var newest: Date?
        public var oldest: Date?
        public var devicesWithAge = 0
        public var totalDevices = 0
    }

    public struct PlatformStats: Sendable, Hashable, Identifiable {
        public var id: Platform { platform }
        public var platform: Platform
        public var count: Int
        public var percentage: Int
        public var architectures: [String: Int]
        public var catalogs: [String: Int]
        public var usages: [String: Int]
        public var departments: [String: Int]
        public var ageStats: AgeStats
    }

    public struct UsageStats: Sendable, Hashable, Identifiable {
        public var id: String { usage }
        public var usage: String
        public var count: Int
        public var percentage: Int
        public var architectures: [String: Int]
        public var catalogs: [String: Int]
        public var departments: [String: Int]
    }

    public struct DistributionFilters: Sendable, Hashable {
        public var architecture: Set<String> = []
        public var catalog: Set<String> = []
        public var usage: Set<String> = []
        public init() {}
        public var isEmpty: Bool { architecture.isEmpty && catalog.isEmpty && usage.isEmpty }
    }

    public static func normalizeArchitecture(_ arch: String?) -> String {
        guard let arch, !arch.isEmpty else { return "Unknown" }
        let n = arch.lowercased().trimmingCharacters(in: .whitespaces)
        if n == "arm x64 processor" { return "arm64" }
        if n.contains("arm64") || n.contains("aarch64") { return "arm64" }
        if n.contains("arm"), n.contains("64") { return "arm64" }
        if n == "64-bit" || n.contains("x64") || n.contains("amd64") || n.contains("x86_64") { return "x64" }
        if n.contains("x86"), !n.contains("64") { return "x86" }
        if n.contains("ia64") { return "IA64" }
        return arch
    }

    public static func architecture(of device: DeviceSummary) -> String {
        if let a = device.raw["modules"]["hardware"]["processor"]["architecture"].nonEmptyString { return normalizeArchitecture(a) }
        if let a = device.osArchitecture { return normalizeArchitecture(a) }
        return "Unknown"
    }

    static func matches(_ d: DeviceSummary, _ f: DistributionFilters) -> Bool {
        if !f.architecture.isEmpty, !f.architecture.contains(architecture(of: d)) { return false }
        if !f.catalog.isEmpty, !f.catalog.contains(d.inventory.catalog ?? "Unknown") { return false }
        if !f.usage.isEmpty, !f.usage.contains(d.inventory.usage ?? "Unknown") { return false }
        return true
    }

    public static func platformDistribution(_ devices: [DeviceSummary], filters: DistributionFilters = DistributionFilters(), now: Date = Date()) -> [PlatformStats] {
        let filtered = devices.filter { matches($0, filters) }
        var stats: [Platform: PlatformStats] = [:]
        var ages: [Platform: [Date]] = [:]
        for p in Platform.allCases {
            stats[p] = PlatformStats(platform: p, count: 0, percentage: 0, architectures: [:], catalogs: [:], usages: [:], departments: [:], ageStats: AgeStats())
            ages[p] = []
        }
        for d in filtered {
            let p = d.platform
            stats[p]!.count += 1
            let arch = architecture(of: d)
            if arch != "Unknown" { stats[p]!.architectures[arch, default: 0] += 1 }
            if let c = d.inventory.catalog { stats[p]!.catalogs[c, default: 0] += 1 }
            if let u = d.inventory.usage { stats[p]!.usages[u, default: 0] += 1 }
            if let dep = d.inventory.department { stats[p]!.departments[dep, default: 0] += 1 }
            if let created = d.createdAt { ages[p]!.append(created) }
        }
        for p in Platform.allCases {
            let dates = ages[p]!
            stats[p]!.ageStats.totalDevices = stats[p]!.count
            stats[p]!.ageStats.devicesWithAge = dates.count
            if !dates.isEmpty {
                stats[p]!.ageStats.newest = dates.max()
                stats[p]!.ageStats.oldest = dates.min()
                stats[p]!.ageStats.averageAgeDays = dates.reduce(0) { $0 + now.timeIntervalSince($1) / 86400 } / Double(dates.count)
            }
        }
        let known = filtered.filter { $0.platform != .unknown }.count
        return Platform.allCases.compactMap { p -> PlatformStats? in
            guard var s = stats[p], s.count > 0, p != .unknown else { return nil }
            s.percentage = known > 0 ? Int((Double(s.count) / Double(known) * 100).rounded()) : 0
            return s
        }.sorted { $0.count > $1.count }
    }

    public static func usageDistribution(_ devices: [DeviceSummary], filters: DistributionFilters = DistributionFilters()) -> [UsageStats] {
        var f = filters
        f.usage = []
        let filtered = devices.filter { matches($0, f) }
        var stats: [String: UsageStats] = [:]
        var order: [String] = []
        for d in filtered {
            let usage = d.inventory.usage ?? "Unknown"
            if stats[usage] == nil {
                stats[usage] = UsageStats(usage: usage, count: 0, percentage: 0, architectures: [:], catalogs: [:], departments: [:])
                order.append(usage)
            }
            stats[usage]!.count += 1
            let arch = architecture(of: d)
            if arch != "Unknown" { stats[usage]!.architectures[arch, default: 0] += 1 }
            if let c = d.inventory.catalog { stats[usage]!.catalogs[c, default: 0] += 1 }
            if let dep = d.inventory.department { stats[usage]!.departments[dep, default: 0] += 1 }
        }
        let total = filtered.count
        return order.compactMap { stats[$0] }.map { s in
            var s = s
            s.percentage = total > 0 ? Int((Double(s.count) / Double(total) * 100).rounded()) : 0
            return s
        }.sorted { $0.count > $1.count }
    }

    public struct AvailableFilters: Sendable, Hashable {
        public var architectures: [String] = []
        public var catalogs: [String] = []
        public var usages: [String] = []
    }

    public static func availableFilters(_ devices: [DeviceSummary]) -> AvailableFilters {
        var a = Set<String>(), c = Set<String>(), u = Set<String>()
        for d in devices {
            let arch = architecture(of: d)
            if arch != "Unknown" { a.insert(arch) }
            if let cat = d.inventory.catalog { c.insert(cat) }
            if let usage = d.inventory.usage { u.insert(usage) }
        }
        return AvailableFilters(architectures: a.sorted(), catalogs: c.sorted(), usages: u.sorted())
    }
}
