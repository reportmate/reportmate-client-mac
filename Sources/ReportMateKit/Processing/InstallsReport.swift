import Foundation

// MARK: - Filter options (`/installs/filters`)

/// A device from the installs filter endpoint: slimmed installs data
/// (items, config, latest session, counts) plus inventory fields.
public struct InstallsDevice: Sendable, Hashable, Identifiable {
    public let raw: JSONValue
    public let serialNumber: String
    public let deviceId: String
    public let deviceName: String
    public let assetTag: String?
    public let usage: String?
    public let catalog: String?
    public let location: String?
    public let fleet: String?
    public let area: String?
    public let rawPlatform: String?
    public let platform: Platform
    public let lastSeen: String?
    public let archived: Bool
    public var id: String { serialNumber }

    public init(json: JSONValue) {
        raw = json
        let inv = json["modules"]["inventory"]
        serialNumber = json["serialNumber"].nonEmptyString ?? json["deviceId"].nonEmptyString ?? ""
        deviceId = json["deviceId"].nonEmptyString ?? serialNumber
        let name = inv.firstString("deviceName", "device_name") ?? json["deviceName"].nonEmptyString ?? serialNumber
        deviceName = name.lowercased() == "unknown" ? serialNumber : name
        assetTag = inv.firstString("assetTag", "asset_tag")
        usage = inv["usage"].nonEmptyString
        catalog = inv["catalog"].nonEmptyString
        location = inv["location"].nonEmptyString
        fleet = inv["fleet"].nonEmptyString
        area = inv["area"].nonEmptyString ?? inv["department"].nonEmptyString
        rawPlatform = json["platform"].nonEmptyString ?? inv["platform"].nonEmptyString
        let installs = json["modules"]["installs"]
        var detected = Platform.detect(device: json)
        if detected == .unknown {
            if installs["cimian"].object != nil { detected = .windows } else if installs["munki"].object != nil { detected = .macOS }
        }
        platform = detected
        lastSeen = json["lastSeen"].nonEmptyString
        archived = json["archived"].boolish
    }

    public var cimian: JSONValue { raw["modules"]["installs"]["cimian"] }
    public var munki: JSONValue { raw["modules"]["installs"]["munki"] }
    public var hasCimian: Bool { cimian.object != nil }
    public var hasMunki: Bool { munki.object != nil }
    public var cimianVersion: String? { cimian["version"].nonEmptyString }
    public var munkiVersion: String? { munki["version"].nonEmptyString }
    public var items: [JSONValue] { InstallItems.items(of: raw) }
    public var status: DeviceStatus { DeviceStatus.calculate(lastSeen: lastSeen, archived: false) }

    /// Cimian's config wins, then Munki's identifier or manifest.
    public var manifest: String? {
        cimian["config"].firstString("ClientIdentifier", "clientIdentifier") ?? munki["clientIdentifier"].nonEmptyString ?? munki["manifest"].nonEmptyString ?? munki["manifestName"].nonEmptyString
    }

    public var softwareRepoURL: String? {
        cimian["config"].firstString("SoftwareRepoURL", "softwareRepoURL") ?? munki["softwareRepoURL"].nonEmptyString
    }

    /// The tool's own status filter labels: a device's raw platform, or the tool it runs.
    public var configType: String { hasCimian ? "Cimian" : hasMunki ? "Munki" : "None" }

    public var searchableInventoryName: String { deviceName.lowercased() }
}

public struct InstallsFilterOptions: Sendable, Hashable {
    public var managedInstalls: [String] = []
    public var cimianInstalls: [String] = []
    public var munkiInstalls: [String] = []
    public var otherInstalls: [String] = []
    public var usages: [String] = []
    public var catalogs: [String] = []
    public var rooms: [String] = []
    public var areas: [String] = []
    public var fleets: [String] = []
    public var platforms: [String] = []
    public var softwareRepos: [String] = []
    public var manifests: [String] = []
    public var devicesWithData = 0
    public var devices: [InstallsDevice] = []

    public init() {}

    public init(json: JSONValue) {
        let j = json.normalizedKeys()
        func list(_ key: String) -> [String] { j[key].elements.compactMap(\.nonEmptyString) }
        managedInstalls = list("managedInstalls")
        cimianInstalls = list("cimianInstalls")
        munkiInstalls = list("munkiInstalls")
        otherInstalls = list("otherInstalls")
        usages = list("usages")
        catalogs = list("catalogs")
        rooms = list("rooms")
        areas = list("areas")
        fleets = list("fleets")
        platforms = list("platforms")
        softwareRepos = list("softwareRepos")
        manifests = list("manifests")
        devices = json["devices"].elements.map(InstallsDevice.init(json:))
        devicesWithData = j["devicesWithData"].int ?? devices.count
    }

    /// Item names for the picker under the platform toggle.
    public func items(for filter: PlatformFilter) -> [String] {
        switch filter {
        case .windows where !cimianInstalls.isEmpty: return cimianInstalls
        case .macOS where !munkiInstalls.isEmpty: return munkiInstalls
        default: return managedInstalls + otherInstalls
        }
    }
}

// MARK: - Config report rows

/// One device in the default "config report": tool, version, manifest,
/// repo and per-status package counts.
public struct ConfigReportRow: Sendable, Hashable, Identifiable {
    public let device: InstallsDevice
    public let configType: String
    public let clientIdentifier: String
    public let softwareRepoUrl: String
    public let version: String
    public let lastSessionStatus: String
    public let totalPackagesManaged: Int
    public let installedCount: Int
    public let pendingCount: Int
    public let errorCount: Int
    public let warningCount: Int
    public let removedCount: Int
    public var id: String { device.serialNumber }

    public var serialNumber: String { device.serialNumber }
    public var deviceName: String { device.deviceName }
    public var assetTag: String? { device.assetTag }
    public var usage: String { device.usage ?? "Unknown" }
    public var catalog: String { device.catalog ?? "Unknown" }
    public var location: String { device.location ?? "Unknown" }
    public var fleet: String { device.fleet ?? "Unknown" }
    public var area: String? { device.area }
    public var lastSeen: String? { device.lastSeen }
    public var platformLabel: String { device.rawPlatform ?? (configType == "Cimian" ? "Windows" : configType == "Munki" ? "macOS" : "Unknown") }

    /// `nil` when the device runs neither tool.
    public init?(device: InstallsDevice) {
        let cimian = device.cimian, munki = device.munki
        let config = device.hasCimian ? cimian : munki
        guard device.hasCimian || device.hasMunki else { return nil }
        self.device = device
        configType = device.configType
        clientIdentifier = device.manifest ?? "N/A"
        softwareRepoUrl = device.softwareRepoURL ?? "N/A"
        version = config["version"].nonEmptyString ?? "N/A"
        lastSessionStatus = config["sessions"].elements.first?["status"].nonEmptyString ?? "N/A"
        let counts = config.first("itemCounts", "item_counts")
        if counts.object != nil {
            installedCount = counts["installed"].int ?? 0
            pendingCount = counts["pending"].int ?? 0
            errorCount = counts["error"].int ?? 0
            warningCount = counts["warning"].int ?? 0
            removedCount = counts["removed"].int ?? 0
            totalPackagesManaged = counts["total"].int ?? 0
        } else {
            var installed = 0, pending = 0, error = 0, warning = 0, removed = 0
            let items = config["items"].elements
            for item in items {
                switch InstallStatusClass.classify(item.firstString("currentStatus", "current_status", "status") ?? "") {
                case .installed: installed += 1
                case .pending: pending += 1
                case .error: error += 1
                case .warning: warning += 1
                case .removed: removed += 1
                }
            }
            installedCount = installed; pendingCount = pending; errorCount = error; warningCount = warning; removedCount = removed
            totalPackagesManaged = items.count
        }
    }

    public func count(for filter: InstallStatusClass) -> Int {
        switch filter {
        case .installed: return installedCount
        case .pending: return pendingCount
        case .warning: return warningCount
        case .error: return errorCount
        case .removed: return removedCount
        }
    }
}

/// The five install-status buckets used by the status pills and config counts.
public enum InstallStatusClass: String, Sendable, Hashable, CaseIterable, Identifiable {
    case installed, pending, warning, error, removed
    public var id: String { rawValue }

    public var label: String {
        switch self {
        case .installed: return "Installed"
        case .pending: return "Pending"
        case .warning: return "Warnings"
        case .error: return "Errors"
        case .removed: return "Removed"
        }
    }

    /// `classifyItemStatus`: buckets a raw status for the config counts.
    public static func classify(_ raw: String) -> InstallStatusClass {
        let status = raw.lowercased()
        if status.contains("error") || status.contains("failed") || status.contains("problem") || status == "needs_reinstall" { return .error }
        if status.contains("warning") || status == "needs-attention" { return .warning }
        if status.contains("will-be-removed") || status.contains("removal-requested") { return .removed }
        if status.contains("will-be-installed") || status.contains("update-available") || status.contains("update_available") || status.contains("pending")
            || status.contains("scheduled") || status == "managed-update-available" { return .pending }
        return .installed
    }

    /// The status-pill predicate over an install record's status string.
    public func matches(recordStatus raw: String?) -> Bool {
        let status = (raw ?? "").lowercased()
        switch self {
        case .installed: return status.contains("installed") || status == "present"
        case .pending: return status.contains("pending") || status.contains("will-be-installed") || status.contains("update-available") || status.contains("scheduled") || status == "managed-update-available"
        case .warning: return status.contains("warning") || status == "needs-attention"
        case .error: return status.contains("error") || status.contains("failed") || status == "needs_reinstall"
        case .removed: return status.contains("removed") || status.contains("will-be-removed") || status.contains("removal")
        }
    }

    /// The bucket a record's status string counts under (first match wins).
    public static func bucket(recordStatus raw: String?) -> InstallStatusClass? {
        let status = (raw ?? "").lowercased()
        if status.contains("installed") || status == "present" { return .installed }
        if InstallStatusClass.pending.matches(recordStatus: status) { return .pending }
        if InstallStatusClass.warning.matches(recordStatus: status) { return .warning }
        if status.contains("error") || status.contains("failed") || status.contains("problem") || status == "needs_reinstall" { return .error }
        if InstallStatusClass.removed.matches(recordStatus: status) { return .removed }
        return nil
    }
}

// MARK: - Install records (`/installs` bulk)

/// One (device, package) row from the bulk installs endpoint.
public struct InstallRecord: Sendable, Hashable, Identifiable {
    public let id: String
    public let deviceId: String
    public let deviceName: String
    public let serialNumber: String
    public let assetTag: String?
    public let lastSeen: String?
    public let name: String
    public let version: String
    public let status: String
    public let source: String
    public let usage: String?
    public let catalog: String?
    public let room: String?
    public let fleet: String?
    public let area: String?
    public let platform: String
    public var manifest: String?

    public init(json: JSONValue) {
        let j = json.normalizedKeys()
        serialNumber = j["serialNumber"].nonEmptyString ?? ""
        deviceId = j["deviceId"].nonEmptyString ?? serialNumber
        deviceName = j["deviceName"].nonEmptyString ?? serialNumber
        assetTag = j["assetTag"].nonEmptyString
        lastSeen = j["lastSeen"].nonEmptyString
        name = j["itemName"].nonEmptyString ?? j["displayName"].nonEmptyString ?? j["name"].nonEmptyString ?? ""
        version = j["installedVersion"].nonEmptyString ?? j["latestVersion"].nonEmptyString ?? ""
        status = j["currentStatus"].nonEmptyString?.lowercased() ?? j["status"].nonEmptyString?.lowercased() ?? "unknown"
        source = j["source"].nonEmptyString ?? "cimian"
        usage = j["usage"].nonEmptyString
        catalog = j["catalog"].nonEmptyString
        room = j["location"].nonEmptyString ?? j["room"].nonEmptyString
        fleet = j["fleet"].nonEmptyString
        area = j["area"].nonEmptyString ?? j["department"].nonEmptyString
        platform = InstallRecord.platformLabel(j["platform"].nonEmptyString)
        manifest = j["manifest"].nonEmptyString
        id = j["id"].nonEmptyString ?? "\(serialNumber)-\(name)"
    }

    /// The web's label: Windows, Macintosh, or the raw value.
    public static func platformLabel(_ raw: String?) -> String {
        guard let raw, !raw.isEmpty else { return "Unknown" }
        let lower = raw.lowercased()
        if raw == "Windows NT" || lower.contains("windows") { return "Windows" }
        if raw == "Darwin" || lower.contains("mac") { return "Macintosh" }
        return raw
    }

    /// Cimian's virtual managed_apps / managed_profiles items are not packages.
    public var isVirtualItem: Bool { name == "managed_apps" || name == "managed_profiles" }
    public var isManaged: Bool { source == "cimian" || source == "munki" }
    public var searchKey: String { "\(name) - \(version.isEmpty ? "Unknown" : version)" }
}

// MARK: - Aggregations

/// A distinct message with the devices that reported it (the Errors and
/// Warnings widgets, and the per-item panel).
public struct AggregatedInstallMessage: Sendable, Hashable, Identifiable {
    public struct Occurrence: Sendable, Hashable {
        public let serialNumber: String
        public let deviceName: String
        public let itemName: String?
        public let timestamp: String?
    }
    public let message: String
    public var count: Int
    public var devices: [Occurrence]
    public let isError: Bool
    public let source: String
    public var id: String { message }
}

/// Distinct message text with every device and package that reported it.
public struct InstallMessageGroup: Sendable, Hashable, Identifiable {
    public struct Device: Sendable, Hashable, Identifiable {
        public let serialNumber: String
        public let deviceName: String
        public let assetTag: String?
        public var itemNames: [String]
        public let timestamp: String?
        public let lastSeen: String?
        public var id: String { serialNumber }
    }
    public let message: String
    public var itemNames: [String]
    public var occurrences: Int
    public var devices: [Device]
    public var deviceCount: Int { devices.count }
    public var id: String { message }
}

/// A package name with how many devices carry it in a given status.
public struct InstallItemCount: Sendable, Hashable, Identifiable {
    public let name: String
    public var count: Int
    public var devices: [String]
    public var id: String { name }
}

public enum InstallsReport {
    /// The web `/api/v1/installs` route: bulk rows narrowed to the chosen
    /// items and inventory selections, with the manifest joined from the
    /// filter devices. Both tools' rows are kept.
    public static func records(from rows: [InstallRecord], selectedInstalls: [String], usages: Set<String>, catalogs: Set<String>,
                               rooms: Set<String>, fleets: Set<String>, areas: Set<String>, manifests: [String: String]) -> [InstallRecord] {
        let names = Set(selectedInstalls.map { $0.lowercased() })
        let usages = Set(usages.map { $0.lowercased() }), catalogs = Set(catalogs.map { $0.lowercased() })
        return rows.compactMap { row in
            if row.isVirtualItem || row.name.isEmpty { return nil }
            if !names.isEmpty, !names.contains(row.name.lowercased()) { return nil }
            if !usages.isEmpty, !usages.contains(row.usage?.lowercased() ?? "") { return nil }
            if !catalogs.isEmpty, !catalogs.contains(row.catalog?.lowercased() ?? "") { return nil }
            if !rooms.isEmpty, !rooms.contains(row.room ?? "") { return nil }
            if !fleets.isEmpty, !fleets.contains(row.fleet ?? "") { return nil }
            if !areas.isEmpty, !areas.contains(row.area ?? "") { return nil }
            var out = row
            if out.manifest == nil { out.manifest = manifests[row.serialNumber] }
            return out
        }
    }

    /// `categorizeDevicesByInstallStatus`.
    public static func categorize(_ devices: [InstallsDevice]) -> (errors: [InstallsDevice], warnings: [InstallsDevice], pending: [InstallsDevice], success: [InstallsDevice]) {
        var errors: [InstallsDevice] = [], warnings: [InstallsDevice] = [], pending: [InstallsDevice] = [], success: [InstallsDevice] = []
        for device in devices where !device.archived {
            let items = device.items
            if items.contains(where: InstallItems.isError) { errors.append(device) }
            if items.contains(where: InstallItems.isWarning) || !InstallItems.runLevelWarnings(of: device.raw).isEmpty { warnings.append(device) }
            if items.contains(where: InstallItems.isPending) { pending.append(device) }
            if items.contains(where: InstallItems.isSuccess) { success.append(device) }
        }
        return (errors, warnings, pending, success)
    }

    /// Items with a status across the fleet, counted per package name.
    public static func itemCounts(_ devices: [InstallsDevice], _ category: InstallItems.Category) -> [InstallItemCount] {
        var map: [String: InstallItemCount] = [:]
        var order: [String] = []
        func add(_ name: String, _ serial: String) {
            if map[name] == nil { map[name] = InstallItemCount(name: name, count: 0, devices: []); order.append(name) }
            map[name]!.count += 1
            map[name]!.devices.append(serial)
        }
        for device in devices where !device.archived {
            let serial = device.serialNumber.isEmpty ? device.deviceId : device.serialNumber
            for item in device.items where InstallItems.matches(item, category) { add(InstallItems.name(of: item), serial) }
            if category == .warning {
                for (_, itemName) in InstallItems.runLevelWarnings(of: device.raw) { if let itemName { add(itemName, serial) } }
            }
        }
        return order.compactMap { map[$0] }
    }

    /// `aggregateInstallErrors` / `aggregateInstallWarnings`.
    public static func aggregateMessages(_ devices: [InstallsDevice], errors: Bool) -> [AggregatedInstallMessage] {
        var map: [String: AggregatedInstallMessage] = [:]
        var order: [String] = []
        func add(_ message: String, _ occurrence: AggregatedInstallMessage.Occurrence, source: String) {
            if map[message] == nil {
                map[message] = AggregatedInstallMessage(message: message, count: 0, devices: [], isError: errors, source: source)
                order.append(message)
            }
            map[message]!.count += 1
            map[message]!.devices.append(occurrence)
        }
        for device in devices where !device.archived {
            let serial = device.serialNumber.isEmpty ? device.deviceId : device.serialNumber
            let source = device.hasCimian ? "cimian" : "munki"
            for item in device.items {
                if !errors, InstallItems.isError(item) { continue }
                guard let text = item.firstString(errors ? "lastError" : "lastWarning", errors ? "last_error" : "last_warning")?.trimmingCharacters(in: .whitespacesAndNewlines), !text.isEmpty else { continue }
                add(text, .init(serialNumber: serial, deviceName: device.deviceName, itemName: InstallItems.name(of: item), timestamp: item.firstString("lastUpdate", "last_update", "lastAttemptTime", "last_attempt_time")), source: source)
            }
            let munki = device.munki
            let runText = munki[errors ? "errors" : "warnings"].nonEmptyString ?? ""
            if !runText.trimmingCharacters(in: .whitespaces).isEmpty {
                for part in runText.replacingOccurrences(of: errors ? "ERROR:" : "WARNING:", with: "\n").components(separatedBy: .newlines) {
                    let t = part.trimmingCharacters(in: .whitespaces)
                    if t.isEmpty { continue }
                    add(t, .init(serialNumber: serial, deviceName: device.deviceName, itemName: nil, timestamp: munki["endTime"].nonEmptyString), source: "munki")
                }
            }
            if !errors, let problems = munki["problemInstalls"].nonEmptyString?.trimmingCharacters(in: .whitespaces), !problems.isEmpty {
                add("Problem installs: \(problems)", .init(serialNumber: serial, deviceName: device.deviceName, itemName: nil, timestamp: munki["endTime"].nonEmptyString), source: "munki")
            }
        }
        return order.compactMap { map[$0] }.sorted { $0.count > $1.count }
    }

    /// `getMessagesForItem`: the messages one package produced.
    public static func messages(forItem itemName: String, in devices: [InstallsDevice], errors: Bool) -> [AggregatedInstallMessage] {
        var map: [String: AggregatedInstallMessage] = [:]
        var order: [String] = []
        let wanted = itemName.lowercased()
        for device in devices where !device.archived {
            let serial = device.serialNumber.isEmpty ? device.deviceId : device.serialNumber
            for item in device.items {
                let name = InstallItems.name(of: item)
                guard name.lowercased() == wanted else { continue }
                guard let text = item.firstString(errors ? "lastError" : "lastWarning", errors ? "last_error" : "last_warning")?.trimmingCharacters(in: .whitespacesAndNewlines), !text.isEmpty else { continue }
                if map[text] == nil {
                    map[text] = AggregatedInstallMessage(message: text, count: 0, devices: [], isError: errors, source: device.hasCimian ? "cimian" : "munki")
                    order.append(text)
                }
                map[text]!.count += 1
                map[text]!.devices.append(.init(serialNumber: serial, deviceName: device.deviceName, itemName: name, timestamp: item.firstString("lastUpdate", "last_update", "lastAttemptTime", "last_attempt_time")))
            }
        }
        return order.compactMap { map[$0] }.sorted { $0.count > $1.count }
    }

    /// `aggregateStatusMessages`: every item in a status grouped by message.
    public static func statusMessageGroups(_ devices: [InstallsDevice], _ category: InstallItems.Category, nameFilter: String = "") -> [InstallMessageGroup] {
        var groups: [String: InstallMessageGroup] = [:]
        var order: [String] = []
        var byDevice: [String: [String: InstallMessageGroup.Device]] = [:]
        let filter = nameFilter.lowercased()
        for device in devices where !device.archived {
            let serial = device.serialNumber.isEmpty ? device.deviceId : device.serialNumber
            for item in device.items where InstallItems.matches(item, category) {
                let itemName = InstallItems.name(of: item)
                let message = InstallItems.message(of: item, category)
                if !filter.isEmpty, !itemName.lowercased().contains(filter), !message.lowercased().contains(filter) { continue }
                if groups[message] == nil {
                    groups[message] = InstallMessageGroup(message: message, itemNames: [], occurrences: 0, devices: [])
                    order.append(message)
                }
                groups[message]!.occurrences += 1
                if !groups[message]!.itemNames.contains(itemName) { groups[message]!.itemNames.append(itemName) }
                var devs = byDevice[message] ?? [:]
                if devs[serial] == nil {
                    devs[serial] = InstallMessageGroup.Device(serialNumber: serial, deviceName: device.deviceName, assetTag: device.assetTag, itemNames: [],
                                                              timestamp: InstallItems.timestamp(of: item), lastSeen: device.lastSeen)
                }
                if !devs[serial]!.itemNames.contains(itemName) { devs[serial]!.itemNames.append(itemName) }
                byDevice[message] = devs
            }
        }
        var out: [InstallMessageGroup] = []
        for key in order {
            guard var g = groups[key] else { continue }
            g.devices = (byDevice[key] ?? [:]).values.sorted { $0.deviceName.localizedCaseInsensitiveCompare($1.deviceName) == .orderedAscending }
            g.itemNames.sort { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending }
            out.append(g)
        }
        return out.sorted { a, b in
            if a.message.isEmpty != b.message.isEmpty { return !a.message.isEmpty }
            if a.deviceCount != b.deviceCount { return a.deviceCount > b.deviceCount }
            return a.message.localizedCaseInsensitiveCompare(b.message) == .orderedAscending
        }
    }

    /// Software repos by device count.
    public static func repoCounts(_ devices: [InstallsDevice]) -> [(repo: String, count: Int)] {
        var counts: [String: Int] = [:]
        for d in devices { if let repo = d.softwareRepoURL { counts[repo, default: 0] += 1 } }
        return counts.sorted { $0.value != $1.value ? $0.value > $1.value : $0.key < $1.key }.map { ($0.key, $0.value) }
    }

    /// Tool versions, newest first, Unknown last.
    public static func versionCounts(_ devices: [InstallsDevice], cimian: Bool) -> (total: Int, versions: [(version: String, count: Int)]) {
        let tool = devices.filter { cimian ? $0.cimianVersion != nil : $0.munkiVersion != nil }
        var counts: [String: Int] = [:]
        for d in tool { counts[(cimian ? d.cimianVersion : d.munkiVersion) ?? "Unknown", default: 0] += 1 }
        let sorted = counts.keys.sorted { a, b in
            if a == "Unknown" { return false }
            if b == "Unknown" { return true }
            return ApplicationsReport.compareVersions(a, b) == .orderedDescending
        }
        return (tool.count, sorted.map { ($0, counts[$0] ?? 0) })
    }

    /// Manifests (Cimian client identifiers and Munki manifests) by device count.
    public static func manifestCounts(_ devices: [InstallsDevice]) -> [(manifest: String, count: Int)] {
        var counts: [String: Int] = [:]
        for d in devices {
            let cimian = d.cimian["config"].firstString("ClientIdentifier", "clientIdentifier")
            if let cimian { counts[cimian, default: 0] += 1 }
            if let munki = d.munki["manifest"].nonEmptyString ?? d.munki["manifestName"].nonEmptyString, munki != cimian { counts[munki, default: 0] += 1 }
        }
        return counts.sorted { $0.value != $1.value ? $0.value > $1.value : $0.key < $1.key }.map { ($0.key, $0.value) }
    }

    /// "Install Item(s) Versions": managed records grouped by item then version.
    public static func itemVersions(_ records: [InstallRecord]) -> [(name: String, total: Int, versions: [(version: String, count: Int)])] {
        var byName: [String: [String: Int]] = [:]
        for r in records where r.isManaged {
            byName[r.name, default: [:]][r.version.isEmpty ? "Unknown" : r.version, default: 0] += 1
        }
        return byName.map { name, versions in
            (name, versions.values.reduce(0, +), ApplicationsReport.sortVersionsDescending(versions.keys).map { ($0, versions[$0] ?? 0) })
        }
        .sorted { $0.total != $1.total ? $0.total > $1.total : $0.name < $1.name }
    }

    /// The reporting bucket a device's last-seen time falls in.
    public static func deviceStatus(lastSeen: String?, now: Date = Date()) -> DeviceStatus {
        guard let lastSeen, !lastSeen.isEmpty else { return .missing }
        guard let date = FlexibleDate.parse(lastSeen) else { return .missing }
        let hours = now.timeIntervalSince(date) / 3600
        if hours <= 24 { return .active }
        if hours <= 168 { return .stale }
        return .missing
    }
}
