import SwiftUI
import ReportMateKit

/// State and loaders for the Applications report. Port of the state half of
/// `app/applications/page.tsx`: filter options load once, then the user
/// builds a Versions or Usage report from the chip cloud and selections.
@MainActor
@Observable
final class ApplicationsReportModel {
    enum ReportType: String { case versions, usage }
    enum ReportMode { case has, missing }

    var filters = ApplicationFilterOptions()
    var filtersLoading = true
    var loading = false
    var loadingMessage = ""
    /// 0…1 while a report loads; 0 hides the bar.
    var progress: Double = 0
    var error: String?

    /// The shared Selections accordion. `locations` holds rooms here, which
    /// is what the web page sends as `rooms=`.
    var selections = DeviceSelections()
    var selectedApplications: [String] = []
    var searchQuery = ""
    var reportType: ReportType?
    var reportMode: ReportMode = .has
    var applications: [FleetApplicationRow] = []
    var utilization: UtilizationData?
    var serverDistribution: [String: ServerDistributionBucket]?
    var utilizationDays = 30
    /// Apps kept in the in-report chip cloud; `nil` before a report exists.
    var enabledApps: Set<String>?
    /// `app:version` filters chosen in the Version Distribution widget.
    var selectedVersions: [String] = []
    var lastAppliedFilters = ""
    var widgetMetric: UsageMetric = .launches
    var builderExpanded = true
    var selectionsExpanded = true
    var widgetsExpanded = false
    /// The platform toggle the current report was fetched under.
    var reportPlatform: PlatformFilter?

    // MARK: Loading

    func loadFilters(api: ReportMateAPI, force: Bool = false) async {
        if !force, !filtersLoading, !filters.applicationNames.isEmpty { return }
        filtersLoading = true
        loading = true
        error = nil
        loadingMessage = "Loading application data..."
        do {
            filters = try await api.applicationFilters()
            loadingMessage = "Complete!"
        } catch {
            self.error = error.localizedDescription
        }
        filtersLoading = false
        loading = false
    }

    /// Query shared by the inventory, distribution and usage endpoints.
    private func reportQuery(platform: PlatformFilter, includeApps: Bool) -> [String: String?] {
        var q: [String: String?] = [:]
        if includeApps, !selectedApplications.isEmpty { q["applicationNames"] = selectedApplications.joined(separator: ",") }
        func join(_ set: Set<String>, lowercased: Bool = false) -> String? {
            set.isEmpty ? nil : set.map { lowercased ? $0.lowercased() : $0 }.sorted().joined(separator: ",")
        }
        if let v = join(selections.usages, lowercased: true) { q["usages"] = v }
        if let v = join(selections.catalogs, lowercased: true) { q["catalogs"] = v }
        if let v = join(selections.areas) { q["areas"] = v }
        if let v = join(selections.fleets) { q["fleets"] = v }
        if let v = join(selections.locations) { q["rooms"] = v }
        if let p = platform.platform { q["platforms"] = p.displayName }
        return q
    }

    private func distributionIfSelected(api: ReportMateAPI, platform: PlatformFilter) async -> [String: ServerDistributionBucket]? {
        guard !selectedApplications.isEmpty else { return nil }
        return try? await api.applicationDistribution(query: reportQuery(platform: platform, includeApps: true))
    }

    func loadVersionsReport(api: ReportMateAPI, platform: PlatformFilter) async {
        loading = true
        error = nil
        searchQuery = ""
        progress = 0.2
        loadingMessage = "Loading version distribution data..."
        var query = reportQuery(platform: platform, includeApps: true)
        if selectedApplications.isEmpty { query["limit"] = "5000" }
        async let inventory = api.applications(query: query)
        async let distribution = distributionIfSelected(api: api, platform: platform)
        do {
            let rows = try await inventory
            let dist = await distribution
            progress = 0.6
            applications = rows
            serverDistribution = dist
            reportType = .versions
            reportPlatform = platform
            selectionsExpanded = false
            utilization = nil
            enabledApps = Set(rows.map(\.name).filter(AppNameNormalizer.shouldInclude))
            progress = 1
            loadingMessage = "Complete!"
            lastAppliedFilters = currentFiltersKey
        } catch {
            self.error = error.localizedDescription
        }
        loading = false
        builderExpanded = false
        progress = 0
    }

    func loadUtilization(api: ReportMateAPI, platform: PlatformFilter, days: Int? = nil) async {
        let effectiveDays = days ?? utilizationDays
        utilizationDays = effectiveDays
        loading = true
        error = nil
        searchQuery = ""
        progress = 0.05
        if !selectedApplications.isEmpty {
            loadingMessage = "Loading inventory data for version analysis..."
            progress = 0.1
            if let rows = try? await api.applications(query: ["applicationNames": selectedApplications.joined(separator: ",")]) {
                applications = rows
            }
            progress = 0.25
        }
        progress = 0.3
        loadingMessage = "Loading application usage data..."
        var query = reportQuery(platform: platform, includeApps: true)
        query["days"] = String(effectiveDays)
        do {
            let data = try await api.applicationUsage(query: query)
            progress = 0.85
            if data.isUnavailable {
                error = data.message ?? "Usage tracking not yet deployed"
                utilization = nil
            } else {
                reportPlatform = platform
                utilization = data
                reportType = .usage
                widgetsExpanded = true
                selectionsExpanded = false
                enabledApps = Set(data.applications.map(\.name))
                progress = 1
                loadingMessage = "Complete!"
            }
            lastAppliedFilters = currentFiltersKey
        } catch {
            self.error = error.localizedDescription
        }
        loading = false
        builderExpanded = false
        progress = 0
    }

    /// Re-fetch whichever report is showing (refresh, or the platform toggle moved).
    func reloadCurrentReport(api: ReportMateAPI, platform: PlatformFilter) async {
        switch reportType {
        case .usage: await loadUtilization(api: api, platform: platform)
        case .versions: await loadVersionsReport(api: api, platform: platform)
        case nil: await loadFilters(api: api, force: true)
        }
    }

    // MARK: Selections

    var currentFiltersKey: String {
        var parts = [selectedApplications.joined(separator: "|"), selections.usages.sorted().joined(separator: "|"),
                     selections.catalogs.sorted().joined(separator: "|"), selections.locations.sorted().joined(separator: "|")]
        if reportType == .usage { parts.insert(String(utilizationDays), at: 0) }
        return parts.joined(separator: "\u{1F}")
    }

    /// "Update Report" appears once the selections differ from the loaded report.
    var filtersChanged: Bool { !lastAppliedFilters.isEmpty && lastAppliedFilters != currentFiltersKey }

    var hasSelections: Bool { !selectedApplications.isEmpty || !selections.isEmpty }

    func toggleApplication(_ name: String) {
        if let i = selectedApplications.firstIndex(of: name) { selectedApplications.remove(at: i) } else { selectedApplications.append(name) }
    }

    func toggleVersion(_ version: String, app: String) {
        let filter = ApplicationsReport.versionFilter(app: app, version: version)
        if let i = selectedVersions.firstIndex(of: filter) { selectedVersions.remove(at: i) } else { selectedVersions.append(filter) }
    }

    func toggleEnabledApp(_ name: String) {
        var set = enabledApps ?? []
        if set.contains(name) { set.remove(name) } else { set.insert(name) }
        enabledApps = set
    }

    func clearAllFilters() {
        selectedApplications = []
        selections.clear()
        selectedVersions = []
        searchQuery = ""
        error = nil
    }

    func reset() {
        applications = []
        utilization = nil
        serverDistribution = nil
        reportType = nil
        reportMode = .has
        clearAllFilters()
        builderExpanded = true
        selectionsExpanded = true
        lastAppliedFilters = ""
        utilizationDays = 30
        enabledApps = nil
        reportPlatform = nil
    }

    // MARK: Derived data

    /// Chip cloud names for the toggled platform, narrowed by the search box.
    func filteredApplicationNames(platform: PlatformFilter) -> [String] {
        let q = searchQuery.lowercased()
        return filters.applicationNames(for: platform).filter { q.isEmpty || $0.lowercased().contains(q) }.sorted()
    }

    /// Installed rows after the junk filter, chip cloud, platform, search and selections.
    func baseFilteredApplications(platform: PlatformFilter) -> [FleetApplicationRow] {
        let q = searchQuery.trimmingCharacters(in: .whitespaces).lowercased()
        let rooms = selections.locations.map { $0.lowercased() }
        return applications.filter { app in
            guard AppNameNormalizer.shouldInclude(app.name) else { return false }
            if reportType == .versions, let enabledApps, !enabledApps.contains(app.name) { return false }
            if platform != .all, !platform.includes(app.platform) { return false }
            if !q.isEmpty, !(app.name.lowercased().contains(q) || app.deviceName.lowercased().contains(q) || app.vendor.lowercased().contains(q)) { return false }
            if !selections.usages.isEmpty, !DeviceSelections.containsCI(selections.usages, app.usage ?? "") { return false }
            if !selections.catalogs.isEmpty, !DeviceSelections.containsCI(selections.catalogs, app.catalog ?? "") { return false }
            if !rooms.isEmpty {
                let loc = app.location?.lowercased() ?? "", room = app.room?.lowercased() ?? ""
                if !rooms.contains(where: { loc.contains($0) || room.contains($0) }) { return false }
            }
            if !selections.fleets.isEmpty, !DeviceSelections.containsCI(selections.fleets, app.fleet ?? "") { return false }
            if !selections.areas.isEmpty, !DeviceSelections.containsCI(selections.areas, app.areaOrDepartment ?? "") { return false }
            return true
        }
    }

    /// Base rows narrowed to the versions picked in the distribution widget.
    func filteredApplications(platform: PlatformFilter) -> [FleetApplicationRow] {
        let base = baseFilteredApplications(platform: platform)
        guard !selectedVersions.isEmpty else { return base }
        return base.filter { app in
            selectedVersions.contains { filter in
                if let (name, version) = ApplicationsReport.splitVersionFilter(filter) {
                    if version == "Unknown" { return false }
                    return AppNameNormalizer.normalize(app.name) == name && app.version == version
                }
                if filter == "Unknown" { return false }
                return app.version == filter
            }
        }
    }

    /// Names offered by the in-report chip cloud.
    var appsInReport: [String] {
        switch reportType {
        case .usage: return utilization?.applications.map(\.name) ?? []
        case .versions:
            var seen = Set<String>(), names: [String] = []
            for a in applications where AppNameNormalizer.shouldInclude(a.name) && seen.insert(a.name).inserted { names.append(a.name) }
            return names
        case nil: return []
        }
    }

    func versionAnalysis(platform: PlatformFilter) -> [String: [String: Int]] {
        ApplicationsReport.versionAnalysis(server: serverDistribution, apps: baseFilteredApplications(platform: platform))
    }

    func missingDevices(platform: PlatformFilter) -> [ApplicationFilterDevice] {
        guard !selectedApplications.isEmpty, reportMode == .missing else { return [] }
        let withApp = Set(baseFilteredApplications(platform: platform).map(\.serialNumber))
        return ApplicationsReport.missingDevices(all: filters.devices, devicesWithApp: withApp, usages: selections.usages,
                                                 catalogs: selections.catalogs, locations: [], rooms: selections.locations)
    }

    /// Usage rows that survive the in-report chip cloud.
    var enabledUtilizationApps: [UtilizationApp] {
        guard let apps = utilization?.applications else { return [] }
        guard let enabledApps else { return apps }
        return apps.filter { enabledApps.contains($0.name) }
    }

    /// Device-level aggregates for the Widgets accordion, narrowed to devices
    /// that used at least one enabled app.
    var aggregates: UsageAggregates {
        guard let utilization else { return UsageAggregates(devices: [DeviceAggregate](), metric: widgetMetric) }
        var devices = utilization.devicesAggregate
        if let enabledApps {
            let keep = Set(utilization.applications.filter { enabledApps.contains($0.name) }.flatMap(\.devices))
            devices = devices.filter { keep.contains($0.serialNumber) }
        }
        return UsageAggregates(devices: devices, metric: widgetMetric)
    }

    /// Distribution cards for the usage report, limited to the selected apps.
    var usageVersionCards: [VersionCard] {
        guard let dist = utilization?.versionDistribution else { return [] }
        let selected = selectedApplications.map { $0.lowercased() }
        return dist.filter { name, _ in
            selected.isEmpty || selected.contains { name.lowercased().contains($0) || $0.contains(name.lowercased()) }
        }
        .map { name, bucket in
            VersionCard(name: name, total: bucket.totalDevices,
                        versions: ApplicationsReport.sortVersionsDescending(bucket.versions.keys).map { ($0, bucket.versions[$0]?.count ?? 0) })
        }
        .sorted { $0.total != $1.total ? $0.total > $1.total : $0.name < $1.name }
    }

    /// Distribution cards for the versions report (top 50 by device count).
    func versionCards(platform: PlatformFilter) -> [VersionCard] {
        versionAnalysis(platform: platform).map { name, versions in
            VersionCard(name: name, total: versions.values.reduce(0, +),
                        versions: ApplicationsReport.sortVersionsDescending(versions.keys).map { ($0, versions[$0] ?? 0) })
        }
        .sorted { $0.total != $1.total ? $0.total > $1.total : $0.name < $1.name }
        .prefix(50).map { $0 }
    }

    /// Rows for "Devices with Selected Versions" in the usage report.
    var devicesWithSelectedVersions: [DeviceVersionRow] {
        guard let dist = utilization?.versionDistribution else { return [] }
        var rows: [DeviceVersionRow] = []
        for filter in selectedVersions {
            guard let (app, version) = ApplicationsReport.splitVersionFilter(filter), let info = dist[app]?.versions[version] else { continue }
            for (i, d) in info.devices.enumerated() {
                rows.append(DeviceVersionRow(id: "\(app)-\(version)-\(d.serialNumber)-\(i)", appName: app, version: version, serialNumber: d.serialNumber,
                                             deviceName: d.deviceName, location: d.location, catalog: d.catalog, lastSeen: d.lastSeen))
            }
        }
        return rows
    }
}

/// One application's version breakdown in the Version Distribution widget.
struct VersionCard: Identifiable, Hashable {
    let name: String
    let total: Int
    let versions: [(version: String, count: Int)]
    var id: String { name }

    static func == (a: VersionCard, b: VersionCard) -> Bool { a.name == b.name && a.total == b.total && a.versions.map(\.version) == b.versions.map(\.version) && a.versions.map(\.count) == b.versions.map(\.count) }
    func hash(into hasher: inout Hasher) { hasher.combine(name); hasher.combine(total) }
}

struct DeviceVersionRow: Identifiable, Hashable {
    let id: String
    let appName: String
    let version: String
    let serialNumber: String
    let deviceName: String
    let location: String?
    let catalog: String?
    let lastSeen: String?
}
