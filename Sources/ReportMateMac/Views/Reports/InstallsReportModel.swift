import SwiftUI
import ReportMateKit

/// State and derivations for the Installs report. Port of the state half of
/// `app/installs/page.tsx`: the config report is the default view, the
/// status widgets drill into devices, and the item picker builds an items
/// report from the bulk install rows.
@MainActor
@Observable
final class InstallsReportModel {
    enum StatusView { case devices, messages }

    var filters = InstallsFilterOptions()
    var filtersLoading = true
    var loading = false
    var loadingMessage = ""
    var reportProgress: Double = 0
    var error: String?

    /// All bulk rows, fetched once and filtered per report.
    private var bulkRows: [InstallRecord]?

    var installs: [InstallRecord] = []
    var isConfigReport = false
    var hasGeneratedReport = false
    var isGeneratingReport = false
    var searchQuery = ""
    var selections = DeviceSelections()
    var selectedInstalls: [String] = []
    var selectedManifest = ""
    var selectedSoftwareRepo = ""
    var selectedMunkiVersion = ""
    var selectedCimianVersion = ""
    var itemsStatusFilter: InstallItems.Category?
    var deviceStatusFilter: DeviceStatus?
    var installStatusFilter: InstallStatusClass?
    var statusView: StatusView = .devices
    var widgetsExpanded = true
    var selectionsExpanded = false
    var expandedMessages: Set<String> = []
    var lastApplied: (installs: [String], selections: DeviceSelections) = ([], DeviceSelections())

    // MARK: Loading

    func loadFilters(api: ReportMateAPI, force: Bool = false) async {
        if !force, !filtersLoading, !filters.devices.isEmpty { return }
        filtersLoading = true
        error = nil
        loadingMessage = "Fetching device data..."
        do {
            filters = try await api.installsFilters()
            loadingMessage = "Processing..."
        } catch {
            self.error = error.localizedDescription
        }
        filtersLoading = false
        if !isGeneratingReport, !hasGeneratedReport { showConfigReport() }
    }

    /// The default view: one row per device that runs Cimian or Munki.
    func showConfigReport() {
        error = nil
        searchQuery = ""
        isConfigReport = true
        installs = []
    }

    func generateReport(api: ReportMateAPI) async {
        guard !selectedInstalls.isEmpty else {
            error = "Please select at least one install to generate the report."
            return
        }
        loading = true
        error = nil
        reportProgress = 0.05
        loadingMessage = "Querying device database..."
        searchQuery = ""
        deviceStatusFilter = nil
        installStatusFilter = nil
        do {
            if bulkRows == nil {
                loadingMessage = "Retrieving install records..."
                reportProgress = 0.1
                var rows: [InstallRecord] = []
                var offset = 0
                let pageSize = 5000
                while true {
                    let page = try await api.installRecords(limit: pageSize, offset: offset)
                    rows.append(contentsOf: page)
                    offset += page.count
                    loadingMessage = "Retrieving install records (\(rows.count.formatted()) so far)..."
                    reportProgress = min(0.65, 0.1 + Double(rows.count) / 150_000 * 0.55)
                    if page.count < pageSize { break }
                }
                bulkRows = rows
            }
            reportProgress = 0.7
            loadingMessage = "Filtering results..."
            var manifests: [String: String] = [:]
            for d in filters.devices { if let m = d.manifest { manifests[d.serialNumber] = m } }
            installs = InstallsReport.records(from: bulkRows ?? [], selectedInstalls: selectedInstalls, usages: selections.usages, catalogs: selections.catalogs,
                                              rooms: selections.locations, fleets: selections.fleets, areas: selections.areas, manifests: manifests)
            hasGeneratedReport = true
            isGeneratingReport = false
            isConfigReport = false
            selectionsExpanded = true
            lastApplied = (selectedInstalls, selections)
            reportProgress = 1
            loadingMessage = "Complete!"
        } catch {
            self.error = error.localizedDescription
            installs = []
        }
        loading = false
        reportProgress = 0
    }

    /// Drop the cached bulk rows so the next report re-fetches.
    func invalidate() { bulkRows = nil }

    func enterGenerateMode() {
        isGeneratingReport = true
        isConfigReport = false
        installs = []
        itemsStatusFilter = nil
        searchQuery = ""
    }

    func backToConfigReport() {
        isGeneratingReport = false
        selectedInstalls = []
        hasGeneratedReport = false
        showConfigReport()
    }

    func resetReport() {
        installs = []
        hasGeneratedReport = false
        selectedManifest = ""
        selectedSoftwareRepo = ""
        selectedMunkiVersion = ""
        selectedCimianVersion = ""
        lastApplied = ([], DeviceSelections())
        searchQuery = ""
        itemsStatusFilter = nil
        deviceStatusFilter = nil
        installStatusFilter = nil
        selectedInstalls = []
        selections.clear()
        isGeneratingReport = true
        isConfigReport = false
    }

    func clearAllFilters() {
        selectedInstalls = []
        selections.clear()
        searchQuery = ""
        itemsStatusFilter = nil
        widgetsExpanded = true
    }

    func toggleInstall(_ name: String) {
        if let i = selectedInstalls.firstIndex(of: name) { selectedInstalls.remove(at: i) } else { selectedInstalls.append(name) }
    }

    /// Clicking a status widget: same status again clears it.
    func selectStatus(_ category: InstallItems.Category?) {
        itemsStatusFilter = category
    }

    var hasWidgetSelection: Bool { !selectedManifest.isEmpty || !selectedSoftwareRepo.isEmpty || !selectedMunkiVersion.isEmpty || !selectedCimianVersion.isEmpty }

    var filtersChanged: Bool {
        guard !installs.isEmpty else { return false }
        return Set(selectedInstalls) != Set(lastApplied.installs) || selections != lastApplied.selections
    }

    // MARK: Devices

    /// `platformFilteredDevices`: the toggle, with a tool-based fallback for
    /// devices whose platform is unknown.
    func platformDevices(_ platform: PlatformFilter) -> [InstallsDevice] {
        platform == .all ? filters.devices : filters.devices.filter { platform.includes($0.platform) }
    }

    func configRows(_ platform: PlatformFilter) -> [ConfigReportRow] {
        platformDevices(platform).compactMap(ConfigReportRow.init(device:))
    }

    private func matchesSelections(usage: String?, catalog: String?, fleet: String?, area: String?, room: String?) -> Bool {
        func contains(_ set: Set<String>, _ value: String?) -> Bool {
            let v = (value ?? "").lowercased()
            return set.contains { v.contains($0.lowercased()) }
        }
        if !selections.usages.isEmpty, !contains(selections.usages, usage) { return false }
        if !selections.catalogs.isEmpty, !contains(selections.catalogs, catalog) { return false }
        if !selections.fleets.isEmpty, !contains(selections.fleets, fleet) { return false }
        if !selections.areas.isEmpty, !contains(selections.areas, area) { return false }
        if !selections.locations.isEmpty, !contains(selections.locations, room) { return false }
        return true
    }

    private func matchesWidgets(_ row: ConfigReportRow) -> Bool {
        if !selectedManifest.isEmpty, row.clientIdentifier != selectedManifest { return false }
        if !selectedSoftwareRepo.isEmpty, row.softwareRepoUrl != selectedSoftwareRepo { return false }
        if !selectedMunkiVersion.isEmpty, !(row.configType == "Munki" && row.version == selectedMunkiVersion) { return false }
        if !selectedCimianVersion.isEmpty, !(row.configType == "Cimian" && row.version == selectedCimianVersion) { return false }
        return true
    }

    /// `filteredConfigData` before sorting.
    func filteredConfigRows(_ platform: PlatformFilter) -> [ConfigReportRow] {
        let q = searchQuery.lowercased()
        return configRows(platform).filter { row in
            if let f = deviceStatusFilter, InstallsReport.deviceStatus(lastSeen: row.lastSeen) != f { return false }
            if let f = installStatusFilter, row.count(for: f) == 0 { return false }
            if !matchesWidgets(row) { return false }
            if !matchesSelections(usage: row.usage, catalog: row.catalog, fleet: row.fleet, area: row.area, room: row.location) { return false }
            if !q.isEmpty {
                let hay = [row.deviceName, row.serialNumber, row.assetTag ?? "", row.clientIdentifier, row.softwareRepoUrl].map { $0.lowercased() }
                if !hay.contains(where: { $0.contains(q) }) { return false }
            }
            return true
        }
    }

    /// `filteredInstalls` before sorting.
    var filteredInstalls: [InstallRecord] {
        let q = searchQuery.lowercased()
        return installs.filter { r in
            if let f = deviceStatusFilter, InstallsReport.deviceStatus(lastSeen: r.lastSeen) != f { return false }
            if let f = installStatusFilter, !f.matches(recordStatus: r.status) { return false }
            if !q.isEmpty {
                let hay = [r.deviceName, r.serialNumber, r.assetTag ?? "", r.name, r.version, r.source, r.manifest ?? "", r.searchKey].map { $0.lowercased() }
                if !hay.contains(where: { $0.contains(q) }) { return false }
            }
            if !selections.usages.isEmpty, !DeviceSelections.containsCI(selections.usages, r.usage ?? "") { return false }
            if !selections.catalogs.isEmpty, !DeviceSelections.containsCI(selections.catalogs, r.catalog ?? "") { return false }
            if !selections.fleets.isEmpty, !selections.fleets.contains(r.fleet ?? "") { return false }
            if !selections.areas.isEmpty, !selections.areas.contains(r.area ?? "") { return false }
            if !selections.locations.isEmpty, !selections.locations.contains(r.room ?? "") { return false }
            return true
        }
    }

    // MARK: Status pills

    /// Active / stale / missing counts for whatever is showing, with every
    /// other filter applied so the pills reconcile with the table.
    func deviceStatusCounts(_ platform: PlatformFilter) -> [DeviceStatus: Int] {
        var counts: [DeviceStatus: Int] = [.active: 0, .stale: 0, .missing: 0]
        func bump(_ lastSeen: String?) { counts[InstallsReport.deviceStatus(lastSeen: lastSeen), default: 0] += 1 }
        if isConfigReport {
            let saved = deviceStatusFilter
            deviceStatusFilter = nil
            defer { deviceStatusFilter = saved }
            for row in filteredConfigRows(platform) { bump(row.lastSeen) }
            return counts
        }
        if !installs.isEmpty {
            let saved = deviceStatusFilter
            deviceStatusFilter = nil
            defer { deviceStatusFilter = saved }
            var latest: [String: String] = [:]
            for r in filteredInstalls {
                if let existing = latest[r.serialNumber], let ls = r.lastSeen, ls <= existing { continue }
                latest[r.serialNumber] = r.lastSeen ?? ""
            }
            for (_, ls) in latest { bump(ls.isEmpty ? nil : ls) }
            return counts
        }
        for d in statusDevices(platform, ignoringDeviceStatus: true) { counts[d.status, default: 0] += 1 }
        return counts
    }

    func installStatusCounts(_ platform: PlatformFilter) -> [InstallStatusClass: Int] {
        var counts: [InstallStatusClass: Int] = [:]
        if isConfigReport {
            let saved = installStatusFilter
            installStatusFilter = nil
            defer { installStatusFilter = saved }
            for row in filteredConfigRows(platform) { for c in InstallStatusClass.allCases { counts[c, default: 0] += row.count(for: c) } }
        } else if !installs.isEmpty {
            let saved = installStatusFilter
            installStatusFilter = nil
            defer { installStatusFilter = saved }
            for r in filteredInstalls { if let b = InstallStatusClass.bucket(recordStatus: r.status) { counts[b, default: 0] += 1 } }
        }
        return counts
    }

    // MARK: Status drill-down

    func categorized(_ platform: PlatformFilter) -> (errors: [InstallsDevice], warnings: [InstallsDevice], pending: [InstallsDevice], success: [InstallsDevice]) {
        InstallsReport.categorize(platformDevices(platform))
    }

    /// `statusFilteredDevices`: devices in the chosen status bucket after
    /// every other filter.
    func statusDevices(_ platform: PlatformFilter, ignoringDeviceStatus: Bool = false) -> [InstallsDevice] {
        let cats = categorized(platform)
        var list: [InstallsDevice]
        switch itemsStatusFilter {
        case .error: list = cats.errors
        case .warning: list = cats.warnings
        case .pending: list = cats.pending
        case .success: list = cats.success
        case nil: list = platformDevices(platform)
        }
        if !ignoringDeviceStatus, let f = deviceStatusFilter { list = list.filter { $0.status == f } }
        list = list.filter { matchesSelections(usage: $0.usage, catalog: $0.catalog, fleet: $0.fleet, area: $0.area, room: $0.location) }
        if !selectedInstalls.isEmpty {
            list = list.filter { d in d.items.contains { selectedInstalls.contains(InstallItems.name(of: $0)) && InstallItems.matches($0, itemsStatusFilter) } }
        }
        let q = searchQuery.lowercased()
        if !q.isEmpty {
            list = list.filter { d in
                if d.deviceName.lowercased().contains(q) || d.serialNumber.lowercased().contains(q) { return true }
                return d.items.contains { item in
                    let name = InstallItems.name(of: item).lowercased()
                    let err = (item.firstString("lastError", "last_error") ?? "").lowercased()
                    let warn = (item.firstString("lastWarning", "last_warning") ?? "").lowercased()
                    guard name.contains(q) || err.contains(q) || warn.contains(q) else { return false }
                    return InstallItems.matches(item, itemsStatusFilter)
                }
            }
        }
        return list
    }

    func statusMessageGroups(_ platform: PlatformFilter) -> [InstallMessageGroup] {
        guard let category = itemsStatusFilter else { return [] }
        return InstallsReport.statusMessageGroups(statusDevices(platform), category, nameFilter: searchQuery)
    }

    /// The packages on one device that match the drill-down and the search.
    func affectedPackages(of device: InstallsDevice) -> [JSONValue] {
        let q = searchQuery.lowercased()
        return device.items.filter { item in
            guard InstallItems.matches(item, itemsStatusFilter) else { return false }
            return q.isEmpty || InstallItems.name(of: item).lowercased().contains(q)
        }
    }

    /// The count shown in "(N) Devices with (M) errors for X".
    func statusFilterItemCount(_ platform: PlatformFilter) -> Int {
        guard let category = itemsStatusFilter, !searchQuery.isEmpty else { return 0 }
        return InstallsReport.itemCounts(platformDevices(platform), category).first { $0.name.lowercased() == searchQuery.lowercased() }?.count ?? 0
    }

    // MARK: Widgets

    func hasMunki(_ platform: PlatformFilter) -> Bool { platformDevices(platform).contains { $0.munkiVersion != nil } }
    func hasCimian(_ platform: PlatformFilter) -> Bool { platformDevices(platform).contains { $0.cimianVersion != nil } }

    /// Selections options: the loaded report's own values once one exists.
    func filterOptions(_ platform: PlatformFilter) -> DeviceFilterOptions {
        var o = DeviceFilterOptions()
        if !installs.isEmpty {
            func distinct(_ pick: (InstallRecord) -> String?) -> [String] { Array(Set(installs.compactMap(pick))).sorted() }
            o.usages = distinct(\.usage)
            o.catalogs = distinct(\.catalog)
            o.fleets = distinct(\.fleet)
            o.areas = distinct(\.area)
            o.locations = distinct(\.room)
            var counts: [String: Int] = [:]
            for r in installs { if let room = r.room { counts[room, default: 0] += 1 } }
            o.locationCounts = counts
        } else {
            o.usages = filters.usages
            o.catalogs = filters.catalogs
            o.fleets = filters.fleets
            o.areas = filters.areas
            o.locations = filters.rooms
            var counts: [String: Int] = [:]
            for d in platformDevices(platform) { if let loc = d.location { counts[loc, default: 0] += 1 } }
            o.locationCounts = counts
        }
        return o
    }

    func pickerItems(_ platform: PlatformFilter) -> [String] {
        let q = searchQuery.lowercased()
        return filters.items(for: platform).filter { q.isEmpty || $0.lowercased().contains(q) }
            .sorted { $0.lowercased().localizedCompare($1.lowercased()) == .orderedAscending }
    }
}
