import SwiftUI
import ReportMateKit

/// Fleet applications report: a Versions report (installed inventory with
/// a version-distribution widget and a Missing mode) and a Usage report
/// (utilization with device-level widgets), both built from a chip cloud of
/// application names. Port of `app/applications/page.tsx`.
struct ApplicationsReportView: View {
    @Environment(AppState.self) private var appState
    @State private var model = ApplicationsReportModel()

    enum UsageColumn { case name, activeHours, totalHours, launchCount, deviceCount, userCount, lastUsed }
    enum VersionsColumn { case application, version, usage, catalog, area, location, device }
    enum MissingColumn { case device, serial, location, catalog }
    enum DeviceVersionColumn { case device, serial, application, version, location, catalog, lastSeen }
    @State private var usageSort: UsageColumn = .activeHours
    @State private var usageAscending = false
    @State private var versionsSort: VersionsColumn = .device
    @State private var versionsAscending = true
    @State private var missingSort: MissingColumn = .device
    @State private var missingAscending = true
    @State private var dvSort: DeviceVersionColumn = .device
    @State private var dvAscending = true

    /// The chip cloud is capped so a fleet with tens of thousands of names
    /// still lays out instantly; the search box narrows it.
    private static let chipLimit = 2000

    private var platform: PlatformFilter { appState.platformFilter }

    var body: some View {
        @Bindable var m = model
        VStack(spacing: 0) {
            header
            if let error = model.error, !model.filtersLoading {
                ErrorBanner(message: error) { Task { await model.reloadCurrentReport(api: appState.api, platform: platform) } }
                    .padding(.horizontal, 16).padding(.top, 8)
            }
            if model.filtersLoading {
                filtersProgress
                Spacer()
            } else {
                DeviceFiltersView(options: filterOptions, selections: $m.selections, expanded: $m.selectionsExpanded)
                if model.reportType == nil {
                    builder
                    Spacer()
                } else {
                    ScrollView { reportContent }
                }
            }
        }
        .navigationTitle("Applications")
        .task(id: appState.configuration) { await model.loadFilters(api: appState.api) }
        .onChange(of: appState.refreshRequested) { _, _ in Task { await model.reloadCurrentReport(api: appState.api, platform: platform) } }
        .onChange(of: appState.platformFilter) { _, new in
            guard model.reportType != nil, !model.loading, model.reportPlatform != new else { return }
            Task { await model.reloadCurrentReport(api: appState.api, platform: new) }
        }
    }

    private var filterOptions: DeviceFilterOptions {
        var o = DeviceFilterOptions()
        o.usages = model.filters.usages
        o.catalogs = model.filters.catalogs
        o.areas = model.filters.areas
        o.locations = model.filters.rooms
        o.fleets = model.filters.fleets
        o.locationCounts = model.filters.roomCounts
        return o
    }

    // MARK: Header

    private var subtitle: String {
        if model.reportType == .usage, let data = model.utilization { return data.summary.headline }
        if model.reportType == .versions {
            let rows = sortedVersionRows
            if !rows.isEmpty { return "\(rows.count) applications across \(Set(rows.map(\.serialNumber)).count) devices" }
        }
        return "Generate report to see application inventory across your fleet"
    }

    private var header: some View {
        @Bindable var m = model
        return HStack(alignment: .top, spacing: 16) {
            VStack(alignment: .leading, spacing: 2) {
                Text(model.reportType == .usage ? "Applications Usage Report" : "Applications Report").appFont(.title3, weight: .semibold)
                Text(subtitle).appFont(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 8) {
                HStack(spacing: 6) {
                    Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                    TextField("Search applications...", text: $m.searchQuery).textFieldStyle(.plain)
                    if !model.searchQuery.isEmpty { Button { model.searchQuery = "" } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary) }.buttonStyle(.plain) }
                }
                .padding(.horizontal, 10).padding(.vertical, 6)
                .background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 8))
                .frame(width: 260)
                HStack(spacing: 8) {
                    if model.loading { ProgressView().controlSize(.small) }
                    if model.reportType == .usage, model.utilization != nil { periodPicker }
                    actionButtons
                    exportButton
                }
            }
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
        .overlay(alignment: .bottom) { Divider() }
    }

    private var periodPicker: some View {
        Picker("Period", selection: Binding(get: { model.utilizationDays }, set: { days in
            Task { await model.loadUtilization(api: appState.api, platform: platform, days: days) }
        })) {
            Text("Last 7 days").tag(7)
            Text("Last 30 days").tag(30)
            Text("Last 45 days").tag(45)
            Text("Last 90 days").tag(90)
            Text("Last year").tag(365)
        }
        .labelsHidden().frame(width: 140)
    }

    @ViewBuilder private var actionButtons: some View {
        let loading = model.loading
        if !loading, model.reportType == nil, model.hasSelections {
            Button("Clear All Selections") { model.clearAllFilters() }
        }
        if !loading, model.reportType == nil {
            Button("Generate Report") { Task { await model.loadVersionsReport(api: appState.api, platform: platform) } }
                .buttonStyle(.borderedProminent)
                .help("Load installed versions for the selected applications")
        }
        if !loading, model.reportType == .versions, model.filtersChanged {
            Button("Update Report") { Task { await model.loadVersionsReport(api: appState.api, platform: platform) } }
                .buttonStyle(.borderedProminent)
        }
        if !loading, model.reportType == .versions, !model.selectedApplications.isEmpty {
            let missing = model.reportMode == .missing
            Button {
                model.reportMode = missing ? .has : .missing
            } label: {
                HStack(spacing: 4) {
                    Label(missing ? "Show Installed" : "Missing Report", systemImage: missing ? "checkmark.circle" : "nosign")
                    if missing { Pill("\(model.missingDevices(platform: platform).count)", tone: .red) }
                }
            }
            .tint(missing ? .green : .red)
            .help(missing ? "Back to devices that have the application" : "Show devices without the selected application")
        }
        if !loading, model.reportType == .versions, model.reportMode != .missing {
            Button { Task { await model.loadUtilization(api: appState.api, platform: platform) } } label: { Label("Usage Report", systemImage: "chart.bar") }
                .tint(.purple)
        }
        if !loading, model.reportType == .usage {
            Button { Task { await model.loadVersionsReport(api: appState.api, platform: platform) } } label: { Label("Versions Report", systemImage: "arrow.left") }
                .tint(.blue)
            Button { Task { await model.loadUtilization(api: appState.api, platform: platform) } } label: {
                Label(model.filtersChanged ? "Update Usage Report" : "Usage Report", systemImage: "chart.bar")
            }
            .tint(.purple)
            Button { appState.openApplicationCoverage() } label: { Label("Coverage", systemImage: "waveform.path.ecg") }
                .help("Per-device collection health for usage telemetry")
        }
        if !loading, model.reportType != nil {
            Button { model.reset() } label: { Label("New Report", systemImage: "plus") }.tint(.yellow)
        }
    }

    @ViewBuilder private var exportButton: some View {
        if model.reportType == .usage, !model.enabledUtilizationApps.isEmpty {
            CSVExportButton(filename: "applications-usage-\(model.utilizationDays)days",
                            headers: ["Application", "Active Hours", "Foreground Hours", "Process Hours", "Launches", "Active Devices", "Devices Installed", "Active Users", "Users Attributed", "Last Used", "Single User"],
                            rows: {
                sortedUsageApps.map { a in
                    [a.name, a.activeHours.map { String(format: "%.1f", $0) } ?? "", a.foregroundHours.map { String(format: "%.1f", $0) } ?? "", String(format: "%.1f", a.totalHours),
                     String(a.launchCount), a.activeDeviceCount.map(String.init) ?? "", String(a.deviceCount), a.activeUserCount.map(String.init) ?? "", String(a.userCount),
                     a.lastUsed ?? "", a.isSingleUser ? "Yes" : "No"]
                }
            }, label: "Export Usage CSV")
        } else if model.reportType == .versions, model.reportMode == .missing, !model.missingDevices(platform: platform).isEmpty {
            let apps = model.selectedApplications.joined(separator: ", ")
            let safe = model.selectedApplications.first?.replacingOccurrences(of: "[^a-zA-Z0-9]", with: "-", options: .regularExpression) ?? "app"
            CSVExportButton(filename: "missing-\(safe)", headers: ["Device", "Serial Number", "Location", "Catalog", "Missing Application"], rows: {
                sortedMissingDevices.map { [$0.name, $0.serialNumber, $0.location ?? "", $0.catalog ?? "", apps] }
            }, label: "Export Missing CSV")
        } else if model.reportType == .versions, model.reportMode == .has, !sortedVersionRows.isEmpty {
            CSVExportButton(filename: "applications", headers: ["Application", "Version", "Usage", "Catalog", "Area", "Location", "Device", "Serial Number"], rows: {
                sortedVersionRows.map { [$0.name, $0.version, $0.usage ?? "", $0.catalog ?? "", $0.areaOrDepartment ?? "", $0.location ?? "", $0.displayDevice, $0.serialNumber] }
            })
        }
    }

    // MARK: Loading and builder

    private var filtersProgress: some View {
        VStack(spacing: 8) {
            HStack {
                Text("Loading applications data from all devices...").appFont(.callout, weight: .medium)
                Spacer()
            }
            ProgressView().progressViewStyle(.linear)
            Text(model.loadingMessage.isEmpty ? "First load may take 60-90 seconds" : model.loadingMessage).appFont(.caption).foregroundStyle(.secondary)
        }
        .frame(maxWidth: 560)
        .padding(.vertical, 32)
        .frame(maxWidth: .infinity)
    }

    private var builder: some View {
        @Bindable var m = model
        let names = model.filteredApplicationNames(platform: platform)
        let allCount = model.filters.applicationNames(for: platform).count
        let selected = model.selectedApplications
        return VStack(spacing: 0) {
            AccordionHeader(title: "Applications", expanded: $m.builderExpanded) {
                if !selected.isEmpty { Pill("\(selected.count) active", tone: .blue) }
            }
            if model.loading { reportProgress }
            if model.builderExpanded {
                VStack(alignment: .leading, spacing: 8) {
                    HStack(spacing: 8) {
                        Text(selected.isEmpty ? "Applications" : "Applications (\(selected.count) selected)").appFont(.callout, weight: .medium)
                        Spacer()
                        if !model.searchQuery.isEmpty, !names.isEmpty, names.count < allCount {
                            Button("Select \(names.count) Results") {
                                for n in names where !selected.contains(n) { model.selectedApplications.append(n) }
                            }
                            .controlSize(.small).tint(.blue)
                        }
                        if selected.count < allCount {
                            Button("Select All (\(allCount))") { model.selectedApplications = model.filters.applicationNames(for: platform) }.controlSize(.small)
                        }
                        if !selected.isEmpty {
                            Button("Clear (\(selected.count))") { model.selectedApplications = [] }.controlSize(.small).tint(.red)
                        }
                    }
                    ScrollView {
                        FlowLayout(spacing: 4) {
                            ForEach(names.prefix(Self.chipLimit), id: \.self) { name in
                                FilterPill(text: name, selected: selected.contains(name), tone: .blue) { model.toggleApplication(name) }
                            }
                            if names.isEmpty {
                                Text(model.searchQuery.isEmpty ? (allCount == 0 ? "No applications reported" : "Loading applications...") : "No applications match \"\(model.searchQuery)\"")
                                    .appFont(.caption).foregroundStyle(.secondary).padding(4)
                            } else if names.count > Self.chipLimit {
                                Text("Showing the first \(Self.chipLimit) of \(names.count) names; search to narrow the list.")
                                    .appFont(.caption).foregroundStyle(.secondary).padding(4)
                            }
                        }
                        .padding(8)
                    }
                    .frame(minHeight: 190, maxHeight: 420)
                    .background(Color.cardBackground, in: RoundedRectangle(cornerRadius: 8))
                    .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.cardBorder))
                }
                .padding(.horizontal, 16).padding(.bottom, 14)
            }
        }
        .overlay(alignment: .bottom) { Divider() }
    }

    private var reportProgress: some View {
        HStack(spacing: 14) {
            Image(systemName: "square.grid.2x2").font(.system(size: 22)).foregroundStyle(.blue)
                .frame(width: 44, height: 44).background(Color.blue.opacity(0.12), in: Circle())
            VStack(alignment: .leading, spacing: 6) {
                Text(model.loadingMessage.isEmpty ? "Processing..." : model.loadingMessage).appFont(.callout, weight: .medium)
                ProgressView(value: model.progress).progressViewStyle(.linear)
                HStack(spacing: 6) {
                    ForEach([0.2, 0.4, 0.6, 0.8, 1.0], id: \.self) { step in
                        Circle().fill(model.progress >= step ? Color.blue : Color.secondary.opacity(0.3)).frame(width: 8, height: 8)
                    }
                }
            }
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
        .background(Color.blue.opacity(0.05))
    }

    // MARK: Report content

    @ViewBuilder private var reportContent: some View {
        switch model.reportType {
        case .usage: usageReport
        case .versions: versionsReport
        case nil: EmptyView()
        }
    }

    @ViewBuilder private var usageReport: some View {
        @Bindable var m = model
        if let data = model.utilization {
            let cards = model.usageVersionCards
            if !data.versionDistribution.isEmpty {
                VersionDistributionStrip(title: "Version Distribution", cards: cards, selected: model.selectedVersions, tone: .purple,
                                         note: model.selectedApplications.isEmpty ? nil : "Showing \(model.selectedApplications.count) selected app\(model.selectedApplications.count == 1 ? "" : "s")",
                                         hint: "Click to show devices with this version") { v, app in model.toggleVersion(v, app: app) }
            }
            if model.selectedVersions.isEmpty {
                if !data.devicesAggregate.isEmpty {
                    UsageWidgetsAccordion(deviceCount: model.aggregates.deviceCount, expanded: $m.widgetsExpanded, metric: $m.widgetMetric, aggregates: model.aggregates)
                }
                if !model.appsInReport.isEmpty { chipFilter }
                usageTable
            } else {
                devicesWithVersionsSection
            }
        }
    }

    @ViewBuilder private var versionsReport: some View {
        let cards = model.versionCards(platform: platform)
        if !cards.isEmpty {
            VersionDistributionStrip(title: "Version Distribution", cards: cards, selected: model.selectedVersions, tone: .blue,
                                     note: model.selectedApplications.isEmpty ? nil : "\(model.selectedApplications.count) app\(model.selectedApplications.count == 1 ? "" : "s") filtered",
                                     hint: "Click to filter devices with this version") { v, app in model.toggleVersion(v, app: app) }
        }
        if !model.appsInReport.isEmpty { chipFilter }
        if model.reportMode == .missing {
            missingSection
        } else {
            versionsTableSection
        }
    }

    private var chipFilter: some View {
        UsageAppChipFilter(apps: model.appsInReport, enabled: model.enabledApps, toggle: { model.toggleEnabledApp($0) },
                           selectAll: { model.enabledApps = Set(model.appsInReport) }, clear: { model.enabledApps = [] })
    }

    // MARK: Usage table

    private var sortedUsageApps: [UtilizationApp] {
        model.enabledUtilizationApps.sorted { a, b in
            var r: ComparisonResult
            switch usageSort {
            case .name: r = UsageCells.compare(a.name, b.name)
            case .activeHours:
                r = UsageCells.compare(a.activeHours ?? 0, b.activeHours ?? 0)
                if r == .orderedSame { r = UsageCells.compare(a.totalHours, b.totalHours) }
            case .totalHours: r = UsageCells.compare(a.totalHours, b.totalHours)
            case .launchCount: r = UsageCells.compare(a.launchCount, b.launchCount)
            case .deviceCount: r = UsageCells.compare(a.shownDeviceCount, b.shownDeviceCount)
            case .userCount: r = UsageCells.compare(a.shownUserCount, b.shownUserCount)
            case .lastUsed: r = UsageCells.compare(UsageCells.date(a.lastUsed), UsageCells.date(b.lastUsed))
            }
            return UsageCells.ordered(r, ascending: usageAscending)
        }
    }

    private func usageSortHeader(_ title: String, _ column: UsageColumn, width: CGFloat? = nil, help: String? = nil) -> some View {
        Button {
            if usageSort == column { usageAscending.toggle() } else { usageSort = column; usageAscending = false }
        } label: {
            HStack(spacing: 4) {
                Text(title.uppercased()).appFont(.caption2, weight: .semibold).foregroundStyle(.secondary)
                SortIndicator(active: usageSort == column, ascending: usageAscending)
            }
            .frame(width: width, alignment: .leading)
            .frame(maxWidth: width == nil ? .infinity : nil, alignment: .leading)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .optionalHelp(help)
    }

    private var usageTable: some View {
        let apps = sortedUsageApps
        let analysis = model.versionAnalysis(platform: platform)
        return StickyTable {
            usageSortHeader("Application", .name, width: 240)
            ReportHeaderLabel(title: "Versions", width: 150)
            usageSortHeader("Active Time", .activeHours, width: 130, help: "Time the application held focus with user input in the preceding 5 minutes. This is the utilization number; Process Time beside it is not.")
            usageSortHeader("Process Time", .totalHours, width: 130, help: "Process lifetime summed across every concurrent process, including background services. Diagnostic only: it has no wall-clock ceiling and does not mean someone used the application.")
            usageSortHeader("Launches", .launchCount, width: 90)
            usageSortHeader("Active Devices", .deviceCount, width: 110)
            usageSortHeader("Active Users", .userCount, width: 100)
            usageSortHeader("Last Used", .lastUsed, width: 110)
            ReportHeaderLabel(title: "Status")
        } rows: {
            if apps.isEmpty {
                ReportEmptyRows(title: "No usage data found", message: "Try adjusting the time period or filters.", systemImage: "chart.bar")
            }
            ForEach(apps) { app in
                usageRow(app, versions: analysis[AppNameNormalizer.normalize(app.name)] ?? analysis[app.name])
                Divider()
            }
        }
    }

    private func usageRow(_ app: UtilizationApp, versions: [String: Int]?) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Button {
                appState.openApplicationUsage(app.name, days: model.utilizationDays, usages: model.selections.usages.sorted(),
                                              catalogs: model.selections.catalogs.sorted(), locations: model.selections.locations.sorted())
            } label: {
                Text(app.name).appFont(.body, weight: .medium).foregroundStyle(.blue).lineLimit(2).multilineTextAlignment(.leading)
            }
            .buttonStyle(.plain)
            .help("View per-device breakdown for \(app.name)")
            .frame(width: 240, alignment: .leading)
            versionsCell(versions).frame(width: 150, alignment: .leading)
            VStack(alignment: .leading, spacing: 2) {
                if let active = app.activeSeconds {
                    Text(ApplicationsReport.duration(seconds: active)).appFont(.callout, weight: .medium).foregroundStyle(active > 0 ? Color.green : Color.secondary)
                    Text(String(format: "%.1f hours", app.activeHours ?? 0)).appFont(.caption2).foregroundStyle(.secondary)
                    if let fg = app.foregroundHours, fg > 0 { Text(String(format: "%.1fh foreground", fg)).appFont(.caption2).foregroundStyle(.secondary) }
                } else {
                    Text("Not reported").appFont(.callout).foregroundStyle(.secondary).help("No client in scope has reported idle-time data for this application yet.")
                }
            }
            .frame(width: 130, alignment: .leading)
            VStack(alignment: .leading, spacing: 2) {
                Text(ApplicationsReport.duration(seconds: app.totalSeconds)).appFont(.callout).foregroundStyle(.secondary)
                Text(String(format: "%.1f hours", app.totalHours)).appFont(.caption2).foregroundStyle(.secondary)
                if let ratio = app.activeRatio { Pill("\(Int((ratio * 100).rounded()))% active", tone: .gray) }
            }
            .frame(width: 130, alignment: .leading)
            Text(app.launchCount.formatted()).appFont(.callout).monospacedDigit().frame(width: 90, alignment: .leading)
            VStack(alignment: .leading, spacing: 2) {
                Text("\(app.shownDeviceCount)").appFont(.callout).monospacedDigit().foregroundStyle((app.activeDeviceCount ?? 0) > 0 ? Color.primary : Color.secondary)
                if let active = app.activeDeviceCount, active != app.deviceCount {
                    Text("\(app.deviceCount) installed").appFont(.caption2).foregroundStyle(.secondary).help("Devices with any usage row, including background-only process time")
                }
            }
            .frame(width: 110, alignment: .leading)
            VStack(alignment: .leading, spacing: 2) {
                Text("\(app.shownUserCount)").appFont(.callout).monospacedDigit().foregroundStyle((app.activeUserCount ?? 0) > 0 ? Color.primary : Color.secondary)
                if let active = app.activeUserCount, active != app.userCount {
                    Text("\(app.userCount) attributed").appFont(.caption2).foregroundStyle(.secondary).help("Users attributed any usage row, including background-only process time")
                }
            }
            .frame(width: 100, alignment: .leading)
            Text(app.lastUsed.map { TimeFormatting.relative($0) } ?? "-").appFont(.callout).frame(width: 110, alignment: .leading)
            Pill(app.statusLabel, tone: app.hasNoData ? .gray : app.isSingleUser ? .yellow : app.userCount > 5 ? .green : .gray)
                .optionalHelp(app.hasNoData ? "No usage records in the selected time window" : nil)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.horizontal, 16).padding(.vertical, 8)
        .opacity(app.hasNoData ? 0.6 : 1)
    }

    @ViewBuilder private func versionsCell(_ versions: [String: Int]?) -> some View {
        if let versions, !versions.isEmpty {
            let sorted = ApplicationsReport.sortVersionsDescending(versions.keys)
            if sorted.count == 1 {
                Text("v\(sorted[0])").appFont(.caption)
            } else {
                VStack(alignment: .leading, spacing: 1) {
                    ForEach(sorted.prefix(3), id: \.self) { v in
                        HStack(spacing: 3) {
                            Text("v\(v)").appFont(.caption)
                            Text("(\(versions[v] ?? 0))").appFont(.caption).foregroundStyle(.secondary)
                        }
                    }
                    if sorted.count > 3 { Text("+\(sorted.count - 3) more").appFont(.caption).foregroundStyle(.secondary) }
                }
            }
        } else {
            Text("-").appFont(.caption).foregroundStyle(.secondary)
        }
    }

    // MARK: Versions table

    private var sortedVersionRows: [FleetApplicationRow] {
        model.filteredApplications(platform: platform).sorted { a, b in
            let av: String, bv: String
            switch versionsSort {
            case .device: av = a.displayDevice; bv = b.displayDevice
            case .application: av = a.name; bv = b.name
            case .version: av = a.version; bv = b.version
            case .usage: av = a.usage ?? ""; bv = b.usage ?? ""
            case .catalog: av = a.catalog ?? ""; bv = b.catalog ?? ""
            case .area: av = a.area ?? a.department ?? ""; bv = b.area ?? b.department ?? ""
            case .location: av = a.location ?? ""; bv = b.location ?? ""
            }
            return UsageCells.ordered(UsageCells.compare(av, bv), ascending: versionsAscending)
        }
    }

    private var versionsTableSection: some View {
        let rows = sortedVersionRows
        return VStack(spacing: 0) {
            HStack(spacing: 8) {
                Image(systemName: "list.bullet.rectangle").foregroundStyle(.blue)
                if model.selectedVersions.isEmpty {
                    Text("Application Versions Inventory").appFont(.headline)
                } else {
                    Text("Filtered: \(model.selectedVersions.count) version\(model.selectedVersions.count == 1 ? "" : "s") selected").appFont(.headline)
                    Button("Clear Selections") { model.selectedVersions = [] }.controlSize(.small).tint(.yellow)
                }
                Spacer()
                Text("\(rows.count) records").appFont(.caption).foregroundStyle(.secondary)
            }
            .padding(.horizontal, 16).padding(.vertical, 10)
            .overlay(alignment: .bottom) { Divider() }
            StickyTable {
                ReportSortHeader(title: "Application", column: .application, sortColumn: $versionsSort, ascending: $versionsAscending, width: 260)
                ReportSortHeader(title: "Version", column: .version, sortColumn: $versionsSort, ascending: $versionsAscending, width: 110)
                ReportSortHeader(title: "Usage", column: .usage, sortColumn: $versionsSort, ascending: $versionsAscending, width: 90)
                ReportSortHeader(title: "Catalog", column: .catalog, sortColumn: $versionsSort, ascending: $versionsAscending, width: 100)
                ReportSortHeader(title: "Area", column: .area, sortColumn: $versionsSort, ascending: $versionsAscending, width: 130)
                ReportSortHeader(title: "Location", column: .location, sortColumn: $versionsSort, ascending: $versionsAscending, width: 140)
                ReportSortHeader(title: "Device", column: .device, sortColumn: $versionsSort, ascending: $versionsAscending)
            } rows: {
                if rows.isEmpty {
                    ReportEmptyRows(title: "No applications match", message: "Adjust the search, selections or version filters.", systemImage: "square.grid.2x2")
                }
                ForEach(rows) { app in
                    HStack(alignment: .top, spacing: 12) {
                        Text(app.name).appFont(.callout).lineLimit(1).truncationMode(.tail).help(app.name).frame(width: 260, alignment: .leading)
                        Text("v\(app.version)").appFont(.callout).frame(width: 110, alignment: .leading)
                        Text(UsageCells.dash(app.usage)).appFont(.callout).foregroundStyle(.secondary).frame(width: 90, alignment: .leading)
                        Text(UsageCells.dash(app.catalog)).appFont(.callout).foregroundStyle(.secondary).frame(width: 100, alignment: .leading)
                        Text(UsageCells.dash(app.areaOrDepartment)).appFont(.callout).foregroundStyle(.secondary).lineLimit(1).frame(width: 130, alignment: .leading)
                        Text(UsageCells.dash(app.location)).appFont(.callout).foregroundStyle(.secondary).lineLimit(1).frame(width: 140, alignment: .leading)
                        HStack(spacing: 6) {
                            Button { appState.open(device: app.serialNumber, tab: .applications) } label: {
                                Text(app.displayDevice).appFont(.callout, weight: .medium).lineLimit(1).truncationMode(.middle)
                            }
                            .buttonStyle(.plain).help(app.serialNumber)
                            PlatformBadge(platform: Platform.normalize(app.platform))
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .padding(.horizontal, 16).padding(.vertical, 7)
                    Divider()
                }
            }
        }
    }

    // MARK: Missing table

    private var sortedMissingDevices: [ApplicationFilterDevice] {
        model.missingDevices(platform: platform).sorted { a, b in
            let av: String, bv: String
            switch missingSort {
            case .device: av = a.name; bv = b.name
            case .serial: av = a.serialNumber; bv = b.serialNumber
            case .location: av = a.location ?? ""; bv = b.location ?? ""
            case .catalog: av = a.catalog ?? ""; bv = b.catalog ?? ""
            }
            return UsageCells.ordered(UsageCells.compare(av, bv), ascending: missingAscending)
        }
    }

    private var missingSection: some View {
        let devices = sortedMissingDevices
        let apps = model.selectedApplications.joined(separator: ", ")
        return VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Image(systemName: "nosign").foregroundStyle(.red)
                    Text("Devices Missing: \(apps)").appFont(.headline).foregroundStyle(.red).lineLimit(1)
                    Spacer()
                    Text("\(devices.count) device\(devices.count == 1 ? "" : "s") without this application").appFont(.callout, weight: .medium).foregroundStyle(.red)
                }
                Text("These devices match your filter criteria but do not have the selected application installed.").appFont(.caption).foregroundStyle(.red.opacity(0.85))
            }
            .padding(.horizontal, 16).padding(.vertical, 10)
            .background(Color.red.opacity(0.07))
            .overlay(alignment: .bottom) { Divider() }
            StickyTable {
                ReportSortHeader(title: "Device", column: .device, sortColumn: $missingSort, ascending: $missingAscending, width: 240)
                ReportSortHeader(title: "Serial Number", column: .serial, sortColumn: $missingSort, ascending: $missingAscending, width: 150)
                ReportSortHeader(title: "Location", column: .location, sortColumn: $missingSort, ascending: $missingAscending, width: 160)
                ReportSortHeader(title: "Catalog", column: .catalog, sortColumn: $missingSort, ascending: $missingAscending, width: 110)
                ReportHeaderLabel(title: "Status")
            } rows: {
                if devices.isEmpty {
                    VStack(spacing: 6) {
                        Image(systemName: "checkmark.circle").font(.system(size: 28)).foregroundStyle(.green)
                        Text("All devices have this application!").appFont(.callout, weight: .medium).foregroundStyle(.green)
                        Text("No devices matching your filters are missing the selected application.").appFont(.caption).foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity).padding(40)
                }
                ForEach(devices) { d in
                    HStack(alignment: .top, spacing: 12) {
                        Button { appState.open(device: d.serialNumber, tab: .applications) } label: {
                            Text(d.name).appFont(.callout, weight: .medium).lineLimit(1).truncationMode(.middle)
                        }
                        .buttonStyle(.plain).frame(width: 240, alignment: .leading)
                        HStack(spacing: 4) {
                            Text(d.serialNumber).appFont(.callout, design: .monospaced).foregroundStyle(.secondary)
                            CopyButton(value: d.serialNumber)
                        }
                        .frame(width: 150, alignment: .leading)
                        Text(UsageCells.dash(d.location)).appFont(.callout).foregroundStyle(.secondary).lineLimit(1).frame(width: 160, alignment: .leading)
                        Text(UsageCells.dash(d.catalog)).appFont(.callout).foregroundStyle(.secondary).frame(width: 110, alignment: .leading)
                        Pill("Missing", tone: .red).frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .padding(.horizontal, 16).padding(.vertical, 7)
                    Divider()
                }
            }
        }
    }

    // MARK: Devices with selected versions (usage report)

    private var sortedDeviceVersionRows: [DeviceVersionRow] {
        model.devicesWithSelectedVersions.sorted { a, b in
            let r: ComparisonResult
            switch dvSort {
            case .device: r = UsageCells.compare(a.deviceName, b.deviceName)
            case .serial: r = UsageCells.compare(a.serialNumber, b.serialNumber)
            case .application: r = UsageCells.compare(a.appName, b.appName)
            case .version: r = ApplicationsReport.compareVersions(a.version, b.version)
            case .location: r = UsageCells.compare(a.location ?? "", b.location ?? "")
            case .catalog: r = UsageCells.compare(a.catalog ?? "", b.catalog ?? "")
            case .lastSeen: r = UsageCells.compare(UsageCells.date(a.lastSeen), UsageCells.date(b.lastSeen))
            }
            return UsageCells.ordered(r, ascending: dvAscending)
        }
    }

    private var devicesWithVersionsSection: some View {
        let rows = sortedDeviceVersionRows
        return VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Image(systemName: "list.bullet.rectangle").foregroundStyle(.blue)
                    Text("Devices with Selected Versions").appFont(.headline)
                    Spacer()
                    Button("Clear Version Selection") { model.selectedVersions = [] }.controlSize(.small)
                }
                FlowLayout(spacing: 6) {
                    ForEach(model.selectedVersions, id: \.self) { filter in
                        if let (app, version) = ApplicationsReport.splitVersionFilter(filter) {
                            HStack(spacing: 4) {
                                Text("\(app) v\(version)").appFont(.caption, weight: .medium)
                                Button { model.toggleVersion(version, app: app) } label: { Image(systemName: "xmark").appFont(.caption2) }.buttonStyle(.plain)
                            }
                            .padding(.horizontal, 10).padding(.vertical, 4)
                            .background(Color.blue.opacity(0.15), in: Capsule())
                            .foregroundStyle(.blue)
                        }
                    }
                }
            }
            .padding(.horizontal, 16).padding(.vertical, 10)
            .overlay(alignment: .bottom) { Divider() }
            StickyTable {
                ReportSortHeader(title: "Device Name", column: .device, sortColumn: $dvSort, ascending: $dvAscending, width: 220)
                ReportSortHeader(title: "Serial Number", column: .serial, sortColumn: $dvSort, ascending: $dvAscending, width: 150)
                ReportSortHeader(title: "Application", column: .application, sortColumn: $dvSort, ascending: $dvAscending, width: 200)
                ReportSortHeader(title: "Version", column: .version, sortColumn: $dvSort, ascending: $dvAscending, width: 100)
                ReportSortHeader(title: "Location", column: .location, sortColumn: $dvSort, ascending: $dvAscending, width: 140)
                ReportSortHeader(title: "Catalog", column: .catalog, sortColumn: $dvSort, ascending: $dvAscending, width: 100)
                ReportSortHeader(title: "Last Seen", column: .lastSeen, sortColumn: $dvSort, ascending: $dvAscending)
            } rows: {
                if rows.isEmpty {
                    ReportEmptyRows(title: "No devices found with the selected versions", systemImage: "desktopcomputer")
                }
                ForEach(rows) { row in
                    HStack(alignment: .top, spacing: 12) {
                        Button { appState.open(device: row.serialNumber, tab: .applications) } label: {
                            Text(row.deviceName).appFont(.callout, weight: .medium).lineLimit(1).truncationMode(.middle)
                        }
                        .buttonStyle(.plain).frame(width: 220, alignment: .leading)
                        HStack(spacing: 4) {
                            Text(row.serialNumber).appFont(.callout, design: .monospaced).foregroundStyle(.secondary)
                            CopyButton(value: row.serialNumber)
                        }
                        .frame(width: 150, alignment: .leading)
                        Text(row.appName).appFont(.callout).lineLimit(1).frame(width: 200, alignment: .leading)
                        Text("v\(row.version)").appFont(.callout).frame(width: 100, alignment: .leading)
                        Text(UsageCells.dash(row.location)).appFont(.callout).foregroundStyle(.secondary).lineLimit(1).frame(width: 140, alignment: .leading)
                        Text(UsageCells.dash(row.catalog)).appFont(.callout).foregroundStyle(.secondary).frame(width: 100, alignment: .leading)
                        Text(TimeFormatting.relative(row.lastSeen)).appFont(.callout).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .padding(.horizontal, 16).padding(.vertical, 7)
                    Divider()
                }
            }
        }
    }
}
