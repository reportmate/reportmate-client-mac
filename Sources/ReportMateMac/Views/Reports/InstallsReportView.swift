import SwiftUI
import ReportMateKit

/// Managed Software Update Reporting: the config report, the status
/// widgets and drill-downs, and the item report builder. Port of
/// `app/installs/page.tsx`.
struct InstallsReportView: View {
    @Environment(AppState.self) private var appState
    @State private var model = InstallsReportModel()

    enum ConfigColumn { case device, total, installed, pending, errors, warnings, removed, manifest, lastSeen, version }
    enum InstallColumn { case device, manifest, name, version, status, lastSeen }
    @State private var configSort: ConfigColumn = .device
    @State private var configAscending = true
    @State private var installSort: InstallColumn = .device
    @State private var installAscending = true
    @State private var errorSort = ItemCountTable.Sort()
    @State private var warningSort = ItemCountTable.Sort()
    @State private var pendingSort = ItemCountTable.Sort()
    @State private var successSort = ItemCountTable.Sort()

    private var platform: PlatformFilter { appState.platformFilter }

    static func category(_ raw: String?) -> InstallItems.Category? {
        switch raw { case "errors": return .error; case "warnings": return .warning; case "pending": return .pending; case "success": return .success; default: return nil }
    }

    private var linkQuery: [String: String] {
        var q: [String: String] = [:]
        switch model.itemsStatusFilter { case .error: q["filter"] = "errors"; case .warning: q["filter"] = "warnings"; case .pending: q["filter"] = "pending"; case .success: q["filter"] = "success"; case nil: break }
        if model.statusView == .messages, model.itemsStatusFilter != nil { q["view"] = "messages" }
        if !model.searchQuery.isEmpty { q["q"] = model.searchQuery }
        return q
    }

    var body: some View {
        @Bindable var m = model
        VStack(spacing: 0) {
            header
            if let error = model.error, !model.filtersLoading {
                ErrorBanner(message: error) { Task { await model.loadFilters(api: appState.api, force: true) } }
                    .padding(.horizontal, 16).padding(.top, 8)
            }
            if model.filtersLoading {
                LoadingView(message: model.loadingMessage.isEmpty ? "Loading managed installs data..." : model.loadingMessage)
            } else {
                ScrollView {
                    VStack(spacing: 0) {
                        if model.isConfigReport, !model.isGeneratingReport, !model.configRows(platform).isEmpty { widgetsAccordion }
                        if !model.installs.isEmpty { itemVersionsStrip }
                        DeviceFiltersView(options: model.filterOptions(platform), selections: $m.selections, expanded: $m.selectionsExpanded)
                        if model.isGeneratingReport { itemPicker }
                        if !model.isGeneratingReport { searchRow }
                        if model.loading { reportProgress }
                        if !model.loading, model.hasGeneratedReport, model.installs.isEmpty, !model.isConfigReport { noResults }
                        if !model.installs.isEmpty, !model.isConfigReport { installsTable }
                        if !model.isGeneratingReport, model.isConfigReport, model.itemsStatusFilter == nil { configTable }
                        if model.itemsStatusFilter != nil { statusSection }
                    }
                }
            }
        }
        .navigationTitle("Installs")
        .task(id: appState.configuration) { await model.loadFilters(api: appState.api) }
        .onChange(of: appState.refreshRequested) { _, _ in
            model.invalidate()
            Task { await model.loadFilters(api: appState.api, force: true) }
        }
        .onChange(of: appState.pendingDeepLink, initial: true) { _, _ in
            guard let link = appState.consumeDeepLink(for: .installs) else { return }
            model.searchQuery = link.query["q"] ?? ""
            model.selectStatus(Self.category(link.query["filter"]))
            model.statusView = link.query["view"] == "messages" ? .messages : .devices
            if model.itemsStatusFilter != nil { model.selectionsExpanded = false }
        }
        .onChange(of: linkQuery, initial: true) { _, q in appState.linkQuery = q }
        .onReceive(NotificationCenter.default.publisher(for: .installsFilter)) { note in
            guard let raw = note.object as? String else { return }
            let category: InstallItems.Category? = raw == "errors" ? .error : raw == "warnings" ? .warning : raw == "pending" ? .pending : raw == "success" ? .success : nil
            model.searchQuery = ""
            model.selectStatus(category)
            model.selectionsExpanded = false
        }
    }

    // MARK: Header

    private var subtitle: String {
        if model.isGeneratingReport { return "Select items from the list below, then click Generate Report" }
        if model.isConfigReport { return "View device configurations, drill down by status, or generate targeted reports using filters" }
        if model.installs.isEmpty { return model.hasGeneratedReport ? "No install records found matching your criteria." : "Select items from filters to generate an items report" }
        return "Filtered install records across selected devices and criteria"
    }

    private var header: some View {
        @Bindable var m = model
        return HStack(alignment: .center, spacing: 12) {
            if model.isGeneratingReport || model.loading || (model.hasGeneratedReport && !model.installs.isEmpty) {
                Button { model.backToConfigReport() } label: { Image(systemName: "arrow.left") }.help("Back to Config Report")
            }
            VStack(alignment: .leading, spacing: 2) {
                Text("Managed Software Update Reporting").appFont(.title3, weight: .semibold)
                Text(subtitle).appFont(.caption).foregroundStyle(.secondary)
            }
            if model.filtersLoading {
                VStack(alignment: .leading, spacing: 3) {
                    Text(model.loadingMessage.isEmpty ? "Loading managed installs data..." : model.loadingMessage).appFont(.caption2).foregroundStyle(.secondary)
                    ProgressView().progressViewStyle(.linear).tint(.green)
                }
                .frame(maxWidth: 320)
                .padding(.leading, 12)
            }
            Spacer()
            if !model.loading, !model.filtersLoading {
                if model.hasGeneratedReport, !model.installs.isEmpty {
                    Button { model.resetReport() } label: { Label("New Report", systemImage: "plus") }
                } else {
                    Button {
                        if model.selectedInstalls.isEmpty {
                            model.enterGenerateMode()
                        } else {
                            Task { await model.generateReport(api: appState.api) }
                        }
                    } label: {
                        Text(!model.selectedInstalls.isEmpty && model.filtersChanged ? "Update Report" : "Generate Report")
                    }
                    .buttonStyle(.borderedProminent)
                }
                exportButton
            }
            if model.isGeneratingReport, !model.loading {
                HStack(spacing: 6) {
                    Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                    TextField("Search items...", text: $m.searchQuery).textFieldStyle(.plain)
                    if !model.searchQuery.isEmpty { Button { model.searchQuery = "" } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary) }.buttonStyle(.plain) }
                }
                .padding(.horizontal, 10).padding(.vertical, 6)
                .background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 8))
                .frame(width: 240)
            }
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
        .overlay(alignment: .bottom) { Divider() }
    }

    @ViewBuilder private var exportButton: some View {
        if model.isConfigReport, !model.configRows(platform).isEmpty {
            CSVExportButton(filename: "config-report", headers: ["Device Name", "Serial Number", "Asset Tag", "System", "Version", "Manifest", "Repo", "Total Items", "Installed", "Pending", "Errors", "Warnings", "Removed", "Last Seen"]) {
                sortedConfigRows.map { d in
                    [d.deviceName, d.serialNumber, d.assetTag ?? "", d.configType, d.version, d.clientIdentifier, d.softwareRepoUrl, String(d.totalPackagesManaged), String(d.installedCount),
                     String(d.pendingCount), String(d.errorCount), String(d.warningCount), String(d.removedCount), d.lastSeen ?? ""]
                }
            }
        } else if !model.filteredInstalls.isEmpty {
            CSVExportButton(filename: "installs-report", headers: ["Device Name", "Serial Number", "Install", "Version", "Status", "Usage", "Catalog", "Room", "Fleet", "Platform", "Last Seen"]) {
                sortedInstalls.map { [$0.deviceName, $0.serialNumber, $0.name, $0.version, $0.status, $0.usage ?? "", $0.catalog ?? "", $0.room ?? "", $0.fleet ?? "", $0.platform, $0.lastSeen ?? ""] }
            }
        }
    }

    // MARK: Widgets

    private var widgetsAccordion: some View {
        @Bindable var m = model
        let devices = model.platformDevices(platform)
        return VStack(spacing: 0) {
            AccordionHeader(title: "Widgets", detail: "Item status, messages and configuration across \(devices.count) devices", expanded: $m.widgetsExpanded)
            if model.widgetsExpanded {
                VStack(alignment: .leading, spacing: 14) {
                    if model.itemsStatusFilter == nil, !model.hasWidgetSelection { itemTablesRow }
                    if model.itemsStatusFilter == nil, !model.hasWidgetSelection, !devices.isEmpty { messagesRow(devices) }
                    if model.itemsStatusFilter == nil { configWidgetsRow(devices) }
                    if !model.searchQuery.isEmpty, let cat = model.itemsStatusFilter, cat == .error || cat == .warning {
                        SelectedItemMessagesPanel(itemName: model.searchQuery, errors: cat == .error,
                                                  messages: InstallsReport.messages(forItem: model.searchQuery, in: devices, errors: cat == .error)) {
                            model.searchQuery = ""
                            model.selectStatus(nil)
                        }
                    }
                }
                .padding(.horizontal, 16).padding(.bottom, 14)
            }
        }
        .overlay(alignment: .bottom) { Divider() }
    }

    private func headerTap(_ category: InstallItems.Category) {
        if model.itemsStatusFilter == category, model.searchQuery.isEmpty {
            model.selectStatus(nil)
            model.selectionsExpanded = false
            model.widgetsExpanded = true
        } else {
            model.searchQuery = ""
            model.selectStatus(category)
            model.selectionsExpanded = true
        }
    }

    private func rowTap(_ category: InstallItems.Category, _ name: String) {
        if model.searchQuery == name, model.itemsStatusFilter == category {
            model.searchQuery = ""
            model.selectStatus(nil)
            model.widgetsExpanded = true
        } else {
            model.searchQuery = name
            model.selectStatus(category)
        }
    }

    private var itemTablesRow: some View {
        let devices = model.platformDevices(platform)
        let errors = InstallsReport.itemCounts(devices, .error)
        let warnings = InstallsReport.itemCounts(devices, .warning)
        let pending = InstallsReport.itemCounts(devices, .pending)
        let success = InstallsReport.itemCounts(devices, .success)
        func selected(_ c: InstallItems.Category) -> String? { model.itemsStatusFilter == c ? model.searchQuery : nil }
        return LazyVGrid(columns: [GridItem(.adaptive(minimum: 260), spacing: 12, alignment: .top)], alignment: .leading, spacing: 12) {
            ItemCountTable(title: "Items with Errors", items: errors, tone: .red, sortable: true, sort: $errorSort, selectedName: selected(.error),
                           headerHelp: "Click to show all devices with errors", onHeader: { headerTap(.error) }, onRow: { rowTap(.error, $0) })
            ItemCountTable(title: "Items with Warnings", items: warnings, tone: .yellow, sortable: true, sort: $warningSort, selectedName: selected(.warning),
                           headerHelp: "Click to show all devices with warnings", onHeader: { headerTap(.warning) }, onRow: { rowTap(.warning, $0) })
            if !pending.isEmpty {
                ItemCountTable(title: "Items with Pending", items: pending, tone: .cyan, sortable: true, sort: $pendingSort, selectedName: selected(.pending),
                               headerHelp: "Click to show all devices with pending updates", onHeader: { headerTap(.pending) }, onRow: { rowTap(.pending, $0) })
            }
            if !success.isEmpty {
                ItemCountTable(title: "Items Installed", items: success, tone: .green, sortable: false, sort: $successSort, selectedName: selected(.success),
                               headerHelp: "Click to show all devices that completed an install in their most recent run", onHeader: { headerTap(.success) }, onRow: { rowTap(.success, $0) })
            }
        }
    }

    private func messagesRow(_ devices: [InstallsDevice]) -> some View {
        let errors = InstallsReport.aggregateMessages(devices, errors: true)
        let warnings = InstallsReport.aggregateMessages(devices, errors: false)
        return LazyVGrid(columns: [GridItem(.adaptive(minimum: 380), spacing: 12, alignment: .top)], alignment: .leading, spacing: 12) {
            if !errors.isEmpty {
                InstallMessagesWidget(messages: errors, errors: true) { message in
                    model.selectStatus(.error)
                    model.searchQuery = message ?? ""
                }
            }
            if !warnings.isEmpty {
                InstallMessagesWidget(messages: warnings, errors: false) { message in
                    model.selectStatus(.warning)
                    model.searchQuery = message ?? ""
                }
            }
        }
    }

    private func configWidgetsRow(_ devices: [InstallsDevice]) -> some View {
        let repos = InstallsReport.repoCounts(devices)
        let repoTotal = max(repos.reduce(0) { $0 + $1.count }, 1)
        let manifests = InstallsReport.manifestCounts(devices)
        let manifestTotal = max(manifests.reduce(0) { $0 + $1.count }, 1)
        let munki = InstallsReport.versionCounts(devices, cimian: false)
        let cimian = InstallsReport.versionCounts(devices, cimian: true)
        func pct(_ n: Int, _ total: Int) -> Int { Int((Double(n) / Double(max(total, 1)) * 100).rounded()) }
        return LazyVGrid(columns: [GridItem(.adaptive(minimum: 260), spacing: 12, alignment: .top)], alignment: .leading, spacing: 12) {
            DistributionBarsWidget(title: "Software Repos", rows: repos.map { .init(key: $0.repo, label: repoDisplay($0.repo), count: $0.count, percentage: pct($0.count, repoTotal)) },
                                   emptyText: "No software repos found", tone: .blue, selected: model.selectedSoftwareRepo, showPercent: false) { repo in
                if !model.isConfigReport { model.showConfigReport() }
                model.selectedSoftwareRepo = model.selectedSoftwareRepo == repo ? "" : repo
            }
            if model.hasMunki(platform) {
                DistributionBarsWidget(title: "Munki Versions", rows: munki.versions.map { .init(key: $0.version, label: $0.version, count: $0.count, percentage: pct($0.count, munki.total)) },
                                       emptyText: "No Munki installations found", tone: .emerald, selected: model.selectedMunkiVersion, showPercent: true) { v in
                    if !model.isConfigReport { model.showConfigReport() }
                    model.selectedMunkiVersion = model.selectedMunkiVersion == v ? "" : v
                    model.selectedCimianVersion = ""
                }
            }
            if model.hasCimian(platform) {
                DistributionBarsWidget(title: "Cimian Versions", rows: cimian.versions.map { .init(key: $0.version, label: $0.version, count: $0.count, percentage: pct($0.count, cimian.total)) },
                                       emptyText: "No Cimian installations found", tone: .emerald, selected: model.selectedCimianVersion, showPercent: true) { v in
                    if !model.isConfigReport { model.showConfigReport() }
                    model.selectedCimianVersion = model.selectedCimianVersion == v ? "" : v
                    model.selectedMunkiVersion = ""
                }
            }
            DistributionBarsWidget(title: "Manifests", rows: manifests.map { .init(key: $0.manifest, label: $0.manifest, count: $0.count, percentage: pct($0.count, manifestTotal)) },
                                   emptyText: "No manifests found", tone: .purple, selected: model.selectedManifest, showPercent: false) { m in
                if !model.isConfigReport { model.showConfigReport() }
                model.selectedManifest = model.selectedManifest == m ? "" : m
            }
        }
    }

    private func repoDisplay(_ repo: String) -> String {
        String(repo.replacingOccurrences(of: #"^https?://"#, with: "", options: .regularExpression).split(separator: "/").first ?? Substring(repo))
    }

    /// "Install Item(s) Versions" for a generated report; a version click
    /// searches for `item - version`.
    private var itemVersionsStrip: some View {
        let groups = InstallsReport.itemVersions(model.installs)
        let cards = groups.map { VersionCard(name: $0.name, total: $0.total, versions: $0.versions) }
        let selected: [String] = {
            guard let range = model.searchQuery.range(of: " - ") else { return [] }
            return [ApplicationsReport.versionFilter(app: String(model.searchQuery[..<range.lowerBound]), version: String(model.searchQuery[range.upperBound...]))]
        }()
        return VersionDistributionStrip(title: "Install Item(s) Versions", cards: cards, selected: selected, tone: .green, hint: "Click to filter the table to this version") { version, name in
            let key = "\(name) - \(version)"
            model.searchQuery = model.searchQuery == key ? "" : key
        }
    }

    // MARK: Picker, search and pills

    private var itemPicker: some View {
        let items = model.pickerItems(platform)
        return VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(model.selectedInstalls.isEmpty ? "Items" : "Items (\(model.selectedInstalls.count) selected)").appFont(.callout, weight: .medium)
                Spacer()
                if !model.selectedInstalls.isEmpty { Button("Clear selection") { model.selectedInstalls = [] }.controlSize(.small).tint(.red) }
            }
            ScrollView {
                FlowLayout(spacing: 4) {
                    ForEach(items.prefix(2000), id: \.self) { name in
                        FilterPill(text: name, selected: model.selectedInstalls.contains(name), tone: .green) { model.toggleInstall(name) }
                    }
                    if items.isEmpty {
                        Text(model.searchQuery.isEmpty ? "No managed items reported" : "No items match \"\(model.searchQuery)\"").appFont(.caption).foregroundStyle(.secondary).padding(4)
                    } else if items.count > 2000 {
                        Text("Showing the first 2000 of \(items.count) items; search to narrow the list.").appFont(.caption).foregroundStyle(.secondary).padding(4)
                    }
                }
                .padding(8)
            }
            .frame(minHeight: 160, maxHeight: 420)
            .background(Color.cardBackground, in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.cardBorder))
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
        .overlay(alignment: .bottom) { Divider() }
    }

    private var searchRow: some View {
        @Bindable var m = model
        let showPills = !model.installs.isEmpty || (model.isConfigReport && !model.configRows(platform).isEmpty)
        let deviceCounts = showPills ? model.deviceStatusCounts(platform) : [:]
        let installCounts = showPills ? model.installStatusCounts(platform) : [:]
        return HStack(spacing: 10) {
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Search", text: $m.searchQuery).textFieldStyle(.plain)
                if !model.searchQuery.isEmpty { Button { model.searchQuery = "" } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary) }.buttonStyle(.plain).help("Clear search") }
            }
            .padding(.horizontal, 10).padding(.vertical, 6)
            .background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 8))
            .frame(maxWidth: 320)
            if showPills {
                ScrollView(.horizontal) {
                    HStack(spacing: 6) {
                        ForEach([DeviceStatus.active, .stale, .missing], id: \.self) { s in
                            StatusPill(label: s.displayName, count: deviceCounts[s] ?? 0, tone: .gray, active: model.deviceStatusFilter == s) {
                                model.deviceStatusFilter = model.deviceStatusFilter == s ? nil : s
                            }
                        }
                        if model.itemsStatusFilter == nil {
                            ForEach([InstallStatusClass.error, .warning, .pending, .installed, .removed]) { c in
                                StatusPill(label: c.label, count: installCounts[c] ?? 0, tone: pillTone(c), active: model.installStatusFilter == c) {
                                    model.installStatusFilter = model.installStatusFilter == c ? nil : c
                                }
                            }
                        }
                    }
                }
            }
            Spacer()
            if model.hasGeneratedReport, !model.installs.isEmpty, !model.loading, model.itemsStatusFilter == nil, !model.hasWidgetSelection {
                Button("New Report") { model.resetReport() }
            }
        }
        .padding(.horizontal, 16).padding(.vertical, 10)
        .overlay(alignment: .bottom) { Divider() }
    }

    private func pillTone(_ c: InstallStatusClass) -> Tone {
        switch c {
        case .error: return .red
        case .warning: return .yellow
        case .pending: return .cyan
        case .installed: return .green
        case .removed: return .purple
        }
    }

    private var reportProgress: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(model.loadingMessage).appFont(.callout, weight: .medium)
                Spacer()
                Text("\(Int((model.reportProgress * 100).rounded()))%").appFont(.caption).foregroundStyle(.secondary)
            }
            ProgressView(value: model.reportProgress).progressViewStyle(.linear)
            Text("Processing \(model.selectedInstalls.count) item\(model.selectedInstalls.count == 1 ? "" : "s") across \(model.filters.devicesWithData > 0 ? String(model.filters.devicesWithData) : "all") devices")
                .appFont(.caption).foregroundStyle(.secondary)
        }
        .padding(16)
    }

    private var noResults: some View {
        VStack(spacing: 8) {
            Image(systemName: "tray").font(.system(size: 28)).foregroundStyle(.tertiary)
            Text("No devices have the selected items installed. Try selecting different items or adjusting your filters.").appFont(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
            Button("Try different items") {
                model.hasGeneratedReport = false
                model.isGeneratingReport = true
                model.itemsStatusFilter = nil
                model.searchQuery = ""
            }
        }
        .frame(maxWidth: .infinity).padding(40)
    }

    // MARK: Installs table

    private var sortedInstalls: [InstallRecord] {
        model.filteredInstalls.sorted { a, b in
            let r: ComparisonResult
            switch installSort {
            case .device: r = UsageCells.compare(a.deviceName, b.deviceName)
            case .manifest: r = UsageCells.compare(a.manifest ?? "", b.manifest ?? "")
            case .name: r = UsageCells.compare(a.name, b.name)
            case .version: r = UsageCells.compare(a.version, b.version)
            case .status: r = UsageCells.compare(a.status, b.status)
            case .lastSeen: r = UsageCells.compare(UsageCells.date(a.lastSeen), UsageCells.date(b.lastSeen))
            }
            return UsageCells.ordered(r, ascending: installAscending)
        }
    }

    private func installStatusTone(_ status: String) -> Tone {
        switch status {
        case "installed": return .green
        case "pending": return .blue
        case "error", "failed": return .red
        case "warning": return .yellow
        default: return .gray
        }
    }

    private var installsTable: some View {
        let rows = sortedInstalls
        return StickyTable {
            ReportSortHeader(title: "Device", column: .device, sortColumn: $installSort, ascending: $installAscending, width: 240)
            ReportSortHeader(title: "Manifest", column: .manifest, sortColumn: $installSort, ascending: $installAscending, width: 180)
            ReportSortHeader(title: "Install", column: .name, sortColumn: $installSort, ascending: $installAscending)
            ReportSortHeader(title: "Version", column: .version, sortColumn: $installSort, ascending: $installAscending, width: 120)
            ReportSortHeader(title: "Status", column: .status, sortColumn: $installSort, ascending: $installAscending, width: 110)
            ReportSortHeader(title: "Last Seen", column: .lastSeen, sortColumn: $installSort, ascending: $installAscending, width: 110)
        } rows: {
            if rows.isEmpty { ReportEmptyRows(title: "No install records match", systemImage: "arrow.down.circle") }
            ForEach(rows) { r in
                HStack(alignment: .top, spacing: 12) {
                    VStack(alignment: .leading, spacing: 2) {
                        Button { appState.open(device: r.serialNumber, tab: .installs) } label: {
                            Text(r.deviceName).appFont(.callout, weight: .medium).lineLimit(1).truncationMode(.middle)
                        }
                        .buttonStyle(.plain).help(r.deviceName)
                        HStack(spacing: 4) {
                            Text(r.serialNumber).appFont(.caption2, design: .monospaced).foregroundStyle(.secondary)
                            if let tag = r.assetTag {
                                Text("|").foregroundStyle(.tertiary).appFont(.caption2)
                                Text(tag).appFont(.caption2, design: .monospaced).foregroundStyle(.secondary)
                                CopyButton(value: tag)
                            }
                        }
                    }
                    .frame(width: 240, alignment: .leading)
                    Text(r.manifest ?? "-").appFont(.callout).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle).help(r.manifest ?? "-").frame(width: 180, alignment: .leading)
                    Text(r.name).appFont(.callout).lineLimit(1).frame(maxWidth: .infinity, alignment: .leading)
                    Text(r.version.isEmpty ? "-" : r.version).appFont(.callout, design: .monospaced).lineLimit(1).frame(width: 120, alignment: .leading)
                    Pill(r.status.uppercased(), tone: installStatusTone(r.status)).frame(width: 110, alignment: .leading)
                    Text(TimeFormatting.relative(r.lastSeen)).appFont(.callout).foregroundStyle(.secondary).frame(width: 110, alignment: .leading)
                }
                .padding(.horizontal, 16).padding(.vertical, 7)
                Divider()
            }
        }
    }

    // MARK: Config table

    private var sortedConfigRows: [ConfigReportRow] {
        model.filteredConfigRows(platform).sorted { a, b in
            let r: ComparisonResult
            switch configSort {
            case .device: r = UsageCells.compare(a.deviceName, b.deviceName)
            case .total: r = UsageCells.compare(a.totalPackagesManaged, b.totalPackagesManaged)
            case .installed: r = UsageCells.compare(a.installedCount, b.installedCount)
            case .pending: r = UsageCells.compare(a.pendingCount, b.pendingCount)
            case .errors: r = UsageCells.compare(a.errorCount, b.errorCount)
            case .warnings: r = UsageCells.compare(a.warningCount, b.warningCount)
            case .removed: r = UsageCells.compare(a.removedCount, b.removedCount)
            case .manifest: r = UsageCells.compare(a.clientIdentifier, b.clientIdentifier)
            case .lastSeen: r = UsageCells.compare(a.lastSeen ?? "", b.lastSeen ?? "")
            case .version: r = UsageCells.compare(a.version, b.version)
            }
            return UsageCells.ordered(r, ascending: configAscending)
        }
    }

    private func countCell(_ n: Int, tone: Tone, width: CGFloat = 62) -> some View {
        Group {
            if n > 0 { Pill("\(n)", tone: tone) } else { Text("–").foregroundStyle(.tertiary) }
        }
        .frame(width: width, alignment: .center)
    }

    private var configTable: some View {
        let rows = sortedConfigRows
        return StickyTable {
            ReportSortHeader(title: "Device", column: .device, sortColumn: $configSort, ascending: $configAscending, width: 240)
            ReportSortHeader(title: "#", column: .total, sortColumn: $configSort, ascending: $configAscending, width: 50, alignment: .center)
            ReportSortHeader(title: "Inst", column: .installed, sortColumn: $configSort, ascending: $configAscending, width: 62, alignment: .center).help("Installed")
            ReportSortHeader(title: "Pend", column: .pending, sortColumn: $configSort, ascending: $configAscending, width: 62, alignment: .center).help("Pending")
            ReportSortHeader(title: "Err", column: .errors, sortColumn: $configSort, ascending: $configAscending, width: 62, alignment: .center).help("Errors")
            ReportSortHeader(title: "Warn", column: .warnings, sortColumn: $configSort, ascending: $configAscending, width: 62, alignment: .center).help("Warnings")
            ReportSortHeader(title: "Rem", column: .removed, sortColumn: $configSort, ascending: $configAscending, width: 62, alignment: .center).help("Removed")
            ReportSortHeader(title: "Manifest / Repo", column: .manifest, sortColumn: $configSort, ascending: $configAscending)
            ReportSortHeader(title: "Last Seen", column: .lastSeen, sortColumn: $configSort, ascending: $configAscending, width: 110)
            ReportSortHeader(title: "Version", column: .version, sortColumn: $configSort, ascending: $configAscending, width: 90)
        } rows: {
            if rows.isEmpty { ReportEmptyRows(title: "No devices match", message: "Adjust the search, status pills, widget selections or selections.", systemImage: "arrow.down.circle") }
            ForEach(rows) { d in
                HStack(alignment: .top, spacing: 12) {
                    VStack(alignment: .leading, spacing: 2) {
                        Button { appState.open(device: d.serialNumber, tab: .installs) } label: {
                            HStack(spacing: 6) {
                                Text(d.deviceName).appFont(.callout, weight: .medium).lineLimit(1).truncationMode(.middle)
                                PlatformBadge(platform: d.device.platform)
                            }
                        }
                        .buttonStyle(.plain).help(d.deviceName)
                        HStack(spacing: 4) {
                            Text(d.serialNumber).appFont(.caption2, design: .monospaced).foregroundStyle(.secondary)
                            CopyButton(value: d.serialNumber)
                            if let tag = d.assetTag {
                                Text("|").foregroundStyle(.tertiary).appFont(.caption2)
                                Text(tag).appFont(.caption2, design: .monospaced).foregroundStyle(.secondary)
                                CopyButton(value: tag)
                            }
                        }
                    }
                    .frame(width: 240, alignment: .leading)
                    Text("\(d.totalPackagesManaged)").appFont(.callout).monospacedDigit().frame(width: 50, alignment: .center)
                    countCell(d.installedCount, tone: .green)
                    countCell(d.pendingCount, tone: .cyan)
                    countCell(d.errorCount, tone: .red)
                    countCell(d.warningCount, tone: .yellow)
                    countCell(d.removedCount, tone: .purple)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(d.clientIdentifier).appFont(.callout).lineLimit(1).truncationMode(.middle)
                        Text(d.softwareRepoUrl).appFont(.caption2).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    Text(TimeFormatting.relative(d.lastSeen)).appFont(.callout).foregroundStyle(.secondary).frame(width: 110, alignment: .leading)
                    Text(d.version).appFont(.callout, design: .monospaced).lineLimit(1).frame(width: 90, alignment: .leading)
                }
                .padding(.horizontal, 16).padding(.vertical, 7)
                Divider()
            }
        }
    }

    // MARK: Status drill-down

    @ViewBuilder private var statusSection: some View {
        if let category = model.itemsStatusFilter {
            let copy = InstallStatusCopy.copy(for: category)
            let devices = model.statusDevices(platform)
            if devices.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: copy.systemImage).font(.system(size: 28)).foregroundStyle(copy.tone.color)
                    Text(model.searchQuery.isEmpty ? copy.emptyHeading : "No devices found").appFont(.headline)
                    Text(model.searchQuery.isEmpty ? copy.emptyBlurb
                         : "No devices have \"\(model.searchQuery)\" with \(copy.noun) status matching the current filters.")
                        .appFont(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
                    Button("Clear Filter") {
                        model.searchQuery = ""
                        model.selectStatus(nil)
                        model.widgetsExpanded = true
                    }
                }
                .frame(maxWidth: .infinity).padding(40)
            } else {
                statusHeader(category, copy, devices)
                if model.statusView == .messages {
                    messagesTable(copy, model.statusMessageGroups(platform), category: category)
                } else {
                    statusDevicesTable(copy, devices, category: category)
                }
            }
        }
    }

    private func statusHeader(_ category: InstallItems.Category, _ copy: InstallStatusCopy, _ devices: [InstallsDevice]) -> some View {
        let cats = model.categorized(platform)
        let groups = model.statusMessageGroups(platform)
        let itemCount = model.statusFilterItemCount(platform)
        return VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 12) {
                HStack(spacing: 4) {
                    StatusPill(label: "By Device - \(devices.count)", tone: .gray, active: model.statusView == .devices) { model.statusView = .devices }
                    StatusPill(label: "By Message - \(groups.filter { !$0.message.isEmpty }.count)", tone: .gray, active: model.statusView == .messages) { model.statusView = .messages }
                }
                Divider().frame(height: 16)
                ForEach([InstallItems.Category.error, .warning, .pending, .success], id: \.self) { c in
                    let cc = InstallStatusCopy.copy(for: c)
                    let n = c == .error ? cats.errors.count : c == .warning ? cats.warnings.count : c == .pending ? cats.pending.count : cats.success.count
                    StatusPill(label: cc.chip, count: n, tone: cc.tone, active: model.itemsStatusFilter == c) {
                        if c != model.itemsStatusFilter { model.searchQuery = ""; model.selectStatus(c) }
                    }
                }
                Spacer()
            }
            Text(model.searchQuery.isEmpty ? "(\(devices.count)) \(copy.devicesHeading)" : "(\(devices.count)) Devices with (\(itemCount)) \(copy.noun) for \(model.searchQuery)")
                .appFont(.headline)
            Text(model.statusView == .messages ? copy.messageBlurb : model.searchQuery.isEmpty ? copy.blurb : "Showing devices with \"\(model.searchQuery)\" packages that have \(copy.noun).")
                .appFont(.caption).foregroundStyle(.secondary)
        }
        .padding(.horizontal, 16).padding(.vertical, 10)
        .background(copy.tone.color.opacity(0.06))
        .overlay(alignment: .bottom) { Divider() }
    }

    private func messagesTable(_ copy: InstallStatusCopy, _ groups: [InstallMessageGroup], category: InstallItems.Category) -> some View {
        StickyTable {
            ReportHeaderLabel(title: copy.messageColumn)
            ReportHeaderLabel(title: "Packages", width: 260)
            ReportHeaderLabel(title: "Devices", width: 340)
        } rows: {
            ForEach(groups) { group in
                let key = group.message.isEmpty ? "__no_message__" : group.message
                let expanded = model.expandedMessages.contains(key)
                let shown = expanded ? group.devices : Array(group.devices.prefix(8))
                HStack(alignment: .top, spacing: 12) {
                    Group {
                        if group.message.isEmpty {
                            Text(category == .success ? "No version reported" : "No message reported — flagged by package status only").appFont(.callout).foregroundStyle(.secondary).italic()
                        } else {
                            HStack(alignment: .top, spacing: 6) {
                                CopyButton(value: group.message)
                                Text(group.message).appFont(.callout).foregroundStyle(copy.tone == .gray ? Color.primary : copy.tone.color).textSelection(.enabled)
                            }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    FlowLayout(spacing: 4) {
                        ForEach(group.itemNames, id: \.self) { Pill($0, tone: .gray) }
                    }
                    .frame(width: 260, alignment: .leading)
                    VStack(alignment: .leading, spacing: 4) {
                        Text("\(group.deviceCount) device\(group.deviceCount == 1 ? "" : "s")").appFont(.caption, weight: .medium)
                        FlowLayout(spacing: 4) {
                            ForEach(shown) { d in
                                Button {
                                    appState.open(device: d.serialNumber, tab: .installs)
                                } label: {
                                    Text(d.itemNames.count > 1 ? "\(d.deviceName) ×\(d.itemNames.count)" : d.deviceName).appFont(.caption).foregroundStyle(.blue)
                                }
                                .buttonStyle(.plain)
                                .help("\(d.serialNumber) — \(d.itemNames.joined(separator: ", "))")
                            }
                            if group.devices.count > 8 {
                                Button(expanded ? "Show fewer" : "+\(group.devices.count - 8) more") {
                                    if expanded { model.expandedMessages.remove(key) } else { model.expandedMessages.insert(key) }
                                }
                                .buttonStyle(.plain).appFont(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                    .frame(width: 340, alignment: .leading)
                }
                .padding(.horizontal, 16).padding(.vertical, 8)
                Divider()
            }
        }
    }

    private func statusDevicesTable(_ copy: InstallStatusCopy, _ devices: [InstallsDevice], category: InstallItems.Category) -> some View {
        StickyTable {
            ReportHeaderLabel(title: "Device", width: 240)
            ReportHeaderLabel(title: copy.packagesColumn)
            ReportHeaderLabel(title: "Manifest / Repo", width: 200)
            ReportHeaderLabel(title: "Last Seen", width: 110)
            ReportHeaderLabel(title: "Actions", width: 100)
        } rows: {
            ForEach(devices) { device in
                let packages = model.affectedPackages(of: device)
                if !packages.isEmpty {
                    HStack(alignment: .top, spacing: 12) {
                        VStack(alignment: .leading, spacing: 2) {
                            Button { appState.open(device: device.serialNumber, tab: .installs) } label: {
                                HStack(spacing: 6) {
                                    Text(device.deviceName).appFont(.callout, weight: .medium).lineLimit(1).truncationMode(.middle)
                                    PlatformBadge(platform: device.platform)
                                }
                            }
                            .buttonStyle(.plain)
                            HStack(spacing: 4) {
                                Text(device.serialNumber).appFont(.caption2, design: .monospaced).foregroundStyle(.secondary)
                                CopyButton(value: device.serialNumber)
                                if let tag = device.assetTag {
                                    Text("|").foregroundStyle(.tertiary).appFont(.caption2)
                                    Text(tag).appFont(.caption2, design: .monospaced).foregroundStyle(.secondary)
                                    CopyButton(value: tag)
                                }
                            }
                        }
                        .frame(width: 240, alignment: .leading)
                        VStack(alignment: .leading, spacing: 3) {
                            ForEach(Array(packages.prefix(5).enumerated()), id: \.offset) { _, pkg in
                                let message = InstallItems.message(of: pkg, category)
                                let status = pkg.firstString("currentStatus", "current_status", "status") ?? ""
                                HStack(alignment: .top, spacing: 6) {
                                    Pill(InstallItems.name(of: pkg), tone: copy.tone).help("\(InstallItems.name(of: pkg)): \(status)")
                                    if message.isEmpty {
                                        Text(status.isEmpty ? "no message reported" : status).appFont(.caption).foregroundStyle(.secondary).italic()
                                    } else {
                                        Text(message).appFont(.caption).lineLimit(2).textSelection(.enabled)
                                            .help(InstallItems.timestamp(of: pkg).map { "\(message) — \(TimeFormatting.relative($0))" } ?? message)
                                    }
                                }
                            }
                            if packages.count > 5 { Text("+\(packages.count - 5) more").appFont(.caption2).foregroundStyle(.secondary) }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(device.manifest ?? "-").appFont(.callout).lineLimit(1).truncationMode(.middle)
                            Text(device.softwareRepoURL ?? "").appFont(.caption2).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                        }
                        .frame(width: 200, alignment: .leading)
                        Text(TimeFormatting.relative(device.lastSeen)).appFont(.callout).foregroundStyle(.secondary).frame(width: 110, alignment: .leading)
                        Button("View Details") { appState.open(device: device.serialNumber, tab: .installs) }.buttonStyle(.link).appFont(.caption).frame(width: 100, alignment: .leading)
                    }
                    .padding(.horizontal, 16).padding(.vertical, 8)
                    Divider()
                }
            }
        }
    }
}
