import SwiftUI
import ReportMateKit

/// The fleet list: sortable table, search, and the Selections accordion.
struct DevicesView: View {
    @Environment(AppState.self) private var appState
    @State private var search = ""
    @State private var selections = DeviceSelections()
    @State private var filtersExpanded = false
    @State private var sortOrder: [KeyPathComparator<DeviceSummary>] = [KeyPathComparator(\.name, comparator: .localizedStandard)]
    @State private var tableSelection: DeviceSummary.ID?

    private var options: DeviceFilterOptions { DeviceFilterOptions(devices: appState.devices) }

    private var filtered: [DeviceSummary] {
        var list = appState.devices.filter { !$0.archived || appState.includeArchived }
        if !selections.isEmpty { list = list.filter(selections.matches) }
        if appState.platformFilter != .all { list = list.filter { appState.platformFilter.includes($0.platform) } }
        let q = search.trimmingCharacters(in: .whitespaces).lowercased()
        if !q.isEmpty {
            list = list.filter { d in
                [d.name, d.inventory.assetTag, d.serialNumber, d.inventory.deviceName, d.hostname, d.inventory.location,
                 d.deviceId, d.raw["modules"]["inventory"]["manufacturer"].string, d.raw["modules"]["inventory"]["model"].string,
                 d.raw["modules"]["inventory"]["domain"].string, d.raw["modules"]["inventory"]["organizationalUnit"].string]
                    .contains { $0?.lowercased().contains(q) ?? false }
            }
        }
        return list.sorted(using: sortOrder)
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            DeviceFiltersView(options: options, selections: $selections, expanded: $filtersExpanded)
            if appState.devicesLoading, appState.devices.isEmpty {
                LoadingView(message: "Loading devices…")
            } else if let error = appState.devicesError, appState.devices.isEmpty {
                ErrorBanner(message: error) { Task { await appState.loadDevices(force: true) } }.padding()
                Spacer()
            } else if appState.devices.isEmpty {
                EmptyStateView(title: "No devices found", message: "No devices have been registered in the fleet yet.", systemImage: "laptopcomputer")
                Spacer()
            } else {
                table
            }
        }
        .navigationTitle("Devices")
        .task { await appState.loadDevices() }
        .onChange(of: appState.refreshRequested) { _, _ in Task { await appState.loadDevices(force: true) } }
        .onReceive(NotificationCenter.default.publisher(for: .devicesSearch)) { note in
            if let q = note.object as? String { search = q }
        }
        .onReceive(NotificationCenter.default.publisher(for: .devicesStatusFilter)) { note in
            // The dashboard's status legend links to `/devices?status=<status>`.
            guard let status = note.object as? String else { return }
            selections.statuses = [status]
            filtersExpanded = true
        }
    }

    private var isFiltered: Bool { !search.trimmingCharacters(in: .whitespaces).isEmpty || !selections.isEmpty }

    private var header: some View {
        HStack(alignment: .center) {
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text("Endpoints Fleet: \(filtered.count)\(isFiltered ? " of \(appState.devices.count)" : "") devices").appFont(.title3, weight: .semibold)
                    if isFiltered { Text("(filtered)").appFont(.callout).foregroundStyle(.secondary) }
                }
                Text(isFiltered ? "Showing filtered results from \(appState.devices.count) total devices" : "Manage and monitor all devices in fleet")
                    .appFont(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Search devices…", text: $search).textFieldStyle(.plain)
                if !search.isEmpty {
                    Button { search = "" } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary) }.buttonStyle(.plain)
                }
            }
            .padding(.horizontal, 10).padding(.vertical, 6)
            .background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 8))
            .frame(width: 260)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .overlay(alignment: .bottom) { Divider() }
    }

    private var table: some View {
        Table(filtered, selection: $tableSelection, sortOrder: $sortOrder) {
            TableColumn("Device Name", value: \.name) { d in
                HStack(spacing: 6) {
                    Text(d.name).appFont(.body, weight: .medium).lineLimit(1).truncationMode(.middle)
                    PlatformBadge(platform: d.platform)
                }
            }
            .width(min: 160, ideal: 240)
            TableColumn("Asset Tag", value: \.inventory.assetTagSortKey) { d in
                HStack(spacing: 4) {
                    Text(d.inventory.assetTag ?? "-").appFont(.body, design: .monospaced)
                    if let tag = d.inventory.assetTag { CopyButton(value: tag) }
                }
            }
            .width(min: 90, ideal: 120)
            TableColumn("Serial Number", value: \.serialNumber) { d in
                HStack(spacing: 4) {
                    Text(d.serialNumber).appFont(.body, design: .monospaced)
                    CopyButton(value: d.serialNumber)
                }
            }
            .width(min: 120, ideal: 150)
            TableColumn("Usage", value: \.inventory.usageSortKey) { d in
                if let usage = d.inventory.usage {
                    Pill(usage, tone: usage.lowercased() == "assigned" ? .yellow : .blue)
                } else { Text("-").foregroundStyle(.secondary) }
            }
            .width(min: 80, ideal: 100)
            TableColumn("Catalog", value: \.inventory.catalogSortKey) { d in
                if let catalog = d.inventory.catalog {
                    Pill(catalog, tone: DevicesView.catalogTone(catalog))
                } else { Text("-").foregroundStyle(.secondary) }
            }
            .width(min: 90, ideal: 110)
            TableColumn("Location", value: \.inventory.locationSortKey) { d in
                Text(d.inventory.location ?? "-").appFont(.body).lineLimit(1)
            }
            .width(min: 90, ideal: 140)
            TableColumn("Last Seen", value: \.lastSeenSortKey) { d in
                Text(TimeFormatting.relative(d.lastSeen)).appFont(.body).foregroundStyle(.secondary)
                    .help(TimeFormatting.exact(d.lastSeen))
            }
            .width(min: 100, ideal: 120)
            TableColumn("Status", value: \.status) { d in
                StatusText(status: d.status).help(d.archived ? "Device is archived" : "Last seen: \(TimeFormatting.relative(d.lastSeen))")
            }
            .width(min: 70, ideal: 80)
            TableColumn("Registered", value: \.createdAtSortKey) { d in
                Text(TimeFormatting.relative(d.createdAt)).appFont(.body).foregroundStyle(.secondary)
            }
            .width(min: 90, ideal: 110)
        }
        .contextMenu(forSelectionType: DeviceSummary.ID.self) { ids in
            if let id = ids.first, let d = filtered.first(where: { $0.id == id }) {
                Button("Open \(d.name)") { appState.open(device: d.serialNumber) }
                Button("Copy Serial Number") { copy(d.serialNumber) }
                if let tag = d.inventory.assetTag { Button("Copy Asset Tag") { copy(tag) } }
            }
        } primaryAction: { ids in
            if let id = ids.first { appState.open(device: id) }
        }
    }

    private func copy(_ s: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(s, forType: .string)
    }

    static func catalogTone(_ catalog: String) -> Tone {
        switch catalog.lowercased() {
        case "curriculum": return .teal
        case "staff": return .orange
        case "faculty": return .red
        case "kiosk": return .cyan
        default: return .gray
        }
    }
}

extension InventorySummary {
    var assetTagSortKey: String { assetTag?.lowercased() ?? "" }
    var usageSortKey: String { usage?.lowercased() ?? "" }
    var catalogSortKey: String { catalog?.lowercased() ?? "" }
    var locationSortKey: String { location?.lowercased() ?? "" }
}

extension DeviceSummary {
    var lastSeenSortKey: Date { lastSeen ?? .distantPast }
    var createdAtSortKey: Date { createdAt ?? .distantPast }
}
