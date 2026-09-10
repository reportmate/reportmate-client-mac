import SwiftUI
import ReportMateKit

/// Loads one bulk report (`/api/v1/<module>`) and hands the rows to a view.
///
/// Every fleet report shares this shape: fetch once, filter by the global
/// platform toggle and the Selections accordion, search, then render a
/// table with per-report columns. Rows are the device-level records the API
/// returns, each carrying `serialNumber`, `deviceName`, and inventory fields.
@MainActor
@Observable
final class FleetReportModel {
    let path: String
    var rows: [ReportRow] = []
    var raw: JSONValue = .null
    var loading = false
    var error: String?
    var loadedAt: Date?

    init(path: String) { self.path = path }

    func load(api: ReportMateAPI, query: [String: String?] = [:], force: Bool = false) async {
        if !force, loadedAt != nil, !rows.isEmpty { return }
        loading = true
        error = nil
        do {
            let json = try await api.fleetReport(path, query: query)
            raw = json
            rows = FleetReportModel.extractRows(json).map(ReportRow.init(json:))
            loadedAt = Date()
        } catch {
            self.error = error.localizedDescription
        }
        loading = false
    }

    /// Reports wrap their rows in different keys (`devices`, `data`, `items`, the module name).
    static func extractRows(_ json: JSONValue) -> [JSONValue] {
        if let arr = json.array { return arr }
        for key in ["devices", "data", "items", "results", "records", "hardware", "installs", "applications", "network", "security", "management", "inventory", "system", "peripherals", "identity", "profiles"] {
            if let arr = json[key].array { return arr }
        }
        return []
    }
}

/// A device-level row in any fleet report.
struct ReportRow: Identifiable, Hashable {
    let json: JSONValue
    let serialNumber: String
    let deviceName: String
    let platform: Platform
    let inventory: InventorySummary
    let lastSeen: Date?
    let status: DeviceStatus
    let archived: Bool

    var id: String { serialNumber.isEmpty ? deviceName : serialNumber }

    init(json: JSONValue) {
        self.json = json
        serialNumber = json.firstString("serialNumber", "serial_number", "deviceId") ?? ""
        let inv = json["inventory"].isNull ? json["modules"]["inventory"] : json["inventory"]
        var inventory = InventorySummary(json: inv)
        inventory.assetTag = inventory.assetTag ?? json.firstString("assetTag", "asset_tag")
        inventory.usage = inventory.usage ?? json["usage"].nonEmptyString
        inventory.catalog = inventory.catalog ?? json["catalog"].nonEmptyString
        inventory.location = inventory.location ?? json["location"].nonEmptyString
        inventory.department = inventory.department ?? json["department"].nonEmptyString
        inventory.area = inventory.area ?? json["area"].nonEmptyString
        inventory.fleet = inventory.fleet ?? json["fleet"].nonEmptyString
        self.inventory = inventory
        let name = json.firstString("deviceName", "device_name", "name", "hostname") ?? inventory.deviceName ?? serialNumber
        deviceName = name.lowercased() == "unknown" ? serialNumber : name
        platform = Platform.detect(device: json)
        lastSeen = FlexibleDate.parse(json.first("lastSeen", "last_seen", "collectedAt", "collected_at"))
        archived = json["archived"].boolish
        status = DeviceStatus.calculate(lastSeen: lastSeen, archived: archived)
    }

    var areaOrDepartment: String? { inventory.area ?? inventory.department }

    /// Adapter so the shared Selections accordion can filter report rows.
    var asDeviceSummary: DeviceSummary {
        var base: [String: JSONValue] = [
            "serialNumber": .string(serialNumber), "name": .string(deviceName), "platform": .string(platform.rawValue),
            "archived": .bool(archived),
            "modules": .object(["inventory": .object([
                "deviceName": inventory.deviceName.map(JSONValue.string) ?? .null,
                "assetTag": inventory.assetTag.map(JSONValue.string) ?? .null,
                "usage": inventory.usage.map(JSONValue.string) ?? .null,
                "catalog": inventory.catalog.map(JSONValue.string) ?? .null,
                "department": inventory.department.map(JSONValue.string) ?? .null,
                "area": inventory.area.map(JSONValue.string) ?? .null,
                "location": inventory.location.map(JSONValue.string) ?? .null,
                "fleet": inventory.fleet.map(JSONValue.string) ?? .null,
            ])]),
        ]
        if let lastSeen { base["lastSeen"] = .string(ISO8601DateFormatter().string(from: lastSeen)) }
        return DeviceSummary(json: .object(base))
    }
}

/// Header, selections, widgets accordion and table chrome around a report's rows.
///
/// `toolbar` and `widgets` receive the rows that survive the platform toggle,
/// the Selections accordion and the search box; `content` receives the same
/// rows and applies the report's own widget-driven filters on top.
struct FleetReportContainer<Content: View, Toolbar: View, Widgets: View>: View {
    @Environment(AppState.self) private var appState
    let section: AppSection
    let model: FleetReportModel
    var query: [String: String?] = [:]
    var subtitle: String? = nil
    var searchPlaceholder = "Search…"
    var searchKeys: (ReportRow) -> [String?]
    var toolbar: ([ReportRow]) -> Toolbar
    var widgets: (([ReportRow]) -> Widgets)?
    var content: ([ReportRow]) -> Content

    init(section: AppSection, model: FleetReportModel, query: [String: String?] = [:], subtitle: String? = nil, searchPlaceholder: String = "Search…",
         searchKeys: @escaping (ReportRow) -> [String?] = { [$0.deviceName, $0.serialNumber, $0.inventory.assetTag] },
         @ViewBuilder toolbar: @escaping ([ReportRow]) -> Toolbar = { _ in EmptyView() },
         widgets: (([ReportRow]) -> Widgets)?,
         @ViewBuilder content: @escaping ([ReportRow]) -> Content) {
        self.section = section
        self.model = model
        self.query = query
        self.subtitle = subtitle
        self.searchPlaceholder = searchPlaceholder
        self.searchKeys = searchKeys
        self.toolbar = toolbar
        self.widgets = widgets
        self.content = content
    }

    @State private var search = ""
    @State private var selections = DeviceSelections()
    @State private var filtersExpanded = false
    @State private var widgetsExpanded = true

    private var summaries: [DeviceSummary] { model.rows.map(\.asDeviceSummary) }

    private func subtitleText(_ count: Int) -> String {
        var parts: [String] = []
        if let subtitle { parts.append(subtitle) }
        let total = model.rows.count
        parts.append(count != total ? "\(count) of \(total) devices" : "\(count) devices")
        if let at = model.loadedAt { parts.append("loaded \(TimeFormatting.relative(at))") }
        return parts.joined(separator: " · ")
    }

    private var filtered: [ReportRow] {
        var list = model.rows
        if appState.platformFilter != .all { list = list.filter { appState.platformFilter.includes($0.platform) } }
        if !selections.isEmpty { list = list.filter { selections.matches($0.asDeviceSummary) } }
        let q = search.trimmingCharacters(in: .whitespaces).lowercased()
        if !q.isEmpty { list = list.filter { row in searchKeys(row).contains { $0?.lowercased().contains(q) ?? false } } }
        return list
    }

    var body: some View {
        let rows = filtered
        VStack(spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(section.title).appFont(.title3, weight: .semibold)
                    Text(subtitleText(rows.count)).appFont(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                if model.loading { ProgressView().controlSize(.small) }
                toolbar(rows)
                HStack(spacing: 6) {
                    Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                    TextField(searchPlaceholder, text: $search).textFieldStyle(.plain)
                    if !search.isEmpty { Button { search = "" } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary) }.buttonStyle(.plain) }
                }
                .padding(.horizontal, 10).padding(.vertical, 6)
                .background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 8))
                .frame(width: 240)
            }
            .padding(.horizontal, 16).padding(.vertical, 12)
            .overlay(alignment: .bottom) { Divider() }
            DeviceFiltersView(options: DeviceFilterOptions(devices: summaries), selections: $selections, expanded: $filtersExpanded)
            if model.loading, model.rows.isEmpty {
                LoadingView(message: "Loading \(section.title.lowercased()) report…")
            } else if let error = model.error, model.rows.isEmpty {
                ErrorBanner(message: error) { Task { await model.load(api: appState.api, query: query, force: true) } }.padding()
                Spacer()
            } else if model.rows.isEmpty {
                EmptyStateView(title: "No data", message: "No devices have reported \(section.title.lowercased()) data yet.", systemImage: section.systemImage)
                Spacer()
            } else {
                if let widgets {
                    VStack(spacing: 0) {
                        Button { withAnimation { widgetsExpanded.toggle() } } label: {
                            HStack {
                                Text("Widgets").appFont(.callout, weight: .medium)
                                Spacer()
                                Image(systemName: "chevron.down").rotationEffect(.degrees(widgetsExpanded ? 180 : 0)).foregroundStyle(.secondary)
                            }
                            .padding(.horizontal, 16).padding(.vertical, 8)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        if widgetsExpanded {
                            ScrollView(.horizontal) { widgets(rows).padding(.horizontal, 16).padding(.bottom, 12) }
                        }
                    }
                    .overlay(alignment: .bottom) { Divider() }
                }
                content(rows)
            }
        }
        .navigationTitle(section.title)
        .task(id: appState.configuration) { await model.load(api: appState.api, query: query) }
        .onChange(of: appState.refreshRequested) { _, _ in Task { await model.load(api: appState.api, query: query, force: true) } }
    }
}

extension FleetReportContainer where Widgets == EmptyView {
    /// A report without a Widgets accordion.
    init(section: AppSection, model: FleetReportModel, query: [String: String?] = [:], subtitle: String? = nil, searchPlaceholder: String = "Search…",
         searchKeys: @escaping (ReportRow) -> [String?] = { [$0.deviceName, $0.serialNumber, $0.inventory.assetTag] },
         @ViewBuilder toolbar: @escaping ([ReportRow]) -> Toolbar = { _ in EmptyView() },
         @ViewBuilder content: @escaping ([ReportRow]) -> Content) {
        self.init(section: section, model: model, query: query, subtitle: subtitle, searchPlaceholder: searchPlaceholder, searchKeys: searchKeys, toolbar: toolbar, widgets: nil, content: content)
    }
}

/// A device-name cell that opens the device.
struct DeviceLink: View {
    @Environment(AppState.self) private var appState
    let row: ReportRow
    var tab: DeviceTab? = nil

    var body: some View {
        Button { appState.open(device: row.serialNumber.isEmpty ? row.deviceName : row.serialNumber, tab: tab) } label: {
            HStack(spacing: 6) {
                Text(row.deviceName).appFont(.body, weight: .medium).lineLimit(1).truncationMode(.middle)
                PlatformBadge(platform: row.platform)
            }
        }
        .buttonStyle(.plain)
        .help(row.serialNumber)
    }
}

/// Scrolling table body with a sticky header row above it.
struct ReportTable<Header: View, Rows: View>: View {
    @ViewBuilder var header: Header
    @ViewBuilder var rows: Rows
    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) { header }
                .padding(.horizontal, 16).padding(.vertical, 8)
                .background(Color.subtleBackground)
            Divider()
            ScrollView {
                LazyVStack(spacing: 0) { rows }
            }
        }
    }
}

/// Centered "nothing matched" message for a report table.
struct ReportEmptyRows: View {
    let title: String
    var message = "Try adjusting your search or filter criteria."
    var systemImage = "tray"
    var body: some View {
        VStack(spacing: 6) {
            Image(systemName: systemImage).font(.system(size: 28)).foregroundStyle(.tertiary)
            Text(title).appFont(.callout, weight: .medium)
            Text(message).appFont(.caption).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity).padding(40)
    }
}
