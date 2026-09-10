import SwiftUI
import ReportMateKit

/// Per-device usage for one application. Port of
/// `app/applications/usage/[appName]/page.tsx`.
struct ApplicationUsageDetailView: View {
    @Environment(AppState.self) private var appState
    let appName: String
    var initialDays = 30
    var usages: [String] = []
    var catalogs: [String] = []
    var locations: [String] = []

    enum Column { case deviceName, location, usage, catalog, area, totalHours, launchCount, userCount, lastUsed }
    @State private var days: Int
    @State private var report: UsageByDeviceReport?
    @State private var loading = true
    @State private var error: String?
    @State private var sortColumn: Column = .totalHours
    @State private var ascending = false
    @State private var widgetsExpanded = true
    @State private var metric: UsageMetric = .launches

    init(appName: String, initialDays: Int = 30, usages: [String] = [], catalogs: [String] = [], locations: [String] = []) {
        self.appName = appName
        self.initialDays = initialDays
        self.usages = usages
        self.catalogs = catalogs
        self.locations = locations
        _days = State(initialValue: initialDays)
    }

    private var sortedDevices: [UsageDeviceRow] {
        (report?.devices ?? []).sorted { a, b in
            let r: ComparisonResult
            switch sortColumn {
            case .deviceName: r = UsageCells.compare(a.deviceName, b.deviceName)
            case .location: r = UsageCells.compare(a.location ?? "", b.location ?? "")
            case .usage: r = UsageCells.compare(a.usage ?? "", b.usage ?? "")
            case .catalog: r = UsageCells.compare(a.catalog ?? "", b.catalog ?? "")
            case .area: r = UsageCells.compare(a.areaOrDepartment ?? "", b.areaOrDepartment ?? "")
            case .totalHours: r = UsageCells.compare(a.totalHours, b.totalHours)
            case .launchCount: r = UsageCells.compare(a.launchCount, b.launchCount)
            case .userCount: r = UsageCells.compare(a.userCount, b.userCount)
            case .lastUsed: r = UsageCells.compare(a.lastUsed ?? "", b.lastUsed ?? "")
            }
            return UsageCells.ordered(r, ascending: ascending)
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            if let report, !loading, error == nil, !report.devices.isEmpty {
                UsageWidgetsAccordion(deviceCount: report.summary.deviceCount, expanded: $widgetsExpanded, metric: $metric,
                                      aggregates: UsageAggregates(devices: report.devices, metric: metric))
            }
            if loading {
                LoadingView(message: "Loading per-device usage for \(appName)...")
            } else if let error {
                ErrorBanner(message: error) { Task { await load() } }.padding()
                Spacer()
            } else if sortedDevices.isEmpty {
                EmptyStateView(title: "No usage data found", message: "No device has used \(appName) in the last \(days) days.", systemImage: "chart.bar")
                Spacer()
            } else {
                ScrollView { table }
            }
        }
        .navigationTitle(appName)
        .task(id: days) { await load() }
        .onChange(of: appState.refreshRequested) { _, _ in Task { await load() } }
    }

    private func load() async {
        loading = true
        error = nil
        do {
            report = try await appState.api.applicationUsageByDevice(app: appName, days: days, usages: usages, catalogs: catalogs, locations: locations)
        } catch {
            self.error = error.localizedDescription
        }
        loading = false
    }

    private var header: some View {
        HStack(alignment: .top, spacing: 16) {
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text("Applications").appFont(.callout).foregroundStyle(.blue)
                    Text("/").foregroundStyle(.tertiary)
                    Text(appName).appFont(.title3, weight: .semibold).lineLimit(1).help(appName)
                }
                Text(report.map(\.headline) ?? "Loading per-device usage...").appFont(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            HStack(spacing: 8) {
                Text("Period:").appFont(.callout).foregroundStyle(.secondary)
                Picker("Period", selection: $days) {
                    Text("Last 7 days").tag(7)
                    Text("Last 30 days").tag(30)
                    Text("Last 45 days").tag(45)
                    Text("Last 90 days").tag(90)
                    Text("Last 180 days").tag(180)
                    Text("Last year").tag(365)
                    Text("Last 18 months").tag(548)
                }
                .labelsHidden().frame(width: 150)
                if !sortedDevices.isEmpty {
                    let safe = appName.replacingOccurrences(of: "[^a-zA-Z0-9]", with: "-", options: .regularExpression)
                    CSVExportButton(filename: "\(safe)-by-device-\(days)d",
                                    headers: ["Usage", "Catalog", "Area", "Location", "Device", "Serial", "Asset Tag", "Hours", "Launches", "Users", "Variants", "First Used", "Last Used"]) {
                        sortedDevices.map { d in
                            [d.usage ?? "", d.catalog ?? "", d.areaOrDepartment ?? "", d.location ?? "", d.deviceName, d.serialNumber, d.assetTag ?? "",
                             String(format: "%.2f", d.totalHours), String(d.launchCount), d.users.joined(separator: "; "), d.appVariants.joined(separator: "; "),
                             d.firstUsed ?? "", d.lastUsed ?? ""]
                        }
                    }
                }
            }
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
        .overlay(alignment: .bottom) { Divider() }
    }

    private func sortHeader(_ title: String, _ column: Column, width: CGFloat? = nil) -> some View {
        Button {
            if sortColumn == column { ascending.toggle() } else { sortColumn = column; ascending = column == .deviceName || column == .location }
        } label: {
            HStack(spacing: 4) {
                Text(title.uppercased()).appFont(.caption2, weight: .semibold).foregroundStyle(.secondary)
                SortIndicator(active: sortColumn == column, ascending: ascending)
            }
            .frame(width: width, alignment: .leading)
            .frame(maxWidth: width == nil ? .infinity : nil, alignment: .leading)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private var table: some View {
        StickyTable {
            sortHeader("Usage", .usage, width: 90)
            sortHeader("Catalog", .catalog, width: 100)
            sortHeader("Area", .area, width: 130)
            sortHeader("Location", .location, width: 140)
            sortHeader("Device", .deviceName, width: 220)
            sortHeader("Total Time", .totalHours, width: 120)
            sortHeader("Launches", .launchCount, width: 90)
            sortHeader("Users", .userCount, width: 70)
            sortHeader("Last Used", .lastUsed)
        } rows: {
            ForEach(sortedDevices) { d in
                HStack(alignment: .top, spacing: 12) {
                    Text(UsageCells.dash(d.usage)).appFont(.callout).frame(width: 90, alignment: .leading)
                    Text(UsageCells.dash(d.catalog)).appFont(.callout).frame(width: 100, alignment: .leading)
                    Text(UsageCells.dash(d.areaOrDepartment)).appFont(.callout).lineLimit(1).frame(width: 130, alignment: .leading)
                    Text(UsageCells.dash(d.location)).appFont(.callout).lineLimit(1).frame(width: 140, alignment: .leading)
                    VStack(alignment: .leading, spacing: 2) {
                        Button { appState.open(device: d.serialNumber) } label: {
                            Text(d.deviceName).appFont(.callout, weight: .medium).foregroundStyle(.blue).lineLimit(1).truncationMode(.middle)
                        }
                        .buttonStyle(.plain).help(d.serialNumber)
                        if d.appVariantCount > 1 {
                            Text("\(d.appVariantCount) variants").appFont(.caption2).foregroundStyle(.secondary).help(d.appVariants.joined(separator: ", "))
                        }
                    }
                    .frame(width: 220, alignment: .leading)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(ApplicationsReport.duration(seconds: d.totalSeconds)).appFont(.callout, weight: .medium).foregroundStyle(.blue)
                        Text(String(format: "%.1f hours", d.totalHours)).appFont(.caption2).foregroundStyle(.secondary)
                    }
                    .frame(width: 120, alignment: .leading)
                    Text(d.launchCount.formatted()).appFont(.callout).monospacedDigit().frame(width: 90, alignment: .leading)
                    Text("\(d.userCount)").appFont(.callout).monospacedDigit().help(d.users.joined(separator: ", ")).frame(width: 70, alignment: .leading)
                    Text(d.lastUsed.map { TimeFormatting.relative($0) } ?? "-").appFont(.callout).frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding(.horizontal, 16).padding(.vertical, 7)
                Divider()
            }
        }
    }
}
