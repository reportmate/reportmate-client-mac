import SwiftUI
import ReportMateKit

/// Usage-telemetry collection health per device. Port of
/// `app/applications/coverage/page.tsx`.
struct ApplicationCoverageView: View {
    @Environment(AppState.self) private var appState

    enum BucketFilter: String, CaseIterable, Identifiable {
        case all, dark, never
        var id: String { rawValue }
        var label: String {
            switch self {
            case .all: return "All non-healthy"
            case .dark: return "Dark only"
            case .never: return "Never only"
            }
        }
    }
    enum Column { case bucket, deviceName, platform, usage, location, lastSeen, lastUsage, daysDark }

    @State private var data: CollectionHealth?
    @State private var error: String?
    @State private var bucket: BucketFilter = .all
    @State private var platform = "all"
    @State private var sortColumn: Column = .daysDark
    @State private var ascending = false

    private var rows: [CollectionHealth.DarkDevice] {
        guard let data else { return [] }
        var list = data.darkDevices
        if bucket != .all { list = list.filter { $0.bucket.rawValue == bucket.rawValue } }
        if platform != "all" { list = list.filter { ($0.platform ?? "Unknown") == platform } }
        return list.sorted { a, b in
            func cmp(_ x: String?, _ y: String?) -> ComparisonResult {
                switch (x, y) {
                case (nil, nil): return .orderedSame
                case (nil, _): return .orderedDescending
                case (_, nil): return .orderedAscending
                case (let x?, let y?): return x.compare(y)
                }
            }
            func cmpInt(_ x: Int?, _ y: Int?) -> ComparisonResult {
                switch (x, y) {
                case (nil, nil): return .orderedSame
                case (nil, _): return .orderedDescending
                case (_, nil): return .orderedAscending
                case (let x?, let y?): return x < y ? .orderedAscending : x > y ? .orderedDescending : .orderedSame
                }
            }
            let r: ComparisonResult
            switch sortColumn {
            case .bucket: r = cmp(a.bucket.rawValue, b.bucket.rawValue)
            case .deviceName: r = cmp(a.deviceName, b.deviceName)
            case .platform: r = cmp(a.platform, b.platform)
            case .usage: r = cmp(a.usage, b.usage)
            case .location: r = cmp(a.location, b.location)
            case .lastSeen: r = cmp(a.lastSeen, b.lastSeen)
            case .lastUsage: r = cmp(a.lastUsageDate, b.lastUsageDate)
            case .daysDark: r = cmpInt(a.daysSinceUsage, b.daysSinceUsage)
            }
            return UsageCells.ordered(r, ascending: ascending)
        }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                summaryCard
                filtersRow
                tableCard
            }
            .padding(16)
        }
        .navigationTitle("Usage Data Coverage")
        .task(id: appState.configuration) { await load() }
        .onChange(of: appState.refreshRequested) { _, _ in Task { await load() } }
    }

    private func load() async {
        error = nil
        do {
            let health = try await appState.api.applicationCollectionHealth()
            if let e = health.error { error = e } else { data = health }
        } catch {
            self.error = error.localizedDescription
        }
    }

    private var summaryCard: some View {
        Card(padding: 20) {
            VStack(alignment: .leading, spacing: 16) {
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Usage Data Coverage").appFont(.title3, weight: .semibold)
                        Text("Per-device collection health for application usage telemetry. Devices in the dark and never buckets aren't contributing to fleet utilization numbers.")
                            .appFont(.callout).foregroundStyle(.secondary)
                    }
                    Spacer()
                    if data != nil {
                        CSVExportButton(filename: "usage-coverage",
                                        headers: ["Status", "Serial", "Device", "Platform", "OS", "Usage", "Catalog", "Location", "LastSeen", "LastUsage", "DaysSinceUsage", "TotalHoursEver"]) {
                            rows.map { r in
                                [r.bucket.rawValue, r.serialNumber, r.deviceName, r.platform ?? "", r.osName ?? "", r.usage ?? "", r.catalog ?? "", r.location ?? "",
                                 r.lastSeen ?? "", r.lastUsageDate ?? "", r.daysSinceUsage.map(String.init) ?? "", String(r.totalHoursEver)]
                            }
                        }
                    }
                }
                if let s = data?.summary {
                    HStack(spacing: 12) {
                        stat("Total devices", s.totalDevices, .primary)
                        stat("Healthy (last \(s.freshDays)d)", s.healthy, .green)
                        stat("Stale (\(s.freshDays)–\(s.staleDays)d)", s.stale, .yellow)
                        stat("Dark (>\(s.staleDays)d)", s.dark, .orange)
                        stat("Never collected", s.never, .red)
                    }
                }
                if let data, !data.byPlatform.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        SectionLabel("By platform")
                        LazyVGrid(columns: [GridItem(.adaptive(minimum: 260), spacing: 12)], spacing: 12) {
                            ForEach(data.platformNames, id: \.self) { name in
                                let c = data.byPlatform[name]!
                                VStack(alignment: .leading, spacing: 6) {
                                    HStack {
                                        Text(name).appFont(.callout, weight: .medium)
                                        Spacer()
                                        Text("\(c.total) devices").appFont(.caption).foregroundStyle(.secondary)
                                    }
                                    HStack(spacing: 12) {
                                        Label("\(c.healthy)", systemImage: "checkmark").foregroundStyle(.green)
                                        Label("\(c.stale)", systemImage: "circle.lefthalf.filled").foregroundStyle(.yellow)
                                        Label("\(c.dark)", systemImage: "circle.fill").foregroundStyle(.orange)
                                        Label("\(c.never)", systemImage: "xmark").foregroundStyle(.red)
                                    }
                                    .appFont(.caption)
                                }
                                .padding(10)
                                .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.cardBorder))
                            }
                        }
                    }
                }
            }
        }
    }

    private func stat(_ label: String, _ value: Int, _ color: Color) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label.uppercased()).appFont(.caption2, weight: .semibold).foregroundStyle(.secondary).lineLimit(1)
            Text(value.formatted()).appFont(.title2, weight: .semibold).foregroundStyle(color)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.cardBorder))
    }

    private var filtersRow: some View {
        Card(padding: 12) {
            HStack(spacing: 16) {
                Picker("Bucket:", selection: $bucket) { ForEach(BucketFilter.allCases) { Text($0.label).tag($0) } }.frame(width: 220)
                if let data, !data.byPlatform.isEmpty {
                    Picker("Platform:", selection: $platform) {
                        Text("All").tag("all")
                        ForEach(data.platformNames, id: \.self) { Text($0).tag($0) }
                    }
                    .frame(width: 200)
                }
                Spacer()
                if let data { Text("\(rows.count) of \(data.darkDevices.count) devices").appFont(.callout).foregroundStyle(.secondary) }
            }
        }
    }

    private var tableCard: some View {
        Card {
            if let error {
                ErrorBanner(message: error) { Task { await load() } }.padding()
            } else if data == nil {
                LoadingView(message: "Loading…").frame(height: 160)
            } else if rows.isEmpty {
                EmptyStateView(title: "No devices match the current filter.", message: "", systemImage: "checkmark.circle").frame(height: 160)
            } else {
                StickyTable {
                    ReportSortHeader(title: "Status", column: .bucket, sortColumn: $sortColumn, ascending: $ascending, width: 80)
                    ReportSortHeader(title: "Device", column: .deviceName, sortColumn: $sortColumn, ascending: $ascending, width: 220)
                    ReportSortHeader(title: "Platform", column: .platform, sortColumn: $sortColumn, ascending: $ascending, width: 90)
                    ReportSortHeader(title: "Usage", column: .usage, sortColumn: $sortColumn, ascending: $ascending, width: 90)
                    ReportSortHeader(title: "Location", column: .location, sortColumn: $sortColumn, ascending: $ascending, width: 150)
                    ReportSortHeader(title: "Last seen", column: .lastSeen, sortColumn: $sortColumn, ascending: $ascending, width: 110)
                    ReportSortHeader(title: "Last usage", column: .lastUsage, sortColumn: $sortColumn, ascending: $ascending, width: 110)
                    ReportSortHeader(title: "Days dark", column: .daysDark, sortColumn: $sortColumn, ascending: $ascending, alignment: .trailing)
                } rows: {
                    ForEach(rows) { d in
                        HStack(alignment: .top, spacing: 12) {
                            Pill(d.bucket.rawValue.uppercased(), tone: d.bucket == .never ? .red : .orange).frame(width: 80, alignment: .leading)
                            VStack(alignment: .leading, spacing: 2) {
                                Button { appState.open(device: d.serialNumber) } label: {
                                    Text(d.deviceName).appFont(.callout, weight: .medium).foregroundStyle(.blue).lineLimit(1).truncationMode(.middle)
                                }
                                .buttonStyle(.plain)
                                Text(d.serialNumber).appFont(.caption2, design: .monospaced).foregroundStyle(.secondary)
                            }
                            .frame(width: 220, alignment: .leading)
                            Text(d.platform ?? "—").appFont(.callout).frame(width: 90, alignment: .leading)
                            Text(d.usage ?? "—").appFont(.callout).frame(width: 90, alignment: .leading)
                            Text(d.location ?? "—").appFont(.callout).lineLimit(1).frame(width: 150, alignment: .leading)
                            Text(d.lastSeen.map { TimeFormatting.relative($0) } ?? "—").appFont(.callout).frame(width: 110, alignment: .leading)
                            Text(d.lastUsageDate ?? "never").appFont(.callout).frame(width: 110, alignment: .leading)
                            Text(d.daysSinceUsage.map { "\($0)d" } ?? "—").appFont(.callout, design: .monospaced).frame(maxWidth: .infinity, alignment: .trailing)
                        }
                        .padding(.horizontal, 16).padding(.vertical, 7)
                        Divider()
                    }
                }
            }
        }
    }
}
