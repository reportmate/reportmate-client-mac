import SwiftUI
import Charts
import ReportMateKit

/// Fleet operating-system report: version, edition, activation, license,
/// uptime and pending-update widgets over the OS table. Port of `app/system/page.tsx`.
struct SystemReportView: View {
    @Environment(AppState.self) private var appState
    @State private var model = FleetReportModel(path: "/system")

    enum Column { case device, os, version, updates, edition, activation, uptime, lastSeen }
    @State private var sortColumn: Column = .device
    @State private var ascending = true
    @State private var osVersionFilter: String? = nil
    @State private var editions: Set<String> = []
    @State private var activations: Set<String> = []
    @State private var licenseSources: Set<String> = []
    @State private var uptimeBuckets: Set<String> = []
    @State private var pendingBuckets: Set<String> = []

    struct Bucket { let key: String; let label: String; let tone: Tone }
    static let uptimeBuckets: [(Bucket, ClosedRange<Double>)] = [
        (Bucket(key: "lt1d", label: "< 1 day", tone: .green), 0...86_399),
        (Bucket(key: "1-3d", label: "1-3 days", tone: .emerald), 86_400...259_199),
        (Bucket(key: "3-7d", label: "3-7 days", tone: .teal), 259_200...604_799),
        (Bucket(key: "1-2w", label: "1-2 weeks", tone: .yellow), 604_800...1_209_599),
        (Bucket(key: "2-4w", label: "2-4 weeks", tone: .orange), 1_209_600...2_591_999),
        (Bucket(key: "30d+", label: "30+ days", tone: .red), 2_592_000...Double.greatestFiniteMagnitude),
    ]
    static let pendingBuckets: [(Bucket, ClosedRange<Int>)] = [
        (Bucket(key: "up-to-date", label: "Up to date", tone: .green), 0...0),
        (Bucket(key: "1-5", label: "1-5 pending", tone: .yellow), 1...5),
        (Bucket(key: "6-10", label: "6-10 pending", tone: .orange), 6...10),
        (Bucket(key: "10+", label: "10+ pending", tone: .red), 11...Int.max),
    ]

    static func uptimeBucket(_ seconds: Double?) -> String? {
        guard let s = seconds, s > 0 else { return nil }
        return uptimeBuckets.first { $0.1.contains(s) }?.0.label
    }
    static func pendingBucket(_ count: Int) -> String? { pendingBuckets.first { $0.1.contains(count) }?.0.label }

    private var isWindowsOnly: Bool { appState.platformFilter == .windows }
    private var widgetLabels: [String] {
        (osVersionFilter.map { ["OS \($0)"] } ?? []) + Array(editions) + Array(activations) + Array(licenseSources) + Array(uptimeBuckets) + Array(pendingBuckets)
    }

    private func clearWidgetFilters() {
        osVersionFilter = nil; editions = []; activations = []; licenseSources = []; uptimeBuckets = []; pendingBuckets = []
    }

    private func s(_ row: ReportRow) -> SystemReportRow { SystemReportRow(json: row.json) }

    /// The web's `osVersion` URL filter: a Windows group name, an exact or normalised version, or a version prefix.
    static func matchesVersionFilter(_ d: SystemReportRow, _ filter: String) -> Bool {
        if filter.hasPrefix("Windows ") { return d.operatingSystem.contains(filter) }
        let version = d.osVersion ?? ""
        func normalize(_ v: String) -> String {
            guard !v.isEmpty else { return "" }
            var parts = v.split(separator: ".").map(String.init)
            while parts.count < 3 { parts.append("0") }
            return parts.prefix(3).joined(separator: ".")
        }
        var groupKey = "", childKey = ""
        if let r = d.operatingSystem.range(of: #"Windows\s+(\d+)"#, options: .regularExpression) {
            let win = d.operatingSystem[r].filter(\.isNumber)
            let build = d.buildNumber ?? "0"
            groupKey = "\(win).\(build)"
            childKey = "\(win).\(build).0"
        }
        return childKey == filter || groupKey == filter || version == filter || normalize(version) == normalize(filter) || version.hasPrefix(filter + ".")
    }

    private func filtered(_ rows: [ReportRow]) -> [(row: ReportRow, s: SystemReportRow)] {
        rows.map { ($0, s($0)) }.filter { pair in
            let d = pair.s
            if !activations.isEmpty, !(d.activationLabel.map { activations.contains($0) } ?? false) { return false }
            if !licenseSources.isEmpty, !(d.licenseSource.map { licenseSources.contains($0) } ?? false) { return false }
            if !editions.isEmpty, !(d.edition.map { editions.contains($0) } ?? false) { return false }
            if !uptimeBuckets.isEmpty, !(Self.uptimeBucket(d.uptime).map { uptimeBuckets.contains($0) } ?? false) { return false }
            if !pendingBuckets.isEmpty, !(Self.pendingBucket(d.pendingUpdatesCount).map { pendingBuckets.contains($0) } ?? false) { return false }
            if let f = osVersionFilter, !Self.matchesVersionFilter(d, f) { return false }
            return true
        }.sorted { a, b in
            switch sortColumn {
            case .device: return ord(a.row.deviceName.lowercased(), b.row.deviceName.lowercased())
            case .os: return ord(a.s.osDisplayName.lowercased(), b.s.osDisplayName.lowercased())
            case .version: return ord((a.s.osVersion ?? "").lowercased(), (b.s.osVersion ?? "").lowercased())
            case .updates: return ascending ? a.s.pendingUpdatesCount < b.s.pendingUpdatesCount : a.s.pendingUpdatesCount > b.s.pendingUpdatesCount
            case .edition: return ord((a.s.edition ?? "").lowercased(), (b.s.edition ?? "").lowercased())
            case .activation:
                func rank(_ v: Bool?) -> Int { v == true ? 0 : v == false ? 1 : 2 }
                return ascending ? rank(a.s.activationStatus) < rank(b.s.activationStatus) : rank(a.s.activationStatus) > rank(b.s.activationStatus)
            case .uptime: return ascending ? (a.s.uptime ?? 0) < (b.s.uptime ?? 0) : (a.s.uptime ?? 0) > (b.s.uptime ?? 0)
            case .lastSeen: return ascending ? (a.row.lastSeen ?? .distantPast) < (b.row.lastSeen ?? .distantPast) : (a.row.lastSeen ?? .distantPast) > (b.row.lastSeen ?? .distantPast)
            }
        }
    }

    private func ord(_ a: String, _ b: String) -> Bool { ascending ? a < b : a > b }

    var body: some View {
        FleetReportContainer(
            section: .system, model: model, subtitle: "OS versions, activation status, and system uptime", searchPlaceholder: "Search by device name or serial number...",
            searchKeys: { [$0.deviceName, $0.serialNumber] },
            toolbar: { rows in
                if !widgetLabels.isEmpty { Button("Clear Selections") { clearWidgetFilters() }.buttonStyle(.bordered).tint(.yellow) }
                CSVExportButton(filename: "system-report", headers: ["Device Name", "Serial Number", "Asset Tag", "OS", "Version", "Build", "Edition", "Activation", "License Source", "Time Zone", "Locale", "Uptime", "Boot Time", "Last Seen"]) {
                    filtered(rows).map { p in
                        let d = p.s
                        let up = d.uptime.map { "\(Int($0 / 86_400))d \(Int($0.truncatingRemainder(dividingBy: 86_400) / 3600))h" } ?? ""
                        return [p.row.deviceName, p.row.serialNumber, p.row.inventory.assetTag ?? "", d.osDisplayName, d.osVersion ?? "", d.buildNumber ?? "", d.edition ?? "", d.activationLabel ?? "", d.licenseSource ?? "", d.timeZone ?? "", d.locale ?? "", up, d.bootTime ?? "", p.row.json["lastSeen"].string ?? ""]
                    }
                }
            },
            widgets: { rows in widgets(rows) }
        ) { rows in
            table(filtered(rows))
        }
        .onReceive(NotificationCenter.default.publisher(for: .systemVersionFilter)) { note in
            if let v = note.object as? String { osVersionFilter = v }
        }
    }

    // MARK: Widgets

    private func summaries(_ rows: [ReportRow]) -> [DeviceSummary] {
        rows.map { row in
            let d = SystemReportRow(json: row.json)
            return DeviceSummary(json: .object([
                "serialNumber": .string(row.serialNumber), "name": .string(row.deviceName), "platform": .string(row.platform.rawValue),
                "modules": .object(["system": .object(["operatingSystem": .object([
                    "name": .string(d.operatingSystem), "version": d.osVersion.map(JSONValue.string) ?? .null, "build": d.buildNumber.map(JSONValue.string) ?? .null,
                    "edition": d.edition.map(JSONValue.string) ?? .null, "displayVersion": d.displayVersion.map(JSONValue.string) ?? .null,
                ])])]),
            ]))
        }
    }

    private func widgets(_ rows: [ReportRow]) -> some View {
        let all = rows.map(s)
        let sums = summaries(rows)
        let forBuckets = osVersionFilter.map { f in all.filter { Self.matchesVersionFilter($0, f) } } ?? all
        let windows = all.filter { !$0.isMac }
        return HStack(alignment: .top, spacing: 12) {
            if appState.platformFilter != .macOS {
                OSVersionFilterWidget(title: "Windows Versions", tone: .blue, nodes: FleetStats.osVersions(sums, platform: .windows), selected: $osVersionFilter).frame(width: 300)
            }
            if appState.platformFilter != .windows {
                OSVersionFilterWidget(title: "macOS Versions", tone: .red, nodes: FleetStats.osVersions(sums, platform: .macOS), selected: $osVersionFilter).frame(width: 300)
            }
            if isWindowsOnly {
                DonutToggleWidget(title: "Edition", data: countLabels(windows.compactMap(\.edition)), selected: $editions, palette: [.indigo, .blue, .purple, .teal, .cyan]).frame(width: 220)
                DonutToggleWidget(title: "Activation", data: countLabels(windows.compactMap(\.activationLabel)), selected: $activations, palette: [.green, .red]).frame(width: 200)
                CountListWidget(title: "License Source", counts: countLabels(windows.compactMap(\.licenseSource)), selected: $licenseSources, tone: .orange).frame(width: 240)
            }
            bucketWidget("Uptime Distribution", buckets: Self.uptimeBuckets.map(\.0), counts: forBuckets.compactMap { Self.uptimeBucket($0.uptime) }, selected: $uptimeBuckets).frame(width: 240)
            bucketWidget("Pending Updates", buckets: Self.pendingBuckets.map(\.0), counts: forBuckets.compactMap { Self.pendingBucket($0.pendingUpdatesCount) }, selected: $pendingBuckets,
                         footer: forBuckets.reduce(0) { $0 + $1.deferredUpdatesCount } > 0 ? "\(forBuckets.reduce(0) { $0 + $1.deferredUpdatesCount }) deferred" : nil).frame(width: 240)
        }
    }

    private func bucketWidget(_ title: String, buckets: [Bucket], counts: [String], selected: Binding<Set<String>>, footer: String? = nil) -> some View {
        let tally = Dictionary(grouping: counts, by: { $0 }).mapValues(\.count)
        let max = tally.values.max() ?? 1
        return ReportWidgetBox(title: title) {
            if tally.isEmpty {
                Text("No data").appFont(.caption).foregroundStyle(.tertiary)
            } else {
                VStack(spacing: 4) {
                    ForEach(buckets, id: \.key) { b in
                        let n = tally[b.label] ?? 0
                        if n > 0 {
                            let on = selected.wrappedValue.contains(b.label)
                            Button {
                                if on { selected.wrappedValue.remove(b.label) } else { selected.wrappedValue.insert(b.label) }
                            } label: {
                                HStack(spacing: 8) {
                                    Text(b.label).appFont(.caption).frame(width: 80, alignment: .leading)
                                    GeometryReader { geo in
                                        Capsule().fill(b.tone.color.opacity(on || selected.wrappedValue.isEmpty ? 0.8 : 0.3)).frame(width: geo.size.width * CGFloat(n) / CGFloat(max))
                                    }
                                    .frame(height: 10)
                                    Text("\(n)").appFont(.caption, weight: .medium).monospacedDigit().frame(width: 30, alignment: .trailing)
                                }
                                .padding(.horizontal, 4).padding(.vertical, 2)
                                .background(on ? Color.secondary.opacity(0.15) : Color.clear, in: RoundedRectangle(cornerRadius: 4))
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    if let footer { Text(footer).appFont(.caption2).foregroundStyle(.purple).frame(maxWidth: .infinity, alignment: .trailing) }
                }
            }
        }
    }

    // MARK: Table

    private func table(_ pairs: [(row: ReportRow, s: SystemReportRow)]) -> some View {
        ReportTable {
            ReportSortHeader(title: "Device", column: .device, sortColumn: $sortColumn, ascending: $ascending, width: 240)
            ReportSortHeader(title: "OS", column: .os, sortColumn: $sortColumn, ascending: $ascending)
            ReportSortHeader(title: "Version", column: .version, sortColumn: $sortColumn, ascending: $ascending, width: 110)
            ReportSortHeader(title: "Updates", column: .updates, sortColumn: $sortColumn, ascending: $ascending, width: 110)
            if isWindowsOnly {
                ReportSortHeader(title: "Edition", column: .edition, sortColumn: $sortColumn, ascending: $ascending, width: 130)
                ReportSortHeader(title: "Activation", column: .activation, sortColumn: $sortColumn, ascending: $ascending, width: 120)
            }
            ReportSortHeader(title: "Uptime", column: .uptime, sortColumn: $sortColumn, ascending: $ascending, width: 90)
            ReportSortHeader(title: "Last Seen", column: .lastSeen, sortColumn: $sortColumn, ascending: $ascending, width: 110)
        } rows: {
            if pairs.isEmpty { ReportEmptyRows(title: "No system records found", message: "No system records match your current search.", systemImage: "gearshape") }
            ForEach(pairs, id: \.row.id) { pair in
                let d = pair.s
                HStack(alignment: .top, spacing: 12) {
                    ReportDeviceCell(row: pair.row, tab: .system).frame(width: 240, alignment: .leading)
                    Text(d.osDisplayName).appFont(.callout, weight: .medium).frame(maxWidth: .infinity, alignment: .leading)
                    Text(d.osVersion ?? "-").appFont(.callout).frame(width: 110, alignment: .leading)
                    VStack(alignment: .leading, spacing: 3) {
                        if d.pendingUpdatesCount > 0 { Pill("\(d.pendingUpdatesCount) pending", tone: .orange) }
                        if d.deferredUpdatesCount > 0 { Pill("\(d.deferredUpdatesCount) deferred", tone: .purple) }
                        if d.pendingUpdatesCount == 0, d.deferredUpdatesCount == 0 { Text("-").foregroundStyle(.tertiary) }
                    }
                    .frame(width: 110, alignment: .leading)
                    if isWindowsOnly {
                        Text(d.edition ?? "-").appFont(.callout).frame(width: 130, alignment: .leading)
                        Group {
                            if let a = d.activationStatus { Pill(a ? "Activated" : "Not Activated", tone: a ? .green : .red) } else { Text("-").foregroundStyle(.tertiary) }
                        }
                        .frame(width: 120, alignment: .leading)
                    }
                    Text(d.uptimeText ?? "-").appFont(.callout).foregroundStyle(d.uptimeText == nil ? .secondary : .primary).frame(width: 90, alignment: .leading)
                    Text(pair.row.lastSeen.map { TimeFormatting.relative($0) } ?? "-").appFont(.callout).frame(width: 110, alignment: .leading)
                }
                .padding(.horizontal, 16).padding(.vertical, 8)
                Divider()
            }
        }
    }
}

/// The OS version pie's legend: groups drill into their patch or feature
/// versions, and clicking a row filters the table by that version.
struct OSVersionFilterWidget: View {
    let title: String
    let tone: Tone
    let nodes: [FleetStats.VersionNode]
    @Binding var selected: String?
    @State private var expanded: Set<String> = []

    var body: some View {
        ReportWidgetBox(title: title) {
            if nodes.isEmpty {
                Text("No data").appFont(.caption).foregroundStyle(.tertiary)
            } else {
                HStack(alignment: .top, spacing: 12) {
                    Chart(nodes) { node in
                        SectorMark(angle: .value("Devices", node.count), innerRadius: .ratio(0.62), angularInset: 1)
                            .foregroundStyle(OSVersionWidget.temperatureColor(index: node.index, total: node.siblingCount, lighten: false))
                    }
                    .chartLegend(.hidden)
                    .frame(width: 84, height: 84)
                    ScrollView {
                        VStack(alignment: .leading, spacing: 2) {
                            ForEach(nodes) { node in
                                HStack(spacing: 4) {
                                    if node.children.count > 1 {
                                        Button {
                                            if expanded.contains(node.name) { expanded.remove(node.name) } else { expanded.insert(node.name) }
                                        } label: { Image(systemName: "chevron.right").rotationEffect(.degrees(expanded.contains(node.name) ? 90 : 0)).appFont(.caption2).foregroundStyle(.secondary) }
                                        .buttonStyle(.plain)
                                    } else {
                                        Color.clear.frame(width: 10, height: 1)
                                    }
                                    row(node.displayName, node.count, key: node.name, small: false)
                                }
                                if node.children.count > 1, expanded.contains(node.name) {
                                    VStack(alignment: .leading, spacing: 1) {
                                        ForEach(node.children) { child in row(child.displayName, child.count, key: child.name, small: true) }
                                    }
                                    .padding(.leading, 18)
                                }
                            }
                        }
                    }
                    .frame(maxHeight: 200)
                }
                if let selected, nodes.contains(where: { $0.name == selected || $0.children.contains { $0.name == selected } }) {
                    Button("Clear filter") { self.selected = nil }.appFont(.caption2).buttonStyle(.plain).foregroundStyle(.blue)
                }
            }
        }
    }

    private func row(_ label: String, _ count: Int, key: String, small: Bool) -> some View {
        let on = selected == key
        return Button { selected = on ? nil : key } label: {
            HStack(spacing: 6) {
                Circle().fill(tone.color.opacity(small ? 0.6 : 1)).frame(width: small ? 6 : 8, height: small ? 6 : 8)
                Text(label).appFont(small ? .caption2 : .caption).lineLimit(1)
                Spacer()
                Text("\(count)").appFont(small ? .caption2 : .caption, weight: .medium).monospacedDigit()
            }
            .padding(.horizontal, 4).padding(.vertical, 2)
            .background(on ? Color.blue.opacity(0.15) : Color.clear, in: RoundedRectangle(cornerRadius: 4))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}
