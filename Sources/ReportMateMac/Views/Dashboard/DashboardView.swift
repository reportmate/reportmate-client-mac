import SwiftUI
import Charts
import ReportMateKit

/// The dashboard: fleet status, install error and warning counters, new
/// clients on the left; recent events, platform distribution and OS version
/// charts on the right. Refreshes every 30 seconds like the web page.
@MainActor
@Observable
final class DashboardModel {
    var data: DashboardData?
    var loading = false
    var error: String?
    var lastUpdate: Date?
    var connectionStatus: ConnectionStatus = .connecting
    /// Bumped every two minutes so relative times re-render.
    var clockTick = 0

    enum ConnectionStatus { case connecting, connected, reconnecting, polling, error }

    private var liveTask: Task<Void, Never>?
    private var reconnectAttempts = 0
    private static let maxReconnectAttempts = 5

    var isLive: Bool { connectionStatus == .connected || connectionStatus == .reconnecting }

    func load(api: ReportMateAPI, includeArchived: Bool, initial: Bool) async {
        if initial { loading = data == nil }
        do {
            let fresh = try await api.dashboard(eventsLimit: 200, includeArchived: includeArchived)
            if var existing = data, !initial {
                // Background refresh: merge, never clear on an empty response.
                if !fresh.devices.isEmpty { existing.devices = fresh.devices; existing.totalDevices = fresh.totalDevices }
                existing.installStats = fresh.installStats
                if !fresh.events.isEmpty {
                    let known = Set(existing.events.map(\.id))
                    let new = fresh.events.filter { !known.contains($0.id) }
                    if !new.isEmpty {
                        existing.events = (new + existing.events).sorted { ($0.ts ?? .distantPast) > ($1.ts ?? .distantPast) }.prefix(1000).map { $0 }
                    }
                }
                existing.lastUpdated = fresh.lastUpdated
                data = existing
            } else {
                var d = fresh
                d.devices.sort { ($0.lastSeen ?? .distantPast) > ($1.lastSeen ?? .distantPast) }
                data = d
            }
            error = nil
            if !isLive { connectionStatus = .polling }
            lastUpdate = Date()
        } catch {
            if initial { self.error = error.localizedDescription; connectionStatus = .error }
        }
        loading = false
    }

    /// Open the Web PubSub event stream like the web dashboard: negotiate a
    /// token, listen, reconnect with exponential backoff up to five times,
    /// then settle on polling. Polling keeps running underneath either way so
    /// the device and install widgets stay fresh.
    func startLive(api: ReportMateAPI) {
        liveTask?.cancel()
        reconnectAttempts = 0
        liveTask = Task { [weak self] in await self?.runLive(api: api) }
    }

    func stopLive() {
        liveTask?.cancel()
        liveTask = nil
    }

    private func runLive(api: ReportMateAPI) async {
        while !Task.isCancelled {
            let negotiated: NegotiateResult
            do {
                negotiated = try await withThrowingTaskGroup(of: NegotiateResult.self) { group in
                    group.addTask { try await api.negotiate() }
                    group.addTask { try await Task.sleep(for: .seconds(10)); throw CancellationError() }
                    let first = try await group.next()!
                    group.cancelAll()
                    return first
                }
            } catch { settle(); return }
            guard negotiated.error == nil, let url = negotiated.url else { settle(); return }
            do {
                for try await frame in LiveEventStream.frames(url: url) {
                    switch frame {
                    case .open:
                        connectionStatus = .connected
                        reconnectAttempts = 0
                        lastUpdate = Date()
                    case .event(let event):
                        insert(event)
                    }
                }
            } catch {
                // Closed: fall through to the reconnect ladder.
            }
            if Task.isCancelled { return }
            guard reconnectAttempts < Self.maxReconnectAttempts else { settle(); return }
            let delay = min(pow(2.0, Double(reconnectAttempts)), 30)
            reconnectAttempts += 1
            connectionStatus = .reconnecting
            try? await Task.sleep(for: .seconds(delay))
        }
    }

    private func settle() {
        if connectionStatus != .error { connectionStatus = .polling }
    }

    private func insert(_ event: FleetEvent) {
        guard var existing = data else { return }
        guard !existing.events.contains(where: { $0.id == event.id }) else { return }
        existing.events = ([event] + existing.events).prefix(1000).map { $0 }
        data = existing
        lastUpdate = Date()
    }
}

struct DashboardView: View {
    @Environment(AppState.self) private var appState
    @State private var model = DashboardModel()

    private var devices: [DeviceSummary] {
        guard let all = model.data?.devices else { return [] }
        if appState.platformFilter == .all { return all }
        return all.filter { appState.platformFilter.includes($0.platform) }
    }

    private var events: [FleetEvent] {
        guard let all = model.data?.events else { return [] }
        if appState.platformFilter == .all { return all }
        return all.filter { appState.platformFilter.includes($0.platform) }
    }

    var body: some View {
        Group {
            if model.loading, model.data == nil {
                LoadingView(message: "Loading dashboard…")
            } else if let error = model.error, model.data == nil {
                ErrorBanner(message: error) { Task { await model.load(api: appState.api, includeArchived: appState.includeArchived, initial: true) } }
                    .padding()
                Spacer()
            } else {
                ScrollView {
                    ViewThatFits(in: .horizontal) {
                        HStack(alignment: .top, spacing: 20) {
                            leftColumn.frame(width: 360)
                            rightColumn
                        }
                        VStack(spacing: 20) {
                            leftColumn
                            rightColumn
                        }
                    }
                    .padding(20)
                }
            }
        }
        .navigationTitle("Dashboard")
        .task(id: appState.configuration) {
            model.startLive(api: appState.api)
            defer { model.stopLive() }
            await model.load(api: appState.api, includeArchived: appState.includeArchived, initial: true)
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(30))
                guard !Task.isCancelled else { break }
                await model.load(api: appState.api, includeArchived: appState.includeArchived, initial: false)
            }
        }
        .task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(120))
                model.clockTick += 1
            }
        }
        .onChange(of: appState.refreshRequested) { _, _ in
            Task { await model.load(api: appState.api, includeArchived: appState.includeArchived, initial: model.data == nil) }
        }
    }

    private var leftColumn: some View {
        VStack(spacing: 20) {
            StatusWidget(devices: devices)
            HStack(spacing: 14) {
                InstallStatWidget(kind: .error, stats: model.data?.installStats, filter: appState.platformFilter)
                InstallStatWidget(kind: .warning, stats: model.data?.installStats, filter: appState.platformFilter)
            }
            NewClientsWidget(devices: devices)
        }
    }

    private var rightColumn: some View {
        VStack(spacing: 20) {
            RecentEventsWidget(events: events, connectionStatus: model.connectionStatus, lastUpdate: model.lastUpdate)
            PlatformDistributionWidget(devices: devices)
            osVersionRow
        }
    }

    @ViewBuilder
    private var osVersionRow: some View {
        let showMac = appState.platformFilter != .windows
        let showWin = appState.platformFilter != .macOS
        ViewThatFits(in: .horizontal) {
            HStack(alignment: .top, spacing: 16) {
                if showMac { OSVersionWidget(devices: devices, platform: .macOS) }
                if showWin { OSVersionWidget(devices: devices, platform: .windows) }
            }
            VStack(spacing: 16) {
                if showMac { OSVersionWidget(devices: devices, platform: .macOS) }
                if showWin { OSVersionWidget(devices: devices, platform: .windows) }
            }
        }
    }
}

// MARK: - Fleet status donut

struct StatusWidget: View {
    @Environment(AppState.self) private var appState
    let devices: [DeviceSummary]

    private var slices: [FleetStats.StatusSlice] { FleetStats.statusDistribution(devices) }

    var body: some View {
        Card {
            VStack(spacing: 0) {
                CardHeader("Fleet Status", subtitle: "Click to view all devices", systemImage: "laptopcomputer", tone: .blue) {
                    appState.section = .devices
                }
                if devices.isEmpty {
                    EmptyStateView(title: "No devices found", message: "Devices will appear here when they report in", systemImage: "laptopcomputer")
                } else {
                    VStack(spacing: 18) {
                        ZStack {
                            Chart(slices) { slice in
                                SectorMark(angle: .value("Devices", slice.count), innerRadius: .ratio(0.62), angularInset: 1)
                                    .foregroundStyle(Color(hex: slice.status.chartColorHex))
                            }
                            .chartLegend(.hidden)
                            .frame(width: 190, height: 190)
                            VStack(spacing: 0) {
                                Text("\(devices.count)").appFont(.title, weight: .bold).monospacedDigit()
                                Text(devices.count == 1 ? "Device" : "Devices").appFont(.callout).foregroundStyle(.secondary)
                            }
                        }
                        .contentShape(Rectangle())
                        .onTapGesture { appState.section = .devices }
                        VStack(spacing: 4) {
                            ForEach(slices) { slice in
                                Button {
                                    NotificationCenter.default.post(name: .devicesStatusFilter, object: slice.status.rawValue)
                                    appState.section = .devices
                                } label: {
                                    HStack {
                                        Circle().fill(Color(hex: slice.status.chartColorHex)).frame(width: 12, height: 12)
                                        Text(slice.status.displayName).appFont(.callout, weight: .medium)
                                        Spacer()
                                        Text("\(slice.count)").appFont(.callout).foregroundStyle(.secondary).monospacedDigit()
                                        Text("\(slice.percentage)%").appFont(.caption).foregroundStyle(.tertiary).monospacedDigit().frame(width: 40, alignment: .trailing)
                                    }
                                    .padding(.horizontal, 8).padding(.vertical, 6)
                                    .contentShape(Rectangle())
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }
                    .padding(16)
                }
            }
        }
    }
}

extension Notification.Name {
    static let devicesStatusFilter = Notification.Name("ReportMate.devicesStatusFilter")
}

// MARK: - Error / warning counters

struct InstallStatWidget: View {
    enum Kind { case error, warning }
    @Environment(AppState.self) private var appState
    let kind: Kind
    let stats: InstallStats?
    let filter: PlatformFilter

    private var value: Int? {
        guard let stats else { return nil }
        return kind == .error ? stats.devicesWithErrors(for: filter) : stats.devicesWithWarnings(for: filter)
    }

    var body: some View {
        let tone: Tone = kind == .error ? .red : .yellow
        let label = kind == .error ? (value == 1 ? "Error" : "Errors") : (value == 1 ? "Warning" : "Warnings")
        Button {
            appState.section = .installs
            NotificationCenter.default.post(name: .installsFilter, object: kind == .error ? "errors" : "warnings")
        } label: {
            Card {
                HStack(spacing: 12) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 8).fill(value == nil ? Color.secondary.opacity(0.12) : tone.color.opacity(0.15))
                        Image(systemName: kind == .error ? "xmark.circle.fill" : "exclamationmark.triangle.fill")
                            .foregroundStyle(value == nil ? Color.secondary : tone.color).appFont(fixed: 20)
                    }
                    .frame(width: 44, height: 44)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(value.map(String.init) ?? "-").appFont(.title, weight: .bold).foregroundStyle(value == nil ? Color.secondary : tone.color).monospacedDigit()
                        Text(label).appFont(.callout).foregroundStyle(.secondary)
                    }
                    Spacer(minLength: 0)
                }
                .padding(.horizontal, 16).padding(.vertical, 20)
            }
        }
        .buttonStyle(.plain)
        .help(kind == .error ? "Devices with one or more failed installs" : "Devices with one or more install warnings")
    }
}

extension Notification.Name {
    static let installsFilter = Notification.Name("ReportMate.installsFilter")
}

// MARK: - New clients

struct NewClientsWidget: View {
    @Environment(AppState.self) private var appState
    let devices: [DeviceSummary]

    private var newDevices: [DeviceSummary] { FleetStats.newClients(devices) }

    var body: some View {
        Card {
            VStack(spacing: 0) {
                CardHeader("New Clients", subtitle: "Registered in the last 7 days") { appState.section = .devices }
                if newDevices.isEmpty {
                    EmptyStateView(title: "No new clients", message: "No devices registered in the last 7 days", systemImage: "laptopcomputer")
                        .frame(minHeight: 200)
                } else {
                    ScrollView {
                        LazyVStack(spacing: 0) {
                            ForEach(newDevices.prefix(10)) { device in
                                Button { appState.open(device: device.serialNumber) } label: {
                                    VStack(alignment: .leading, spacing: 3) {
                                        HStack {
                                            Text(device.name).appFont(.body, weight: .medium).lineLimit(1)
                                            Spacer()
                                            PlatformBadge(platform: device.platform)
                                        }
                                        Text(device.identifierLine).appFont(.caption).foregroundStyle(.secondary)
                                        Text("Registered: \(TimeFormatting.relative(device.createdAt))").appFont(.caption2).foregroundStyle(.tertiary)
                                    }
                                    .padding(.horizontal, 16).padding(.vertical, 10)
                                    .contentShape(Rectangle())
                                }
                                .buttonStyle(.plain)
                                Divider().padding(.leading, 16)
                            }
                        }
                    }
                    .frame(maxHeight: 560)
                }
            }
        }
    }
}

// MARK: - Platform distribution

struct PlatformDistributionWidget: View {
    @Environment(AppState.self) private var appState
    let devices: [DeviceSummary]
    @State private var filters = FleetStats.DistributionFilters()
    @State private var expanded: String?

    private var stats: [FleetStats.PlatformStats] { FleetStats.platformDistribution(devices, filters: filters) }
    private var available: FleetStats.AvailableFilters { FleetStats.availableFilters(devices) }

    var body: some View {
        Card {
            VStack(spacing: 0) {
                CardHeader("Platform Distribution", systemImage: "laptopcomputer", tone: .purple) { appState.section = .devices }
                VStack(alignment: .leading, spacing: 10) {
                    if devices.isEmpty {
                        EmptyStateView(title: "No devices found", message: "Platform distribution will appear when devices are detected")
                    } else if stats.count == 1, let single = stats.first {
                        singlePlatform(single)
                    } else {
                        ForEach(stats) { s in platformCard(s) }
                    }
                    filterPills
                }
                .padding(16)
            }
        }
    }

    private func platformCard(_ s: FleetStats.PlatformStats) -> some View {
        let isOpen = expanded == s.platform.rawValue
        return VStack(spacing: 0) {
            Button { withAnimation(.easeInOut(duration: 0.15)) { expanded = isOpen ? nil : s.platform.rawValue } } label: {
                HStack(spacing: 12) {
                    Image(systemName: s.platform.systemImage).appFont(fixed: 22).foregroundStyle(.secondary).frame(width: 28)
                    VStack(alignment: .leading, spacing: 6) {
                        HStack(alignment: .firstTextBaseline, spacing: 6) {
                            Text(s.platform.chartLabel).appFont(.headline)
                            Text("\(s.percentage)%").appFont(.callout).foregroundStyle(.tertiary)
                        }
                        GeometryReader { geo in
                            ZStack(alignment: .leading) {
                                Capsule().fill(Color.secondary.opacity(0.12))
                                Capsule().fill(Color.purple.opacity(0.8)).frame(width: geo.size.width * CGFloat(s.percentage) / 100)
                            }
                        }
                        .frame(height: 8)
                    }
                    Text("\(s.count)").appFont(.title3, weight: .semibold).monospacedDigit()
                    Image(systemName: "chevron.down").rotationEffect(.degrees(isOpen ? 180 : 0)).foregroundStyle(.secondary).appFont(.caption)
                }
                .padding(12)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            if isOpen {
                Divider()
                VStack(alignment: .leading, spacing: 12) {
                    drill("Architecture", s.architectures, total: s.count)
                    drill("Usage", s.usages, total: s.count)
                    drill("Catalog", s.catalogs, total: s.count)
                    drill("Department", s.departments, total: s.count)
                    ageLine(s.ageStats)
                }
                .padding(12)
                .background(Color.subtleBackground)
            }
        }
        .clipShape(RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.cardBorder))
    }

    private func singlePlatform(_ platform: FleetStats.PlatformStats) -> some View {
        let usages = FleetStats.usageDistribution(devices, filters: filters)
        let known = usages.filter { $0.usage != "Unknown" }
        let unknown = usages.filter { $0.usage == "Unknown" }.reduce(0) { $0 + $1.count }
        return VStack(alignment: .leading, spacing: 10) {
            HStack {
                Image(systemName: platform.platform.systemImage).foregroundStyle(.secondary)
                Text("\(platform.platform.chartLabel) — \(platform.count) \(platform.count == 1 ? "device" : "devices") — by Usage").appFont(.callout, weight: .medium).foregroundStyle(.secondary)
                Spacer()
                if unknown > 0 { Text("\(unknown) unknown").appFont(.caption).foregroundStyle(.tertiary) }
            }
            ForEach(known) { u in
                let isOpen = expanded == "usage:\(u.usage)"
                VStack(spacing: 0) {
                    Button { withAnimation(.easeInOut(duration: 0.15)) { expanded = isOpen ? nil : "usage:\(u.usage)" } } label: {
                        HStack(spacing: 12) {
                            VStack(alignment: .leading, spacing: 6) {
                                HStack(alignment: .firstTextBaseline, spacing: 6) {
                                    Text(u.usage).appFont(.headline)
                                    Text("\(u.percentage)%").appFont(.callout).foregroundStyle(.tertiary)
                                }
                                GeometryReader { geo in
                                    ZStack(alignment: .leading) {
                                        Capsule().fill(Color.secondary.opacity(0.12))
                                        Capsule().fill(Color.purple.opacity(0.8)).frame(width: geo.size.width * CGFloat(u.percentage) / 100)
                                    }
                                }
                                .frame(height: 8)
                            }
                            Text("\(u.count)").appFont(.title3, weight: .semibold).monospacedDigit()
                            Image(systemName: "chevron.down").rotationEffect(.degrees(isOpen ? 180 : 0)).foregroundStyle(.secondary).appFont(.caption)
                        }
                        .padding(12).contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    if isOpen {
                        Divider()
                        VStack(alignment: .leading, spacing: 12) {
                            drill("Architecture", u.architectures, total: u.count)
                            drill("Catalog", u.catalogs, total: u.count)
                            drill("Department", u.departments, total: u.count)
                        }
                        .padding(12).background(Color.subtleBackground)
                    }
                }
                .clipShape(RoundedRectangle(cornerRadius: 10))
                .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.cardBorder))
            }
        }
    }

    @ViewBuilder
    private func drill(_ title: String, _ data: [String: Int], total: Int) -> some View {
        if !data.isEmpty {
            VStack(alignment: .leading, spacing: 4) {
                SectionLabel(title)
                ForEach(data.sorted { $0.value > $1.value }, id: \.key) { entry in
                    BarRow(label: entry.key, count: entry.value, total: total)
                }
            }
        }
    }

    @ViewBuilder
    private func ageLine(_ age: FleetStats.AgeStats) -> some View {
        if age.devicesWithAge > 0 {
            HStack(spacing: 12) {
                SectionLabel("Fleet age")
                Text("avg \(Int(age.averageAgeDays.rounded())) days").appFont(.caption)
                if let n = age.newest { Text("newest \(TimeFormatting.shortDate(n))").appFont(.caption).foregroundStyle(.secondary) }
                if let o = age.oldest { Text("oldest \(TimeFormatting.shortDate(o))").appFont(.caption).foregroundStyle(.secondary) }
            }
        }
    }

    @ViewBuilder
    private var filterPills: some View {
        let single = stats.count == 1
        if !available.usages.isEmpty || !available.catalogs.isEmpty || !available.architectures.isEmpty {
            VStack(alignment: .leading, spacing: 6) {
                if !single, !available.usages.isEmpty {
                    pillRow("Usage", available.usages.prefix(6).map { $0 }, selected: filters.usage, tone: .purple) { toggle(&filters.usage, $0) }
                }
                if !available.catalogs.isEmpty {
                    pillRow("Catalog", available.catalogs.prefix(6).map { $0 }, selected: filters.catalog, tone: .green) { toggle(&filters.catalog, $0) }
                }
                if !available.architectures.isEmpty {
                    pillRow("Arch", available.architectures, selected: filters.architecture, tone: .blue) { toggle(&filters.architecture, $0) }
                }
                if !filters.isEmpty {
                    Button("Clear filters") { filters = FleetStats.DistributionFilters() }.buttonStyle(.link).appFont(.caption)
                }
            }
            .padding(.top, 4)
        }
    }

    private func pillRow(_ label: String, _ values: [String], selected: Set<String>, tone: Tone, toggle: @escaping (String) -> Void) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Text(label.uppercased()).appFont(.caption2).foregroundStyle(.tertiary).frame(width: 52, alignment: .leading).padding(.top, 4)
            FlowLayout(spacing: 4) {
                ForEach(values, id: \.self) { v in
                    FilterPill(text: v, selected: selected.contains(v), tone: tone, size: 10) { toggle(v) }
                }
            }
        }
    }

    private func toggle(_ set: inout Set<String>, _ value: String) {
        // The web widget keeps a single selection per dimension.
        if set.contains(value) { set = [] } else { set = [value] }
    }
}

// MARK: - OS versions

struct OSVersionWidget: View {
    @Environment(AppState.self) private var appState
    let devices: [DeviceSummary]
    let platform: Platform
    @State private var selectedGroup: String?
    @State private var hovered: String?

    private var nodes: [FleetStats.VersionNode] { FleetStats.osVersions(devices, platform: platform) }

    private var visible: [FleetStats.VersionNode] {
        if let selectedGroup, let g = nodes.first(where: { $0.name == selectedGroup }) { return g.children }
        return nodes
    }

    private var total: Int {
        if let selectedGroup, let g = nodes.first(where: { $0.name == selectedGroup }) { return g.count }
        return nodes.reduce(0) { $0 + $1.count }
    }

    var body: some View {
        Card {
            VStack(spacing: 0) {
                HStack(spacing: 10) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 8).fill((platform == .macOS ? Color.red : Color.blue).opacity(0.15))
                        Image(systemName: platform.systemImage).foregroundStyle(platform == .macOS ? Color.red : Color.blue).appFont(fixed: 14)
                    }
                    .frame(width: 30, height: 30)
                    Text("\(platform.displayName) Versions").appFont(.headline)
                    Spacer()
                    if selectedGroup != nil {
                        Button { withAnimation { selectedGroup = nil } } label: { Label("All versions", systemImage: "chevron.left").appFont(.caption) }
                            .buttonStyle(.link)
                    }
                }
                .padding(.horizontal, 14).padding(.vertical, 10)
                .overlay(alignment: .bottom) { Divider() }

                if nodes.isEmpty {
                    Text("No \(platform.displayName) devices found").appFont(.callout).foregroundStyle(.secondary).padding(16)
                } else {
                    HStack(alignment: .top, spacing: 14) {
                        Chart(visible) { node in
                            SectorMark(angle: .value("Devices", node.count), innerRadius: .ratio(0.64), angularInset: 1.5)
                                .foregroundStyle(OSVersionWidget.temperatureColor(index: node.index, total: node.siblingCount, lighten: selectedGroup != nil))
                                .opacity(hovered == nil || hovered == node.name ? 1 : 0.4)
                        }
                        .chartLegend(.hidden)
                        .frame(width: 150, height: 150)
                        ScrollView {
                            VStack(spacing: 3) {
                                ForEach(visible) { node in
                                    let maxCount = max(visible.map(\.count).max() ?? 1, 1)
                                    let pct = total > 0 ? Int((Double(node.count) / Double(total) * 100).rounded()) : 0
                                    Button { select(node) } label: {
                                        HStack(spacing: 8) {
                                            Text(node.displayName).appFont(.caption, weight: .medium).monospacedDigit().frame(minWidth: 52, alignment: .leading)
                                            GeometryReader { geo in
                                                ZStack(alignment: .leading) {
                                                    RoundedRectangle(cornerRadius: 4).fill(Color.secondary.opacity(0.12))
                                                    RoundedRectangle(cornerRadius: 4)
                                                        .fill(OSVersionWidget.temperatureColor(index: node.index, total: node.siblingCount, lighten: selectedGroup != nil))
                                                        .frame(width: max(24, geo.size.width * max(CGFloat(node.count) / CGFloat(maxCount), 0.15)))
                                                        .overlay(alignment: .trailing) {
                                                            Text("\(node.count)").appFont(fixed: 10, weight: .medium).foregroundStyle(.white).padding(.trailing, 4)
                                                        }
                                                }
                                            }
                                            .frame(height: 20)
                                            Text("\(pct)%").appFont(.caption).foregroundStyle(.secondary).monospacedDigit().frame(width: 36, alignment: .trailing)
                                        }
                                        .padding(.horizontal, 4).padding(.vertical, 2)
                                        .background(hovered == node.name ? Color.subtleBackground : Color.clear, in: RoundedRectangle(cornerRadius: 6))
                                        .contentShape(Rectangle())
                                    }
                                    .buttonStyle(.plain)
                                    .onHover { hovered = $0 ? node.name : nil }
                                }
                            }
                        }
                        .frame(maxHeight: 190)
                    }
                    .padding(14)
                }
            }
        }
    }

    private func select(_ node: FleetStats.VersionNode) {
        if selectedGroup == nil, !node.children.isEmpty {
            withAnimation { selectedGroup = node.name }
        } else {
            NotificationCenter.default.post(name: .systemVersionFilter, object: node.name)
            appState.section = .system
        }
    }

    /// Green (newest) through yellow and orange to red (oldest).
    static func temperatureColor(index: Int, total: Int, lighten: Bool) -> Color {
        guard total > 1 else { return lighten ? Color(hex: "#34d399") : Color(hex: "#10B981") }
        let ratio = Double(index) / Double(total - 1)
        let stops: [(Double, Double, Double)] = [(16, 185, 129), (132, 204, 22), (234, 179, 8), (249, 115, 22), (239, 68, 68)]
        let segment = ratio * Double(stops.count - 1)
        let start = Int(segment)
        let end = min(start + 1, stops.count - 1)
        let t = segment - Double(start)
        var r = stops[start].0 + (stops[end].0 - stops[start].0) * t
        var g = stops[start].1 + (stops[end].1 - stops[start].1) * t
        var b = stops[start].2 + (stops[end].2 - stops[start].2) * t
        if lighten {
            let amt = 2.55 * Double(5 + index * 10)
            r = min(255, r + amt); g = min(255, g + amt); b = min(255, b + amt)
        }
        return Color(red: r / 255, green: g / 255, blue: b / 255)
    }
}

extension Notification.Name {
    static let systemVersionFilter = Notification.Name("ReportMate.systemVersionFilter")
}
