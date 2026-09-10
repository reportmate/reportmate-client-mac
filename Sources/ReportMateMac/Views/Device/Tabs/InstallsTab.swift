import SwiftUI
import ReportMateKit

/// Managed Installs: configuration card, last-run log, system-level run
/// problems, and the managed items table with status filters.
struct InstallsTabView: View {
    @Environment(AppState.self) private var appState
    let device: DeviceDetail
    var initialFilter: String?

    var body: some View {
        let info = InstallsInfo(modules: device.asJSON["modules"])
        VStack(alignment: .leading, spacing: 16) {
            header(info)
            if info.hasData {
                configCard(info)
                RunLogDisclosure(serial: device.serialNumber)
                InstallsRunStatusView(installs: info.raw, serial: device.serialNumber)
                if info.hasManagementSystem || !info.packages.isEmpty {
                    ManagedInstallsTable(info: info, initialFilter: initialFilter, runFailed: SystemProblems.collect(installs: info.raw).failedWithoutItems)
                } else {
                    Card { EmptyStateView(title: "No Managed Installs", message: "This device does not have managed software installations configured.", systemImage: "shippingbox") }
                }
            } else {
                Card { EmptyStateView(title: "No install data available", message: "The installs module has not reported for this device.", systemImage: "arrow.down.circle") }
            }
            JSONTreeView(value: device[.installs], label: "device.modules.installs")
        }
    }

    private func header(_ info: InstallsInfo) -> some View {
        HStack(alignment: .center) {
            HStack(spacing: 12) {
                ZStack {
                    RoundedRectangle(cornerRadius: 10).fill(Color.green.opacity(0.15))
                    Image(systemName: "arrow.down.circle").foregroundStyle(.green).appFont(fixed: 20)
                }
                .frame(width: 44, height: 44)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Managed Installs").appFont(.title2, weight: .bold)
                    Text("Software deployment report").appFont(.callout).foregroundStyle(.secondary)
                }
            }
            Spacer()
            if let last = info.lastRunTimestamp {
                VStack(alignment: .trailing, spacing: 2) {
                    Text("Last Run").appFont(.caption).foregroundStyle(.secondary)
                    Text(InstallsTabView.compactRelative(last)).appFont(.title2, weight: .bold).foregroundStyle(.green)
                }
            }
        }
    }

    private func configCard(_ info: InstallsInfo) -> some View {
        let c = info.config
        let manifest = c?.manifest.isEmpty == false ? c!.manifest : "No manifest configured"
        let repo = c?.softwareRepoURL.isEmpty == false ? c!.softwareRepoURL : "No repo configured"
        let version = c?.version.isEmpty == false ? c!.version : "Unknown"
        let lastSeen = info.lastRunTimestamp.map { TimeFormatting.exact($0) } ?? "Never"
        return Card {
            Grid(alignment: .leading, horizontalSpacing: 24, verticalSpacing: 14) {
                GridRow {
                    monoField("Manifest", manifest).gridColumnAlignment(.leading)
                    VStack(alignment: .center, spacing: 4) {
                        Text("Run Type").appFont(.caption, weight: .medium).foregroundStyle(.secondary)
                        Pill(c?.runType ?? "Auto", tone: .green)
                    }
                    monoField("Catalog", c?.catalogs ?? "Not configured", alignment: .trailing)
                }
                GridRow {
                    monoField("Repo", repo)
                    monoField("\(info.systemName) Version", version, alignment: .center)
                    monoField("Last Seen", lastSeen, alignment: .trailing)
                }
            }
            .padding(16)
        }
    }

    private func monoField(_ label: String, _ value: String, alignment: HorizontalAlignment = .leading) -> some View {
        VStack(alignment: alignment, spacing: 4) {
            Text(label).appFont(.caption, weight: .medium).foregroundStyle(.secondary)
            Text(value).appFont(.callout, design: .monospaced).textSelection(.enabled)
                .padding(.horizontal, 10).padding(.vertical, 6)
                .background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 6))
                .lineLimit(1).truncationMode(.middle).help(value)
        }
        .frame(maxWidth: .infinity, alignment: alignment == .leading ? .leading : alignment == .trailing ? .trailing : .center)
    }

    /// `formatCompactRelativeTime`: "2h 37m ago".
    static func compactRelative(_ timestamp: String) -> String {
        guard let date = FlexibleDate.parse(timestamp) else { return "unknown" }
        let diff = Date().timeIntervalSince(date)
        if diff < 0 { return "just now" }
        let minutes = Int(diff / 60), hours = minutes / 60, days = hours / 24
        if diff < 60 { return "just now" }
        if minutes < 60 { return "\(minutes)m ago" }
        if hours < 24 { return minutes % 60 > 0 ? "\(hours)h \(minutes % 60)m ago" : "\(hours)h ago" }
        return "\(days)d ago"
    }
}

/// The "Managed Software Update Last Run Log" disclosure with search and copy.
struct RunLogDisclosure: View {
    @Environment(AppState.self) private var appState
    let serial: String
    @State private var expanded = false
    @State private var log: String?
    @State private var loading = false
    @State private var search = ""

    var body: some View {
        Card {
            VStack(spacing: 0) {
                Button {
                    expanded.toggle()
                    if expanded, log == nil { Task { await load() } }
                } label: {
                    HStack {
                        Image(systemName: "doc.text").foregroundStyle(.secondary)
                        Text("Managed Software Update Last Run Log").appFont(.body, weight: .medium)
                        Spacer()
                        Image(systemName: "chevron.down").rotationEffect(.degrees(expanded ? 180 : 0)).foregroundStyle(.secondary)
                    }
                    .padding(.horizontal, 16).padding(.vertical, 12)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                if expanded {
                    Divider()
                    if loading {
                        LoadingView(message: "Loading run log…").frame(height: 120)
                    } else {
                        HStack {
                            HStack(spacing: 6) {
                                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                                TextField("Search log…", text: $search).textFieldStyle(.plain).appFont(.caption)
                            }
                            .padding(.horizontal, 10).padding(.vertical, 5)
                            .background(Color.subtleBackground, in: Capsule())
                            .frame(width: 260)
                            Spacer()
                            if let log { CopyButton(value: log) }
                        }
                        .padding(.horizontal, 12).padding(.vertical, 8)
                        ScrollView([.vertical, .horizontal]) {
                            Text(filteredLog)
                                .appFont(.caption, design: .monospaced)
                                .textSelection(.enabled)
                                .padding(12)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .frame(maxHeight: 500)
                        .background(Color.black.opacity(0.85))
                        .foregroundStyle(Color.white)
                    }
                }
            }
        }
    }

    private var filteredLog: String {
        guard let log else { return "No log data available" }
        let q = search.trimmingCharacters(in: .whitespaces).lowercased()
        guard !q.isEmpty else { return log }
        return log.split(separator: "\n", omittingEmptySubsequences: false).filter { $0.lowercased().contains(q) }.joined(separator: "\n")
    }

    private func load() async {
        loading = true
        do {
            log = try await appState.api.deviceInstallsLog(serial) ?? "No log data available"
        } catch {
            log = "Failed to load log data: \(error.localizedDescription)"
        }
        loading = false
    }
}

/// System-level problems from the last run: manifest, catalog, preflight
/// failures, or a failed run that reported no items.
struct InstallsRunStatusView: View {
    @Environment(AppState.self) private var appState
    let installs: JSONValue
    let serial: String
    @State private var eventLines: [InlineLine] = []

    var body: some View {
        let summary = SystemProblems.collect(installs: installs)
        if summary.isEmpty {
            EmptyView()
        } else {
            let isError = summary.failedWithoutItems || summary.problems.contains(where: \.isError)
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 8) {
                    Pill(isError ? "Last run failed" : "Last run warnings", tone: isError ? .red : .yellow)
                    if summary.failedWithoutItems { Text("The run did not complete, so no items were reported.").appFont(.callout).foregroundStyle(.secondary) }
                    Spacer()
                    Text([summary.sessionId, summary.time.flatMap { FlexibleDate.parse($0) }.map { TimeFormatting.relative($0) }].compactMap { $0 }.joined(separator: " · "))
                        .appFont(.caption2, design: .monospaced).foregroundStyle(.tertiary)
                }
                ForEach(Array(summary.problems.enumerated()), id: \.offset) { _, p in
                    Text(p.message).appFont(.caption, design: .monospaced).foregroundStyle(p.isError ? Color.red : Color.yellow)
                        .padding(.horizontal, 8).padding(.vertical, 5).background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 6))
                        .fixedSize(horizontal: false, vertical: true)
                }
                if summary.problems.isEmpty {
                    ForEach(Array(eventLines.enumerated()), id: \.offset) { _, l in
                        Text(l.text).appFont(.caption, design: .monospaced).foregroundStyle(.red)
                            .padding(.horizontal, 8).padding(.vertical, 5).background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 6))
                    }
                }
            }
            .padding(14)
            .background((isError ? Color.red : Color.yellow).opacity(0.08), in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).stroke((isError ? Color.red : Color.yellow).opacity(0.35)))
            .task(id: serial) {
                guard summary.failedWithoutItems, summary.problems.isEmpty else { return }
                let events = (try? await appState.api.deviceEvents(serial, limit: 5, kind: .error)) ?? []
                let installsEvent = events.first { $0.message.range(of: "munki|cimian|install", options: [.regularExpression, .caseInsensitive]) != nil } ?? events.first
                guard let installsEvent, let payload = await EventPayloadCache.shared.load(installsEvent.id, api: appState.api) else { return }
                let extracted = EventInlineDetails.extract(payload)
                eventLines = (extracted.errors + extracted.warnings).filter { l in
                    l.name == nil && !l.text.lowercased().hasPrefix("installer:") && l.text.range(of: #"^-{3,}"#, options: .regularExpression) == nil && InstallItems.itemName(fromMessage: l.text) == nil
                }.prefix(10).map { $0 }
            }
        }
    }
}

/// The managed items table with status pills, search, category grouping and
/// expandable error, warning and pending-reason rows.
struct ManagedInstallsTable: View {
    let info: InstallsInfo
    var initialFilter: String?
    var runFailed = false

    @State private var statusFilter: Set<String>
    @State private var search = ""
    @State private var expanded: Set<String> = []
    @State private var collapsedCategories: Set<String> = []

    init(info: InstallsInfo, initialFilter: String? = nil, runFailed: Bool = false) {
        self.info = info
        self.initialFilter = initialFilter
        self.runFailed = runFailed
        _statusFilter = State(initialValue: initialFilter.map { Set([$0]) } ?? [])
    }

    private var lastRunActive: Bool { statusFilter.contains("last_run") }
    private var statusOnly: Set<String> { statusFilter.subtracting(["last_run"]) }

    private var filtered: [InstallPackage] {
        var list = info.packages
        if lastRunActive { list = list.filter { !$0.lastUpdate.isEmpty } }
        if !statusOnly.isEmpty { list = list.filter { statusOnly.contains($0.status.rawValue.lowercased()) } }
        let q = search.trimmingCharacters(in: .whitespaces).lowercased()
        if !q.isEmpty { list = list.filter { $0.displayName.lowercased().contains(q) || $0.name.lowercased().contains(q) } }
        return list
    }

    private var grouped: [(category: String, packages: [InstallPackage])] {
        var groups: [String: [InstallPackage]] = [:]
        var uncategorized: [InstallPackage] = []
        for p in filtered {
            let c = p.category.trimmingCharacters(in: .whitespaces)
            if c.isEmpty { uncategorized.append(p) } else { groups[c, default: []].append(p) }
        }
        var out = groups.keys.sorted().map { (category: $0, packages: groups[$0]!.sorted { $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending }) }
        if !uncategorized.isEmpty { out.append((category: "Uncategorized", packages: uncategorized.sorted { $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending })) }
        return out
    }

    private var hasCategories: Bool { filtered.contains { !$0.category.trimmingCharacters(in: .whitespaces).isEmpty } }

    var body: some View {
        Card {
            VStack(spacing: 0) {
                toolbar
                if !statusFilter.isEmpty {
                    HStack {
                        Text("Showing \(filtered.count) of \(info.packages.count) packages, filtered by \(statusFilter.map { $0 == "last_run" ? "Last Run" : $0 }.sorted().joined(separator: ", "))")
                            .appFont(.caption).foregroundStyle(.secondary)
                        Spacer()
                    }
                    .padding(.horizontal, 16).padding(.vertical, 6)
                    .background(Color.subtleBackground)
                }
                columnHeader
                if info.packages.isEmpty {
                    emptyBody
                } else if filtered.isEmpty {
                    VStack(spacing: 8) {
                        Image(systemName: "line.3.horizontal.decrease.circle").font(.system(size: 28)).foregroundStyle(.tertiary)
                        Text("No items with \(statusFilter.map { $0 == "last_run" ? "last run" : $0 }.joined(separator: " or "))").appFont(.headline)
                        Text("No packages match the selected filter\(statusFilter.count > 1 ? "s" : "").").appFont(.callout).foregroundStyle(.secondary)
                        Button("Clear Filters") { statusFilter = [] }
                    }
                    .frame(maxWidth: .infinity).padding(40)
                } else if hasCategories, !lastRunActive {
                    ForEach(grouped, id: \.category) { group in
                        let collapsed = collapsedCategories.contains(group.category)
                        Button {
                            if collapsed { collapsedCategories.remove(group.category) } else { collapsedCategories.insert(group.category) }
                        } label: {
                            HStack(spacing: 8) {
                                Image(systemName: "chevron.right").rotationEffect(.degrees(collapsed ? 0 : 90)).foregroundStyle(.secondary).appFont(.caption)
                                Text(group.category).appFont(.callout, weight: .semibold)
                                Text("(\(group.packages.count) item\(group.packages.count == 1 ? "" : "s"))").appFont(.caption).foregroundStyle(.secondary)
                                Spacer()
                            }
                            .padding(.horizontal, 16).padding(.vertical, 8)
                            .background(Color.subtleBackground)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        if !collapsed {
                            ForEach(group.packages) { packageRow($0, indented: true) }
                        }
                    }
                } else {
                    ForEach(filtered.sorted { $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending }) { packageRow($0, indented: false) }
                }
            }
        }
        .onAppear { autoExpand() }
        .onChange(of: statusFilter) { _, _ in autoExpand() }
    }

    /// A status filter narrows to the items needing attention, so open their detail rows.
    private func autoExpand() {
        if statusFilter.isEmpty { expanded = [] } else { expanded = Set(filtered.filter(\.hasExpandableContent).map(\.id)) }
    }

    private var toolbar: some View {
        HStack(spacing: 10) {
            HStack(spacing: 4) {
                Text("Managed Items: \(info.totalPackages)").appFont(.callout, weight: .semibold)
                if let mb = info.cacheSizeMb { Text("· Cache: \(String(format: "%.1f", mb)) MB").appFont(.caption).foregroundStyle(.secondary) }
            }
            if !statusFilter.isEmpty {
                Button("Clear Filters") { statusFilter = [] }.buttonStyle(.plain).appFont(.caption, weight: .medium).foregroundStyle(.yellow)
                    .padding(.horizontal, 8).padding(.vertical, 3).background(Color.yellow.opacity(0.15), in: Capsule())
            }
            if hasCategories, !lastRunActive {
                Button(collapsedCategories.isEmpty ? "Collapse All" : "Expand All") {
                    collapsedCategories = collapsedCategories.isEmpty ? Set(grouped.map(\.category)) : []
                }
                .buttonStyle(.plain).appFont(.caption, weight: .medium)
                .padding(.horizontal, 8).padding(.vertical, 3).background(Color.subtleBackground, in: Capsule())
            }
            Spacer()
            FlowLayout(spacing: 6) {
                if info.lastRunCount > 0, statusOnly.isEmpty {
                    statusPill("last_run", "Last Run", info.lastRunCount, .gray)
                }
                ForEach(InstallStatus.allCases, id: \.self) { s in
                    statusPill(s.rawValue.lowercased(), s.rawValue, info.count(s, lastRunOnly: lastRunActive), ManagedInstallsTable.tone(s))
                }
            }
            .fixedSize()
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Search items…", text: $search).textFieldStyle(.plain).appFont(.caption)
            }
            .padding(.horizontal, 10).padding(.vertical, 5)
            .background(Color.subtleBackground, in: Capsule())
            .frame(width: 180)
        }
        .padding(.horizontal, 16).padding(.vertical, 10)
        .overlay(alignment: .bottom) { Divider() }
    }

    private func statusPill(_ key: String, _ label: String, _ count: Int, _ tone: Tone) -> some View {
        let active = statusFilter.contains(key)
        return Button {
            if active {
                statusFilter.remove(key)
            } else {
                statusFilter.insert(key)
                if key == "last_run" { statusFilter = ["last_run"] } else { statusFilter.remove("last_run") }
            }
        } label: {
            Text("\(label) - \(count)")
                .appFont(.caption, weight: .medium)
                .padding(.horizontal, 10).padding(.vertical, 4)
                .background(active ? tone.color : tone.color.opacity(0.15), in: Capsule())
                .foregroundStyle(active ? Color.white : (tone == .gray ? Color.primary : tone.color))
        }
        .buttonStyle(.plain)
    }

    private var columnHeader: some View {
        HStack(spacing: 12) {
            Text("STATUS").frame(width: 90, alignment: .leading)
            Text("PACKAGE").frame(maxWidth: .infinity, alignment: .leading)
            Text("VERSION").frame(width: 150, alignment: .leading)
            Text("ITEM SIZE").frame(width: 80, alignment: .leading)
            Text("DATE PROCESSED").frame(width: 150, alignment: .leading)
        }
        .appFont(.caption2, weight: .semibold).foregroundStyle(.secondary).kerning(0.5)
        .padding(.horizontal, 16).padding(.vertical, 8)
        .background(Color.subtleBackground)
        .overlay(alignment: .bottom) { Divider() }
    }

    @ViewBuilder
    private var emptyBody: some View {
        if !info.runErrors.isEmpty {
            VStack(alignment: .leading, spacing: 8) {
                Label("Last Run Failed", systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red).appFont(.headline)
                ForEach(info.runErrors) { e in
                    Text(e.message).appFont(.caption, design: .monospaced).foregroundStyle(.red)
                        .padding(8).background(Color.red.opacity(0.08), in: RoundedRectangle(cornerRadius: 6))
                }
                if let last = info.config?.lastRun, !last.isEmpty { Text(TimeFormatting.medium(last)).appFont(.caption).foregroundStyle(.red) }
            }
            .padding(16)
        } else {
            VStack(spacing: 8) {
                Image(systemName: runFailed ? "exclamationmark.circle" : "checkmark.circle").font(.system(size: 28)).foregroundStyle(runFailed ? Color.red : Color.green)
                Text(runFailed ? "Last run did not complete" : "\(info.systemName.isEmpty ? "Management" : info.systemName) System Active").appFont(.headline)
                Text(runFailed ? "No items were reported because the run failed before it could evaluate the manifest." : "The managed installs system is configured and running, but no packages are currently assigned to this device.")
                    .appFont(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
                if let last = info.config?.lastRun, !last.isEmpty { Text("Last check: \(TimeFormatting.relative(last))").appFont(.caption).foregroundStyle(.tertiary) }
            }
            .frame(maxWidth: .infinity).padding(40)
        }
    }

    private func packageRow(_ pkg: InstallPackage, indented: Bool) -> some View {
        let isOpen = expanded.contains(pkg.id)
        return VStack(spacing: 0) {
            HStack(spacing: 12) {
                Pill(pkg.status.displayName, tone: ManagedInstallsTable.tone(pkg.status)).frame(width: 90, alignment: .leading)
                Text(pkg.displayName).appFont(.body, weight: .medium).frame(maxWidth: .infinity, alignment: .leading).lineLimit(1)
                VStack(alignment: .leading, spacing: 1) {
                    Text(pkg.version.isEmpty ? "Unknown" : pkg.version).appFont(.body)
                    if !pkg.installedVersion.isEmpty, pkg.installedVersion != pkg.version {
                        Text("\(pkg.installedVersion) installed").appFont(.caption).foregroundStyle(.secondary)
                    }
                }
                .frame(width: 150, alignment: .leading)
                Text(pkg.formattedItemSize).appFont(.body).foregroundStyle(.secondary).frame(width: 80, alignment: .leading)
                HStack {
                    Text(pkg.lastUpdate.isEmpty ? "" : TimeFormatting.relative(pkg.lastUpdate)).appFont(.body).foregroundStyle(.secondary)
                        .help(pkg.lastUpdate.isEmpty ? "" : TimeFormatting.exact(pkg.lastUpdate))
                    Spacer()
                    if pkg.hasExpandableContent {
                        Image(systemName: "chevron.right").rotationEffect(.degrees(isOpen ? 90 : 0)).foregroundStyle(.secondary).appFont(.caption)
                    }
                }
                .frame(width: 150)
            }
            .padding(.leading, indented ? 32 : 16).padding(.trailing, 16).padding(.vertical, 9)
            .contentShape(Rectangle())
            .onTapGesture { if pkg.hasExpandableContent { if isOpen { expanded.remove(pkg.id) } else { expanded.insert(pkg.id) } } }
            if isOpen, pkg.hasExpandableContent {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(pkg.errors) { messageCard($0, tone: .red) }
                    ForEach(pkg.warnings) { messageCard($0, tone: .yellow) }
                    if pkg.status == .pending, !pkg.pendingReason.trimmingCharacters(in: .whitespaces).isEmpty {
                        HStack(alignment: .top, spacing: 10) {
                            Image(systemName: "info.circle").foregroundStyle(.cyan)
                            VStack(alignment: .leading, spacing: 6) {
                                HStack { Pill("PENDING", tone: .cyan); Spacer(); CopyButton(value: pkg.pendingReason) }
                                Text(pkg.pendingReason).appFont(.callout).foregroundStyle(.cyan)
                            }
                        }
                        .padding(12).background(Color.cardBackground, in: RoundedRectangle(cornerRadius: 8))
                        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.cyan.opacity(0.4)))
                    }
                }
                .padding(.horizontal, 24).padding(.vertical, 12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.subtleBackground)
            }
            Divider()
        }
    }

    private func messageCard(_ m: InstallMessage, tone: Tone) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                if let code = m.code { Pill(code, tone: tone) }
                if let t = m.timestamp { Text(TimeFormatting.exact(t)).appFont(.caption).foregroundStyle(.secondary) }
                Spacer()
                CopyButton(value: "\(m.code.map { "[\($0)] " } ?? "")\(m.message)\(m.details.map { "\n\nDetails: \($0)" } ?? "")")
            }
            Text(m.message).appFont(.callout).foregroundStyle(tone.color).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
            if let details = m.details {
                ScrollView {
                    Text(details).appFont(.caption, design: .monospaced).foregroundStyle(.secondary).textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading).padding(8)
                }
                .frame(maxHeight: 300)
                .background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 6))
            }
        }
        .padding(12)
        .background(Color.cardBackground, in: RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(tone.color.opacity(0.4)))
    }

    static func tone(_ status: InstallStatus) -> Tone {
        switch status {
        case .installed: return .green
        case .pending: return .cyan
        case .warning: return .yellow
        case .error: return .red
        case .removed: return .purple
        }
    }
}
