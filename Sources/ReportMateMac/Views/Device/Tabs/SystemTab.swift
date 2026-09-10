import SwiftUI
import ReportMateKit

/// System information: OS cards, updates, background activity, extensions,
/// helpers and environment. Port of `SystemTab.tsx` and its tables.
struct SystemTabView: View {
    let device: DeviceDetail
    @State private var helperSearch = ""

    var body: some View {
        let sys = SystemInfo(modules: device.asJSON["modules"], platform: device.platform)
        VStack(alignment: .leading, spacing: 20) {
            header(sys)
            osCard(sys)
            if !sys.isMac, !sys.pendingWindowsUpdates.isEmpty { pendingWindowsUpdates(sys.pendingWindowsUpdates) }
            if !sys.isMac, !sys.installedUpdateRows.isEmpty { recentWindowsUpdates(sys.installedUpdateRows) }
            if sys.isMac { macUpdates(sys) }
            if sys.isMac, !sys.installHistoryRows.isEmpty { installHistory(sys.installHistoryRows) }
            stats(sys)
            if !sys.isMac, !sys.taskItems.isEmpty { ScheduledTasksTable(tasks: sys.taskItems) }
            if sys.isMac, !(sys.scheduledTasks.isEmpty && sys.services.isEmpty) { LaunchdTable(items: sys.launchdItems, title: "Background Activity", defaultScope: .system) }
            if !sys.isMac, !sys.serviceItems.isEmpty { WindowsServicesTable(services: sys.serviceItems) }
            if sys.isMac, !(sys.extensionRows.isEmpty && sys.loginItemRows.isEmpty) {
                HStack(alignment: .top, spacing: 16) {
                    if !sys.extensionRows.isEmpty { ExtensionsTable(extensions: sys.extensionRows, title: "Extensions").frame(maxWidth: .infinity) }
                    if !sys.loginItemRows.isEmpty { openAtLogin(sys.loginItemRows).frame(width: 360) }
                }
            }
            if sys.isMac, !sys.kextRows.isEmpty { kernelExtensions(sys.kextRows) }
            if sys.isMac, !sys.helperRows.isEmpty { helpers(sys.helperRows) }
            if !sys.environment.isEmpty { environment(sys.environment) }
            JSONTreeView(value: device[.system], label: "device.modules.system")
        }
    }

    // MARK: Header and OS

    private func header(_ sys: SystemInfo) -> some View {
        let pending = sys.isMac ? sys.pendingAppleUpdates.count : sys.pendingWindowsUpdates.count
        return HStack {
            HStack(spacing: 12) {
                ZStack {
                    RoundedRectangle(cornerRadius: 10).fill(Color.purple.opacity(0.15))
                    Image(systemName: "gearshape").foregroundStyle(.purple).appFont(fixed: 20)
                }
                .frame(width: 44, height: 44)
                VStack(alignment: .leading, spacing: 2) {
                    Text("System Information").appFont(.title2, weight: .bold)
                    Text("Operating system and apps access").appFont(.callout).foregroundStyle(.secondary)
                }
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 4) {
                Text("Software Update").appFont(.caption).foregroundStyle(.secondary)
                if pending > 0 {
                    Label("\(pending) Pending Update\(pending == 1 ? "" : "s")", systemImage: "exclamationmark.triangle")
                        .appFont(.callout, weight: .medium).foregroundStyle(.yellow)
                        .padding(.horizontal, 12).padding(.vertical, 6).background(Color.yellow.opacity(0.15), in: Capsule())
                } else {
                    Label("Up to Date", systemImage: "checkmark.circle.fill")
                        .appFont(.callout, weight: .medium).foregroundStyle(.green)
                        .padding(.horizontal, 12).padding(.vertical, 6).background(Color.green.opacity(0.15), in: Capsule())
                }
            }
        }
    }

    private func tile(_ label: String, _ value: String, tone: Tone, big: Bool = true, mono: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label.uppercased()).appFont(.caption2, weight: .semibold).foregroundStyle(tone.color).kerning(0.5)
            Text(value).appFont(big ? .title3 : .callout, weight: .bold, design: mono ? .monospaced : .default).lineLimit(2).minimumScaleFactor(0.8)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.cardBorder))
    }

    private func osCard(_ sys: SystemInfo) -> some View {
        let os = sys.operatingSystem
        let label = OSNames.osLabel(name: os.name, isMac: sys.isMac)
        let marketing = sys.isMac ? OSNames.macOSMarketingName(version: os.version) : (os.displayVersion ?? "")
        return Card {
            VStack(spacing: 12) {
                HStack(spacing: 12) {
                    tile(label, marketing, tone: .purple)
                    tile("Version", OSNames.formattedVersion(sys.isMac ? os.displayVersion : os.version, isMac: sys.isMac), tone: .blue, mono: true)
                    if sys.isMac {
                        tile("Build", os.build ?? "Unknown", tone: .indigo, mono: true)
                    } else {
                        tile("Feature", os.featureUpdate ?? "Unknown", tone: .indigo)
                        VStack(alignment: .leading, spacing: 4) {
                            Text("EDITION").appFont(.caption2, weight: .semibold).foregroundStyle(Tone.violet.color).kerning(0.5)
                            Text(os.edition ?? "-").appFont(.title3, weight: .bold).lineLimit(2).minimumScaleFactor(0.8)
                            if let act = os.activation { Pill(act.isActivated == true ? "Activated" : "Not Activated", tone: act.isActivated == true ? .green : .red) }
                        }
                        .padding(12).frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 10))
                        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.cardBorder))
                    }
                }
                HStack(spacing: 12) {
                    tile("System Uptime", sys.uptime ?? "Unknown", tone: .emerald, big: false)
                    tile("Last Boot", sys.bootTime.map { "\(TimeFormatting.exact($0)) (\(TimeFormatting.relative($0)))" } ?? "Unknown", tone: .cyan, big: false)
                    tile("System Locale", os.locale ?? "Unknown", tone: .orange, big: false)
                    tile("Keyboard Layout", os.keyboardLayout ?? "-", tone: .pink, big: false)
                    tile("Time Zone", os.timeZone ?? "Unknown", tone: .teal, big: false)
                }
            }
            .padding(16)
        }
    }

    // MARK: Updates

    private func tableHeader(_ cols: [(String, CGFloat?)]) -> some View {
        HStack(spacing: 12) {
            ForEach(Array(cols.enumerated()), id: \.offset) { _, c in
                Text(c.0.uppercased()).appFont(.caption2, weight: .semibold).foregroundStyle(.secondary)
                    .frame(width: c.1, alignment: .leading)
                    .frame(maxWidth: c.1 == nil ? .infinity : nil, alignment: .leading)
            }
        }
        .padding(.horizontal, 16).padding(.vertical, 8)
        .background(Color.subtleBackground)
    }

    private func severityTone(_ s: String) -> Tone {
        switch s { case "Critical": return .red; case "Important": return .orange; case "Moderate": return .yellow; default: return .gray }
    }

    private func pendingWindowsUpdates(_ updates: [SystemInfo.PendingUpdate]) -> some View {
        Card {
            VStack(spacing: 0) {
                CardHeader("Pending Windows Updates", subtitle: "\(updates.count) update\(updates.count == 1 ? "" : "s") available for installation")
                tableHeader([("Update", nil), ("KB", 100), ("Category", 140), ("Severity", 90), ("CVEs", 200), ("Status", 130), ("Released", 100)])
                ForEach(updates) { u in
                    HStack(alignment: .top, spacing: 12) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(u.name).appFont(.callout, weight: .medium)
                            if let d = u.description, d != u.name { Text(d).appFont(.caption2).foregroundStyle(.secondary).lineLimit(1).help(d) }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        Group {
                            if let kb = u.kbNumber, let url = URL(string: "https://support.microsoft.com/help/\(kb.replacingOccurrences(of: "KB", with: ""))") {
                                Link(kb, destination: url).appFont(.caption, design: .monospaced)
                            } else { Text("-").foregroundStyle(.tertiary) }
                        }
                        .frame(width: 100, alignment: .leading)
                        Pill(u.category ?? "Update", tone: .blue).frame(width: 140, alignment: .leading)
                        Group { if let s = u.severity { Pill(s, tone: severityTone(s)) } else { Text("-").foregroundStyle(.tertiary) } }.frame(width: 90, alignment: .leading)
                        Group {
                            if u.cves.isEmpty { Text("-").foregroundStyle(.tertiary) } else {
                                FlowLayout(spacing: 4) {
                                    ForEach(u.cves.prefix(2), id: \.self) { cve in
                                        if let url = URL(string: "https://msrc.microsoft.com/update-guide/vulnerability/\(cve)") {
                                            Link(cve, destination: url).appFont(.caption2, design: .monospaced).foregroundStyle(.red)
                                        }
                                    }
                                    if u.cves.count > 2 { Pill("+\(u.cves.count - 2) more", tone: .gray).help(u.cves.dropFirst(2).joined(separator: ", ")) }
                                }
                            }
                        }
                        .frame(width: 200, alignment: .leading)
                        HStack(spacing: 4) {
                            Pill(u.isDownloaded ? "Downloaded" : "Pending", tone: u.isDownloaded ? .green : .gray)
                            if u.restartRequired { Pill("Reboot", tone: .yellow) }
                        }
                        .frame(width: 130, alignment: .leading)
                        Text(u.releaseDate.map { TimeFormatting.shortDate($0) } ?? "-").appFont(.caption).monospacedDigit().frame(width: 100, alignment: .leading)
                    }
                    .padding(.horizontal, 16).padding(.vertical, 8)
                    Divider()
                }
            }
        }
    }

    private func recentWindowsUpdates(_ updates: [SystemItems.InstalledUpdate]) -> some View {
        Card {
            VStack(spacing: 0) {
                CardHeader("Recent Windows Updates", subtitle: "Recently installed system updates")
                tableHeader([("Update", nil), ("Category", 160), ("Install Date", 110), ("Restart Required", 120)])
                ForEach(updates.prefix(10)) { u in
                    HStack(alignment: .top, spacing: 12) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(u.title ?? u.updateId).appFont(.callout, weight: .medium)
                            if u.title != nil, !u.updateId.isEmpty { Text(u.updateId).appFont(.caption, design: .monospaced).foregroundStyle(.secondary) }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        Pill(u.category ?? "Windows Update", tone: .blue).frame(width: 160, alignment: .leading)
                        Text(u.installDate.map { TimeFormatting.shortDate($0) } ?? "Unknown").appFont(.caption).frame(width: 110, alignment: .leading)
                        Pill(u.requiresRestart ? "Required" : "No", tone: u.requiresRestart ? .yellow : .green).frame(width: 120, alignment: .leading)
                    }
                    .padding(.horizontal, 16).padding(.vertical, 8)
                    Divider()
                }
            }
        }
    }

    private func macUpdates(_ sys: SystemInfo) -> some View {
        let pending = sys.pendingAppleUpdates
        let systemUpdates = Array(sys.installHistoryRows.filter(\.isSystemUpdate).prefix(10))
        return Card {
            VStack(spacing: 0) {
                CardHeader("macOS Updates", subtitle: pending.isEmpty ? "System software and security updates" : "\(pending.count) available system update\(pending.count == 1 ? "" : "s") from Apple")
                if !pending.isEmpty || !systemUpdates.isEmpty {
                    tableHeader([("Update", nil), ("Version", 140), ("Status", 200), ("Installed", 120)])
                    ForEach(pending) { u in
                        HStack(alignment: .top, spacing: 12) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(u.name).appFont(.callout, weight: .medium)
                                if let b = u.buildVersion { Text(b).appFont(.caption2, design: .monospaced).foregroundStyle(.secondary) }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            Text(u.version ?? "Unknown").appFont(.caption).frame(width: 140, alignment: .leading)
                            VStack(alignment: .leading, spacing: 3) {
                                if u.deferred { Pill("Deferred", tone: .orange) }
                                else if u.restartRequired { Pill("Restart Required", tone: .yellow) }
                                else { Pill("Pending", tone: .blue) }
                                if u.deferred, let until = u.deferredUntil { Text("Available \(TimeFormatting.shortDate(until))").appFont(.caption2).foregroundStyle(.orange) }
                                else if u.deferred, let offered = u.firstOfferedAt { Text("Offered \(TimeFormatting.shortDate(offered))").appFont(.caption2).foregroundStyle(.secondary) }
                            }
                            .frame(width: 200, alignment: .leading)
                            Color.clear.frame(width: 120, height: 1)
                        }
                        .padding(.horizontal, 16).padding(.vertical, 8)
                        Divider()
                    }
                    ForEach(systemUpdates) { item in
                        HStack(alignment: .top, spacing: 12) {
                            Text(item.packageId).appFont(.callout, weight: .medium, design: .monospaced).frame(maxWidth: .infinity, alignment: .leading)
                            Text(item.version ?? "Unknown").appFont(.caption).frame(width: 140, alignment: .leading)
                            Color.clear.frame(width: 200, height: 1)
                            Text(item.installDate.map { TimeFormatting.relative($0) } ?? "Unknown").appFont(.caption).foregroundStyle(.secondary).frame(width: 120, alignment: .trailing)
                        }
                        .padding(.horizontal, 16).padding(.vertical, 6)
                        Divider()
                    }
                }
            }
        }
    }

    private func installHistory(_ history: [SystemItems.InstallHistoryItem]) -> some View {
        let sorted = history.sorted { ($0.installDate ?? .distantPast) > ($1.installDate ?? .distantPast) }
        return Card {
            VStack(spacing: 0) {
                CardHeader("Install History", subtitle: "Packages installed in the last 90 days (\(history.count) packages)")
                tableHeader([("Install Date", 180), ("Package", nil), ("Version", 140)])
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(sorted) { item in
                            HStack(alignment: .top, spacing: 12) {
                                Text(item.installTime.map { TimeFormatting.exact($0) } ?? "Unknown").appFont(.caption).frame(width: 180, alignment: .leading)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(item.packageId).appFont(.callout, weight: .medium, design: .monospaced)
                                    if let f = item.packageFilename { Text(f).appFont(.caption2).foregroundStyle(.secondary) }
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                                Text(item.version ?? "Unknown").appFont(.caption).frame(width: 140, alignment: .leading)
                            }
                            .padding(.horizontal, 16).padding(.vertical, 8)
                            Divider()
                        }
                    }
                }
                .frame(maxHeight: 500)
            }
        }
    }

    // MARK: Stats

    private func stat(_ value: Int, _ label: String, tone: Tone) -> some View {
        Card {
            VStack(alignment: .leading, spacing: 4) {
                Text("\(value)").appFont(.title2, weight: .bold).foregroundStyle(tone.color)
                Text(label).appFont(.callout).foregroundStyle(.secondary)
            }
            .padding(16).frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func stats(_ sys: SystemInfo) -> some View {
        HStack(spacing: 12) {
            stat(sys.isMac ? sys.services.count + sys.scheduledTasks.count : sys.services.count, sys.isMac ? "Background Items" : "Total Services", tone: .blue)
            stat(sys.runningServiceCount, "Running", tone: .green)
            if !sys.isMac { stat(sys.installedUpdates.count, "Windows Updates", tone: .orange) }
            stat(sys.isMac ? sys.systemExtensions.count : sys.environment.count, sys.isMac ? "Extensions" : "Environment Vars", tone: .purple)
            stat(sys.isMac ? sys.loginItems.count : sys.scheduledTasks.count, sys.isMac ? "Open at Login" : "Scheduled Tasks", tone: .pink)
        }
    }

    // MARK: Mac lists

    private func openAtLogin(_ items: [SystemItems.LoginItem]) -> some View {
        Card {
            VStack(spacing: 0) {
                CardHeader("Open at Login", subtitle: "Applications that open automatically when you log in (\(items.count) items)")
                tableHeader([("Item", nil), ("Kind", 110)])
                ForEach(items) { item in
                    HStack(spacing: 12) {
                        HStack(spacing: 8) {
                            Image(systemName: "doc.text").foregroundStyle(.secondary).appFont(.caption)
                            Text(item.name).appFont(.callout, weight: .medium).lineLimit(1)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        Text(item.type).appFont(.caption).foregroundStyle(.secondary).frame(width: 110, alignment: .leading)
                    }
                    .padding(.horizontal, 16).padding(.vertical, 6)
                    Divider()
                }
            }
        }
    }

    private func kernelExtensions(_ kexts: [SystemItems.KernelExtension]) -> some View {
        Card {
            VStack(spacing: 0) {
                CardHeader("Kernel Extensions", subtitle: "Third-party kernel extensions (kexts) - \(kexts.count) loaded")
                tableHeader([("Name", nil), ("Version", 120), ("Size", 100), ("Status", 100)])
                ForEach(kexts) { k in
                    HStack(alignment: .top, spacing: 12) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(k.name).appFont(.callout, weight: .medium, design: .monospaced)
                            if let p = k.path { Text(p).appFont(.caption2).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle) }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        Text(k.version ?? "Unknown").appFont(.caption).frame(width: 120, alignment: .leading)
                        Text(k.size > 0 ? String(format: "%.1f KB", k.size / 1024) : "Unknown").appFont(.caption).frame(width: 100, alignment: .leading)
                        Pill(k.loaded ? "Loaded" : "Not Loaded", tone: k.loaded ? .green : .gray).frame(width: 100, alignment: .leading)
                    }
                    .padding(.horizontal, 16).padding(.vertical, 8)
                    Divider()
                }
            }
        }
    }

    private func helpers(_ tools: [SystemItems.HelperTool]) -> some View {
        let q = helperSearch.trimmingCharacters(in: .whitespaces).lowercased()
        let filtered = q.isEmpty ? tools : tools.filter { h in
            h.name.lowercased().contains(q) || (h.bundleIdentifier ?? "").lowercased().contains(q) || (h.teamId ?? "").lowercased().contains(q) || (h.path ?? "").lowercased().contains(q)
        }
        return Card {
            VStack(spacing: 0) {
                CardHeader("Privileged Helper Tools", subtitle: "Background services installed by applications (\(filtered.count) of \(tools.count) tools)") {
                    TextField("Search helpers...", text: $helperSearch).textFieldStyle(.roundedBorder).frame(width: 220)
                }
                tableHeader([("Name", nil), ("Team ID", 140), ("Signed", 90), ("Bundle ID", 260)])
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(filtered) { h in
                            HStack(alignment: .top, spacing: 12) {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(h.name).appFont(.callout, weight: .medium)
                                    if let p = h.path { Text(p).appFont(.caption2, design: .monospaced).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle) }
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                                HStack(spacing: 6) {
                                    Text(h.teamId ?? "Unknown").appFont(.caption, design: .monospaced)
                                    if let t = h.teamId, t != "Unknown" { CopyButton(value: t) }
                                }
                                .frame(width: 140, alignment: .leading)
                                Pill(h.signed ? "Signed" : "Unsigned", tone: h.signed ? .green : .yellow).frame(width: 90, alignment: .leading)
                                Text(h.bundleIdentifier ?? "Unknown").appFont(.caption, design: .monospaced).foregroundStyle(.secondary).frame(width: 260, alignment: .leading).lineLimit(1).truncationMode(.middle)
                            }
                            .padding(.horizontal, 16).padding(.vertical, 8)
                            Divider()
                        }
                    }
                }
                .frame(maxHeight: 416)
            }
        }
    }

    // MARK: Environment

    private func environment(_ env: [(name: String, value: String)]) -> some View {
        let sorted = env.sorted { a, b in
            let an = a.name.lowercased(), bn = b.name.lowercased()
            if an == "path" { return true }
            if bn == "path" { return false }
            if an == "hosts_file" { return true }
            if bn == "hosts_file" { return false }
            return a.name < b.name
        }
        return Card {
            VStack(spacing: 0) {
                CardHeader("Environment Variables", subtitle: "System environment variables")
                tableHeader([("Variable", 200), ("Value", nil)])
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(Array(sorted.enumerated()), id: \.offset) { _, e in
                            let lower = e.name.lowercased()
                            HStack(alignment: .top, spacing: 12) {
                                Text(e.name).appFont(.callout, weight: .medium, design: .monospaced).frame(width: 200, alignment: .leading).lineLimit(1)
                                Group {
                                    if lower == "path" {
                                        let parts = e.value.split(separator: e.value.contains(";") ? ";" : ":").map(String.init).filter { !$0.isEmpty }
                                        EnvDisclosure(title: "\(parts.count) paths", text: parts.joined(separator: "\n"))
                                    } else if lower == "hosts_file" {
                                        EnvDisclosure(title: "hosts file", text: e.value)
                                    } else {
                                        Text(e.value).appFont(.caption, design: .monospaced).textSelection(.enabled)
                                    }
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                            }
                            .padding(.horizontal, 16).padding(.vertical, 8)
                            Divider()
                        }
                    }
                }
                .frame(maxHeight: 400)
            }
        }
    }
}

/// PATH and hosts file expand into a monospaced block, open by default.
struct EnvDisclosure: View {
    let title: String
    let text: String
    @State private var open = true
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Button { open.toggle() } label: {
                HStack(spacing: 4) {
                    Text(title).appFont(.callout).foregroundStyle(.blue)
                    Image(systemName: "chevron.right").rotationEffect(.degrees(open ? 90 : 0)).appFont(.caption2).foregroundStyle(.blue)
                }
            }
            .buttonStyle(.plain)
            if open {
                Text(text).appFont(.caption2, design: .monospaced).textSelection(.enabled)
                    .padding(10).frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 8))
            }
        }
    }
}

// MARK: - Launchd table

/// macOS launchd daemons and agents, Lingon-style. Port of `LaunchdTable.tsx`.
struct LaunchdTable: View {
    let items: [SystemItems.Service]
    var title = "Background Activity"
    var defaultScope: SystemItems.LaunchdScope = .system

    @State private var search = ""
    @State private var scope: SystemItems.LaunchdScope
    @State private var typeFilter: SystemItems.LaunchdKind? = nil
    @State private var statusFilter: SystemItems.LaunchdStatus? = nil
    @State private var expanded: Set<String> = []

    init(items: [SystemItems.Service], title: String = "Background Activity", defaultScope: SystemItems.LaunchdScope = .system) {
        self.items = items
        self.title = title
        self.defaultScope = defaultScope
        _scope = State(initialValue: defaultScope)
    }

    private var scopeFiltered: [SystemItems.Service] { scope == .all ? items : items.filter { SystemItems.scope(of: $0) == scope } }

    private var filtered: [SystemItems.Service] {
        var list = items
        let q = search.trimmingCharacters(in: .whitespaces).lowercased()
        if !q.isEmpty {
            list = list.filter { i in
                i.name.lowercased().contains(q) || (i.label ?? "").lowercased().contains(q) || i.path.lowercased().contains(q) || (i.program ?? "").lowercased().contains(q) || i.status.lowercased().contains(q)
            }
        }
        if scope != .all { list = list.filter { SystemItems.scope(of: $0) == scope } }
        if let typeFilter { list = list.filter { SystemItems.kind(of: $0) == typeFilter } }
        if let statusFilter { list = list.filter { SystemItems.launchdStatus(of: $0) == statusFilter } }
        return list
    }

    var body: some View {
        let counts = (
            daemon: scopeFiltered.filter { SystemItems.kind(of: $0) == .daemon }.count,
            agent: scopeFiltered.filter { SystemItems.kind(of: $0) == .agent }.count,
            running: scopeFiltered.filter { SystemItems.launchdStatus(of: $0) == .running }.count,
            stopped: scopeFiltered.filter { SystemItems.launchdStatus(of: $0) == .stopped }.count,
            disabled: scopeFiltered.filter { SystemItems.launchdStatus(of: $0) == .disabled }.count
        )
        let rows = filtered
        Card {
            VStack(spacing: 0) {
                HStack(spacing: 10) {
                    Text(title).appFont(.title3, weight: .semibold)
                    Spacer()
                    Picker("Scope", selection: $scope) {
                        ForEach(SystemItems.LaunchdScope.allCases, id: \.self) { s in
                            Text("\(s.label) (\(s == .all ? items.count : items.filter { SystemItems.scope(of: $0) == s }.count))").tag(s)
                        }
                    }
                    .labelsHidden().frame(width: 220)
                    HStack(spacing: 0) {
                        segment("Daemons (\(counts.daemon))", selected: typeFilter == .daemon, tone: .purple) { typeFilter = typeFilter == .daemon ? nil : .daemon }
                        Divider().frame(height: 22)
                        segment("Agents (\(counts.agent))", selected: typeFilter == .agent, tone: .blue) { typeFilter = typeFilter == .agent ? nil : .agent }
                    }
                    .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.cardBorder))
                    HStack(spacing: 0) {
                        if counts.running > 0 { segment("Running (\(counts.running))", selected: statusFilter == .running, tone: .green) { statusFilter = statusFilter == .running ? nil : .running } }
                        if counts.stopped > 0 { Divider().frame(height: 22); segment("Stopped (\(counts.stopped))", selected: statusFilter == .stopped, tone: .yellow) { statusFilter = statusFilter == .stopped ? nil : .stopped } }
                        if counts.disabled > 0 { Divider().frame(height: 22); segment("Disabled (\(counts.disabled))", selected: statusFilter == .disabled, tone: .gray) { statusFilter = statusFilter == .disabled ? nil : .disabled } }
                    }
                    .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.cardBorder))
                    TextField("Search by name or path...", text: $search).textFieldStyle(.roundedBorder).frame(width: 200)
                }
                .padding(16)
                Divider()
                HStack(spacing: 12) {
                    Color.clear.frame(width: 14)
                    Text("LABEL / NAME").frame(maxWidth: .infinity, alignment: .leading)
                    Text("TYPE").frame(width: 130, alignment: .leading)
                    Text("STATUS").frame(width: 140, alignment: .leading)
                    Text("RUN AT LOAD").frame(width: 90)
                    Text("KEEP ALIVE").frame(width: 90)
                }
                .appFont(.caption2, weight: .semibold).foregroundStyle(.secondary)
                .padding(.horizontal, 16).padding(.vertical, 8)
                .background(Color.subtleBackground)
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(rows) { item in
                            launchdRow(item)
                            Divider()
                        }
                        if rows.isEmpty, !search.isEmpty {
                            Text("No items found matching “\(search)”").appFont(.callout).foregroundStyle(.secondary).padding(24)
                        }
                    }
                }
                .frame(maxHeight: 600)
            }
        }
    }

    private func segment(_ text: String, selected: Bool, tone: Tone, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(text).appFont(.caption, weight: .medium)
                .padding(.horizontal, 10).padding(.vertical, 6)
                .background(selected ? tone.color : Color.clear)
                .foregroundStyle(selected ? Color.white : Color.primary)
        }
        .buttonStyle(.plain)
    }

    private func launchdRow(_ item: SystemItems.Service) -> some View {
        let open = expanded.contains(item.id)
        let hasPlist = item.plistContent != nil
        let status = SystemItems.launchdStatus(of: item)
        let kind = SystemItems.kind(of: item)
        return VStack(spacing: 0) {
            Button {
                guard hasPlist else { return }
                if open { expanded.remove(item.id) } else { expanded.insert(item.id) }
            } label: {
                HStack(spacing: 12) {
                    Group {
                        if hasPlist { Image(systemName: "chevron.right").rotationEffect(.degrees(open ? 90 : 0)).foregroundStyle(.blue).appFont(.caption2) } else { Color.clear }
                    }
                    .frame(width: 14)
                    HStack(spacing: 6) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(item.label ?? item.name).appFont(.callout, weight: .medium).lineLimit(1)
                            Text(item.path.isEmpty ? (item.program ?? "") : item.path).appFont(.caption2, design: .monospaced).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                        }
                        if hasPlist { Pill("plist", tone: .blue).help("Click to view plist configuration") }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    HStack(spacing: 4) {
                        Pill(kind == .daemon ? "Daemon" : "Agent", tone: kind == .daemon ? .purple : .blue)
                        if SystemItems.scope(of: item) == .apple { Pill("Apple", tone: .gray) }
                    }
                    .frame(width: 130, alignment: .leading)
                    VStack(alignment: .leading, spacing: 3) {
                        if item.managedByProfile { Pill("Managed", tone: .indigo).help(item.profileIdentifier ?? "Managed by MDM Profile") }
                        switch status {
                        case .disabled: Pill("Disabled", tone: .gray)
                        case .running: Pill("Running", tone: .green)
                        case .stopped: Pill("Stopped", tone: .yellow)
                        }
                    }
                    .frame(width: 140, alignment: .leading)
                    check(item.runAtLoad).frame(width: 90)
                    check(item.keepAlive).frame(width: 90)
                }
                .padding(.horizontal, 16).padding(.vertical, 8)
                .background(open ? Color.blue.opacity(0.06) : Color.clear)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            if open, let plist = item.plistContent {
                HStack(alignment: .top, spacing: 12) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 8).fill(Color.blue.opacity(0.15))
                        Image(systemName: "doc.text").foregroundStyle(.blue).appFont(.caption)
                    }
                    .frame(width: 32, height: 32)
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Plist Configuration").appFont(.callout, weight: .medium)
                        ScrollView {
                            Text(JSONValue.parse(plist)?.prettyPrinted ?? plist).appFont(.caption2, design: .monospaced).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .frame(maxHeight: 400)
                        .padding(10)
                        .background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 8))
                    }
                }
                .padding(16)
                .background(Color.subtleBackground.opacity(0.6))
            }
        }
    }

    private func check(_ on: Bool) -> some View {
        Image(systemName: on ? "checkmark.circle.fill" : "xmark.circle.fill").foregroundStyle(on ? Color.green : Color.secondary.opacity(0.3))
    }
}

// MARK: - Scheduled tasks

/// Windows scheduled tasks with source, status and search filters. Port of `ScheduledTasksTable.tsx`.
struct ScheduledTasksTable: View {
    let tasks: [SystemItems.ScheduledTask]
    enum StatusFilter: String, CaseIterable { case all, enabled, disabled, running, ready, error
        var label: String {
            switch self {
            case .all: return "All Tasks"
            case .enabled: return "Enabled Only"
            case .disabled: return "Disabled Only"
            case .running: return "Running"
            case .ready: return "Ready"
            case .error: return "Error"
            }
        }
    }
    @State private var search = ""
    @State private var statusFilter: StatusFilter = .all
    @State private var sourceFilter: SystemItems.WindowsSource? = nil

    private func isError(_ t: SystemItems.ScheduledTask) -> Bool { t.status.lowercased().contains("error") || t.state.lowercased().contains("error") }

    private func count(_ f: StatusFilter) -> Int {
        switch f {
        case .all: return tasks.count
        case .enabled: return tasks.filter(\.enabled).count
        case .disabled: return tasks.filter { !$0.enabled }.count
        case .running: return tasks.filter { $0.state.lowercased().contains("running") }.count
        case .ready: return tasks.filter { $0.state.lowercased().contains("ready") }.count
        case .error: return tasks.filter(isError).count
        }
    }

    private var filtered: [SystemItems.ScheduledTask] {
        var list = tasks
        let q = search.trimmingCharacters(in: .whitespaces).lowercased()
        if !q.isEmpty {
            list = list.filter { t in t.name.lowercased().contains(q) || t.path.lowercased().contains(q) || t.action.lowercased().contains(q) || t.state.lowercased().contains(q) || t.status.lowercased().contains(q) }
        }
        if let sourceFilter { list = list.filter { SystemItems.classifyTaskPath($0.path) == sourceFilter } }
        switch statusFilter {
        case .all: break
        case .enabled: list = list.filter(\.enabled)
        case .disabled: list = list.filter { !$0.enabled }
        case .running: list = list.filter { $0.state.lowercased().contains("running") }
        case .ready: list = list.filter { $0.state.lowercased().contains("ready") }
        case .error: list = list.filter(isError)
        }
        return list
    }

    var body: some View {
        let rows = filtered
        let builtIn = tasks.filter { SystemItems.classifyTaskPath($0.path) == .windows }.count
        Card {
            VStack(spacing: 0) {
                HStack(spacing: 10) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Scheduled Tasks").appFont(.title3, weight: .semibold)
                        Text("Windows scheduled tasks and their execution status (\(rows.count) of \(tasks.count) tasks)").appFont(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    HStack(spacing: 4) {
                        FilterPill(text: "All (\(tasks.count))", selected: sourceFilter == nil) { sourceFilter = nil }
                        FilterPill(text: "Windows (\(builtIn))", selected: sourceFilter == .windows) { sourceFilter = .windows }
                        FilterPill(text: "Third-party (\(tasks.count - builtIn))", selected: sourceFilter == .thirdParty) { sourceFilter = .thirdParty }
                    }
                    Picker("Status", selection: $statusFilter) {
                        ForEach(StatusFilter.allCases, id: \.self) { f in Text("\(f.label) (\(count(f)))").tag(f) }
                    }
                    .labelsHidden().frame(width: 180)
                    TextField("Search tasks...", text: $search).textFieldStyle(.roundedBorder).frame(width: 180)
                }
                .padding(16)
                Divider()
                HStack(spacing: 12) {
                    Text("TASK NAME").frame(width: 200, alignment: .leading)
                    Text("ACTION").frame(maxWidth: .infinity, alignment: .leading)
                    Text("ENABLED").frame(width: 80, alignment: .leading)
                    Text("STATUS").frame(width: 80, alignment: .leading)
                    Text("LAST RUN").frame(width: 130, alignment: .leading)
                    Text("NEXT RUN").frame(width: 130, alignment: .leading)
                    Text("RESULT").frame(width: 140, alignment: .leading)
                }
                .appFont(.caption2, weight: .semibold).foregroundStyle(.secondary)
                .padding(.horizontal, 16).padding(.vertical, 8)
                .background(Color.subtleBackground)
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(rows) { t in
                            HStack(alignment: .top, spacing: 12) {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(t.name).appFont(.callout, weight: .medium).lineLimit(1)
                                    Text(t.path).appFont(.caption2, design: .monospaced).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                                    if t.hidden { Pill("Hidden", tone: .gray) }
                                }
                                .frame(width: 200, alignment: .leading)
                                ScrollView {
                                    Text(t.action.isEmpty ? "No action specified" : t.action).appFont(.caption2, design: .monospaced).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                                }
                                .frame(maxHeight: 80)
                                .padding(6)
                                .background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 6))
                                .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.cardBorder))
                                Pill(t.enabled ? "Enabled" : "Disabled", tone: t.enabled ? .green : .gray).frame(width: 80, alignment: .leading)
                                taskStatus(t).frame(width: 80, alignment: .leading)
                                Text(t.lastRunTime.map { TimeFormatting.exact($0) } ?? "Never").appFont(.caption2).frame(width: 130, alignment: .leading)
                                Text(t.nextRunTime.map { TimeFormatting.exact($0) } ?? "Not scheduled").appFont(.caption2).frame(width: 130, alignment: .leading)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(t.lastRunCode.isEmpty ? "N/A" : t.lastRunCode).appFont(.caption2)
                                    if !t.lastRunMessage.isEmpty { Text(t.lastRunMessage).appFont(.caption2).foregroundStyle(.secondary).lineLimit(3).help(t.lastRunMessage) }
                                }
                                .frame(width: 140, alignment: .leading)
                            }
                            .padding(.horizontal, 16).padding(.vertical, 8)
                            Divider()
                        }
                        if rows.isEmpty, !search.isEmpty || sourceFilter != nil || statusFilter != .all {
                            Text("No scheduled tasks match the current filters").appFont(.callout).foregroundStyle(.secondary).padding(24)
                        }
                    }
                }
                .frame(maxHeight: 400)
            }
        }
    }

    @ViewBuilder
    private func taskStatus(_ t: SystemItems.ScheduledTask) -> some View {
        if !t.enabled {
            Color.clear.frame(height: 1)
        } else {
            let s = (t.status.isEmpty ? t.state : t.status).lowercased()
            if s.contains("running") { Pill("Running", tone: .blue) }
            else if s.contains("ready") { Pill("Ready", tone: .green) }
            else if s.contains("error") || s.contains("failed") { Pill("Error", tone: .red) }
            else { Pill(s.isEmpty ? "Unknown" : (t.status.isEmpty ? t.state : t.status), tone: .yellow) }
        }
    }
}

// MARK: - Windows services

/// Windows services with status, source and search filters. The Services card in `SystemTab.tsx`.
struct WindowsServicesTable: View {
    let services: [SystemItems.Service]
    enum Status: String { case all, running, stopped }
    @State private var search = ""
    @State private var status: Status = .all
    @State private var source: SystemItems.WindowsSource? = nil

    private var filtered: [SystemItems.Service] {
        let q = search.trimmingCharacters(in: .whitespaces).lowercased()
        return services.filter { s in
            if status == .running, !s.isRunning { return false }
            if status == .stopped, s.isRunning { return false }
            if let source, SystemItems.classifyServicePath(s.path) != source { return false }
            if q.isEmpty { return true }
            return s.name.lowercased().contains(q) || s.displayName.lowercased().contains(q) || s.description.lowercased().contains(q) || s.path.lowercased().contains(q) || s.status.lowercased().contains(q)
        }
    }

    var body: some View {
        let rows = filtered
        let running = services.filter(\.isRunning).count
        let builtIn = services.filter { SystemItems.classifyServicePath($0.path) == .windows }.count
        Card {
            VStack(spacing: 0) {
                HStack(spacing: 10) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Windows Services").appFont(.title3, weight: .semibold)
                        Text("System services and their status (\(rows.count) of \(services.count) services)").appFont(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    HStack(spacing: 4) {
                        FilterPill(text: "All (\(services.count))", selected: status == .all) { status = .all }
                        FilterPill(text: "Running (\(running))", selected: status == .running, tone: .green) { status = .running }
                        FilterPill(text: "Stopped (\(services.count - running))", selected: status == .stopped, tone: .red) { status = .stopped }
                    }
                    HStack(spacing: 4) {
                        FilterPill(text: "All (\(services.count))", selected: source == nil) { source = nil }
                        FilterPill(text: "Windows (\(builtIn))", selected: source == .windows) { source = .windows }
                        FilterPill(text: "Third-party (\(services.count - builtIn))", selected: source == .thirdParty) { source = .thirdParty }
                    }
                    TextField("Search services...", text: $search).textFieldStyle(.roundedBorder).frame(width: 180)
                }
                .padding(16)
                Divider()
                HStack(spacing: 12) {
                    Text("SERVICE").frame(width: 260, alignment: .leading)
                    Text("STATUS").frame(width: 100, alignment: .leading)
                    Text("START TYPE").frame(width: 140, alignment: .leading)
                    Text("DESCRIPTION").frame(maxWidth: .infinity, alignment: .leading)
                }
                .appFont(.caption2, weight: .semibold).foregroundStyle(.secondary)
                .padding(.horizontal, 16).padding(.vertical, 8)
                .background(Color.subtleBackground)
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(rows) { s in
                            HStack(alignment: .top, spacing: 12) {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(s.displayName.isEmpty ? s.name : s.displayName).appFont(.callout, weight: .medium).lineLimit(1)
                                    if !s.displayName.isEmpty, s.displayName != s.name { Text(s.name).appFont(.caption2, design: .monospaced).foregroundStyle(.secondary).lineLimit(1) }
                                }
                                .frame(width: 260, alignment: .leading)
                                Pill(s.status, tone: s.isRunning ? .green : .red).frame(width: 100, alignment: .leading)
                                Text(s.startType ?? "Unknown").appFont(.caption).frame(width: 140, alignment: .leading)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(s.description.isEmpty ? "No description available" : s.description).appFont(.caption).lineLimit(1).help(s.description)
                                    if !s.path.isEmpty { Text(s.path).appFont(.caption2, design: .monospaced).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle).help(s.path) }
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                            }
                            .padding(.horizontal, 16).padding(.vertical, 8)
                            Divider()
                        }
                        if rows.isEmpty, !search.isEmpty || status != .all || source != nil {
                            Text("No services found matching “\(search)”").appFont(.callout).foregroundStyle(.secondary).padding(24)
                        }
                    }
                }
                .frame(maxHeight: 400)
            }
        }
    }
}

// MARK: - Extensions

/// macOS extensions grouped by app or by category, as System Settings does. Port of `ExtensionsTable.tsx`.
struct ExtensionsTable: View {
    let extensions: [SystemItems.Extension]
    var title = "Extensions"
    enum ViewMode { case byApp, byCategory }
    @State private var mode: ViewMode = .byCategory
    @State private var search = ""
    @State private var statusFilter: SystemItems.Extension.Status = .all
    @State private var expanded: Set<String> = []

    private var statusFiltered: [SystemItems.Extension] {
        statusFilter == .all ? extensions : extensions.filter { $0.normalizedState.status == statusFilter }
    }

    private var byApp: [(key: String, items: [SystemItems.Extension])] {
        let q = search.trimmingCharacters(in: .whitespaces).lowercased()
        let groups = Dictionary(grouping: statusFiltered, by: \.resolvedAppName).sorted { $0.key < $1.key }
        if q.isEmpty { return groups.map { ($0.key, $0.value) } }
        return groups.compactMap { app, exts in
            let kept = exts.filter { $0.identifier.lowercased().contains(q) || app.lowercased().contains(q) || $0.resolvedCategory.lowercased().contains(q) }
            return kept.isEmpty ? nil : (app, kept)
        }
    }

    private var byCategory: [(key: String, items: [SystemItems.Extension])] {
        let q = search.trimmingCharacters(in: .whitespaces).lowercased()
        let groups = Dictionary(grouping: statusFiltered, by: \.resolvedCategory)
        let ordered = SystemItems.Extension.categories.compactMap { cat in groups[cat].map { (cat, $0) } }
        if q.isEmpty { return ordered }
        return ordered.compactMap { cat, exts in
            let kept = exts.filter { $0.identifier.lowercased().contains(q) || $0.resolvedAppName.lowercased().contains(q) || cat.lowercased().contains(q) }
            return kept.isEmpty ? nil : (cat, kept)
        }
    }

    var body: some View {
        let enabled = extensions.filter { $0.normalizedState.status == .enabled }.count
        let waiting = extensions.filter { $0.normalizedState.status == .waiting }.count
        let disabled = extensions.filter { $0.normalizedState.status == .disabled }.count
        let groups = mode == .byCategory ? byCategory : byApp
        Card {
            VStack(spacing: 0) {
                VStack(alignment: .leading, spacing: 10) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(title).appFont(.title3, weight: .semibold)
                        Text("Extensions add extra functionality to your Mac and apps, and some may run in the background.").appFont(.caption).foregroundStyle(.secondary)
                    }
                    HStack(spacing: 10) {
                        Picker("View", selection: $mode) {
                            Text("By App").tag(ViewMode.byApp)
                            Text("By Category").tag(ViewMode.byCategory)
                        }
                        .pickerStyle(.segmented).labelsHidden().frame(width: 200)
                        Divider().frame(height: 20)
                        if enabled > 0 { FilterPill(text: "Enabled (\(enabled))", selected: statusFilter == .enabled, tone: .green) { statusFilter = statusFilter == .enabled ? .all : .enabled } }
                        if waiting > 0 { FilterPill(text: "Waiting for User Action (\(waiting))", selected: statusFilter == .waiting, tone: .yellow) { statusFilter = statusFilter == .waiting ? .all : .waiting } }
                        if disabled > 0 { FilterPill(text: "Disabled (\(disabled))", selected: statusFilter == .disabled, tone: .gray) { statusFilter = statusFilter == .disabled ? .all : .disabled } }
                        TextField("Search...", text: $search).textFieldStyle(.roundedBorder).frame(width: 160)
                    }
                }
                .padding(16)
                Divider()
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(groups, id: \.key) { group in
                            let key = (mode == .byCategory ? "cat-" : "app-") + group.key
                            let open = expanded.contains(key)
                            Button {
                                if open { expanded.remove(key) } else { expanded.insert(key) }
                            } label: {
                                HStack(spacing: 12) {
                                    ZStack {
                                        RoundedRectangle(cornerRadius: 8).fill(Color.subtleBackground)
                                        Image(systemName: mode == .byCategory ? categoryIcon(group.key) : "square.grid.2x2").foregroundStyle(.secondary)
                                    }
                                    .frame(width: 32, height: 32)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(group.key).appFont(.callout, weight: .medium)
                                        if mode == .byCategory {
                                            let apps = unique(group.items.map(\.resolvedAppName))
                                            Text(apps.prefix(3).joined(separator: ", ") + (group.items.count > 3 ? " and \(group.items.count - 3) more." : "")).appFont(.caption).foregroundStyle(.secondary).lineLimit(1)
                                        } else {
                                            Text("\(group.items.count) extension\(group.items.count == 1 ? "" : "s") • \(unique(group.items.map(\.resolvedCategory)).joined(separator: ", "))").appFont(.caption).foregroundStyle(.secondary).lineLimit(1)
                                        }
                                    }
                                    Spacer()
                                    Image(systemName: "chevron.down").rotationEffect(.degrees(open ? 180 : 0)).foregroundStyle(.secondary)
                                }
                                .padding(.horizontal, 16).padding(.vertical, 10)
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            if open {
                                VStack(spacing: 6) {
                                    ForEach(group.items) { ext in
                                        let state = ext.normalizedState
                                        HStack(alignment: .top, spacing: 10) {
                                            Pill(state.label, tone: state.status == .enabled ? .green : state.status == .waiting ? .yellow : .gray)
                                            VStack(alignment: .leading, spacing: 2) {
                                                Text(mode == .byCategory ? ext.resolvedAppName : ext.resolvedCategory).appFont(.callout, weight: .medium).lineLimit(1)
                                                Text(ext.identifier).appFont(.caption2, design: .monospaced).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                                            }
                                            Spacer()
                                            if ext.managedByProfile { Pill("Managed", tone: .indigo).help(ext.profileIdentifier ?? "Managed by MDM Profile") }
                                        }
                                        .padding(8)
                                        .background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 8))
                                    }
                                }
                                .padding(.leading, 60).padding(.trailing, 16).padding(.bottom, 12)
                            }
                            Divider()
                        }
                        if groups.isEmpty, !search.isEmpty {
                            Text("No extensions found matching “\(search)”").appFont(.callout).foregroundStyle(.secondary).padding(24)
                        }
                    }
                }
                .frame(minHeight: 200, maxHeight: 800)
            }
        }
        .onChange(of: search) { if !search.trimmingCharacters(in: .whitespaces).isEmpty { expandAll() } }
        .onChange(of: statusFilter) { if statusFilter == .waiting { expandAll() } }
        .onChange(of: mode) { if statusFilter == .waiting || !search.trimmingCharacters(in: .whitespaces).isEmpty { expandAll() } }
    }

    private func expandAll() {
        let groups = mode == .byCategory ? byCategory : byApp
        expanded = Set(groups.map { (mode == .byCategory ? "cat-" : "app-") + $0.key })
    }

    private func unique(_ list: [String]) -> [String] {
        var seen = Set<String>(); var out: [String] = []
        for s in list where !seen.contains(s) { seen.insert(s); out.append(s) }
        return out
    }

    private func categoryIcon(_ category: String) -> String {
        switch category {
        case "Actions": return "bolt"
        case "Network Extensions": return "globe"
        case "Endpoint Security Extensions": return "checkmark.shield"
        case "Driver Extensions": return "cpu"
        case "File Providers": return "folder"
        case "Quick Look": return "eye"
        case "Sharing": return "square.and.arrow.up"
        case "Spotlight": return "magnifyingglass"
        default: return "square.grid.2x2"
        }
    }
}
