import SwiftUI
import ReportMateKit

/// Installed applications with usage: stat cards, most-used list, and the
/// searchable table with usage filter pills.
struct ApplicationsTabView: View {
    let device: DeviceDetail
    @State private var usageFilter: ApplicationUsageFilter = .all
    @State private var hideNested = true
    @State private var search = ""
    @State private var visibleCount = 50

    var body: some View {
        let info = ApplicationsInfo(modules: device.asJSON["modules"])
        VStack(alignment: .leading, spacing: 16) {
            header(info)
            if !info.hasData {
                Card { EmptyStateView(title: "No applications reported", message: "The applications module has not reported an inventory for this device.", systemImage: "app.badge") }
            } else {
                stats(info)
                if !info.topApps.isEmpty { mostUsed(info) }
                table(info)
            }
            JSONTreeView(value: device[.applications], label: "device.modules.applications")
        }
    }

    private func header(_ info: ApplicationsInfo) -> some View {
        HStack {
            HStack(spacing: 12) {
                ZStack {
                    RoundedRectangle(cornerRadius: 10).fill(Color.blue.opacity(0.15))
                    Image(systemName: "app.badge").foregroundStyle(.blue).appFont(fixed: 20)
                }
                .frame(width: 44, height: 44)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Applications").appFont(.title2, weight: .bold)
                    Text("Versions installed and how much each is used").appFont(.callout).foregroundStyle(.secondary)
                }
            }
            Spacer()
            if !info.applications.isEmpty {
                VStack(alignment: .trailing, spacing: 2) {
                    Text("Applications").appFont(.caption).foregroundStyle(.secondary)
                    Text(ByteFormatting.count(info.baseApps.count)).appFont(.title2, weight: .bold).foregroundStyle(.blue)
                    if info.nestedCount > 0 { Text("+\(ByteFormatting.count(info.nestedCount)) bundled helpers").appFont(.caption2).foregroundStyle(.tertiary) }
                }
            }
        }
    }

    private func stats(_ info: ApplicationsInfo) -> some View {
        let days = info.historyDays
        let sessions = info.activeSessionCount
        return HStack(spacing: 14) {
            statCard("Used", ByteFormatting.count(info.usedApps.count), days > 0 ? "across \(days) day\(days > 1 ? "s" : "") of history" : "in the current capture window")
            statCard("Running now", ByteFormatting.count(info.runningApps.count), sessions > 0 ? "\(ByteFormatting.count(sessions)) session\(sessions == 1 ? "" : "s") in the capture window" : nil)
            statCard("Time in apps", ApplicationsInfo.formatDuration(info.totalUsageSeconds), "process lifetime, summed")
            statCard("People", ByteFormatting.count(info.distinctUsers), info.distinctUsers == 1 ? "one account seen" : "accounts seen in usage")
        }
    }

    private func statCard(_ label: String, _ value: String, _ hint: String?) -> some View {
        Card {
            VStack(alignment: .leading, spacing: 2) {
                Text(label).appFont(.callout).foregroundStyle(.secondary)
                Text(value).appFont(.title2, weight: .semibold).monospacedDigit()
                if let hint { Text(hint).appFont(.caption2).foregroundStyle(.tertiary) }
            }
            .padding(.horizontal, 16).padding(.vertical, 12)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func mostUsed(_ info: ApplicationsInfo) -> some View {
        let top = info.topApps
        let maxSeconds = top.first?.usageSeconds ?? 0
        return Card {
            VStack(spacing: 0) {
                CardHeader("Most used")
                ForEach(top) { app in
                    let seconds = app.usageSeconds
                    let share = maxSeconds > 0 ? max(0.02, seconds / maxSeconds) : 0
                    VStack(alignment: .leading, spacing: 6) {
                        HStack(alignment: .firstTextBaseline, spacing: 8) {
                            if app.isRunning { Circle().fill(Color.green).frame(width: 8, height: 8).help("Running now") }
                            Text(app.cleanName).appFont(.body, weight: .medium).lineLimit(1)
                            if app.version != "Unknown" { Text(app.version).appFont(.caption, design: .monospaced).foregroundStyle(.secondary) }
                            Spacer()
                            HStack(spacing: 14) {
                                Text(ApplicationsInfo.formatDuration(seconds)).appFont(.body).monospacedDigit()
                                Text("\(ByteFormatting.count(app.usage?.launchCount ?? 0)) launch\((app.usage?.launchCount ?? 0) == 1 ? "" : "es")").appFont(.caption).foregroundStyle(.secondary)
                                if let u = app.usage?.uniqueUserCount, u > 0 { Text("\(u) user\(u > 1 ? "s" : "")").appFont(.caption).foregroundStyle(.secondary) }
                                if let last = app.usage?.lastUsed { Text(TimeFormatting.relative(last)).appFont(.caption).foregroundStyle(.secondary) }
                            }
                        }
                        GeometryReader { geo in
                            ZStack(alignment: .leading) {
                                Capsule().fill(Color.secondary.opacity(0.12))
                                Capsule().fill(Color.blue.opacity(0.7)).frame(width: geo.size.width * share)
                            }
                        }
                        .frame(height: 6)
                    }
                    .padding(.horizontal, 16).padding(.vertical, 8)
                    Divider().padding(.leading, 16)
                }
            }
        }
    }

    private func table(_ info: ApplicationsInfo) -> some View {
        let base = ApplicationsInfo.deduplicate(info.filtered(usageFilter, hideNested: hideNested))
        let rows = ApplicationsInfo.search(base, query: search)
        let maxSeconds = rows.map(\.usageSeconds).max() ?? 0
        let visible = Array(rows.prefix(visibleCount))
        return Card {
            VStack(spacing: 0) {
                HStack(spacing: 12) {
                    HStack(spacing: 0) {
                        ForEach(ApplicationUsageFilter.allCases) { f in
                            let count: Int = {
                                switch f {
                                case .all: return hideNested ? info.baseApps.count : info.applications.count
                                case .used: return info.usedApps.count
                                case .active: return info.runningApps.count
                                case .unused: return info.unusedApps.count
                                }
                            }()
                            Button { usageFilter = f; visibleCount = 50 } label: {
                                HStack(spacing: 4) {
                                    Text(f.label)
                                    Text("\(count)").monospacedDigit().opacity(0.7)
                                }
                                .appFont(.caption, weight: .medium)
                                .padding(.horizontal, 10).padding(.vertical, 5)
                                .background(usageFilter == f ? Color.primary.opacity(0.85) : Color.clear)
                                .foregroundStyle(usageFilter == f ? Color(nsColor: .windowBackgroundColor) : Color.primary)
                            }
                            .buttonStyle(.plain)
                            if f != ApplicationUsageFilter.allCases.last { Divider().frame(height: 18) }
                        }
                    }
                    .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.cardBorder))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                    if info.nestedCount > 0 {
                        Toggle("Hide \(ByteFormatting.count(info.nestedCount)) bundled helpers", isOn: $hideNested).toggleStyle(.checkbox).appFont(.caption)
                    }
                    Spacer()
                    HStack(spacing: 6) {
                        Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                        TextField("Search applications…", text: $search).textFieldStyle(.plain)
                        if !search.isEmpty { Button { search = "" } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary) }.buttonStyle(.plain) }
                    }
                    .padding(.horizontal, 10).padding(.vertical, 6)
                    .background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 8))
                    .frame(width: 260)
                }
                .padding(.horizontal, 16).padding(.vertical, 10)
                .overlay(alignment: .bottom) { Divider() }

                HStack(spacing: 12) {
                    Text("APPLICATION").frame(maxWidth: .infinity, alignment: .leading)
                    Text("VERSION").frame(width: 150, alignment: .leading)
                    Text("LAST USED").frame(width: 110, alignment: .leading)
                    Text("TIME").frame(width: 110, alignment: .leading)
                    Text("LAUNCHES").frame(width: 70, alignment: .trailing)
                    Text("USERS").frame(width: 130, alignment: .leading)
                }
                .appFont(.caption2, weight: .semibold).foregroundStyle(.secondary).kerning(0.5)
                .padding(.horizontal, 16).padding(.vertical, 8)
                .background(Color.subtleBackground)
                .overlay(alignment: .bottom) { Divider() }

                if visible.isEmpty {
                    Text(search.isEmpty ? "No applications in this view" : "No applications match “\(search)”").appFont(.callout).foregroundStyle(.secondary).padding(40)
                } else {
                    LazyVStack(spacing: 0) {
                        ForEach(visible) { app in appRow(app, maxSeconds: maxSeconds) }
                        if rows.count > visible.count {
                            Button("Show \(min(100, rows.count - visible.count)) more of \(rows.count)") { visibleCount += 100 }.padding(10)
                        }
                    }
                }
            }
        }
        .onChange(of: search) { _, _ in visibleCount = 50 }
    }

    private func appRow(_ app: ApplicationItem, maxSeconds: Double) -> some View {
        let used = app.hasUsage
        let seconds = app.usageSeconds
        let users = app.usage?.users ?? []
        let share = maxSeconds > 0 ? max(0.02, seconds / maxSeconds) : 0
        return VStack(spacing: 0) {
            HStack(alignment: .top, spacing: 12) {
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        if app.isRunning { Circle().fill(Color.green).frame(width: 8, height: 8).help("Running now") }
                        Text(app.cleanName).appFont(.body, weight: .medium).foregroundStyle(used ? Color.primary : Color.secondary).lineLimit(1)
                        if app.nested { Text("HELPER").appFont(.caption2).foregroundStyle(.tertiary) }
                    }
                    Text(app.secondaryLine).appFont(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle).help(app.path ?? "")
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(app.version == "Unknown" ? "—" : app.version).appFont(.body, design: .monospaced).lineLimit(1).truncationMode(.middle)
                        if let source = app.source?.lowercased(), ["apple", "system", "user"].contains(source) {
                            Pill(app.source ?? "", tone: source == "user" ? .orange : .gray)
                        }
                    }
                    if let arch = app.architecture { Text(arch).appFont(.caption).foregroundStyle(.tertiary) }
                }
                .frame(width: 150, alignment: .leading)
                Text(used ? (app.usage?.lastUsed.map { TimeFormatting.relative($0) } ?? "—") : "—").appFont(.body).foregroundStyle(used ? .primary : .secondary).frame(width: 110, alignment: .leading)
                VStack(alignment: .leading, spacing: 4) {
                    Text(used && seconds > 0 ? ApplicationsInfo.formatDuration(seconds) : "—").appFont(.body).monospacedDigit()
                    if used, seconds > 0 {
                        GeometryReader { geo in
                            ZStack(alignment: .leading) {
                                Capsule().fill(Color.secondary.opacity(0.12))
                                Capsule().fill(Color.blue.opacity(0.7)).frame(width: geo.size.width * share)
                            }
                        }
                        .frame(height: 4)
                    }
                }
                .frame(width: 110, alignment: .leading)
                VStack(alignment: .trailing, spacing: 2) {
                    Text(used && (app.usage?.launchCount ?? 0) > 0 ? ByteFormatting.count(app.usage!.launchCount) : "—").appFont(.body).monospacedDigit()
                    if used, let d = app.usage?.daysSeen, d > 0 { Text("\(d) day\(d > 1 ? "s" : "")").appFont(.caption).foregroundStyle(.tertiary) }
                }
                .frame(width: 70, alignment: .trailing)
                Text(used && !users.isEmpty ? (users.prefix(2).map(ApplicationsInfo.shortUser).joined(separator: ", ") + (users.count > 2 ? " +\(users.count - 2)" : "")) : "—")
                    .appFont(.body).lineLimit(1).help(users.joined(separator: ", "))
                    .frame(width: 130, alignment: .leading)
            }
            .padding(.horizontal, 16).padding(.vertical, 8)
            Divider()
        }
    }
}
