import SwiftUI
import ReportMateKit

/// Copy and colours for each status drill-down (`STATUS_VIEW_COPY`).
struct InstallStatusCopy {
    let chip: String
    let devicesHeading: String
    let packagesColumn: String
    let messageColumn: String
    let blurb: String
    let messageBlurb: String
    let emptyHeading: String
    let emptyBlurb: String
    let noun: String
    let tone: Tone
    let systemImage: String

    static func copy(for category: InstallItems.Category) -> InstallStatusCopy {
        switch category {
        case .error:
            return InstallStatusCopy(chip: "Errors", devicesHeading: "Devices with Install Errors", packagesColumn: "Failed Packages", messageColumn: "Error Message",
                                     blurb: "These devices have one or more packages with failed installations or errors.",
                                     messageBlurb: "Every distinct error reported across these devices, most widespread first.",
                                     emptyHeading: "No Install Errors!", emptyBlurb: "All devices have successful installations. Great job keeping everything running smoothly!",
                                     noun: "errors", tone: .red, systemImage: "exclamationmark.circle.fill")
        case .warning:
            return InstallStatusCopy(chip: "Warnings", devicesHeading: "Devices with Warnings", packagesColumn: "Warning Packages", messageColumn: "Warning Message",
                                     blurb: "These devices have packages with warnings that need attention.",
                                     messageBlurb: "Every distinct warning reported across these devices, most widespread first.",
                                     emptyHeading: "No Warnings!", emptyBlurb: "No packages have warnings. Everything looks good!",
                                     noun: "warnings", tone: .yellow, systemImage: "exclamationmark.triangle.fill")
        case .pending:
            return InstallStatusCopy(chip: "Pending", devicesHeading: "Devices with Pending Updates", packagesColumn: "Pending Packages", messageColumn: "Reason",
                                     blurb: "These devices have packages with pending updates.",
                                     messageBlurb: "Every distinct reason a package is waiting, most widespread first.",
                                     emptyHeading: "No Pending Updates!", emptyBlurb: "All managed packages are up to date across your fleet.",
                                     noun: "pending updates", tone: .cyan, systemImage: "clock.fill")
        case .success:
            return InstallStatusCopy(chip: "Successes", devicesHeading: "Devices with Successful Installs", packagesColumn: "Installed Packages", messageColumn: "Installed Version",
                                     blurb: "These devices completed one or more installs in their most recent run — not everything they have installed, only what landed this time.",
                                     messageBlurb: "Every version that landed in the most recent run, most widespread first.",
                                     emptyHeading: "No Recent Installs", emptyBlurb: "No package completed an install in the most recent run on any device.",
                                     noun: "successful installs", tone: .green, systemImage: "checkmark.circle.fill")
        }
    }
}

/// Coloured status pill that goes solid when active.
struct StatusPill: View {
    let label: String
    var count: Int? = nil
    var tone: Tone = .gray
    let active: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(count.map { "\(label) - \($0)" } ?? label)
                .appFont(.caption, weight: .medium)
                .padding(.horizontal, 10).padding(.vertical, 4)
                .background(active ? tone.color.opacity(tone == .gray ? 0.25 : 0.9) : tone.color.opacity(tone == .gray ? 0.0 : 0.15), in: Capsule())
                .overlay(Capsule().stroke(tone == .gray ? Color.secondary.opacity(0.4) : Color.clear))
                .foregroundStyle(active && tone != .gray ? Color.white : (tone == .gray ? Color.primary : tone.color))
        }
        .buttonStyle(.plain)
        .focusable(false)
    }
}

/// "Items with Errors" style box: a sortable name/count table whose header
/// filters the page to the status and whose rows filter to one item.
struct ItemCountTable: View {
    struct Sort: Equatable { var byName = false; var ascending = false }
    let title: String
    let items: [InstallItemCount]
    let tone: Tone
    let sortable: Bool
    @Binding var sort: Sort
    let selectedName: String?
    let headerHelp: String
    let onHeader: () -> Void
    let onRow: (String) -> Void

    private var sorted: [InstallItemCount] {
        items.sorted { a, b in
            if sort.byName {
                let r = a.name.localizedCaseInsensitiveCompare(b.name)
                return sort.ascending ? r == .orderedAscending : r == .orderedDescending
            }
            return sort.ascending ? a.count < b.count : a.count > b.count
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            Button(action: onHeader) {
                HStack {
                    Text(title).appFont(.callout, weight: .semibold)
                    Spacer()
                    Text("\(items.reduce(0) { $0 + $1.count }) total").appFont(.caption).foregroundStyle(.secondary)
                }
                .padding(.horizontal, 12).padding(.vertical, 8)
                .background(tone.color.opacity(0.12))
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help(headerHelp)
            HStack(spacing: 8) {
                columnHeader("Item Name", byName: true).frame(maxWidth: .infinity, alignment: .leading)
                columnHeader("Count", byName: false).frame(width: 60, alignment: .trailing)
            }
            .padding(.horizontal, 12).padding(.vertical, 5)
            .background(Color.subtleBackground)
            Divider()
            ScrollView {
                LazyVStack(spacing: 0) {
                    if items.isEmpty {
                        Text("None").appFont(.caption).foregroundStyle(.tertiary).padding(12)
                    }
                    ForEach(sorted) { item in
                        let on = selectedName == item.name
                        Button { onRow(item.name) } label: {
                            HStack(spacing: 8) {
                                Text(item.name).appFont(.caption).lineLimit(1).truncationMode(.middle).help(item.name)
                                Spacer()
                                Text("\(item.count)").appFont(.caption, weight: .medium).monospacedDigit()
                            }
                            .padding(.horizontal, 12).padding(.vertical, 5)
                            .background(on ? tone.color.opacity(0.25) : Color.clear)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        Divider()
                    }
                }
            }
            .frame(minHeight: 120, maxHeight: 220)
        }
        .background(Color.cardBackground, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.cardBorder))
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }

    private func columnHeader(_ title: String, byName: Bool) -> some View {
        Button {
            guard sortable else { return }
            if sort.byName == byName { sort.ascending.toggle() } else { sort = Sort(byName: byName, ascending: byName) }
        } label: {
            HStack(spacing: 3) {
                Text(title.uppercased()).appFont(.caption2, weight: .semibold).foregroundStyle(.secondary)
                if sortable { SortIndicator(active: sort.byName == byName, ascending: sort.ascending) }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

/// The Errors / Warnings message widgets: distinct messages with counts.
struct InstallMessagesWidget: View {
    let messages: [AggregatedInstallMessage]
    let errors: Bool
    var maxItems = 8
    let onFilter: (_ message: String?) -> Void

    var body: some View {
        let tone: Tone = errors ? .red : .yellow
        VStack(spacing: 0) {
            Button { onFilter(nil) } label: {
                HStack {
                    Image(systemName: errors ? "exclamationmark.circle.fill" : "exclamationmark.triangle.fill").foregroundStyle(tone.color)
                    Text(errors ? "Errors" : "Warnings").appFont(.callout, weight: .semibold)
                    Spacer()
                    Pill("\(messages.reduce(0) { $0 + $1.count })", tone: tone)
                }
                .padding(.horizontal, 12).padding(.vertical, 8)
                .background(tone.color.opacity(0.12))
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help(errors ? "Click to filter by errors" : "Click to filter by warnings")
            VStack(spacing: 0) {
                ForEach(messages.prefix(maxItems)) { m in
                    Button { onFilter(m.message) } label: {
                        HStack(alignment: .top, spacing: 8) {
                            Text(m.message).appFont(.caption).lineLimit(2).multilineTextAlignment(.leading).help(m.message)
                            Spacer()
                            Text("\(m.count)").appFont(.caption, weight: .medium).monospacedDigit().foregroundStyle(tone.color)
                        }
                        .padding(.horizontal, 12).padding(.vertical, 6)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .help(errors ? "Click to show devices with this error" : "Click to show devices with this warning")
                    Divider()
                }
                if messages.count > maxItems {
                    Text("+\(messages.count - maxItems) more \(errors ? "error" : "warning") messages").appFont(.caption2).foregroundStyle(.secondary).padding(8)
                }
            }
        }
        .background(Color.cardBackground, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.cardBorder))
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }
}

/// Software Repos / Munki Versions / Cimian Versions / Manifests: ranked
/// bars that filter the config report when clicked.
struct DistributionBarsWidget: View {
    struct Row: Identifiable { let key: String; let label: String; let count: Int; let percentage: Int; var id: String { key } }
    let title: String
    let rows: [Row]
    let emptyText: String
    let tone: Tone
    let selected: String
    let showPercent: Bool
    let onSelect: (String) -> Void

    var body: some View {
        ReportWidgetBox(title: title) {
            if rows.isEmpty {
                Text(emptyText).appFont(.caption).foregroundStyle(.tertiary)
            } else {
                ScrollView {
                    VStack(spacing: 8) {
                        ForEach(rows) { row in
                            let on = selected == row.key
                            Button { onSelect(row.key) } label: {
                                VStack(spacing: 3) {
                                    HStack {
                                        Text(row.label).appFont(.caption, weight: on ? .bold : .regular).foregroundStyle(on ? tone.color : Color.primary).lineLimit(1).truncationMode(.middle).help(row.key)
                                        Spacer()
                                        Text(showPercent ? "\(row.count) (\(row.percentage)%)" : "\(row.count)").appFont(.caption2).foregroundStyle(.secondary).monospacedDigit()
                                    }
                                    GeometryReader { geo in
                                        ZStack(alignment: .leading) {
                                            Capsule().fill(on ? tone.color.opacity(0.3) : Color.secondary.opacity(0.2))
                                            Capsule().fill(tone.color).frame(width: geo.size.width * CGFloat(row.percentage) / 100)
                                        }
                                    }
                                    .frame(height: 6)
                                }
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                        }
                    }
                }
                .frame(maxHeight: 220)
            }
        }
    }
}

/// Messages for one selected item, shown above the drill-down table.
struct SelectedItemMessagesPanel: View {
    @Environment(AppState.self) private var appState
    let itemName: String
    let errors: Bool
    let messages: [AggregatedInstallMessage]
    let onClose: () -> Void

    var body: some View {
        let tone: Tone = errors ? .red : .yellow
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Image(systemName: errors ? "exclamationmark.circle.fill" : "exclamationmark.triangle.fill").foregroundStyle(tone.color)
                Text("\(errors ? "Errors" : "Warnings") for \"\(itemName)\"").appFont(.callout, weight: .semibold)
                if !messages.isEmpty { Pill("\(messages.reduce(0) { $0 + $1.count }) total", tone: tone) }
                Spacer()
                Button { onClose() } label: { Image(systemName: "xmark") }.buttonStyle(.plain).help("Close messages")
            }
            if messages.isEmpty {
                Text("No \(errors ? "errors" : "warnings") messages found for \"\(itemName)\"").appFont(.caption).foregroundStyle(.secondary)
            }
            ForEach(messages) { m in
                VStack(alignment: .leading, spacing: 6) {
                    HStack(alignment: .top) {
                        Text(m.message).appFont(.caption).foregroundStyle(tone.color).textSelection(.enabled)
                        Spacer()
                        Pill("\(m.count) device\(m.count == 1 ? "" : "s")", tone: tone)
                    }
                    HStack(spacing: 8) {
                        ForEach(Array(m.devices.prefix(3).enumerated()), id: \.offset) { _, d in
                            Button(d.deviceName) { appState.open(device: d.serialNumber, tab: .installs) }.buttonStyle(.link).appFont(.caption)
                        }
                        if m.devices.count > 3 { Text("+\(m.devices.count - 3) more").appFont(.caption2).foregroundStyle(.secondary) }
                    }
                }
                .padding(10)
                .background(Color.cardBackground, in: RoundedRectangle(cornerRadius: 8))
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(tone.color.opacity(0.3)))
            }
        }
        .padding(12)
        .background(tone.color.opacity(0.07), in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(tone.color.opacity(0.35)))
    }
}
