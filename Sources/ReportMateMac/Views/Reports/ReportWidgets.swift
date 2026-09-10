import SwiftUI
import AppKit
import Charts
import ReportMateKit

/// A titled widget box in a report's Widgets accordion.
struct ReportWidgetBox<Content: View>: View {
    let title: String
    @ViewBuilder var content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title).appFont(.callout, weight: .medium).foregroundStyle(.secondary)
            content
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.cardBorder))
    }
}

/// Rows of "label … count" that toggle a multi-select filter when clicked.
struct CountListWidget: View {
    let title: String
    let counts: [(label: String, count: Int)]
    @Binding var selected: Set<String>
    var tone: Tone = .blue
    var maxRows: Int? = nil
    var emptyText = "No data"
    var showBars = true

    var body: some View {
        let rows = maxRows.map { Array(counts.prefix($0)) } ?? counts
        let max = counts.map(\.count).max() ?? 1
        ReportWidgetBox(title: title) {
            if rows.isEmpty {
                Text(emptyText).appFont(.caption).foregroundStyle(.tertiary)
            } else {
                ScrollView {
                    VStack(spacing: 2) {
                        ForEach(rows, id: \.label) { row in
                            let on = selected.contains(row.label)
                            Button {
                                if on { selected.remove(row.label) } else { selected.insert(row.label) }
                            } label: {
                                HStack(spacing: 8) {
                                    Circle().fill(tone.color).frame(width: 8, height: 8)
                                    Text(row.label).appFont(.caption).lineLimit(1).truncationMode(.middle).help(row.label)
                                    Spacer()
                                    if showBars {
                                        Capsule().fill(tone.color.opacity(0.35)).frame(width: CGFloat(row.count) / CGFloat(max) * 60, height: 6)
                                    }
                                    Text("\(row.count)").appFont(.caption, weight: .medium).monospacedDigit()
                                }
                                .padding(.horizontal, 6).padding(.vertical, 3)
                                .background(on ? tone.color.opacity(0.18) : Color.clear, in: RoundedRectangle(cornerRadius: 5))
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                        }
                    }
                }
                .frame(maxHeight: 190)
            }
        }
    }
}

/// Single-select variant with a nullable binding.
struct SingleCountListWidget: View {
    let title: String
    let counts: [(label: String, count: Int, color: Color)]
    @Binding var selected: String?
    var emptyText = "No data"

    var body: some View {
        ReportWidgetBox(title: title) {
            if counts.isEmpty {
                Text(emptyText).appFont(.caption).foregroundStyle(.tertiary)
            } else {
                ScrollView {
                    VStack(spacing: 2) {
                        ForEach(counts, id: \.label) { row in
                            let on = selected == row.label
                            Button { selected = on ? nil : row.label } label: {
                                HStack(spacing: 8) {
                                    Circle().fill(row.color).frame(width: 8, height: 8)
                                    Text(row.label).appFont(.caption).lineLimit(1).truncationMode(.middle).help(row.label)
                                    Spacer()
                                    Text("\(row.count)").appFont(.caption, weight: .medium).monospacedDigit()
                                }
                                .padding(.horizontal, 6).padding(.vertical, 3)
                                .background(on ? Color.blue.opacity(0.18) : Color.clear, in: RoundedRectangle(cornerRadius: 5))
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                        }
                    }
                }
                .frame(maxHeight: 190)
            }
        }
    }
}

/// The Security report's `MiniDonut`: a small ring with a clickable legend.
struct MiniDonutWidget: View {
    let title: String
    let data: [(label: String, value: Int)]
    let colors: [String: Color]
    @Binding var selected: String?

    var body: some View {
        let total = data.reduce(0) { $0 + $1.value }
        ReportWidgetBox(title: title) {
            if total == 0 {
                Text("No data").appFont(.caption).foregroundStyle(.tertiary)
            } else {
                HStack(alignment: .top, spacing: 12) {
                    Chart(data, id: \.label) { item in
                        SectorMark(angle: .value("Count", item.value), innerRadius: .ratio(0.62), angularInset: 1)
                            .foregroundStyle(colors[item.label] ?? Color.secondary.opacity(0.4))
                    }
                    .frame(width: 76, height: 76)
                    VStack(spacing: 2) {
                        ForEach(data, id: \.label) { item in
                            let on = selected == item.label
                            Button { selected = on ? nil : item.label } label: {
                                HStack(spacing: 6) {
                                    Circle().fill(colors[item.label] ?? Color.secondary.opacity(0.4)).frame(width: 8, height: 8)
                                    Text(item.label).appFont(.caption).lineLimit(1)
                                    Spacer()
                                    Text("\(item.value)").appFont(.caption, weight: .medium).monospacedDigit()
                                }
                                .padding(.horizontal, 4).padding(.vertical, 2)
                                .background(on ? Color.secondary.opacity(0.2) : Color.clear, in: RoundedRectangle(cornerRadius: 4))
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                        }
                    }
                }
            }
        }
    }
}

/// Small ring with a two-way toggle legend for the hardware donuts.
struct DonutToggleWidget: View {
    let title: String
    let data: [(label: String, count: Int)]
    @Binding var selected: Set<String>
    var palette: [Color] = [.blue, .green, .orange, .purple, .pink, .teal, .yellow, .red]

    var body: some View {
        ReportWidgetBox(title: title) {
            if data.isEmpty {
                Text("No data").appFont(.caption).foregroundStyle(.tertiary)
            } else {
                VStack(spacing: 8) {
                    Chart(Array(data.enumerated()), id: \.element.label) { i, item in
                        SectorMark(angle: .value("Count", item.count), innerRadius: .ratio(0.62), angularInset: 1)
                            .foregroundStyle(palette[i % palette.count].opacity(selected.isEmpty || selected.contains(item.label) ? 1 : 0.3))
                    }
                    .frame(height: 90)
                    VStack(spacing: 2) {
                        ForEach(Array(data.enumerated()), id: \.element.label) { i, item in
                            let on = selected.contains(item.label)
                            Button {
                                if on { selected.remove(item.label) } else { selected.insert(item.label) }
                            } label: {
                                HStack(spacing: 6) {
                                    Circle().fill(palette[i % palette.count]).frame(width: 8, height: 8)
                                    Text(item.label).appFont(.caption).lineLimit(1)
                                    Spacer()
                                    Text("\(item.count)").appFont(.caption, weight: .medium).monospacedDigit()
                                }
                                .padding(.horizontal, 4).padding(.vertical, 2)
                                .background(on ? Color.secondary.opacity(0.2) : Color.clear, in: RoundedRectangle(cornerRadius: 4))
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                        }
                    }
                }
            }
        }
    }
}

/// Counts values into sorted (label, count) pairs, most common first.
func countLabels<S: Sequence>(_ values: S) -> [(label: String, count: Int)] where S.Element == String {
    var counts: [String: Int] = [:]
    for v in values { counts[v, default: 0] += 1 }
    return counts.sorted { $0.value != $1.value ? $0.value > $1.value : $0.key < $1.key }.map { ($0.key, $0.value) }
}

/// Sortable table column header.
struct ReportSortHeader<Column: Equatable>: View {
    let title: String
    let column: Column
    @Binding var sortColumn: Column
    @Binding var ascending: Bool
    var width: CGFloat? = nil
    var alignment: Alignment = .leading

    var body: some View {
        Button {
            if sortColumn == column { ascending.toggle() } else { sortColumn = column; ascending = true }
        } label: {
            HStack(spacing: 4) {
                Text(title.uppercased()).appFont(.caption2, weight: .semibold).foregroundStyle(.secondary)
                SortIndicator(active: sortColumn == column, ascending: ascending)
            }
            .frame(width: width, alignment: alignment)
            .frame(maxWidth: width == nil ? .infinity : nil, alignment: alignment)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

/// Plain (unsortable) header label sized like the sortable ones.
struct ReportHeaderLabel: View {
    let title: String
    var width: CGFloat? = nil
    var body: some View {
        Text(title.uppercased()).appFont(.caption2, weight: .semibold).foregroundStyle(.secondary)
            .frame(width: width, alignment: .leading)
            .frame(maxWidth: width == nil ? .infinity : nil, alignment: .leading)
    }
}

/// Device name, serial with copy, and asset tag; opens the device on click.
struct ReportDeviceCell: View {
    let row: ReportRow
    var tab: DeviceTab? = nil
    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            DeviceLink(row: row, tab: tab)
            HStack(spacing: 4) {
                Text(row.serialNumber).appFont(.caption2, design: .monospaced).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                if !row.serialNumber.isEmpty { CopyButton(value: row.serialNumber) }
                if let tag = row.inventory.assetTag {
                    Text("|").foregroundStyle(.tertiary).appFont(.caption2)
                    Text(tag).appFont(.caption2, design: .monospaced).foregroundStyle(.secondary).lineLimit(1)
                }
            }
        }
    }
}

/// Export button that saves CSV through a save panel.
struct CSVExportButton: View {
    let filename: String
    let headers: [String]
    let rows: () -> [[String]]
    var label = "Export CSV"

    var body: some View {
        Button {
            let panel = NSSavePanel()
            panel.nameFieldStringValue = "\(filename)-\(CSVText.dateStamp()).csv"
            panel.allowedContentTypes = [.commaSeparatedText]
            panel.begin { response in
                guard response == .OK, let url = panel.url else { return }
                try? CSVText.encode(headers: headers, rows: rows()).write(to: url, atomically: true, encoding: .utf8)
            }
        } label: { Label(label, systemImage: "square.and.arrow.down") }
        .help("Export the filtered rows to CSV")
    }
}

/// The yellow "Filters Active … Clear Filters" bar.
struct ActiveFiltersBar: View {
    let labels: [String]
    let clear: () -> Void
    var body: some View {
        if !labels.isEmpty {
            HStack {
                Image(systemName: "line.3.horizontal.decrease.circle").foregroundStyle(.yellow)
                Text("Filters Active").appFont(.callout, weight: .medium)
                Text(labels.joined(separator: ", ")).appFont(.callout).foregroundStyle(.secondary).lineLimit(1)
                Spacer()
                Button("Clear Filters", action: clear).buttonStyle(.bordered)
            }
            .padding(.horizontal, 16).padding(.vertical, 8)
            .background(Color.yellow.opacity(0.08))
            .overlay(alignment: .bottom) { Divider() }
        }
    }
}
