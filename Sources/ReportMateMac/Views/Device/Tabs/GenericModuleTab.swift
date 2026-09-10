import SwiftUI
import ReportMateKit

/// Fallback rendering for a module: every scalar as a stat, every array as a
/// table-like list, and the raw JSON at the bottom. The dedicated tabs build
/// on this for sections the web app renders generically too.
struct GenericModuleView: View {
    let title: String
    let subtitle: String?
    let systemImage: String
    let tone: Tone
    let data: JSONValue

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if data.isNull || data.isEmptyContainer {
                Card {
                    VStack(spacing: 0) {
                        CardHeader(title, subtitle: subtitle, systemImage: systemImage, tone: tone)
                        EmptyStateView(title: "\(title) information not available", message: "The device has not reported this module yet.")
                    }
                }
            } else {
                let scalars = JSONValue.object((data.object ?? [:]).filter { $0.value.object == nil && $0.value.array == nil })
                if !(scalars.object?.isEmpty ?? true) {
                    Card {
                        VStack(spacing: 0) {
                            CardHeader(title, subtitle: subtitle, systemImage: systemImage, tone: tone)
                            KeyValueGrid(value: scalars).padding(16)
                        }
                    }
                }
                ForEach((data.object ?? [:]).filter { $0.value.object != nil || $0.value.array != nil }.sorted { $0.key < $1.key }, id: \.key) { entry in
                    GenericSectionCard(title: entry.key.humanized, value: entry.value, tone: tone)
                }
            }
            JSONTreeView(value: data, label: "Raw \(title.lowercased()) module")
        }
    }
}

/// One nested object or array as a card.
struct GenericSectionCard: View {
    let title: String
    let value: JSONValue
    var tone: Tone = .gray
    @State private var expanded = true

    var body: some View {
        Card {
            VStack(spacing: 0) {
                CardHeader(title, subtitle: subtitle, tone: tone, action: { withAnimation { expanded.toggle() } }, trailing: {
                    Image(systemName: "chevron.down").rotationEffect(.degrees(expanded ? 0 : -90)).foregroundStyle(.secondary)
                })
                if expanded {
                    Group {
                        if let arr = value.array {
                            GenericArrayTable(items: arr)
                        } else if value.object != nil {
                            VStack(alignment: .leading, spacing: 14) {
                                KeyValueGrid(value: value)
                                ForEach((value.object ?? [:]).filter { $0.value.object != nil || $0.value.array != nil }.sorted { $0.key < $1.key }, id: \.key) { entry in
                                    VStack(alignment: .leading, spacing: 6) {
                                        SectionLabel(entry.key.humanized)
                                        if let arr = entry.value.array {
                                            GenericArrayTable(items: arr)
                                        } else {
                                            KeyValueGrid(value: entry.value)
                                        }
                                    }
                                }
                            }
                        }
                    }
                    .padding(16)
                }
            }
        }
    }

    private var subtitle: String? {
        if let a = value.array { return "\(a.count) item\(a.count == 1 ? "" : "s")" }
        return nil
    }
}

/// Rows of objects rendered as a simple table; scalar arrays as chips.
struct GenericArrayTable: View {
    let items: [JSONValue]
    @State private var showAll = false

    private var columns: [String] {
        var keys: [String] = []
        for item in items.prefix(50) {
            for k in (item.object ?? [:]).keys where !keys.contains(k) && item[k].object == nil && item[k].array == nil { keys.append(k) }
        }
        return Array(keys.sorted().prefix(8))
    }

    var body: some View {
        if items.isEmpty {
            Text("None").appFont(.callout).foregroundStyle(.secondary)
        } else if items.allSatisfy({ $0.object == nil }) {
            FlowLayout(spacing: 6) {
                ForEach(Array(items.enumerated()), id: \.offset) { _, item in
                    Pill(item.string ?? item.prettyPrinted, tone: .gray)
                }
            }
        } else {
            let cols = columns
            let visible = showAll ? items : Array(items.prefix(25))
            VStack(spacing: 0) {
                HStack(spacing: 8) {
                    ForEach(cols, id: \.self) { c in
                        Text(c.humanized.uppercased()).appFont(.caption2, weight: .semibold).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading).lineLimit(1)
                    }
                }
                .padding(.vertical, 6)
                Divider()
                ForEach(Array(visible.enumerated()), id: \.offset) { _, item in
                    HStack(spacing: 8) {
                        ForEach(cols, id: \.self) { c in
                            Text(item[c].string ?? (item[c].isNull ? "" : item[c].prettyPrinted))
                                .appFont(.caption).frame(maxWidth: .infinity, alignment: .leading).lineLimit(2).truncationMode(.middle)
                                .help(item[c].string ?? "")
                        }
                    }
                    .padding(.vertical, 5)
                    Divider()
                }
                if items.count > 25, !showAll {
                    Button("Show all \(items.count)") { showAll = true }.appFont(.caption).padding(.top, 6)
                }
            }
        }
    }
}

/// Filter pills row with a single-select semantics helper.
struct PillFilterRow<T: Hashable>: View {
    let items: [(value: T, label: String, count: Int?)]
    @Binding var selection: T?
    var tone: Tone = .blue

    var body: some View {
        FlowLayout(spacing: 6) {
            ForEach(Array(items.enumerated()), id: \.offset) { _, item in
                FilterPill(text: item.count.map { "\(item.label) (\($0))" } ?? item.label, selected: selection == item.value, tone: tone) {
                    selection = selection == item.value ? nil : item.value
                }
            }
        }
    }
}
