import SwiftUI
import ReportMateKit

/// A collapsible tree over a JSON value, used for the "raw data" disclosure
/// at the bottom of every tab and for module data no view has claimed yet.
struct JSONTreeView: View {
    let value: JSONValue
    var label: String = "Raw data"
    @State private var expanded = false

    var body: some View {
        DisclosureGroup(isExpanded: $expanded) {
            ScrollView([.horizontal, .vertical]) {
                Text(value.prettyPrinted)
                    .appFont(.caption, design: .monospaced)
                    .textSelection(.enabled)
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(maxHeight: 480)
            .background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 8))
        } label: {
            HStack(spacing: 6) {
                Image(systemName: "curlybraces").foregroundStyle(.secondary)
                Text(label).appFont(.caption, weight: .medium).foregroundStyle(.secondary)
                if !expanded {
                    Text(summary).appFont(.caption2).foregroundStyle(.tertiary)
                }
                Spacer()
                if expanded { CopyButton(value: value.prettyPrinted) }
            }
        }
    }

    private var summary: String {
        switch value {
        case .object(let o): return "\(o.count) keys"
        case .array(let a): return "\(a.count) items"
        case .null: return "empty"
        default: return ""
        }
    }
}

/// Key/value rows for a flat object, used by generic sections.
struct KeyValueGrid: View {
    let value: JSONValue
    var skipKeys: Set<String> = []

    var body: some View {
        let pairs = (value.object ?? [:]).filter { !skipKeys.contains($0.key) && $0.value.object == nil && $0.value.array == nil }
            .sorted { $0.key < $1.key }
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 200, maximum: 400), spacing: 12, alignment: .top)], alignment: .leading, spacing: 12) {
            ForEach(pairs, id: \.key) { pair in
                StatRow(label: humanize(pair.key), value: pair.value.string ?? (pair.value.isNull ? "—" : pair.value.prettyPrinted))
            }
        }
    }

    func humanize(_ key: String) -> String {
        var out = ""
        for (i, ch) in key.enumerated() {
            if ch == "_" { out.append(" "); continue }
            if ch.isUppercase, i > 0, !out.hasSuffix(" ") { out.append(" ") }
            out.append(ch)
        }
        return out.prefix(1).uppercased() + out.dropFirst()
    }
}

extension String {
    /// `snake_case` or `camelCase` to `Title Case`.
    var humanized: String {
        var out = ""
        for (i, ch) in enumerated() {
            if ch == "_" { out.append(" "); continue }
            if ch.isUppercase, i > 0, !out.hasSuffix(" ") { out.append(" ") }
            out.append(ch)
        }
        return out.prefix(1).uppercased() + out.dropFirst()
    }
}
