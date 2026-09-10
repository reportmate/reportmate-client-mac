import SwiftUI
import ReportMateKit

/// Widget palette shared by the usage report and the per-app drill-down.
enum UsagePalette {
    static let colors: [Color] = [.blue, .green, .purple, .orange, .pink, .cyan, Color(red: 0.52, green: 0.80, blue: 0.09), .red]
    static func color(_ i: Int) -> Color { colors[i % colors.count] }
}

/// Horizontal strip of per-application version cards; each version toggles
/// an `app:version` filter.
struct VersionDistributionStrip: View {
    let title: String
    let cards: [VersionCard]
    let selected: [String]
    var tone: Tone = .blue
    var note: String? = nil
    var hint: String
    let toggle: (_ version: String, _ app: String) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Image(systemName: "chart.bar.doc.horizontal").foregroundStyle(tone.color)
                Text(title).appFont(.headline)
                if !selected.isEmpty { Text("(\(selected.count) selected)").appFont(.callout).foregroundStyle(.secondary) }
                if let note { Text("- \(note)").appFont(.callout).foregroundStyle(.blue) }
            }
            if cards.isEmpty {
                Text("No version data available").appFont(.caption).foregroundStyle(.secondary).frame(maxWidth: .infinity).padding(.vertical, 12)
            } else {
                ScrollView(.horizontal) {
                    HStack(alignment: .top, spacing: 12) {
                        ForEach(cards) { card in cardView(card) }
                    }
                    .padding(.bottom, 4)
                }
            }
        }
        .padding(16)
        .overlay(alignment: .bottom) { Divider() }
    }

    private func cardView(_ card: VersionCard) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(card.name).appFont(.callout, weight: .semibold).lineLimit(1).truncationMode(.tail).help(card.name)
                Spacer()
                Text("\(card.total) device\(card.total == 1 ? "" : "s")").appFont(.caption2).foregroundStyle(.secondary)
            }
            ScrollView {
                VStack(spacing: 4) {
                    ForEach(card.versions, id: \.version) { entry in
                        versionRow(card: card, version: entry.version, count: entry.count)
                    }
                }
            }
            .frame(maxHeight: 190)
        }
        .padding(12)
        .frame(width: 250)
        .background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.cardBorder))
    }

    private func versionRow(card: VersionCard, version: String, count: Int) -> some View {
        let pct = card.total > 0 ? Int((Double(count) / Double(card.total) * 100).rounded()) : 0
        let on = selected.contains(ApplicationsReport.versionFilter(app: card.name, version: version))
        return Button { toggle(version, card.name) } label: {
            VStack(spacing: 3) {
                HStack {
                    Text("v\(version)").appFont(.caption, weight: on ? .bold : .medium).foregroundStyle(on ? Color.blue : Color.primary)
                    Spacer()
                    Text("\(count) (\(pct)%)").appFont(.caption2).foregroundStyle(.secondary)
                }
                GeometryReader { geo in
                    ZStack(alignment: .leading) {
                        Capsule().fill(Color.secondary.opacity(0.2))
                        Capsule().fill(Color.blue.opacity(on ? 1 : 0.8)).frame(width: geo.size.width * CGFloat(pct) / 100)
                    }
                }
                .frame(height: 6)
            }
            .padding(6)
            .background(on ? Color.blue.opacity(0.15) : Color.clear, in: RoundedRectangle(cornerRadius: 6))
            .overlay(RoundedRectangle(cornerRadius: 6).stroke(on ? Color.blue : Color.clear, lineWidth: 1.5))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(hint)
    }
}

/// Chip-cloud accordion inside a generated report: narrows the table and the
/// widget device set without regenerating the report.
struct UsageAppChipFilter: View {
    let apps: [String]
    let enabled: Set<String>?
    let toggle: (String) -> Void
    let selectAll: () -> Void
    let clear: () -> Void
    @State private var expanded = false
    @State private var query = ""

    private var sortedApps: [String] { apps.sorted { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending } }
    private var visible: [String] {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        return q.isEmpty ? sortedApps : sortedApps.filter { $0.lowercased().contains(q) }
    }

    var body: some View {
        VStack(spacing: 0) {
            AccordionHeader(title: "Filter applications", expanded: $expanded) {
                Pill("\(enabled?.count ?? apps.count) / \(apps.count) active", tone: .blue)
            }
            if expanded {
                VStack(alignment: .leading, spacing: 10) {
                    HStack(spacing: 8) {
                        HStack(spacing: 6) {
                            Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                            TextField("Filter chips…", text: $query).textFieldStyle(.plain)
                        }
                        .padding(.horizontal, 10).padding(.vertical, 5)
                        .background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 8))
                        .frame(maxWidth: 320)
                        Button("Select All", action: selectAll).controlSize(.small)
                        Button("Clear", action: clear).controlSize(.small).tint(.red)
                        Spacer()
                    }
                    ScrollView {
                        FlowLayout(spacing: 6) {
                            ForEach(visible, id: \.self) { name in
                                FilterPill(text: name, selected: enabled?.contains(name) ?? true, tone: .blue) { toggle(name) }
                                    .help(name)
                            }
                            if visible.isEmpty {
                                Text("No apps match \"\(query)\"").appFont(.caption).foregroundStyle(.secondary).padding(4)
                            }
                        }
                    }
                    .frame(maxHeight: 250)
                }
                .padding(.horizontal, 16).padding(.bottom, 14)
            }
        }
        .overlay(alignment: .bottom) { Divider() }
    }
}

/// The six usage widgets, shared by the Usage report and the per-app page.
struct UsageWidgetsGrid: View {
    let aggregates: UsageAggregates
    let metric: UsageMetric

    var body: some View {
        let label = metric.label
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 280), spacing: 12, alignment: .top)], alignment: .leading, spacing: 12) {
            if !aggregates.byUsage.isEmpty { StackedBarWidget(title: "\(label) by Usage Type", items: aggregates.byUsage, total: aggregates.grandTotal, metric: metric) }
            if !aggregates.byCatalog.isEmpty { StackedBarWidget(title: "\(label) by Catalog", items: aggregates.byCatalog, total: aggregates.grandTotal, metric: metric) }
            if aggregates.hasBins { BinsWidget(title: "Device \(label) Distribution", bins: aggregates.bins) }
            if !aggregates.byFleet.isEmpty { StackedBarWidget(title: "\(label) by Fleet", items: aggregates.byFleet, total: aggregates.grandTotal, metric: metric) }
            if !aggregates.byArea.isEmpty { RankedBarsWidget(title: "\(label) by Area", subtitle: "(top 10)", items: aggregates.byArea, metric: metric, color: .green) }
            if !aggregates.byLocation.isEmpty { RankedBarsWidget(title: "\(label) by Location", subtitle: "(top 10)", items: aggregates.byLocation, metric: metric, color: .blue) }
        }
    }
}

/// One stacked bar over the grand total with a legend beneath it.
struct StackedBarWidget: View {
    let title: String
    let items: [(label: String, value: Double)]
    let total: Double
    let metric: UsageMetric

    var body: some View {
        ReportWidgetBox(title: title) {
            GeometryReader { geo in
                HStack(spacing: 0) {
                    ForEach(Array(items.enumerated()), id: \.element.label) { i, item in
                        Rectangle().fill(UsagePalette.color(i))
                            .frame(width: max(0, geo.size.width * CGFloat(item.value / total)))
                            .help("\(item.label): \(metric.format(item.value))")
                    }
                }
            }
            .frame(height: 14)
            .background(Color.secondary.opacity(0.2))
            .clipShape(RoundedRectangle(cornerRadius: 4))
            VStack(spacing: 3) {
                ForEach(Array(items.enumerated()), id: \.element.label) { i, item in
                    HStack(spacing: 8) {
                        RoundedRectangle(cornerRadius: 2).fill(UsagePalette.color(i)).frame(width: 10, height: 10)
                        Text(item.label).appFont(.caption).lineLimit(1).truncationMode(.middle).help(item.label)
                        Spacer()
                        Text("\(metric.format(item.value)) (\(Int((item.value / total * 100).rounded()))%)").appFont(.caption).foregroundStyle(.secondary).monospacedDigit()
                    }
                }
            }
        }
    }
}

/// Top-N rows with bars scaled to the largest value.
struct RankedBarsWidget: View {
    let title: String
    var subtitle: String? = nil
    let items: [(label: String, value: Double)]
    let metric: UsageMetric
    let color: Color

    var body: some View {
        let maxValue = max(items.first?.value ?? 1, 1)
        ReportWidgetBox(title: subtitle.map { "\(title) \($0)" } ?? title) {
            Grid(alignment: .leading, horizontalSpacing: 8, verticalSpacing: 5) {
                ForEach(items, id: \.label) { item in
                    GridRow {
                        Text(item.label).appFont(.caption).lineLimit(1).truncationMode(.middle).help(item.label).frame(maxWidth: 140, alignment: .leading)
                        GeometryReader { geo in
                            ZStack(alignment: .leading) {
                                RoundedRectangle(cornerRadius: 3).fill(Color.secondary.opacity(0.2))
                                RoundedRectangle(cornerRadius: 3).fill(color).frame(width: geo.size.width * CGFloat(item.value / maxValue))
                            }
                        }
                        .frame(height: 12)
                        Text(metric.format(item.value)).appFont(.caption).monospacedDigit().gridColumnAlignment(.trailing)
                    }
                }
            }
        }
    }
}

/// Histogram of devices per hours/launches bucket.
struct BinsWidget: View {
    let title: String
    let bins: [UsageAggregates.Bin]

    var body: some View {
        let maxCount = max(bins.map(\.count).max() ?? 1, 1)
        ReportWidgetBox(title: title) {
            VStack(spacing: 5) {
                ForEach(bins, id: \.label) { bin in
                    HStack(spacing: 8) {
                        Text(bin.label).appFont(.caption).frame(width: 70, alignment: .leading)
                        GeometryReader { geo in
                            ZStack(alignment: .leading) {
                                RoundedRectangle(cornerRadius: 3).fill(Color.secondary.opacity(0.2))
                                RoundedRectangle(cornerRadius: 3).fill(Color.purple).frame(width: geo.size.width * CGFloat(bin.count) / CGFloat(maxCount))
                            }
                        }
                        .frame(height: 12)
                        Text("\(bin.count.formatted()) device\(bin.count == 1 ? "" : "s")").appFont(.caption).monospacedDigit().frame(width: 90, alignment: .trailing)
                    }
                }
            }
        }
    }
}

/// Widgets accordion with the Launches/Hours toggle in its header.
struct UsageWidgetsAccordion: View {
    let deviceCount: Int
    @Binding var expanded: Bool
    @Binding var metric: UsageMetric
    let aggregates: UsageAggregates

    var body: some View {
        VStack(spacing: 0) {
            AccordionHeader(title: "Widgets", detail: "Aggregate stats across \(deviceCount.formatted()) \(deviceCount == 1 ? "device" : "devices")", expanded: $expanded) {
                Picker("Metric", selection: $metric) {
                    ForEach(UsageMetric.allCases) { Text($0.label).tag($0) }
                }
                .pickerStyle(.segmented).labelsHidden().frame(width: 170)
            }
            if expanded {
                UsageWidgetsGrid(aggregates: aggregates, metric: metric)
                    .padding(.horizontal, 16).padding(.bottom, 14)
            }
        }
        .overlay(alignment: .bottom) { Divider() }
    }
}

/// Small helpers shared by the applications tables.
enum UsageCells {
    static func date(_ s: String?) -> TimeInterval {
        s.flatMap { FlexibleDate.parse(.string($0)) }?.timeIntervalSince1970 ?? 0
    }

    static func compare(_ a: String, _ b: String) -> ComparisonResult { a.localizedCaseInsensitiveCompare(b) }
    static func compare(_ a: Double, _ b: Double) -> ComparisonResult { a < b ? .orderedAscending : a > b ? .orderedDescending : .orderedSame }
    static func compare(_ a: Int, _ b: Int) -> ComparisonResult { compare(Double(a), Double(b)) }

    static func ordered(_ r: ComparisonResult, ascending: Bool) -> Bool {
        ascending ? r == .orderedAscending : r == .orderedDescending
    }

    static func dash(_ s: String?) -> String { s?.isEmpty == false ? s! : "-" }
}
