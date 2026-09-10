import SwiftUI
import ReportMateKit

/// The "Selections" accordion shared by every report: status, usage,
/// catalog on one row, then fleet, area and location rows. Multi-select is
/// OR within a dimension and AND across dimensions.
struct DeviceSelections: Equatable {
    var statuses: Set<String> = []
    var usages: Set<String> = []
    var catalogs: Set<String> = []
    var areas: Set<String> = []
    var locations: Set<String> = []
    var fleets: Set<String> = []

    var count: Int { statuses.count + usages.count + catalogs.count + areas.count + locations.count + fleets.count }
    var isEmpty: Bool { count == 0 }

    mutating func clear() { self = DeviceSelections() }

    static func containsCI(_ set: Set<String>, _ value: String?) -> Bool {
        guard let value else { return false }
        let v = value.lowercased()
        return set.contains { $0.lowercased() == v }
    }

    static func toggle(_ set: inout Set<String>, _ value: String) {
        if let existing = set.first(where: { $0.lowercased() == value.lowercased() }) {
            set.remove(existing)
        } else {
            set.insert(value)
        }
    }

    /// Does a device pass every selected dimension?
    func matches(_ device: DeviceSummary) -> Bool {
        if !statuses.isEmpty, !Self.containsCI(statuses, device.status.rawValue) { return false }
        if !usages.isEmpty, !Self.containsCI(usages, device.inventory.usage) { return false }
        if !catalogs.isEmpty, !Self.containsCI(catalogs, device.inventory.catalog) { return false }
        if !areas.isEmpty, !Self.containsCI(areas, device.areaOrDepartment) { return false }
        if !locations.isEmpty, !Self.containsCI(locations, device.inventory.location) { return false }
        if !fleets.isEmpty, !Self.containsCI(fleets, DeviceFilterOptions.cleanLabel(device.inventory.fleet ?? "")) { return false }
        return true
    }
}

struct DeviceFilterOptions: Equatable {
    var statuses: [String] = []
    var usages: [String] = []
    var catalogs: [String] = []
    var areas: [String] = []
    var locations: [String] = []
    var fleets: [String] = []
    var locationCounts: [String: Int] = [:]

    static func cleanLabel(_ s: String) -> String {
        s.replacingOccurrences(of: #"[,;]+\s*$"#, with: "", options: .regularExpression).trimmingCharacters(in: .whitespaces)
    }

    init() {}

    init(devices: [DeviceSummary]) {
        let active = devices.filter { !$0.archived }
        func distinct(_ pick: (DeviceSummary) -> String?) -> [String] {
            Array(Set(active.compactMap(pick).filter { !$0.isEmpty })).sorted { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending }
        }
        statuses = distinct { $0.status.rawValue }
        usages = distinct { $0.inventory.usage }
        catalogs = distinct { $0.inventory.catalog }
        areas = distinct { $0.areaOrDepartment }
        locations = distinct { $0.inventory.location }
        fleets = Array(Set(distinct { $0.inventory.fleet }.map(DeviceFilterOptions.cleanLabel).filter { !$0.isEmpty })).sorted()
        var counts: [String: Int] = [:]
        for d in active { if let l = d.inventory.location { counts[l, default: 0] += 1 } }
        locationCounts = counts
    }

    var isEmpty: Bool { statuses.isEmpty && usages.isEmpty && catalogs.isEmpty && areas.isEmpty && locations.isEmpty && fleets.isEmpty }
}

struct DeviceFiltersView: View {
    let options: DeviceFilterOptions
    @Binding var selections: DeviceSelections
    @Binding var expanded: Bool

    var body: some View {
        VStack(spacing: 0) {
            Button {
                withAnimation(.easeInOut(duration: 0.15)) { expanded.toggle() }
            } label: {
                HStack(spacing: 8) {
                    Text("Selections").appFont(.callout, weight: .medium)
                    if selections.count > 0 {
                        Pill("\(selections.count) active", tone: .blue)
                    }
                    Spacer()
                    if selections.count > 0 {
                        Button("Clear") { selections.clear() }
                            .buttonStyle(.plain)
                            .appFont(.caption, weight: .medium)
                            .foregroundStyle(.red)
                            .padding(.horizontal, 8).padding(.vertical, 2)
                            .background(Color.red.opacity(0.12), in: Capsule())
                    }
                    Image(systemName: "chevron.right")
                        .rotationEffect(.degrees(expanded ? 90 : 0))
                        .foregroundStyle(.secondary).appFont(.caption)
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 9)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .focusable(false)

            if expanded {
                VStack(alignment: .leading, spacing: 12) {
                    HStack(alignment: .top, spacing: 24) {
                        if !options.statuses.isEmpty {
                            dimension("Status", options.statuses, selected: selections.statuses, tone: .blue, capitalize: true) { DeviceSelections.toggle(&selections.statuses, $0) }
                        }
                        if !options.usages.isEmpty {
                            dimension("Usage", options.usages, selected: selections.usages, tone: .yellow) { DeviceSelections.toggle(&selections.usages, $0) }
                        }
                        if !options.catalogs.isEmpty {
                            dimension("Catalog", options.catalogs, selected: selections.catalogs, tone: .teal) { DeviceSelections.toggle(&selections.catalogs, $0) }
                        }
                    }
                    if !options.fleets.isEmpty {
                        dimension("Fleet", options.fleets, selected: selections.fleets, tone: .indigo) { DeviceSelections.toggle(&selections.fleets, $0) }
                    }
                    if !options.areas.isEmpty {
                        dimension("Area", options.areas, selected: selections.areas, tone: .purple) { DeviceSelections.toggle(&selections.areas, $0) }
                    }
                    if !options.locations.isEmpty {
                        VStack(alignment: .leading, spacing: 6) {
                            SectionLabel("Location")
                            ScrollView {
                                FlowLayout(spacing: 6) {
                                    ForEach(options.locations, id: \.self) { location in
                                        let count = options.locationCounts[location] ?? 0
                                        let maxCount = max(options.locationCounts.values.max() ?? 1, 1)
                                        let scale = Double(count) / Double(maxCount)
                                        FilterPill(text: location, selected: DeviceSelections.containsCI(selections.locations, location), tone: .green,
                                                   size: scale > 0.7 ? 13 : scale > 0.3 ? 11 : 10) {
                                            DeviceSelections.toggle(&selections.locations, location)
                                        }
                                        .help("\(location) (\(count) device\(count == 1 ? "" : "s"))")
                                    }
                                }
                            }
                            .frame(maxHeight: 140)
                        }
                    }
                }
                .padding(.horizontal, 16)
                .padding(.bottom, 14)
            }
        }
        .overlay(alignment: .bottom) { Divider() }
    }

    private func dimension(_ title: String, _ values: [String], selected: Set<String>, tone: Tone, capitalize: Bool = false, toggle: @escaping (String) -> Void) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            SectionLabel(title)
            FlowLayout(spacing: 6) {
                ForEach(values, id: \.self) { value in
                    FilterPill(text: capitalize ? value.prefix(1).uppercased() + value.dropFirst() : value,
                               selected: DeviceSelections.containsCI(selected, value), tone: tone) { toggle(value) }
                }
            }
        }
    }
}

/// Wrapping horizontal layout for pills.
struct FlowLayout: Layout {
    var spacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let width = proposal.width ?? 600
        var x: CGFloat = 0, y: CGFloat = 0, rowHeight: CGFloat = 0
        for view in subviews {
            let size = view.sizeThatFits(.unspecified)
            if x + size.width > width, x > 0 {
                x = 0
                y += rowHeight + spacing
                rowHeight = 0
            }
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
        }
        return CGSize(width: width, height: y + rowHeight)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x = bounds.minX, y = bounds.minY, rowHeight: CGFloat = 0
        for view in subviews {
            let size = view.sizeThatFits(.unspecified)
            if x + size.width > bounds.maxX, x > bounds.minX {
                x = bounds.minX
                y += rowHeight + spacing
                rowHeight = 0
            }
            view.place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(size))
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
        }
    }
}
