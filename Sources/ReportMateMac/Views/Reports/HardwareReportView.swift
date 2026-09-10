import SwiftUI
import ReportMateKit

/// Fleet hardware report. Port of `app/hardware/page.tsx`.
struct HardwareReportView: View {
    @Environment(AppState.self) private var appState
    @State private var model = FleetReportModel(path: "/hardware")

    enum Column { case device, model, chip, processor, memory, storage, arch }
    @State private var sortColumn: Column = .device
    @State private var ascending = true
    @State private var models: Set<String> = []
    @State private var memoryRanges: Set<String> = []
    @State private var storageRanges: Set<String> = []
    @State private var architectures: Set<String> = []
    @State private var deviceTypes: Set<String> = []
    @State private var processors: Set<String> = []
    @State private var graphics: Set<String> = []
    @State private var chipConfigs: Set<String> = []

    private var isMacOnly: Bool { appState.platformFilter == .macOS }
    private var activeCount: Int { models.count + memoryRanges.count + storageRanges.count + architectures.count + deviceTypes.count + processors.count + graphics.count + chipConfigs.count }

    private func clearWidgetFilters() {
        models = []; memoryRanges = []; storageRanges = []; architectures = []; deviceTypes = []; processors = []; graphics = []; chipConfigs = []
    }

    private func hw(_ row: ReportRow) -> HardwareReportRow { HardwareReportRow(json: row.json) }

    private func applyWidgetFilters(_ rows: [ReportRow]) -> [(row: ReportRow, hw: HardwareReportRow)] {
        rows.map { ($0, hw($0)) }.filter { pair in
            let h = pair.hw
            if !models.isEmpty, !models.contains(h.model) { return false }
            if !memoryRanges.isEmpty, !memoryRanges.contains(h.memoryRange) { return false }
            if !architectures.isEmpty, !architectures.contains(h.architecture) { return false }
            if !deviceTypes.isEmpty, !deviceTypes.contains(h.deviceType) { return false }
            if !storageRanges.isEmpty, !storageRanges.contains(h.storageRange) { return false }
            if !processors.isEmpty, !processors.contains(h.processorGroup) { return false }
            if !graphics.isEmpty, !graphics.contains(h.graphicsGroup) { return false }
            if !chipConfigs.isEmpty, !chipConfigs.contains(h.chipSku ?? "") { return false }
            return true
        }
    }

    private func sorted(_ pairs: [(row: ReportRow, hw: HardwareReportRow)]) -> [(row: ReportRow, hw: HardwareReportRow)] {
        pairs.sorted { a, b in
            let av: String, bv: String
            switch sortColumn {
            case .device: av = a.row.deviceName.lowercased(); bv = b.row.deviceName.lowercased()
            case .model: av = a.hw.model.lowercased(); bv = b.hw.model.lowercased()
            case .chip: av = (a.hw.chipName ?? "").lowercased(); bv = (b.hw.chipName ?? "").lowercased()
            case .processor: av = a.hw.processorGroup.lowercased(); bv = b.hw.processorGroup.lowercased()
            case .memory: av = a.hw.memoryRange; bv = b.hw.memoryRange
            case .storage: av = a.hw.storageRange; bv = b.hw.storageRange
            case .arch: av = a.hw.architecture.lowercased(); bv = b.hw.architecture.lowercased()
            }
            return ascending ? av < bv : av > bv
        }
    }

    var body: some View {
        FleetReportContainer(
            section: .hardware, model: model, subtitle: "Processor, memory, storage, and architecture details", searchPlaceholder: "Search devices...",
            searchKeys: { row in
                let h = HardwareReportRow(json: row.json)
                return [row.deviceName, row.serialNumber, row.inventory.assetTag, h.processorName, h.model]
            },
            toolbar: { rows in
                if activeCount > 0 { Button("Clear Selection") { clearWidgetFilters() }.buttonStyle(.bordered).tint(.yellow) }
                CSVExportButton(filename: "hardware-report", headers: ["Device Name", "Serial Number", "Asset Tag", "Model", "Processor", "Memory", "Storage", "Architecture"]) {
                    sorted(applyWidgetFilters(rows)).map { p in [p.row.deviceName, p.row.serialNumber, p.row.inventory.assetTag ?? "", p.hw.model, p.hw.processorGroup, p.hw.memoryText, p.hw.storageText.total, p.hw.architecture] }
                }
            },
            widgets: { rows in widgets(rows.map(hw)) }
        ) { rows in
            table(sorted(applyWidgetFilters(rows)))
        }
    }

    private func widgets(_ all: [HardwareReportRow]) -> some View {
        HStack(alignment: .top, spacing: 12) {
            CountListWidget(title: "Hardware Type", counts: countLabels(all.map(\.model)), selected: $models, tone: .orange).frame(width: 300)
            if isMacOnly {
                CountListWidget(title: "Chip Configuration", counts: countLabels(all.compactMap(\.chipSku)), selected: $chipConfigs, tone: .purple).frame(width: 340)
            } else {
                CountListWidget(title: "Processors", counts: countLabels(all.map(\.processorGroup)), selected: $processors, tone: .blue).frame(width: 260)
                CountListWidget(title: "Graphics", counts: countLabels(all.map(\.graphicsGroup)), selected: $graphics, tone: .green).frame(width: 260)
            }
            VStack(spacing: 12) {
                CountListWidget(title: "Memory", counts: countLabels(all.map(\.memoryRange)).sorted { memorySort($0.label, $1.label) }, selected: $memoryRanges, tone: .indigo, showBars: false)
                CountListWidget(title: "Storage", counts: countLabels(all.map(\.storageRange)), selected: $storageRanges, tone: .teal, showBars: false)
            }
            .frame(width: 220)
            VStack(spacing: 12) {
                DonutToggleWidget(title: "Device Type", data: countLabels(all.map(\.deviceType)), selected: $deviceTypes)
                DonutToggleWidget(title: "Architecture", data: countLabels(all.map(\.architecture)), selected: $architectures, palette: [.blue, .orange, .purple, .gray])
            }
            .frame(width: 190)
        }
    }

    private func memorySort(_ a: String, _ b: String) -> Bool {
        let na = Double(a.filter(\.isNumber)) ?? .infinity, nb = Double(b.filter(\.isNumber)) ?? .infinity
        return na < nb
    }

    private func table(_ pairs: [(row: ReportRow, hw: HardwareReportRow)]) -> some View {
        ReportTable {
            ReportSortHeader(title: "Device", column: .device, sortColumn: $sortColumn, ascending: $ascending, width: 220)
            ReportSortHeader(title: "Model", column: .model, sortColumn: $sortColumn, ascending: $ascending, width: isMacOnly ? 220 : 170)
            if isMacOnly { ReportSortHeader(title: "Chip", column: .chip, sortColumn: $sortColumn, ascending: $ascending, width: 100) }
            ReportSortHeader(title: "Processor", column: .processor, sortColumn: $sortColumn, ascending: $ascending)
            ReportHeaderLabel(title: "Graphics", width: 150)
            ReportSortHeader(title: "Memory", column: .memory, sortColumn: $sortColumn, ascending: $ascending, width: 90)
            ReportSortHeader(title: "Storage", column: .storage, sortColumn: $sortColumn, ascending: $ascending, width: 90)
            if !isMacOnly { ReportSortHeader(title: "Arch", column: .arch, sortColumn: $sortColumn, ascending: $ascending, width: 70) }
        } rows: {
            if pairs.isEmpty {
                ReportEmptyRows(title: "No hardware found", systemImage: "cpu")
            }
            ForEach(pairs, id: \.row.id) { p in
                let h = p.hw
                HStack(alignment: .top, spacing: 12) {
                    ReportDeviceCell(row: p.row, tab: .hardware).frame(width: 220, alignment: .leading)
                    VStack(alignment: .leading, spacing: 1) {
                        if let m = h.manufacturer { Text(m).appFont(.caption2).foregroundStyle(.secondary).lineLimit(1) }
                        Text(h.model).appFont(.callout).lineLimit(2).minimumScaleFactor(0.8)
                    }
                    .frame(width: isMacOnly ? 220 : 170, alignment: .leading)
                    if isMacOnly { Text(h.chipName ?? "-").appFont(.callout, weight: .semibold).frame(width: 100, alignment: .leading) }
                    VStack(alignment: .leading, spacing: 1) {
                        if let chip = h.chipName {
                            Text(h.processorCores > 0 ? "\(h.processorCores) Cores" : chip).appFont(.callout, weight: .semibold)
                            if h.performanceCores > 0, h.efficiencyCores > 0 { Text("\(h.performanceCores) Performance + \(h.efficiencyCores) Efficiency").appFont(.caption2).foregroundStyle(.secondary) }
                        } else {
                            Text(h.processorName).appFont(.callout).lineLimit(2).minimumScaleFactor(0.8)
                            if h.processorCores > 0 { Text("\(h.processorCores) cores" + (h.processorSpeed.map { " \($0)" } ?? "")).appFont(.caption2).foregroundStyle(.secondary) }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    VStack(alignment: .leading, spacing: 1) {
                        if let chip = h.chipName {
                            Text(h.graphicsCores > 0 ? "\(h.graphicsCores) Cores" : chip).appFont(.callout, weight: h.graphicsCores > 0 ? .semibold : .regular)
                        } else if let g = h.graphicsRawName {
                            Text(g).appFont(.callout).lineLimit(2).minimumScaleFactor(0.8)
                            if h.graphicsCount > 1 { Text("+\(h.graphicsCount - 1) more").appFont(.caption2).foregroundStyle(.secondary) }
                        } else {
                            Text("Unknown").appFont(.callout).foregroundStyle(.secondary)
                        }
                    }
                    .frame(width: 150, alignment: .leading)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(h.memoryText).appFont(.callout)
                        if h.memoryModuleCount > 0 { Text("\(h.memoryModuleCount) modules").appFont(.caption2).foregroundStyle(.secondary) }
                    }
                    .frame(width: 90, alignment: .leading)
                    VStack(alignment: .leading, spacing: 1) {
                        let s = h.storageText
                        Text(s.total).appFont(.callout)
                        if let f = s.free { Text("\(f) free").appFont(.caption2).foregroundStyle(.secondary) }
                    }
                    .frame(width: 90, alignment: .leading)
                    if !isMacOnly { Text(h.architecture).appFont(.callout).frame(width: 70, alignment: .leading) }
                }
                .padding(.horizontal, 16).padding(.vertical, 8)
                Divider()
            }
        }
    }
}
