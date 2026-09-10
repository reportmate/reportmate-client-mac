import SwiftUI
import ReportMateKit

/// Fleet management report: providers, enrollment status and type widgets
/// over the enrollment table. Port of `app/management/page.tsx`.
struct ManagementReportView: View {
    @State private var model = FleetReportModel(path: "/management")

    enum Column { case device, provider, status, type, deviceId }
    @State private var sortColumn: Column = .device
    @State private var ascending = true
    @State private var providerFilter: String? = nil
    @State private var statusFilter: String? = nil
    @State private var typeFilter: String? = nil

    private func m(_ row: ReportRow) -> ManagementReportRow { ManagementReportRow(json: row.json) }

    private var widgetFilters: [String] { [providerFilter, statusFilter, typeFilter].compactMap { $0 } }

    private func filtered(_ rows: [ReportRow]) -> [(row: ReportRow, m: ManagementReportRow)] {
        rows.map { ($0, m($0)) }.filter { pair in
            if let providerFilter, pair.m.provider != providerFilter { return false }
            if let statusFilter, pair.m.enrollmentStatus != statusFilter { return false }
            if let typeFilter {
                if typeFilter == "Unmanaged" { if pair.m.enrollmentType != "Unmanaged" { return false } }
                else if pair.m.bootstrapMethod != typeFilter { return false }
            }
            return true
        }.sorted { a, b in
            let av: String, bv: String
            switch sortColumn {
            case .device: av = a.row.deviceName.lowercased(); bv = b.row.deviceName.lowercased()
            case .provider: av = a.m.provider.lowercased(); bv = b.m.provider.lowercased()
            case .status: av = a.m.enrollmentStatus.lowercased(); bv = b.m.enrollmentStatus.lowercased()
            case .type: av = a.m.enrollmentType.lowercased(); bv = b.m.enrollmentType.lowercased()
            case .deviceId: av = a.m.intuneId.lowercased(); bv = b.m.intuneId.lowercased()
            }
            return ascending ? av < bv : av > bv
        }
    }

    var body: some View {
        FleetReportContainer(
            section: .management, model: model, subtitle: "Enrollment status and type, providers, and configurations", searchPlaceholder: "Search devices",
            searchKeys: { row in
                let d = ManagementReportRow(json: row.json)
                return [row.deviceName, row.serialNumber, d.intuneId, d.provider, row.inventory.usage, row.inventory.catalog, row.inventory.assetTag, row.inventory.location, row.inventory.department]
            },
            toolbar: { rows in
                CSVExportButton(filename: "management-report", headers: ["Device Name", "Serial Number", "Asset Tag", "Provider", "Enrollment Status", "Enrollment Type", "Usage", "Catalog", "Location"]) {
                    filtered(rows).map { p in [p.row.deviceName, p.row.serialNumber, p.row.inventory.assetTag ?? "", p.m.provider, p.m.enrollmentStatus, p.m.enrollmentType, p.row.inventory.usage ?? "", p.row.inventory.catalog ?? "", p.row.inventory.location ?? ""] }
                }
            },
            widgets: { rows in widgets(rows.map(m)) }
        ) { rows in
            VStack(spacing: 0) {
                ActiveFiltersBar(labels: widgetFilters) { providerFilter = nil; statusFilter = nil; typeFilter = nil }
                table(filtered(rows))
            }
        }
    }

    private func widgets(_ all: [ManagementReportRow]) -> some View {
        let providers = countLabels(all.map(\.provider)).map { ($0.label, $0.count, providerColor($0.label)) }
        let statuses = countLabels(all.map(\.enrollmentStatus).filter { $0 != "Unknown" && $0 != "N/A" }).map { ($0.label, $0.count) }
        let order = ["Automated", "User Approved", "Manual", "Other"]
        let types = countLabels(all.compactMap(\.bootstrapMethod)).sorted { (order.firstIndex(of: $0.label) ?? 99) < (order.firstIndex(of: $1.label) ?? 99) }.map { ($0.label, $0.count) }
        return HStack(alignment: .top, spacing: 12) {
            SingleCountListWidget(title: "Providers", counts: providers, selected: $providerFilter, emptyText: "No data available").frame(width: 300)
            MiniDonutWidget(title: "Enrollment Status", data: statuses, colors: ["Enrolled": .green, "Pending": .orange, "Unenrolled": .red, "Not Enrolled": .red, "Error": .red], selected: $statusFilter).frame(width: 300)
            MiniDonutWidget(title: "Enrollment Type", data: types, colors: ["Automated": .green, "User Approved": .cyan, "Manual": .red, "Other": Color.secondary.opacity(0.5)], selected: $typeFilter).frame(width: 300)
        }
    }

    private func providerColor(_ p: String) -> Color { p == "Microsoft Intune" ? .blue : p == "Apple" ? .gray : .purple }
    private func providerTone(_ p: String) -> Tone { p == "Microsoft Intune" ? .blue : p == "Apple" ? .gray : .purple }

    private func statusTone(_ s: String) -> Tone {
        switch s {
        case "Enrolled": return .green
        case "Pending": return .yellow
        case "Not Enrolled", "Unenrolled": return .red
        default: return .gray
        }
    }

    private func table(_ pairs: [(row: ReportRow, m: ManagementReportRow)]) -> some View {
        ReportTable {
            ReportSortHeader(title: "Device", column: .device, sortColumn: $sortColumn, ascending: $ascending, width: 240)
            ReportSortHeader(title: "Provider", column: .provider, sortColumn: $sortColumn, ascending: $ascending, width: 170)
            ReportSortHeader(title: "Status", column: .status, sortColumn: $sortColumn, ascending: $ascending, width: 130)
            ReportSortHeader(title: "Type", column: .type, sortColumn: $sortColumn, ascending: $ascending, width: 140)
            ReportSortHeader(title: "Device ID", column: .deviceId, sortColumn: $sortColumn, ascending: $ascending)
        } rows: {
            if pairs.isEmpty { ReportEmptyRows(title: "No management records found", message: "No management records match your current search.", systemImage: "checkmark.shield") }
            ForEach(pairs, id: \.row.id) { pair in
                let d = pair.m
                HStack(alignment: .top, spacing: 12) {
                    ReportDeviceCell(row: pair.row, tab: .management).frame(width: 240, alignment: .leading)
                    Pill(d.provider, tone: providerTone(d.provider)).frame(width: 170, alignment: .leading)
                    Pill(d.enrollmentStatus, tone: statusTone(d.enrollmentStatus)).frame(width: 130, alignment: .leading)
                    Group {
                        if let method = d.bootstrapMethod {
                            Pill(method, tone: method == "Automated" ? .emerald : method == "User Approved" ? .cyan : .red).optionalHelp(d.bootstrapHint)
                        } else {
                            Pill("-", tone: .gray)
                        }
                    }
                    .frame(width: 140, alignment: .leading)
                    HStack(spacing: 6) {
                        Text(d.intuneId).appFont(.caption, design: .monospaced).textSelection(.enabled)
                        if d.intuneId != "N/A" { CopyButton(value: d.intuneId) }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding(.horizontal, 16).padding(.vertical, 6)
                Divider()
            }
        }
    }
}
