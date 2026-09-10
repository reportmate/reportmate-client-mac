import SwiftUI
import ReportMateKit

/// Fleet network report. Port of `app/network/page.tsx`.
struct NetworkReportView: View {
    @State private var model = FleetReportModel(path: "/network")

    enum Column { case device, ip, mac, network }
    enum Connection { case wired, wireless, vpn }
    @State private var sortColumn: Column = .device
    @State private var ascending = true
    @State private var connection: Connection? = nil
    @State private var speedFilter: NetworkReportRow.Speed? = nil

    private func n(_ row: ReportRow) -> NetworkReportRow { NetworkReportRow(json: row.json) }

    private func filtered(_ rows: [ReportRow]) -> [(row: ReportRow, n: NetworkReportRow)] {
        rows.map { ($0, n($0)) }.filter { pair in
            switch connection {
            case .wired: if !pair.n.isWired { return false }
            case .wireless: if !pair.n.isWireless { return false }
            case .vpn: if !pair.n.info.vpnActive { return false }
            case nil: break
            }
            if let speedFilter, pair.n.speed != speedFilter { return false }
            return true
        }.sorted { a, b in
            let av: String, bv: String
            switch sortColumn {
            case .device: av = a.row.deviceName.lowercased(); bv = b.row.deviceName.lowercased()
            case .ip: av = (a.n.info.ipAddress ?? "").lowercased(); bv = (b.n.info.ipAddress ?? "").lowercased()
            case .mac: av = (a.n.info.macAddress ?? "").lowercased(); bv = (b.n.info.macAddress ?? "").lowercased()
            case .network: av = (a.n.ssid ?? a.n.info.connectionType ?? "").lowercased(); bv = (b.n.ssid ?? b.n.info.connectionType ?? "").lowercased()
            }
            return ascending ? av < bv : av > bv
        }
    }

    var body: some View {
        FleetReportContainer(
            section: .network, model: model, subtitle: "IP addresses, MAC addresses, and connectivity status", searchPlaceholder: "Search devices, IPs, MACs...",
            searchKeys: { row in
                let q = NetworkReportRow(json: row.json)
                return [row.deviceName, row.serialNumber, row.inventory.assetTag, q.info.ipAddress, q.info.macAddress, q.info.ssid, q.info.connectionType, q.info.dnsAddress, q.info.hostname]
                    + q.info.interfaces.flatMap { [$0.name, $0.ipAddress, $0.macAddress] }
            },
            toolbar: { rows in
                let vpnCount = rows.filter { NetworkReportRow(json: $0.json).info.vpnActive }.count
                HStack(spacing: 4) {
                    FilterPill(text: "Wired", selected: connection == .wired, tone: .green, size: 12) { connection = connection == .wired ? nil : .wired }
                    FilterPill(text: "Wireless", selected: connection == .wireless, tone: .teal, size: 12) { connection = connection == .wireless ? nil : .wireless }
                    FilterPill(text: vpnCount > 0 ? "VPN (\(vpnCount))" : "VPN", selected: connection == .vpn, tone: .purple, size: 12) { connection = connection == .vpn ? nil : .vpn }
                }
                CSVExportButton(filename: "network-report", headers: ["Device Name", "Serial Number", "Asset Tag", "IP Address", "MAC Address", "Connection Type", "Network/SSID", "DNS", "Download Mbps", "Upload Mbps", "Latency"]) {
                    filtered(rows).map { p in
                        [p.row.deviceName, p.row.serialNumber, p.row.inventory.assetTag ?? "", p.n.ipv4 ?? p.n.info.ipAddress ?? "", p.n.info.macAddress ?? "", p.n.info.connectionType ?? "",
                         p.n.info.ssid ?? "", p.n.info.dnsAddress ?? "", p.n.downlink.map { String($0) } ?? "", p.n.uplink.map { String($0) } ?? "", p.n.info.networkQuality?.idleLatency ?? ""]
                    }
                }
            },
            widgets: { rows in widgets(rows.map(n)) }
        ) { rows in
            table(filtered(rows))
        }
    }

    private func widgets(_ all: [NetworkReportRow]) -> some View {
        let names = countLabels(all.compactMap { r -> String? in
            guard let s = r.ssid, s != "Unknown", s != "N/A" else { return nil }
            return s
        })
        return HStack(alignment: .top, spacing: 12) {
            ReportWidgetBox(title: "Wireless State") {
                statRow("Off", all.filter { $0.wirelessState == .off }.count, .gray)
                statRow("On", all.filter { $0.wirelessState == .on }.count, .yellow)
                statRow("Connected", all.filter { $0.wirelessState == .connected }.count, .green)
            }
            .frame(width: 220)
            ReportWidgetBox(title: "Wireless Networks") {
                if names.isEmpty { Text("No networks detected").appFont(.caption).foregroundStyle(.tertiary) }
                ForEach(names.prefix(5), id: \.label) { statRow($0.label, $0.count, nil) }
            }
            .frame(width: 240)
            SingleCountListWidget(title: "Network Quality", counts: NetworkReportRow.Speed.allCases.compactMap { s in
                let count = all.filter { $0.speed == s }.count
                if s == .nodata, count == 0 { return nil }
                return (s.label, count, speedColor(s))
            }, selected: Binding(get: { speedFilter?.label }, set: { label in speedFilter = NetworkReportRow.Speed.allCases.first { $0.label == label } }))
            .frame(width: 220)
            ReportWidgetBox(title: "Signal Quality") {
                statRow("Excellent", all.filter { $0.signal == .excellent }.count, .green)
                statRow("Good", all.filter { $0.signal == .good }.count, .teal)
                statRow("Fair", all.filter { $0.signal == .fair }.count, .yellow)
                statRow("Poor", all.filter { $0.signal == .poor }.count, .red)
            }
            .frame(width: 220)
        }
    }

    private func speedColor(_ s: NetworkReportRow.Speed) -> Color {
        switch s { case .excellent: return .green; case .good: return .teal; case .fair: return .yellow; case .poor: return .red; case .nodata: return .gray }
    }

    private func statRow(_ label: String, _ count: Int, _ tone: Tone?) -> some View {
        HStack(spacing: 8) {
            if let tone { Circle().fill(tone.color).frame(width: 8, height: 8) }
            Text(label).appFont(.caption).lineLimit(1).truncationMode(.middle).help(label)
            Spacer()
            Text("\(count)").appFont(.caption, weight: .medium).monospacedDigit()
        }
        .padding(.vertical, 2)
    }

    private func table(_ pairs: [(row: ReportRow, n: NetworkReportRow)]) -> some View {
        ReportTable {
            ReportSortHeader(title: "Device", column: .device, sortColumn: $sortColumn, ascending: $ascending, width: 220)
            ReportHeaderLabel(title: "DNS Address", width: 190)
            ReportSortHeader(title: "IP Address", column: .ip, sortColumn: $sortColumn, ascending: $ascending, width: 150)
            ReportSortHeader(title: "MAC Address", column: .mac, sortColumn: $sortColumn, ascending: $ascending, width: 160)
            ReportSortHeader(title: "Connection", column: .network, sortColumn: $sortColumn, ascending: $ascending)
            ReportHeaderLabel(title: "Speed", width: 130)
        } rows: {
            if pairs.isEmpty { ReportEmptyRows(title: "No network devices found", systemImage: "wifi") }
            ForEach(pairs, id: \.row.id) { pair in
                let q = pair.n
                HStack(alignment: .top, spacing: 12) {
                    ReportDeviceCell(row: pair.row, tab: .network).frame(width: 220, alignment: .leading)
                    monoCell(q.info.dnsAddress ?? q.info.hostname, width: 190)
                    monoCell(q.ipv4 ?? q.info.ipAddress, width: 150)
                    monoCell(q.info.macAddress, width: 160)
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            if let c = q.connectionDisplay { Text(c).appFont(.callout).lineLimit(1) }
                            if q.info.vpnActive { Pill("VPN", tone: .purple).help(q.info.vpnName ?? "VPN active") }
                        }
                        if let pb = q.protocolBand { Text(pb).appFont(.caption2).foregroundStyle(.secondary).lineLimit(1) }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    Group {
                        if let dl = q.downlink {
                            Text("↓ \(trim(dl))  ↑ \(trim(q.uplink ?? 0))").appFont(.callout, design: .monospaced)
                                .help("DL: \(q.info.networkQuality?.downlinkCapacity ?? ""), UL: \(q.info.networkQuality?.uplinkCapacity ?? "N/A")" + (q.info.networkQuality?.idleLatency.map { ", Latency: \($0)" } ?? ""))
                        } else {
                            Text("-").foregroundStyle(.tertiary)
                        }
                    }
                    .frame(width: 130, alignment: .leading)
                }
                .padding(.horizontal, 16).padding(.vertical, 8)
                Divider()
            }
        }
    }

    private func trim(_ v: Double) -> String { v == v.rounded() ? String(Int(v)) : String(v) }

    private func monoCell(_ value: String?, width: CGFloat) -> some View {
        HStack(spacing: 4) {
            Text(value ?? "N/A").appFont(.callout, design: .monospaced).lineLimit(1).truncationMode(.middle)
            if let value, !value.isEmpty { CopyButton(value: value) }
        }
        .frame(width: width, alignment: .leading)
    }
}
