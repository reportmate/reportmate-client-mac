import SwiftUI
import ReportMateKit

/// Fleet security report: eight posture donuts, a certificate search and the
/// posture table. Port of `app/security/page.tsx`.
struct SecurityReportView: View {
    @Environment(AppState.self) private var appState
    @State private var model = FleetReportModel(path: "/security")

    enum Column { case device, encryption, protection, detection, firewall, tampering, remote, certificates, cve }
    @State private var sortColumn: Column = .device
    @State private var ascending = true
    @State private var encryptionFilter: String? = nil
    @State private var protectionFilter: String? = nil
    @State private var detectionFilter: String? = nil
    @State private var firewallFilter: String? = nil
    @State private var tamperingFilter: String? = nil
    @State private var remoteFilter: String? = nil
    @State private var certFilter: String? = nil
    @State private var cveFilter: String? = nil

    @State private var certSearchExpanded = false
    @State private var certQuery = ""
    @State private var certStatus = "all"
    @State private var certGroups: [CertificateSearchGroup] = []
    @State private var certSearching = false
    @State private var certSearched = false
    @State private var selectedCertName: String? = nil

    private var widgetFilters: [String] { [encryptionFilter, protectionFilter, detectionFilter, firewallFilter, tamperingFilter, remoteFilter, certFilter, cveFilter].compactMap { $0 } }

    private func clearWidgetFilters() {
        encryptionFilter = nil; protectionFilter = nil; detectionFilter = nil; firewallFilter = nil
        tamperingFilter = nil; remoteFilter = nil; certFilter = nil; cveFilter = nil
    }

    private func s(_ row: ReportRow) -> SecurityReportRow { SecurityReportRow(json: row.json, platform: row.platform) }

    private var certSerials: Set<String>? {
        guard let selectedCertName, let group = certGroups.first(where: { $0.commonName == selectedCertName }) else { return nil }
        return Set(group.devices.map(\.serialNumber))
    }

    private func filtered(_ rows: [ReportRow]) -> [(row: ReportRow, s: SecurityReportRow)] {
        let serials = certSerials
        return rows.map { ($0, s($0)) }.filter { pair in
            let d = pair.s
            if let f = encryptionFilter, d.encryptionLabel != f { return false }
            if let f = protectionFilter, d.protectionLabel != f { return false }
            if let f = detectionFilter, d.detectionLabel != f { return false }
            if let f = firewallFilter, d.firewallLabel != f { return false }
            if let f = tamperingFilter, d.tamperLabel != f { return false }
            if let f = remoteFilter, d.remoteLabel != f { return false }
            if let f = certFilter, d.certLabel != f { return false }
            if let f = cveFilter, d.cveLabel != f { return false }
            if let serials, !serials.contains(pair.row.serialNumber) { return false }
            return true
        }.sorted { a, b in
            let av: String, bv: String
            func pad(_ n: Int) -> String { String(format: "%05d", n) }
            switch sortColumn {
            case .device: av = a.row.deviceName.lowercased(); bv = b.row.deviceName.lowercased()
            case .encryption: av = a.s.encryptionEnabled ? "1" : "0"; bv = b.s.encryptionEnabled ? "1" : "0"
            case .protection: av = a.s.protectionLabel; bv = b.s.protectionLabel
            case .detection: av = pad(a.s.detectionCount); bv = pad(b.s.detectionCount)
            case .firewall: av = a.s.firewallEnabled ? "1" : "0"; bv = b.s.firewallEnabled ? "1" : "0"
            case .tampering: av = a.s.tamperLabel; bv = b.s.tamperLabel
            case .remote: av = a.s.remoteLabel; bv = b.s.remoteLabel
            case .certificates: av = pad(a.s.expiredCertCount + a.s.expiringSoonCertCount); bv = pad(b.s.expiredCertCount + b.s.expiringSoonCertCount)
            case .cve: av = pad(a.s.cveCount); bv = pad(b.s.cveCount)
            }
            return ascending ? av < bv : av > bv
        }
    }

    var body: some View {
        FleetReportContainer(
            section: .security, model: model, subtitle: "Security posture across the fleet", searchPlaceholder: "Search devices...",
            searchKeys: { row in
                let d = SecurityReportRow(json: row.json, platform: row.platform)
                return [row.deviceName, row.serialNumber, d.antivirusName, d.autoLoginUser]
            },
            toolbar: { rows in
                CSVExportButton(filename: "security-report", headers: ["Device Name", "Serial Number", "Platform", "Encryption", "Protection Name", "Protection Status", "Detections", "Tampering", "Firewall", "Access", "Expired Certs", "Expiring Certs", "Vulnerabilities", "Critical Vulnerabilities"], rows: {
                    filtered(rows).map { p in
                        let d = p.s
                        return [p.row.deviceName, p.row.serialNumber, p.row.platform.displayName, d.encryptionLabel, d.antivirusName ?? "", d.protectionLabel,
                                d.detectionCount > 0 ? "\(d.detectionCount) threat\(d.detectionCount == 1 ? "" : "s")" : "Clean", d.tamperSummary, d.firewallEnabled ? "On" : "Off",
                                [d.sshRunning ? "SSH" : nil, d.isWindows && d.rdpEnabled ? "RDP" : nil].compactMap { $0 }.joined(separator: "+").isEmpty ? "None" : [d.sshRunning ? "SSH" : nil, d.isWindows && d.rdpEnabled ? "RDP" : nil].compactMap { $0 }.joined(separator: "+"),
                                String(d.expiredCertCount), String(d.expiringSoonCertCount), String(d.cveCount), String(d.criticalCveCount)]
                    }
                }, label: "Export")
            },
            widgets: { rows in widgets(rows.map(s)) }
        ) { rows in
            VStack(spacing: 0) {
                ActiveFiltersBar(labels: widgetFilters, clear: clearWidgetFilters)
                certificateSearch
                table(filtered(rows))
            }
        }
    }

    private func donutData(_ all: [SecurityReportRow], _ label: (SecurityReportRow) -> String) -> [(label: String, value: Int)] {
        countLabels(all.map(label)).map { ($0.label, $0.count) }
    }

    private func widgets(_ all: [SecurityReportRow]) -> some View {
        let green = Color.green, red = Color.red, amber = Color.orange, gray = Color.secondary.opacity(0.5), blue = Color.blue
        return LazyVGrid(columns: Array(repeating: GridItem(.fixed(250), spacing: 12), count: 4), spacing: 12) {
            MiniDonutWidget(title: "Encryption", data: donutData(all, \.encryptionLabel), colors: ["Encrypted": green, "Not Encrypted": red], selected: $encryptionFilter)
            MiniDonutWidget(title: "Protection", data: donutData(all, \.protectionLabel), colors: ["Current": green, "Out of Date": amber, "Disabled": red], selected: $protectionFilter)
            MiniDonutWidget(title: "Detection", data: donutData(all, \.detectionLabel), colors: ["Clean": green, "Threats Detected": red], selected: $detectionFilter)
            MiniDonutWidget(title: "Firewall", data: donutData(all, \.firewallLabel), colors: ["Enabled": green, "Disabled": gray], selected: $firewallFilter)
            MiniDonutWidget(title: "Tampering", data: donutData(all, \.tamperLabel), colors: ["Secured": green, "Insecure": red], selected: $tamperingFilter)
            MiniDonutWidget(title: "Access", data: donutData(all, \.remoteLabel), colors: ["SSH + RDP": blue, "SSH Only": green, "RDP Only": amber, "SSH Enabled": green, "Disabled": gray], selected: $remoteFilter)
            MiniDonutWidget(title: "Certificates", data: donutData(all, \.certLabel), colors: ["Valid": green, "Expiring Soon": amber, "Has Expired": red], selected: $certFilter)
            MiniDonutWidget(title: "Vulnerabilities", data: donutData(all, \.cveLabel), colors: ["None": green, "Has CVEs": amber, "Critical": red], selected: $cveFilter)
        }
    }

    // MARK: Certificate search

    private var certificateSearch: some View {
        VStack(spacing: 0) {
            Button { withAnimation { certSearchExpanded.toggle() } } label: {
                HStack(spacing: 8) {
                    Text("Certificates").appFont(.callout, weight: .medium)
                    if let name = selectedCertName { Pill("Filtering: \(name)", tone: .blue) }
                    Spacer()
                    Image(systemName: "chevron.down").rotationEffect(.degrees(certSearchExpanded ? 180 : 0)).foregroundStyle(.secondary)
                }
                .padding(.horizontal, 16).padding(.vertical, 8)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            if certSearchExpanded {
                VStack(alignment: .leading, spacing: 10) {
                    HStack(spacing: 8) {
                        if selectedCertName != nil { Button("Clear filter") { selectedCertName = nil }.buttonStyle(.bordered).tint(.orange) }
                        TextField("Search certificates (e.g. UEFI, Microsoft, DigiCert...)", text: $certQuery).textFieldStyle(.roundedBorder).onSubmit { Task { await searchCertificates() } }
                        ForEach(["all", "valid", "expiring", "expired"], id: \.self) { st in
                            FilterPill(text: st.prefix(1).uppercased() + st.dropFirst(), selected: certStatus == st, tone: .gray, size: 12) {
                                certStatus = st
                                if !certQuery.trimmingCharacters(in: .whitespaces).isEmpty, st != "all" { Task { await searchCertificates() } }
                            }
                        }
                        Button(certSearching ? "Searching..." : "Search") { Task { await searchCertificates() } }.buttonStyle(.borderedProminent).disabled(certSearching)
                    }
                    if !certGroups.isEmpty {
                        ScrollView {
                            VStack(spacing: 6) {
                                ForEach(certGroups) { group in
                                    let on = selectedCertName == group.commonName
                                    Button { selectedCertName = on ? nil : group.commonName } label: {
                                        HStack(alignment: .top, spacing: 12) {
                                            VStack(alignment: .leading, spacing: 3) {
                                                HStack(spacing: 6) {
                                                    Text(group.commonName).appFont(.callout, weight: .medium).lineLimit(1)
                                                    if on { Image(systemName: "checkmark").foregroundStyle(.blue).appFont(.caption) }
                                                }
                                                if let issuer = group.issuer { Text("Issuer: \(issuer)").appFont(.caption2).foregroundStyle(.secondary).lineLimit(1) }
                                                if on, !group.devices.isEmpty {
                                                    FlowLayout(spacing: 4) {
                                                        ForEach(group.devices.prefix(5)) { d in
                                                            Button { appState.open(device: d.serialNumber, tab: .security) } label: { Pill(d.deviceName, tone: .gray) }.buttonStyle(.plain)
                                                        }
                                                        if group.devices.count > 5 { Text("+\(group.devices.count - 5) more").appFont(.caption2).foregroundStyle(.secondary) }
                                                    }
                                                }
                                            }
                                            Spacer()
                                            HStack(spacing: 6) {
                                                if group.expiredCount > 0 { Pill("\(group.expiredCount) expired", tone: .red) }
                                                if group.expiringCount > 0 { Pill("\(group.expiringCount) expiring", tone: .orange) }
                                                Pill("\(group.devices.count) device\(group.devices.count == 1 ? "" : "s")", tone: .gray)
                                            }
                                        }
                                        .padding(10)
                                        .background(on ? Color.blue.opacity(0.08) : Color.cardBackground, in: RoundedRectangle(cornerRadius: 8))
                                        .overlay(RoundedRectangle(cornerRadius: 8).stroke(on ? Color.blue.opacity(0.5) : Color.cardBorder))
                                        .contentShape(Rectangle())
                                    }
                                    .buttonStyle(.plain)
                                }
                                Text("\(certGroups.count) unique certificate\(certGroups.count == 1 ? "" : "s")").appFont(.caption2).foregroundStyle(.secondary)
                            }
                        }
                        .frame(maxHeight: 260)
                    } else if certSearched, !certSearching {
                        Text("No certificates found" + (certQuery.trimmingCharacters(in: .whitespaces).isEmpty ? "" : " matching “\(certQuery.trimmingCharacters(in: .whitespaces))”") + (certStatus == "all" ? "" : " with status “\(certStatus)”"))
                            .appFont(.callout).foregroundStyle(.secondary)
                    }
                    if let name = selectedCertName {
                        Text("Table filtered to devices with certificate: \(name)").appFont(.caption).foregroundStyle(.blue)
                    }
                }
                .padding(16)
            }
        }
        .overlay(alignment: .bottom) { Divider() }
    }

    private func searchCertificates() async {
        let q = certQuery.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty || certStatus != "all" else { return }
        certSearching = true
        certSearched = true
        defer { certSearching = false }
        do {
            let json = try await appState.api.fleetReport("/security/certificates", query: ["search": q.isEmpty ? nil : q, "status": certStatus == "all" ? nil : certStatus])
            certGroups = CertificateSearchGroup.group(json.array ?? json["data"].elements)
            selectedCertName = nil
        } catch {
            certGroups = []
            appState.note(error)
        }
    }

    // MARK: Table

    private func table(_ pairs: [(row: ReportRow, s: SecurityReportRow)]) -> some View {
        ReportTable {
            ReportSortHeader(title: "Device", column: .device, sortColumn: $sortColumn, ascending: $ascending, width: 200)
            ReportSortHeader(title: "Encryption", column: .encryption, sortColumn: $sortColumn, ascending: $ascending, width: 110)
            ReportSortHeader(title: "Protection", column: .protection, sortColumn: $sortColumn, ascending: $ascending, width: 90)
            ReportSortHeader(title: "Detection", column: .detection, sortColumn: $sortColumn, ascending: $ascending, width: 90)
            ReportSortHeader(title: "Tampering", column: .tampering, sortColumn: $sortColumn, ascending: $ascending)
            ReportSortHeader(title: "Firewall", column: .firewall, sortColumn: $sortColumn, ascending: $ascending, width: 70)
            ReportSortHeader(title: "Access", column: .remote, sortColumn: $sortColumn, ascending: $ascending, width: 100)
            ReportSortHeader(title: "Certs", column: .certificates, sortColumn: $sortColumn, ascending: $ascending, width: 80)
            ReportSortHeader(title: "Vulnerabilities", column: .cve, sortColumn: $sortColumn, ascending: $ascending, width: 110)
        } rows: {
            if pairs.isEmpty { ReportEmptyRows(title: "No security records found", systemImage: "lock") }
            ForEach(pairs, id: \.row.id) { pair in
                let d = pair.s
                HStack(alignment: .top, spacing: 12) {
                    ReportDeviceCell(row: pair.row, tab: .security).frame(width: 200, alignment: .leading)
                    Pill("\(d.isWindows ? "BitLocker" : "FileVault") \(d.encryptionEnabled ? "On" : "Off")", tone: d.encryptionEnabled ? .green : .red).frame(width: 110, alignment: .leading)
                    Pill(d.antivirusEnabled ? (d.antivirusUpToDate ? "Current" : "Outdated") : "Disabled", tone: d.antivirusEnabled ? (d.antivirusUpToDate ? .green : .orange) : .red).frame(width: 90, alignment: .leading)
                    Pill(d.detectionCount == 0 ? "Clean" : "\(d.detectionCount) threat\(d.detectionCount == 1 ? "" : "s")", tone: d.detectionCount == 0 ? .green : .red).frame(width: 90, alignment: .leading)
                    FlowLayout(spacing: 4) {
                        if d.isWindows {
                            Pill("TPM \(d.tpmPresent && d.tpmEnabled ? "On" : "Off")", tone: d.tpmPresent && d.tpmEnabled ? .green : .red)
                        } else if let sip = d.sipEnabled {
                            Pill("SIP \(sip ? "On" : "Off")", tone: sip ? .green : .red)
                        }
                        Pill("SB \(d.secureBootEnabled ? "On" : "Off")", tone: d.secureBootEnabled ? .green : .red)
                        if d.firmwarePasswordStatus == "Set" || d.firmwarePasswordStatus == "Not Set" {
                            Pill("FW \(d.firmwarePasswordStatus == "Set" ? "On" : "Off")", tone: d.firmwarePasswordStatus == "Set" ? .green : .red)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    Pill(d.firewallEnabled ? "On" : "Off", tone: .gray).frame(width: 70, alignment: .leading)
                    HStack(spacing: 4) {
                        if d.sshRunning { Pill("SSH", tone: .gray) }
                        if d.isWindows, d.rdpEnabled { Pill("RDP", tone: .gray) }
                        if !d.sshRunning, !(d.isWindows && d.rdpEnabled) { Text("None").appFont(.caption).foregroundStyle(.tertiary) }
                    }
                    .frame(width: 100, alignment: .leading)
                    HStack(spacing: 4) {
                        if d.expiredCertCount > 0 { Pill("\(d.expiredCertCount)", tone: .red) }
                        if d.expiringSoonCertCount > 0 { Pill("\(d.expiringSoonCertCount)", tone: .orange) }
                        if d.expiredCertCount == 0, d.expiringSoonCertCount == 0 { Text("OK").appFont(.caption).foregroundStyle(.green) }
                    }
                    .frame(width: 80, alignment: .leading)
                    HStack(spacing: 4) {
                        if d.cveCount > 0 {
                            if d.criticalCveCount > 0 { Pill("\(d.criticalCveCount)C", tone: .red) }
                            Text("\(d.cveCount)").appFont(.caption).foregroundStyle(.secondary)
                        } else {
                            Text("None").appFont(.caption).foregroundStyle(.green)
                        }
                    }
                    .frame(width: 110, alignment: .leading)
                }
                .padding(.horizontal, 16).padding(.vertical, 8)
                Divider()
            }
        }
    }
}
