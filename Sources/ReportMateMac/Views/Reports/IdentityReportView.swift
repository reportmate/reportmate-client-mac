import SwiftUI
import Charts
import ReportMateKit

/// Fleet identity report: directory, authentication and administrator
/// widgets, the device table, and the admins and utilization reports.
/// Port of `app/identity/page.tsx`.
struct IdentityReportView: View {
    @Environment(AppState.self) private var appState
    @State private var model = FleetReportModel(path: "/identity")

    enum Column { case device, directory, auth, users, loggedIn, lastSeen }
    enum TokenFilter { case withToken, missingToken }
    enum BootstrapFilter { case escrowed, notEscrowed }

    @State private var sortColumn: Column = .device
    @State private var ascending = true
    @State private var noAdminsOnly = false
    @State private var showAdminsReport = false
    @State private var showUtilization = false
    @State private var directoryFilter: String? = nil
    @State private var authFilter: String? = nil
    @State private var adminAccountFilter: String? = nil
    @State private var tokenFilter: TokenFilter? = nil
    @State private var bootstrapFilter: BootstrapFilter? = nil
    @State private var domainExpanded = false

    private func i(_ row: ReportRow) -> IdentityReportRow { IdentityReportRow(json: row.json) }

    private var widgetLabels: [String] {
        [directoryFilter, authFilter, adminAccountFilter.map { "Admin: \($0)" }, showAdminsReport ? "Admins Report" : nil,
         tokenFilter.map { $0 == .withToken ? "SecureToken: holders" : "SecureToken: missing" },
         bootstrapFilter.map { $0 == .escrowed ? "Bootstrap: escrowed" : "Bootstrap: not escrowed" }].compactMap { $0 }
    }

    private func clearWidgetFilters() {
        directoryFilter = nil; authFilter = nil; adminAccountFilter = nil; showAdminsReport = false; tokenFilter = nil; bootstrapFilter = nil
    }

    private func filtered(_ rows: [ReportRow]) -> [(row: ReportRow, i: IdentityReportRow)] {
        rows.map { ($0, i($0)) }.filter { pair in
            let d = pair.i
            if noAdminsOnly, d.adminUsers > 0 { return false }
            if let directoryFilter {
                switch directoryFilter {
                case "Broken", "Unconfirmed", "Trusted": if d.trustLabel != directoryFilter { return false }
                default: if d.enrollmentType != directoryFilter { return false }
                }
            }
            if let adminAccountFilter, !d.hasAdmin(adminAccountFilter) { return false }
            if tokenFilter == .withToken, d.secureTokenUsers == 0 { return false }
            if tokenFilter == .missingToken, d.secureTokenMissing == 0 { return false }
            if bootstrapFilter == .escrowed, !(d.hasBootstrapData && d.bootstrapEscrowed) { return false }
            if bootstrapFilter == .notEscrowed, !(d.hasBootstrapData && !d.bootstrapEscrowed) { return false }
            if let authFilter, d.authLabel != authFilter { return false }
            return true
        }.sorted { a, b in
            switch sortColumn {
            case .device: return ordered(a.row.deviceName.lowercased(), b.row.deviceName.lowercased())
            case .directory: return ordered((a.i.enrollmentType ?? "").lowercased(), (b.i.enrollmentType ?? "").lowercased())
            case .auth: return ordered((a.i.authMethod ?? "").lowercased(), (b.i.authMethod ?? "").lowercased())
            case .users: return ascending ? a.i.totalUsers < b.i.totalUsers : a.i.totalUsers > b.i.totalUsers
            case .loggedIn: return ascending ? a.i.currentlyLoggedIn < b.i.currentlyLoggedIn : a.i.currentlyLoggedIn > b.i.currentlyLoggedIn
            case .lastSeen: return ascending ? (a.row.lastSeen ?? .distantPast) < (b.row.lastSeen ?? .distantPast) : (a.row.lastSeen ?? .distantPast) > (b.row.lastSeen ?? .distantPast)
            }
        }
    }

    private func ordered(_ a: String, _ b: String) -> Bool { ascending ? a < b : a > b }

    var body: some View {
        FleetReportContainer(
            section: .identity, model: model, subtitle: "User accounts, sessions, and identity management", searchPlaceholder: "Search devices or users...",
            searchKeys: { row in
                let d = IdentityReportRow(json: row.json)
                return [row.deviceName, row.serialNumber] + d.usernames + d.loggedInUsernames
            },
            toolbar: { rows in
                Toggle(isOn: $showAdminsReport) { Label("Admins Report", systemImage: "checkmark.shield") }.toggleStyle(.button).help("Flat per-(admin, device) report for security review")
                if showAdminsReport {
                    Toggle(isOn: Binding(get: { noAdminsOnly }, set: { on in noAdminsOnly = on; if on { showAdminsReport = false } })) { Label("No Admin Users", systemImage: "exclamationmark.triangle") }.toggleStyle(.button).tint(.yellow)
                }
                if rows.contains(where: { (IdentityReportRow(json: $0.json).sessionSummary?.totalSessions ?? 0) > 0 }) {
                    Toggle(isOn: $showUtilization) { Label(showUtilization ? "Back to List" : "Utilization Report", systemImage: "chart.bar") }.toggleStyle(.button).help("Show session utilization report for devices with RDP data")
                }
                CSVExportButton(filename: "identity-report", headers: ["Device Name", "Serial Number", "Platform", "Total Users", "Admin Users", "Currently Logged In", "Last Seen"]) {
                    filtered(rows).map { p in [p.row.deviceName, p.row.serialNumber, p.i.platformText, String(p.i.totalUsers), String(p.i.adminUsers), String(p.i.currentlyLoggedIn), p.row.json["lastSeen"].string ?? ""] }
                }
            },
            widgets: { rows in widgets(rows.map(i)) }
        ) { rows in
            let pairs = filtered(rows)
            VStack(spacing: 0) {
                ActiveFiltersBar(labels: widgetLabels, clear: clearWidgetFilters)
                if showAdminsReport { adminsReport(pairs) }
                else if showUtilization { utilization(pairs) }
                else { table(pairs) }
            }
        }
    }

    // MARK: Widgets

    private func widgets(_ all: [IdentityReportRow]) -> some View {
        HStack(alignment: .top, spacing: 12) {
            directoryWidget(all).frame(width: 320)
            authWidget(all).frame(width: 300)
            adminsWidget(all).frame(width: 320)
        }
    }

    private static let directoryOrder = ["Cloud Joined", "Domain Joined", "Standard", "Unjoined"]
    private static let directoryColors: [String: Color] = ["Cloud Joined": .green, "Domain Joined": .orange, "Standard": .blue, "Unjoined": .red]
    private static let trustColors: [String: Color] = ["Trusted": .yellow, "Unconfirmed": .orange, "Broken": .red]

    private func directoryWidget(_ all: [IdentityReportRow]) -> some View {
        let entries = countLabels(all.compactMap(\.enrollmentType).filter { $0 != "Unknown" })
            .sorted { (Self.directoryOrder.firstIndex(of: $0.label) ?? 99) < (Self.directoryOrder.firstIndex(of: $1.label) ?? 99) }
        let trust: [(label: String, count: Int)] = ["Trusted", "Unconfirmed", "Broken"].map { l in (label: l, count: all.filter { $0.trustLabel == l }.count) }
        let hasTrust = trust.contains { $0.count > 0 }
        var segments: [(label: String, count: Int, color: Color)] = []
        for e in entries {
            if e.label == "Domain Joined", domainExpanded, hasTrust {
                segments += trust.filter { $0.count > 0 }.map { ($0.label, $0.count, Self.trustColors[$0.label] ?? .gray) }
            } else {
                segments.append((e.label, e.count, Self.directoryColors[e.label] ?? .gray))
            }
        }
        return ReportWidgetBox(title: "Directory Services") {
            if entries.isEmpty {
                Text("No data available").appFont(.caption).foregroundStyle(.tertiary)
            } else {
                HStack(alignment: .top, spacing: 12) {
                    Chart(segments, id: \.label) { s in
                        SectorMark(angle: .value("Count", s.count), innerRadius: .ratio(0.62), angularInset: 1).foregroundStyle(s.color)
                    }
                    .frame(width: 90, height: 90)
                    VStack(alignment: .leading, spacing: 3) {
                        ForEach(entries, id: \.label) { e in
                            let expandable = e.label == "Domain Joined" && hasTrust
                            HStack(spacing: 4) {
                                if expandable {
                                    Button { domainExpanded.toggle() } label: { Image(systemName: "chevron.right").rotationEffect(.degrees(domainExpanded ? 90 : 0)).appFont(.caption2).foregroundStyle(.secondary) }.buttonStyle(.plain)
                                } else {
                                    Color.clear.frame(width: 10, height: 1)
                                }
                                legendButton(e.label, e.count, Self.directoryColors[e.label] ?? .gray, selected: directoryFilter == e.label) { directoryFilter = directoryFilter == e.label ? nil : e.label }
                            }
                            if expandable, domainExpanded {
                                VStack(alignment: .leading, spacing: 2) {
                                    ForEach(trust.filter { $0.count > 0 }, id: \.label) { t in
                                        legendButton(t.label, t.count, Self.trustColors[t.label] ?? .gray, selected: directoryFilter == t.label, small: true) { directoryFilter = directoryFilter == t.label ? nil : t.label }
                                    }
                                }
                                .padding(.leading, 18)
                                .overlay(alignment: .leading) { Rectangle().fill(Color.cardBorder).frame(width: 2).padding(.leading, 12) }
                            }
                        }
                    }
                }
            }
        }
    }

    private func legendButton(_ label: String, _ count: Int, _ color: Color, selected: Bool, small: Bool = false, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 6) {
                Circle().fill(color).frame(width: small ? 6 : 8, height: small ? 6 : 8)
                Text(label).appFont(small ? .caption2 : .caption).lineLimit(1)
                Spacer()
                Text("\(count)").appFont(small ? .caption2 : .caption, weight: .medium).monospacedDigit()
            }
            .padding(.horizontal, 4).padding(.vertical, 2)
            .background(selected ? Color.blue.opacity(0.15) : Color.clear, in: RoundedRectangle(cornerRadius: 4))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private func authWidget(_ all: [IdentityReportRow]) -> some View {
        let data: [(label: String, value: Int)] = [("Modern", all.filter { $0.authLabel == "Modern" }.count), ("Legacy", all.filter { $0.authLabel == "Legacy" }.count), ("Standard", all.filter { $0.authLabel == "Standard" }.count)].filter { $0.value > 0 }
        let isMac = appState.platformFilter == .macOS
        return VStack(spacing: 0) {
            MiniDonutWidget(title: "Authentication", data: data, colors: ["Modern": .green, "Legacy": .orange, "Standard": .blue], selected: $authFilter)
            if isMac, !all.isEmpty {
                let holders = all.filter { $0.secureTokenUsers > 0 }.count
                let missing = all.filter { $0.secureTokenMissing > 0 }.count
                let escrowed = all.filter { $0.hasBootstrapData && $0.bootstrapEscrowed }.count
                let notEscrowed = all.filter { $0.hasBootstrapData && !$0.bootstrapEscrowed }.count
                VStack(alignment: .leading, spacing: 6) {
                    SectionLabel("SecureToken")
                    tokenRow("Token holders", holders, on: tokenFilter == .withToken, tone: .green) { tokenFilter = tokenFilter == .withToken ? nil : .withToken }
                    tokenRow("Users missing token", missing, on: tokenFilter == .missingToken, tone: missing > 0 ? .orange : nil) { tokenFilter = tokenFilter == .missingToken ? nil : .missingToken }
                    if all.contains(where: \.hasBootstrapData) {
                        SectionLabel("Bootstrap Token").padding(.top, 4)
                        tokenRow("Escrowed", escrowed, on: bootstrapFilter == .escrowed, tone: .green) { bootstrapFilter = bootstrapFilter == .escrowed ? nil : .escrowed }
                        tokenRow("Not escrowed", notEscrowed, on: bootstrapFilter == .notEscrowed, tone: notEscrowed > 0 ? .orange : nil) { bootstrapFilter = bootstrapFilter == .notEscrowed ? nil : .notEscrowed }
                    }
                }
                .padding(.horizontal, 12).padding(.bottom, 12)
            }
        }
        .background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 10))
    }

    private func tokenRow(_ label: String, _ count: Int, on: Bool, tone: Tone?, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack {
                Text(label).appFont(.caption)
                Spacer()
                Text("\(count)").appFont(.caption, weight: .medium).monospacedDigit().foregroundStyle(tone?.color ?? .primary)
            }
            .padding(.horizontal, 4).padding(.vertical, 2)
            .background(on ? Color.yellow.opacity(0.18) : Color.clear, in: RoundedRectangle(cornerRadius: 4))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help("Filter to \(label)")
    }

    private func adminsWidget(_ all: [IdentityReportRow]) -> some View {
        var counts: [String: (display: String, count: Int)] = [:]
        for d in all {
            var seen = Set<String>()
            for raw in d.adminUsernames {
                let key = raw.lowercased()
                guard !seen.contains(key) else { continue }
                seen.insert(key)
                counts[key, default: (raw, 0)].count += 1
            }
        }
        let entries = counts.values.sorted { $0.count != $1.count ? $0.count > $1.count : $0.display < $1.display }
        let maxCount = entries.first?.count ?? 0
        return ReportWidgetBox(title: "Administrator Accounts") {
            if entries.isEmpty {
                Text("No admin accounts found").appFont(.caption).foregroundStyle(.tertiary)
            } else {
                ScrollView {
                    VStack(spacing: 4) {
                        ForEach(entries, id: \.display) { e in
                            let on = adminAccountFilter?.lowercased() == e.display.lowercased()
                            Button { adminAccountFilter = on ? nil : e.display } label: {
                                VStack(alignment: .leading, spacing: 3) {
                                    HStack {
                                        Text(e.display).appFont(.caption, weight: .medium).lineLimit(1).foregroundStyle(on ? Color.yellow : Color.primary)
                                        Spacer()
                                        Text("\(e.count)").appFont(.caption).foregroundStyle(.secondary).monospacedDigit()
                                    }
                                    GeometryReader { geo in
                                        Capsule().fill(Color.yellow.opacity(on ? 1 : 0.7)).frame(width: maxCount > 0 ? geo.size.width * CGFloat(e.count) / CGFloat(maxCount) : 0)
                                    }
                                    .frame(height: 6)
                                }
                                .padding(.horizontal, 4).padding(.vertical, 2)
                                .background(on ? Color.yellow.opacity(0.15) : Color.clear, in: RoundedRectangle(cornerRadius: 4))
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            .help("Filter devices with admin “\(e.display)”")
                        }
                    }
                }
                .frame(maxHeight: 200)
            }
        }
    }

    // MARK: Tables

    private static let dirTones: [String: Tone] = ["Cloud Joined": .purple, "Domain Joined": .orange, "Standard": .blue, "Unjoined": .red]

    private func table(_ pairs: [(row: ReportRow, i: IdentityReportRow)]) -> some View {
        ReportTable {
            ReportSortHeader(title: "Device", column: .device, sortColumn: $sortColumn, ascending: $ascending, width: 240)
            ReportSortHeader(title: "Directory", column: .directory, sortColumn: $sortColumn, ascending: $ascending)
            ReportSortHeader(title: "Auth", column: .auth, sortColumn: $sortColumn, ascending: $ascending)
            ReportSortHeader(title: "Users", column: .users, sortColumn: $sortColumn, ascending: $ascending, width: 130)
            ReportSortHeader(title: "Current", column: .loggedIn, sortColumn: $sortColumn, ascending: $ascending, width: 170)
            ReportSortHeader(title: "Last Seen", column: .lastSeen, sortColumn: $sortColumn, ascending: $ascending, width: 110)
        } rows: {
            if pairs.isEmpty { ReportEmptyRows(title: "No identity records found", message: "No identity records match your current filters.", systemImage: "person.2") }
            ForEach(pairs, id: \.row.id) { pair in
                let d = pair.i
                HStack(alignment: .top, spacing: 12) {
                    VStack(alignment: .leading, spacing: 2) {
                        DeviceLink(row: pair.row, tab: .identity)
                        Text("\(pair.row.serialNumber) | \(d.platformText)").appFont(.caption2, design: .monospaced).foregroundStyle(.secondary).lineLimit(1)
                    }
                    .frame(width: 240, alignment: .leading)
                    VStack(alignment: .leading, spacing: 3) {
                        Pill(d.enrollmentType ?? "Unknown", tone: Self.dirTones[d.enrollmentType ?? ""] ?? .gray)
                        if let t = d.trustLabel, t != "Trusted" { Pill((t == "Broken" ? "⚠ " : "ⓘ ") + t, tone: t == "Broken" ? .red : .orange) }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    Group {
                        if let m = d.authMethod { Pill(m, tone: .emerald) }
                        else if d.adBound || d.ldapBound { Pill("Legacy", tone: .orange) }
                        else { Pill("Standard", tone: .blue) }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    VStack(alignment: .leading, spacing: 3) {
                        HStack(spacing: 4) {
                            Text("\(d.totalUsers)").appFont(.callout, weight: .medium)
                            Text(d.adminUsers == 0 ? "(no admins)" : "(\(d.adminUsers) admin\(d.adminUsers == 1 ? "" : "s"))").appFont(.caption2).foregroundStyle(d.adminUsers == 0 ? .yellow : .secondary)
                        }
                        if let f = adminAccountFilter {
                            FlowLayout(spacing: 3) {
                                ForEach(d.adminUsernames.filter { $0.lowercased() == f.lowercased() }, id: \.self) { Pill($0, tone: .yellow) }
                            }
                        }
                    }
                    .frame(width: 130, alignment: .leading)
                    Group {
                        if d.currentlyLoggedIn > 0, !d.loggedInUsernames.isEmpty {
                            FlowLayout(spacing: 3) { ForEach(d.loggedInUsernames, id: \.self) { Pill("● \($0)", tone: .green) } }
                        } else if d.currentlyLoggedIn > 0 {
                            Pill("● \(d.currentlyLoggedIn) logged in", tone: .green)
                        } else {
                            Text("-").foregroundStyle(.tertiary)
                        }
                    }
                    .frame(width: 170, alignment: .leading)
                    Text(pair.row.lastSeen.map { TimeFormatting.relative($0) } ?? "-").appFont(.callout).frame(width: 110, alignment: .leading)
                }
                .padding(.horizontal, 16).padding(.vertical, 8)
                Divider()
            }
        }
    }

    private func adminsReport(_ pairs: [(row: ReportRow, i: IdentityReportRow)]) -> some View {
        var rows: [(admin: String, row: ReportRow, i: IdentityReportRow)] = []
        for p in pairs {
            for a in p.i.adminUsernames {
                if let f = adminAccountFilter, a.lowercased() != f.lowercased() { continue }
                rows.append((a, p.row, p.i))
            }
        }
        rows.sort { a, b in
            let c = a.admin.lowercased().compare(b.admin.lowercased())
            if c != .orderedSame { return c == .orderedAscending }
            return a.row.deviceName.lowercased() < b.row.deviceName.lowercased()
        }
        return VStack(spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Local Administrators Report").appFont(.headline)
                    HStack(spacing: 6) {
                        Text("\(rows.count) admin assignments across \(pairs.count) devices.").appFont(.caption).foregroundStyle(.secondary)
                        if let f = adminAccountFilter { Text("Filtered to: \(f)").appFont(.caption, design: .monospaced).foregroundStyle(.yellow) }
                    }
                }
                Spacer()
                CSVExportButton(filename: "local-admins", headers: ["Admin Account", "Device Name", "Serial Number", "Platform", "Last Seen"]) {
                    rows.map { [$0.admin, $0.row.deviceName, $0.row.serialNumber, $0.i.platformText, $0.row.json["lastSeen"].string ?? ""] }
                }
            }
            .padding(16)
            ReportTable {
                ReportHeaderLabel(title: "Admin Account", width: 220)
                ReportHeaderLabel(title: "Device")
                ReportHeaderLabel(title: "Platform", width: 100)
                ReportHeaderLabel(title: "Last Seen", width: 120)
            } rows: {
                if rows.isEmpty { ReportEmptyRows(title: "No local admin accounts found.", message: "", systemImage: "person.badge.shield.checkmark") }
                ForEach(Array(rows.enumerated()), id: \.offset) { _, r in
                    let on = adminAccountFilter?.lowercased() == r.admin.lowercased()
                    HStack(spacing: 12) {
                        Button { adminAccountFilter = on ? nil : r.admin } label: { Pill(r.admin, tone: .yellow, filled: on) }.buttonStyle(.plain).help("Click to filter by this admin").frame(width: 220, alignment: .leading)
                        VStack(alignment: .leading, spacing: 2) {
                            DeviceLink(row: r.row, tab: .identity)
                            Text(r.row.serialNumber).appFont(.caption2, design: .monospaced).foregroundStyle(.secondary)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        Text(r.i.platformText).appFont(.callout).frame(width: 100, alignment: .leading)
                        Text(r.row.lastSeen.map { TimeFormatting.relative($0) } ?? "-").appFont(.callout).frame(width: 120, alignment: .leading)
                    }
                    .padding(.horizontal, 16).padding(.vertical, 6)
                    Divider()
                }
            }
        }
    }

    private func utilization(_ pairs: [(row: ReportRow, i: IdentityReportRow)]) -> some View {
        let devices = pairs.filter { ($0.i.sessionSummary?.totalSessions ?? 0) > 0 }.sorted { ($0.i.sessionSummary?.totalSessions ?? 0) > ($1.i.sessionSummary?.totalSessions ?? 0) }
        let totalSessions = devices.reduce(0) { $0 + ($1.i.sessionSummary?.totalSessions ?? 0) }
        let uniqueUsers = devices.reduce(0) { $0 + ($1.i.sessionSummary?.uniqueUsers ?? 0) }
        let avgs = devices.compactMap { $0.i.sessionSummary?.avgSessionMinutes }.filter { $0 > 0 }
        let fleetAvg = avgs.isEmpty ? 0 : avgs.reduce(0, +) / Double(avgs.count)
        return VStack(spacing: 16) {
            HStack(spacing: 12) {
                summaryCard("\(devices.count)", "Devices with Sessions", .indigo)
                summaryCard(ByteFormatting.count(totalSessions), "Total Sessions", .blue)
                summaryCard("\(uniqueUsers)", "Total Unique Users", .green)
                summaryCard(IdentityInfo.minutes(fleetAvg), "Avg Session Duration", .orange)
            }
            .padding(.horizontal, 16).padding(.top, 16)
            ReportTable {
                ReportHeaderLabel(title: "Device")
                ReportHeaderLabel(title: "Sessions", width: 100)
                ReportHeaderLabel(title: "Unique Users", width: 110)
                ReportHeaderLabel(title: "Avg Duration", width: 110)
                ReportHeaderLabel(title: "Median Duration", width: 120)
                ReportHeaderLabel(title: "Last Seen", width: 120)
            } rows: {
                if devices.isEmpty {
                    ReportEmptyRows(title: "No devices have session history data yet.", message: "Session data is collected from TerminalServices event logs on Windows devices.", systemImage: "clock")
                }
                ForEach(devices, id: \.row.id) { p in
                    let s = p.i.sessionSummary
                    HStack(spacing: 12) {
                        VStack(alignment: .leading, spacing: 2) {
                            DeviceLink(row: p.row, tab: .identity)
                            Text(p.row.serialNumber).appFont(.caption2, design: .monospaced).foregroundStyle(.secondary)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        Text(ByteFormatting.count(s?.totalSessions ?? 0)).appFont(.callout, weight: .medium).frame(width: 100, alignment: .trailing)
                        Text("\(s?.uniqueUsers ?? 0)").appFont(.callout, weight: .medium).frame(width: 110, alignment: .trailing)
                        Text(IdentityInfo.minutes(s?.avgSessionMinutes ?? 0)).appFont(.callout).frame(width: 110, alignment: .trailing)
                        Text(IdentityInfo.minutes(s?.medianSessionMinutes ?? 0)).appFont(.callout).frame(width: 120, alignment: .trailing)
                        Text(p.row.lastSeen.map { TimeFormatting.relative($0) } ?? "-").appFont(.callout).frame(width: 120, alignment: .leading)
                    }
                    .padding(.horizontal, 16).padding(.vertical, 8)
                    Divider()
                }
            }
        }
    }

    private func summaryCard(_ value: String, _ label: String, _ tone: Tone) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(value).appFont(.title, weight: .bold).foregroundStyle(tone.color)
            Text(label).appFont(.caption).foregroundStyle(tone.color.opacity(0.8))
        }
        .padding(14).frame(maxWidth: .infinity, alignment: .leading)
        .background(tone.color.opacity(0.08), in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(tone.color.opacity(0.3)))
    }
}
