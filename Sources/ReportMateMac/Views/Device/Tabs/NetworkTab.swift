import SwiftUI
import ReportMateKit

/// Network: active connections as cards on the left; VPN, quality, saved
/// Wi-Fi and inactive interfaces on the right.
struct NetworkTabView: View {
    let device: DeviceDetail
    @State private var showInactive = false
    @State private var wifiSearch = ""

    var body: some View {
        let net = NetworkInfo(modules: device.asJSON["modules"])
        let active = net.interfaces.filter(\.isActive).sorted { a, b in
            let ae = (a.type ?? "").lowercased().contains("ethernet") || (a.type ?? "").lowercased().contains("wired")
            let be = (b.type ?? "").lowercased().contains("ethernet") || (b.type ?? "").lowercased().contains("wired")
            return ae && !be
        }
        let inactive = net.interfaces.filter { !$0.isActive }
        let connectedVpns = net.vpnConnections.filter { ($0["status"].string ?? "").lowercased() == "connected" }
        let currentWiFi = net.raw["currentWiFiNetwork"]["output"].parsedIfString()
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                HStack(spacing: 12) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 10).fill(Color.teal.opacity(0.15))
                        Image(systemName: "globe").foregroundStyle(.teal).appFont(fixed: 20)
                    }
                    .frame(width: 44, height: 44)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Network").appFont(.title2, weight: .bold)
                        Text("\(active.count) active connection\(active.count == 1 ? "" : "s")\(connectedVpns.isEmpty ? "" : " • VPN connected")").appFont(.callout).foregroundStyle(.secondary)
                    }
                }
                Spacer()
                if let primary = active.first {
                    VStack(alignment: .trailing, spacing: 2) {
                        Text("Primary Connection").appFont(.caption).foregroundStyle(.secondary)
                        Text(primary.isWireless ? "Wireless" : "Ethernet").appFont(.title2, weight: .bold).foregroundStyle(.teal)
                    }
                }
            }
            HStack(alignment: .top, spacing: 16) {
                VStack(spacing: 12) {
                    if let host = net.raw["localHostname"].nonEmptyString ?? net.hostname {
                        Card {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(net.raw["localHostname"].nonEmptyString != nil ? "Local Hostname" : "Hostname").appFont(.caption, weight: .medium).foregroundStyle(.secondary)
                                HStack(spacing: 6) {
                                    Text(host).appFont(.title3, weight: .semibold, design: .monospaced).textSelection(.enabled)
                                    CopyButton(value: host)
                                }
                            }
                            .padding(.horizontal, 20).padding(.vertical, 14)
                            .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                    if active.isEmpty {
                        VStack(spacing: 8) {
                            Image(systemName: "exclamationmark.triangle").font(.system(size: 30)).foregroundStyle(.yellow)
                            Text("No active network connections").appFont(.headline).foregroundStyle(.yellow)
                        }
                        .frame(maxWidth: .infinity).padding(24)
                        .background(Color.yellow.opacity(0.08), in: RoundedRectangle(cornerRadius: 12))
                    } else {
                        ForEach(active) { iface in
                            ActiveConnectionCard(iface: iface, wifiData: iface.isWireless ? currentWiFi : .null, dnsServers: net.activeDnsServers.isEmpty ? iface.dnsServers : net.activeDnsServers)
                        }
                    }
                }
                .frame(maxWidth: .infinity)
                VStack(spacing: 12) {
                    if !net.vpnConnections.isEmpty {
                        Card {
                            VStack(spacing: 0) {
                                HStack {
                                    Label("VPN", systemImage: "lock.shield").appFont(.callout, weight: .semibold)
                                    Spacer()
                                    if !connectedVpns.isEmpty { Pill("\(connectedVpns.count) connected", tone: .purple) }
                                    Text("\(net.vpnConnections.count)").appFont(.caption).foregroundStyle(.secondary)
                                }
                                .padding(.horizontal, 14).padding(.vertical, 10)
                                .overlay(alignment: .bottom) { Divider() }
                                ForEach(Array(net.vpnConnections.enumerated()), id: \.offset) { _, vpn in
                                    let connected = (vpn["status"].string ?? "").lowercased() == "connected"
                                    HStack {
                                        VStack(alignment: .leading, spacing: 1) {
                                            Text(vpn["name"].string ?? "VPN").appFont(.body, weight: .medium).lineLimit(1)
                                            if let t = vpn["type"].nonEmptyString, t != "VPN" { Text(t).appFont(.caption).foregroundStyle(.secondary) }
                                            if let s = vpn["serverAddress"].nonEmptyString { Text(s).appFont(.caption, design: .monospaced).foregroundStyle(.tertiary).lineLimit(1) }
                                        }
                                        Spacer()
                                        Pill(connected ? "Connected" : "Off", tone: connected ? .green : .gray)
                                    }
                                    .padding(.horizontal, 14).padding(.vertical, 8)
                                    Divider().padding(.leading, 14)
                                }
                            }
                        }
                    }
                    if let q = net.networkQuality, q.hasCapacity || q.idleLatency != nil {
                        Card {
                            VStack(alignment: .leading, spacing: 10) {
                                Label("Network Quality", systemImage: "chart.bar").appFont(.callout, weight: .semibold)
                                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 8) {
                                    if let d = q.downlinkCapacity { qualityTile("Download", d) }
                                    if let u = q.uplinkCapacity { qualityTile("Upload", u) }
                                    if let l = q.idleLatency { qualityTile("Latency", l) }
                                    if let r = q.downlinkResponsiveness { qualityTile("Quality", r) }
                                    if let j = q.jitter { qualityTile("Jitter", j) }
                                    if let s = q.serverName { qualityTile("Server", s) }
                                }
                            }
                            .padding(14)
                        }
                    }
                    if !net.wifiNetworks.isEmpty {
                        let filtered = net.wifiNetworks.filter { wifiSearch.isEmpty || $0.ssid.lowercased().contains(wifiSearch.lowercased()) }.sorted { $0.ssid.localizedCaseInsensitiveCompare($1.ssid) == .orderedAscending }
                        Card {
                            VStack(spacing: 0) {
                                VStack(spacing: 8) {
                                    HStack {
                                        Label("Saved WiFi", systemImage: "wifi").appFont(.callout, weight: .semibold)
                                        Spacer()
                                        Text("\(net.wifiNetworks.count)").appFont(.caption).foregroundStyle(.secondary)
                                    }
                                    HStack(spacing: 6) {
                                        Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                                        TextField("Search networks…", text: $wifiSearch).textFieldStyle(.plain).appFont(.caption)
                                    }
                                    .padding(.horizontal, 8).padding(.vertical, 5)
                                    .background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 7))
                                }
                                .padding(.horizontal, 14).padding(.vertical, 10)
                                .overlay(alignment: .bottom) { Divider() }
                                ScrollView {
                                    VStack(spacing: 0) {
                                        if filtered.isEmpty {
                                            Text("No networks match “\(wifiSearch)”").appFont(.caption).foregroundStyle(.secondary).padding(10)
                                        }
                                        ForEach(filtered) { n in
                                            HStack {
                                                Text(n.ssid).appFont(.body).lineLimit(1)
                                                Spacer()
                                                if n.isConnected { Pill("Connected", tone: .green) }
                                                if n.security != "Unknown" { Text(n.security).appFont(.caption).foregroundStyle(.tertiary) }
                                            }
                                            .padding(.horizontal, 14).padding(.vertical, 6)
                                            Divider().padding(.leading, 14)
                                        }
                                    }
                                }
                                .frame(maxHeight: 220)
                            }
                        }
                    }
                    if !inactive.isEmpty {
                        VStack(spacing: 0) {
                            Button { withAnimation { showInactive.toggle() } } label: {
                                HStack(spacing: 8) {
                                    Image(systemName: "chevron.right").rotationEffect(.degrees(showInactive ? 90 : 0)).foregroundStyle(.secondary).appFont(.caption)
                                    Text("\(inactive.count) Inactive").appFont(.callout).foregroundStyle(.secondary)
                                    Spacer()
                                }
                                .padding(12).contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            if showInactive {
                                VStack(spacing: 0) {
                                    ForEach(inactive) { iface in
                                        HStack {
                                            Text(iface.name).appFont(.callout).foregroundStyle(.secondary)
                                            Spacer()
                                            Text(iface.type ?? "").appFont(.caption).foregroundStyle(.tertiary)
                                        }
                                        .padding(.horizontal, 12).padding(.vertical, 6)
                                        Divider()
                                    }
                                }
                                .background(Color.cardBackground, in: RoundedRectangle(cornerRadius: 8))
                                .padding([.horizontal, .bottom], 12)
                            }
                        }
                        .background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 12))
                        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.cardBorder))
                    }
                }
                .frame(width: 320)
            }
            JSONTreeView(value: device[.network], label: "device.modules.network")
        }
    }

    private func qualityTile(_ label: String, _ value: String) -> some View {
        VStack(spacing: 2) {
            Text(label).appFont(.caption).foregroundStyle(.secondary)
            Text(value).appFont(.headline)
        }
        .frame(maxWidth: .infinity).padding(10)
        .background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 8))
    }
}

/// An active Ethernet or Wireless interface with its addresses and Wi-Fi details.
struct ActiveConnectionCard: View {
    let iface: NetworkInfo.Interface
    let wifiData: JSONValue
    let dnsServers: [String]

    var body: some View {
        let wireless = iface.isWireless
        let ipv4 = iface.ipAddress.flatMap { NetworkInfo.isIPv4($0) ? $0 : nil } ?? iface.ipAddresses.first(where: NetworkInfo.isIPv4)
        Card {
            VStack(spacing: 0) {
                HStack(spacing: 10) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 8).fill((wireless ? Color.blue : Color.green).opacity(0.15))
                        Image(systemName: wireless ? "wifi" : "cable.connector").foregroundStyle(wireless ? Color.blue : Color.green)
                    }
                    .frame(width: 38, height: 38)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(wireless ? "Wireless" : "Ethernet").appFont(.title3, weight: .semibold)
                        Text(iface.name + ((iface.friendlyName != nil && iface.friendlyName != iface.name) ? " • \(iface.friendlyName!)" : "")).appFont(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    HStack(spacing: 6) {
                        Circle().fill(Color.green).frame(width: 8, height: 8)
                        Text("Connected").appFont(.callout, weight: .semibold).foregroundStyle(.green)
                    }
                    .padding(.horizontal, 10).padding(.vertical, 5).background(Color.green.opacity(0.12), in: Capsule())
                }
                .padding(.horizontal, 18).padding(.vertical, 12)
                .overlay(alignment: .bottom) { Divider() }
                HStack(alignment: .top, spacing: 24) {
                    VStack(spacing: 0) {
                        infoRow("IP Address", ipv4, mono: true)
                        infoRow("MAC Address", iface.macAddress, mono: true)
                        ForEach(Array(dnsServers.enumerated()), id: \.offset) { i, dns in infoRow(i == 0 ? "DNS Server" : "", dns, mono: true, copy: false) }
                        infoRow("Link Speed", iface.linkSpeed, copy: false)
                        if !wireless { infoRow("Duplex", nil, copy: false) }
                    }
                    .frame(maxWidth: .infinity)
                    if wireless {
                        VStack(spacing: 0) {
                            infoRow("SSID", (wifiData["ssid"].nonEmptyString).flatMap { $0 == "[Location Services Required]" ? nil : $0 } ?? iface.ssid, copy: false)
                            infoRow("Protocol", wifiData["wifi_version"].nonEmptyString ?? iface.wirelessProtocol, copy: false)
                            infoRow("Band", wifiData["channel_band"].nonEmptyString ?? iface.wirelessBand, copy: false)
                            infoRow("Channel", wifiData["channel"].string ?? iface.channel, copy: false)
                            infoRow("Security", wifiData["security"].nonEmptyString, copy: false)
                            infoRow("Mode", wifiData.firstString("phyMode", "phy_mode", "mode"), copy: false)
                        }
                        .frame(maxWidth: .infinity)
                    }
                }
                .padding(18)
            }
        }
    }

    @ViewBuilder
    private func infoRow(_ label: String, _ value: String?, mono: Bool = false, copy: Bool = true) -> some View {
        if let value, !value.isEmpty {
            HStack(alignment: .top, spacing: 12) {
                Text(label).appFont(.callout).foregroundStyle(.secondary).frame(width: 110, alignment: .leading)
                HStack(spacing: 6) {
                    Text(value).appFont(.callout, weight: .medium, design: mono ? .monospaced : .default).textSelection(.enabled)
                    if copy { CopyButton(value: value) }
                }
                Spacer(minLength: 0)
            }
            .padding(.vertical, 5)
            Divider().opacity(0.5)
        }
    }
}
