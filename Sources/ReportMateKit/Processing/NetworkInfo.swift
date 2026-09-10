import Foundation

/// Network facts, ported from `data-processing/modules/network.ts`.
public struct NetworkInfo: Sendable, Hashable {
    public struct Interface: Sendable, Hashable, Identifiable {
        public var id: String { name + (macAddress ?? "") }
        public var name: String
        public var friendlyName: String?
        public var ipAddress: String?
        public var ipAddresses: [String]
        public var macAddress: String?
        public var type: String?
        public var isActive: Bool
        public var status: String
        public var mtu: Int?
        public var linkSpeed: String?
        public var wirelessProtocol: String?
        public var wirelessBand: String?
        public var ssid: String?
        public var channel: String?
        public var dnsServers: [String]
        public var bytesSent: Double?
        public var bytesReceived: Double?

        public var isWireless: Bool {
            let t = (type ?? "").lowercased()
            return t == "wireless" || t == "wifi" || t.contains("wifi") || t.contains("wireless") || name == "en0" && t.isEmpty
        }

        public var isEthernet: Bool {
            let t = (type ?? "").lowercased()
            return t == "ethernet" || name == "en1" || t.contains("ethernet")
        }
    }

    public struct WiFiInterface: Sendable, Hashable {
        public var ssid: String?
        public var protocolName: String?
        public var channel: String?
        public var band: String?
        public var signalStrength: String?
        public var ipAddress: String?
        public var macAddress: String?
    }

    public struct WiFiNetwork: Sendable, Hashable, Identifiable {
        public var id: String { ssid }
        public var ssid: String
        public var security: String
        public var isConnected: Bool
        public var channel: String?
        public var signalStrength: String?
        public var raw: JSONValue
    }

    public struct Quality: Sendable, Hashable {
        public var uplinkCapacity: String?
        public var downlinkCapacity: String?
        public var uplinkResponsiveness: String?
        public var downlinkResponsiveness: String?
        public var idleLatency: String?
        public var jitter: String?
        public var serverName: String?
        public var source: String?
        public var raw: String?

        public var hasCapacity: Bool { uplinkCapacity != nil || downlinkCapacity != nil }
    }

    public var ipAddress: String?
    public var macAddress: String?
    public var hostname: String?
    public var gateway: String?
    public var connectionType: String?
    public var interfaceName: String?
    public var ssid: String?
    public var signalStrength: String?
    public var vpnName: String?
    public var vpnActive: Bool
    public var vpnConnections: [JSONValue]
    public var dns: JSONValue
    public var activeDnsServers: [String]
    public var dnsAddress: String?
    public var interfaces: [Interface]
    public var wifiNetworks: [WiFiNetwork]
    public var wifiInterface: WiFiInterface?
    public var activeWifiSsid: String?
    public var networkQuality: Quality?
    public var routes: [JSONValue]
    public var raw: JSONValue

    public var activeInterfaces: [Interface] { interfaces.filter(\.isActive) }
    public var ethernetInterface: Interface? { activeInterfaces.first(where: \.isEthernet) }
    public var wirelessInterface: Interface? { activeInterfaces.first(where: \.isWireless) }

    public init(modules: JSONValue) {
        let network = modules["network"].unwrappingSingleton()
        raw = network
        vpnActive = false
        vpnConnections = []
        dns = .null
        activeDnsServers = []
        interfaces = []
        wifiNetworks = []
        routes = []
        guard !network.isNull else { return }

        // Active connection
        let active = network.first("active_connection", "activeConnection")
        var isVpnTunnel = false
        if !active.isNull {
            var primaryInterface = active.firstString("interface_name", "interfaceName", "interface", "friendly_name", "friendlyName")
            var primaryIP = active.firstString("ip_address", "ipAddress")
            var primaryType = active.firstString("connection_type", "connectionType")
            isVpnTunnel = (primaryInterface ?? "").hasPrefix("utun") || (primaryInterface ?? "").hasPrefix("ppp")
            if isVpnTunnel, let ifaces = network["interfaces"].array {
                let physical = ifaces.first { iface in
                    let hasIP = iface["addresses"].elements.contains { $0["family"].string == "IPv4" && ($0["address"].string ?? "").isEmpty == false && !($0["address"].string ?? "").hasPrefix("127.") }
                        || ((iface["address"].string ?? "").isEmpty == false && !(iface["address"].string ?? "").hasPrefix("127."))
                    let t = iface["type"].string ?? ""
                    return hasIP && (t == "Ethernet" || t == "WiFi" || t == "Wireless")
                }
                if let physical {
                    primaryInterface = physical.firstString("displayName", "name", "interface")
                    if let ipv4 = physical["addresses"].elements.first(where: { $0["family"].string == "IPv4" })?["address"].nonEmptyString {
                        primaryIP = ipv4
                    } else if let addr = physical["address"].nonEmptyString {
                        primaryIP = addr
                    }
                    primaryType = physical["type"].nonEmptyString ?? "Ethernet"
                }
            }
            ipAddress = primaryIP
            macAddress = active.firstString("mac_address", "macAddress")
            gateway = active["gateway"].nonEmptyString
            connectionType = primaryType
            interfaceName = primaryInterface
            ssid = active.firstString("active_wifi_ssid", "activeWifiSsid")
            signalStrength = active.firstString("wifi_signal_strength", "wifiSignalStrength")
            vpnName = active.firstString("vpn_name", "vpnName")
            vpnActive = active["is_vpn_active"].boolish || active["isVpnActive"].boolish || isVpnTunnel
            if macAddress == nil, let ifaces = network["interfaces"].array {
                var activeIface = ifaces.first { ($0["name"].string ?? $0["interface"].string) == interfaceName }
                if activeIface?.firstString("macAddress", "mac_address", "mac") == nil {
                    activeIface = ifaces.first { $0.firstString("macAddress", "mac_address", "mac") != nil && ["Ethernet", "WiFi", "Wireless"].contains($0["type"].string ?? "") }
                }
                macAddress = activeIface?.firstString("macAddress", "mac_address", "mac")
            }
        }

        // VPN connections
        if let vpns = network.first("vpn_connections", "vpnConnections").array {
            let filtered = vpns.filter { v in
                let name = v["name"].string ?? ""
                return !name.isEmpty && name != "Unknown VPN" && !name.trimmingCharacters(in: .whitespaces).isEmpty
            }
            if let connected = filtered.first(where: { ($0["status"].string ?? "").lowercased() == "connected" }) {
                vpnActive = true
                vpnName = connected["name"].string
            }
            vpnConnections = filtered
        }

        // DNS
        let dnsConfig = network.first("dns", "dnsConfiguration", "dns_configuration")
        if !dnsConfig.isNull {
            dns = dnsConfig
            let servers = dnsConfig.first("servers", "nameservers").elements.compactMap(\.string)
            if !servers.isEmpty {
                let v4 = servers.filter { NetworkInfo.isIPv4($0) }
                let v6 = servers.filter { $0.contains(":") && $0.range(of: #"^[0-9a-fA-F:]+$"#, options: .regularExpression) != nil }
                activeDnsServers = Array((Array(v4.prefix(2)) + Array(v6.prefix(1))).prefix(3))
            }
            if let domainName = dnsConfig["domainName"].nonEmptyString, hostname == nil {
                hostname = domainName
            }
        }

        // Interfaces (deduplicated by name, merging addresses)
        if let ifaces = network["interfaces"].array {
            var order: [String] = []
            var merged: [String: (iface: JSONValue, addresses: [JSONValue], isUp: Bool, hasIPv4: Bool)] = [:]
            for iface in ifaces {
                let name = iface.firstString("name", "interface") ?? "Unknown"
                if merged[name] == nil {
                    order.append(name)
                    merged[name] = (iface, [], iface["isUp"].boolish, false)
                }
                merged[name]!.addresses.append(contentsOf: iface["addresses"].elements)
                if iface["isUp"].boolish { merged[name]!.isUp = true }
                if iface["addresses"].elements.contains(where: { $0["family"].string == "IPv4" && NetworkInfo.isIPv4($0["address"].string ?? "") && !($0["address"].string ?? "").hasPrefix("127.") }) {
                    merged[name]!.hasIPv4 = true
                }
            }
            var all: [Interface] = []
            for name in order {
                guard let entry = merged[name] else { continue }
                let iface = entry.iface
                var ips: [String] = iface["ipAddresses"].elements.compactMap(\.string)
                ips.append(contentsOf: entry.addresses.compactMap { $0["address"].nonEmptyString })
                if ips.isEmpty, let single = iface["address"].nonEmptyString { ips.append(single) }
                let status = iface["status"].string ?? ""
                let isUp = ["Up", "Active", "Connected", "active"].contains(status) || entry.isUp
                    || ips.contains { NetworkInfo.isIPv4($0) && !$0.hasPrefix("127.") }
                var display = ""
                if !ips.isEmpty {
                    if isUp || iface["isActive"].boolish {
                        display = ips.first(where: NetworkInfo.isIPv4) ?? ips[0]
                    } else {
                        display = ips.first { !$0.hasPrefix("fe80::") && !$0.hasPrefix("169.254.") && !$0.hasPrefix("127.") } ?? ips[0]
                    }
                }
                let hasValidIP = ips.contains { NetworkInfo.isIPv4($0) && !$0.hasPrefix("127.") && !$0.hasPrefix("169.254.") }
                let isActive = iface["isActive"].boolish || iface["is_active"].boolish || entry.isUp || entry.hasIPv4 || hasValidIP
                all.append(Interface(
                    name: iface.firstString("name", "interface", "friendly_name", "friendlyName") ?? "Unknown",
                    friendlyName: iface.firstString("friendly_name", "friendlyName", "displayName"),
                    ipAddress: display.isEmpty ? nil : display, ipAddresses: ips,
                    macAddress: iface.firstString("mac_address", "macAddress", "mac"),
                    type: iface["type"].nonEmptyString, isActive: isActive, status: isActive ? "Active" : "Disconnected",
                    mtu: iface["mtu"].int, linkSpeed: iface.firstString("link_speed", "linkSpeed"),
                    wirelessProtocol: iface.firstString("wireless_protocol", "wirelessProtocol"),
                    wirelessBand: iface.firstString("wireless_band", "wirelessBand"),
                    ssid: nil, channel: nil, dnsServers: [],
                    bytesSent: iface.firstDouble("bytes_sent", "bytesSent"), bytesReceived: iface.firstDouble("bytes_received", "bytesReceived")))
            }
            // Filter virtual adapters
            var physical = all.filter { iface in
                if iface.name.range(of: #"^en\d+$"#, options: .regularExpression) != nil { return true }
                let mac = (iface.macAddress ?? "").lowercased()
                let virtualMac = ["00:15:5d", "00:50:56", "08:00:27", "0a:00:27"].contains { mac.hasPrefix($0) }
                let virtualIP = iface.ipAddresses.contains { $0.hasPrefix("172.") || $0.hasPrefix("10.0.75.") || $0.hasPrefix("169.254.") }
                return !virtualMac && !virtualIP
            }
            physical.sort { a, b in
                if a.isActive != b.isActive { return a.isActive }
                if a.isActive, b.isActive {
                    if a.type == "Wireless", b.type != "Wireless" { return true }
                    if a.type != "Wireless", b.type == "Wireless" { return false }
                }
                return a.name.localizedCaseInsensitiveCompare(b.name) == .orderedAscending
            }
            // Enhance the WiFi interface with currentWiFiNetwork details
            let current = network["currentWiFiNetwork"]
            let wifiDetails: JSONValue = current["output"].string != nil ? current["output"].parsedIfString() : current
            if !wifiDetails.isNull, wifiDetails.object != nil {
                if let idx = physical.firstIndex(where: { iface in
                    (wifiDetails["interface"].string != nil && iface.name == wifiDetails["interface"].string) || iface.isWireless
                }) {
                    if physical[idx].wirelessBand == nil { physical[idx].wirelessBand = wifiDetails["channel_band"].nonEmptyString }
                    if physical[idx].channel == nil { physical[idx].channel = wifiDetails["channel"].string }
                    if physical[idx].wirelessProtocol == nil, let mode = wifiDetails["mode"].nonEmptyString {
                        physical[idx].wirelessProtocol = NetworkInfo.wifiProtocol(fromMode: mode)
                    }
                    if physical[idx].wirelessProtocol == nil { physical[idx].wirelessProtocol = wifiDetails["wifi_version"].nonEmptyString }
                    if let s = wifiDetails["ssid"].nonEmptyString, s != "[Location Services Required]" {
                        physical[idx].ssid = s
                    } else if wifiDetails["ssid"].string == "[Location Services Required]",
                              let known = network["wifiInfo"]["knownNetworks"].elements.first?["ssid"].nonEmptyString {
                        physical[idx].ssid = known
                    }
                }
            }
            if !activeDnsServers.isEmpty {
                for i in physical.indices where physical[i].isActive { physical[i].dnsServers = activeDnsServers }
            }
            interfaces = physical
            if active.isNull, let first = physical.first(where: \.isActive) {
                ipAddress = ipAddress ?? first.ipAddress
                macAddress = macAddress ?? first.macAddress
                interfaceName = interfaceName ?? first.friendlyName ?? first.name
                connectionType = connectionType ?? first.type
                if let proto = first.wirelessProtocol { connectionType = proto }
            }
        }

        // WiFi networks
        if let list = network["wifiNetworks"].array, !list.isEmpty {
            wifiNetworks = list.map { NetworkInfo.wifiNetwork($0, activeSSID: nil) }
        } else if !network["wifiInfo"].isNull {
            let wifiInfo = network["wifiInfo"]
            var activeSSID: String?
            if let parsed = Optional(network["currentWiFiNetwork"]["output"].parsedIfString()), let s = parsed["ssid"].nonEmptyString, s != "[Location Services Required]" {
                activeSSID = s
            }
            if activeSSID == nil { activeSSID = wifiInfo["currentNetwork"]["ssid"].nonEmptyString }
            activeWifiSsid = activeSSID
            if let known = wifiInfo["knownNetworks"].array, !known.isEmpty {
                wifiNetworks = known.map { NetworkInfo.wifiNetwork($0, activeSSID: activeSSID) }
            } else if let available = wifiInfo["availableNetworks"].array, !available.isEmpty {
                wifiNetworks = available.map { NetworkInfo.wifiNetwork($0, activeSSID: nil) }
            }
            let current = wifiInfo["currentNetwork"]
            if !current.isNull {
                if ssid == nil { ssid = current.firstString("ssid", "networkName") }
                if signalStrength == nil, let rssi = current["rssi"].string { signalStrength = "\(rssi) dBm" }
            }
            if let proto = wifiInfo["wifiProtocol"].nonEmptyString ?? wifiInfo["phyMode"].nonEmptyString.map(NetworkInfo.wifiProtocol(fromMode:)),
               connectionType == "WiFi" {
                connectionType = proto
            }
            let parsedCurrent = network["currentWiFiNetwork"]["output"].parsedIfString()
            if parsedCurrent.object != nil {
                let s = parsedCurrent["ssid"].nonEmptyString
                wifiInterface = WiFiInterface(ssid: s == "[Location Services Required]" ? nil : s,
                                              protocolName: parsedCurrent["mode"].nonEmptyString.map(NetworkInfo.wifiProtocol(fromMode:)),
                                              channel: parsedCurrent["channel"].string, band: parsedCurrent["channel_band"].nonEmptyString,
                                              signalStrength: nil, ipAddress: nil, macAddress: nil)
            }
            if wifiInterface == nil, !current.isNull {
                wifiInterface = WiFiInterface(ssid: current.firstString("ssid", "networkName"), protocolName: nil,
                                              channel: current["channel"].string, band: nil,
                                              signalStrength: current["rssi"].string.map { "\($0) dBm" }, ipAddress: nil, macAddress: nil)
            }
        }
        if wifiInterface == nil, let w = wirelessInterface {
            wifiInterface = WiFiInterface(ssid: w.ssid, protocolName: w.wirelessProtocol, channel: w.channel, band: w.wirelessBand,
                                          signalStrength: nil, ipAddress: w.ipAddress, macAddress: w.macAddress)
        } else if var w = wifiInterface, let iface = wirelessInterface {
            w.ipAddress = w.ipAddress ?? iface.ipAddress
            w.macAddress = w.macAddress ?? iface.macAddress
            if w.ssid == nil { w.ssid = iface.ssid }
            if w.protocolName == nil { w.protocolName = iface.wirelessProtocol }
            wifiInterface = w
        }

        routes = network["routes"].elements

        // Hostname
        if let h = network["hostname"].nonEmptyString {
            hostname = h
        } else if hostname == nil {
            let env = modules["system"]["environment"].elements
            if let v = env.first(where: { ["COMPUTERNAME", "HOSTNAME"].contains($0["name"].string ?? "") })?["value"].nonEmptyString {
                hostname = v
            }
        }
        if let h = hostname {
            let domain = network["domain"].nonEmptyString ?? network["dns"]["domain"].nonEmptyString ?? network["dns"]["dhcpDomain"].nonEmptyString
            dnsAddress = (domain?.isEmpty == false) ? "\(h).\(domain!)" : h
        }
        if dnsAddress == nil, let first = activeDnsServers.first { dnsAddress = first }

        // Network quality
        let nq = network["networkQuality"]
        if let output = nq["output"].string {
            var q = Quality(raw: output)
            func match(_ pattern: String) -> String? {
                guard let re = try? NSRegularExpression(pattern: pattern, options: .caseInsensitive),
                      let m = re.firstMatch(in: output, range: NSRange(output.startIndex..., in: output)),
                      m.numberOfRanges > 1, let r = Range(m.range(at: 1), in: output) else { return nil }
                return String(output[r])
            }
            if let v = match(#"Uplink capacity:\s*([\d.]+)\s*Mbps"#).flatMap(Double.init) { q.uplinkCapacity = "\(Int(v.rounded())) Mbps" }
            if let v = match(#"Downlink capacity:\s*([\d.]+)\s*Mbps"#).flatMap(Double.init) { q.downlinkCapacity = "\(Int(v.rounded())) Mbps" }
            q.uplinkResponsiveness = match(#"Uplink Responsiveness:\s*(\w+)"#)
            q.downlinkResponsiveness = match(#"Downlink Responsiveness:\s*(\w+)"#)
            if let v = match(#"Idle Latency:\s*([\d.]+)\s*milliseconds"#).flatMap(Double.init) { q.idleLatency = "\(Int(v.rounded())) ms" }
            networkQuality = q
        } else if !nq.isNull, nq.firstDouble("dlThroughput", "dl_throughput", "ulThroughput", "ul_throughput") != nil || nq["rating"].string != nil {
            var q = Quality()
            if let dl = nq.firstDouble("dlThroughput", "dl_throughput") { q.downlinkCapacity = "\(Int(dl.rounded())) Mbps" }
            if let ul = nq.firstDouble("ulThroughput", "ul_throughput") { q.uplinkCapacity = "\(Int(ul.rounded())) Mbps" }
            q.downlinkResponsiveness = nq.firstString("dlRating", "dl_rating")
            q.uplinkResponsiveness = nq.firstString("ulRating", "ul_rating")
            if let l = nq.firstDouble("idleLatency", "idle_latency") { q.idleLatency = "\(Int(l.rounded())) ms" }
            if let j = nq["jitter"].double { q.jitter = "\(Int(j.rounded())) ms" }
            q.serverName = nq["serverName"].nonEmptyString
            q.source = nq["source"].nonEmptyString
            networkQuality = q
        }

        if ipAddress == nil, let iface = interfaces.first(where: { $0.isActive && NetworkInfo.isIPv4($0.ipAddress ?? "") }) {
            ipAddress = iface.ipAddress
            macAddress = iface.macAddress
            interfaceName = iface.name
            if iface.name == "en0" { connectionType = "WiFi" } else if iface.name.range(of: #"^en\d+$"#, options: .regularExpression) != nil { connectionType = "Ethernet" }
        }
    }

    static func wifiNetwork(_ net: JSONValue, activeSSID: String?) -> WiFiNetwork {
        let ssid = net.firstString("ssid", "name", "networkName") ?? ""
        let connected = activeSSID != nil ? (ssid == activeSSID) : (net["isConnected"].boolish || net["connected"].boolish)
        return WiFiNetwork(ssid: ssid, security: net.firstString("security", "securityType") ?? "Unknown", isConnected: connected,
                           channel: net["channel"].string, signalStrength: net.firstString("rssi", "signalStrength"), raw: net)
    }

    public static func isIPv4(_ s: String) -> Bool {
        s.range(of: #"^(\d{1,3}\.){3}\d{1,3}$"#, options: .regularExpression) != nil
    }

    static func wifiProtocol(fromMode mode: String) -> String {
        if mode.contains("be") { return "WiFi 7" }
        if mode.contains("ax") { return "WiFi 6" }
        if mode.contains("ac") { return "WiFi 5" }
        if mode.contains("n") { return "WiFi 4" }
        return mode
    }
}
