import Foundation
import CoreWLAN

/// Network module processor for collecting network information  
public class NetworkModuleProcessor: BaseModuleProcessor, @unchecked Sendable {
    
    // Private struct to handle raw OSQuery output decoding
    private struct RawNetworkInterface: Codable {
        let name: String
        let address: String?
        let mask: String?
        let mac: String?
        let type: String?
        
        enum CodingKeys: String, CodingKey {
            case name = "interface" // Map 'interface' from OSQuery to 'name'
            case address
            case mask
            case mac
            case type
        }
    }
    
    public init(configuration: ReportMateConfiguration) {
        super.init(moduleId: "network", configuration: configuration)
    }
    
    public override func collectData() async throws -> ModuleData {
        // Total collection steps for progress tracking
        let totalSteps = 7
        
        // Collect network data sequentially with progress tracking
        ConsoleFormatter.writeQueryProgress(queryName: "network_interfaces", current: 1, total: totalSteps)
        let networkInfo = try await collectNetworkInfo()
        
        ConsoleFormatter.writeQueryProgress(queryName: "hostname_info", current: 2, total: totalSteps)
        let hostnameInfo = try await collectHostnameInfo()
        
        ConsoleFormatter.writeQueryProgress(queryName: "network_quality", current: 3, total: totalSteps)
        let networkQuality = try await collectNetworkQuality()
        
        ConsoleFormatter.writeQueryProgress(queryName: "wifi_network", current: 4, total: totalSteps)
        let wifiNetwork = try await collectWiFiNetwork()
        
        ConsoleFormatter.writeQueryProgress(queryName: "vpn_connections", current: 5, total: totalSteps)
        let vpnConnections = try await collectVPNConnections()
        
        ConsoleFormatter.writeQueryProgress(queryName: "saved_wifi", current: 6, total: totalSteps)
        let savedWifi = try await collectSavedWiFiNetworks()
        
        ConsoleFormatter.writeQueryProgress(queryName: "dns_config", current: 7, total: totalSteps)
        let dnsConfig = try await collectDNSConfiguration()
        
        // Convert NetworkInfo to [String: Any]
        let jsonData = try JSONEncoder().encode(networkInfo)
        var dictionary = try JSONSerialization.jsonObject(with: jsonData) as? [String: Any] ?? [:]
        
        // Add hostname information at the top level
        dictionary["hostname"] = hostnameInfo["hostname"]
        dictionary["localHostname"] = hostnameInfo["localHostname"]
        dictionary["sharingName"] = hostnameInfo["sharingName"]
        
        // Add extension data
        dictionary["networkQuality"] = networkQuality
        
        // If SSID is unavailable due to location services, use first known network as fallback
        var updatedWifiNetwork = wifiNetwork
        if let ssid = updatedWifiNetwork["ssid"] as? String,
           ssid == "[Location Services Required]",
           let firstKnownNetwork = savedWifi.first,
           let knownSSID = firstKnownNetwork["ssid"] as? String {
            updatedWifiNetwork["ssid"] = knownSSID
            updatedWifiNetwork["note"] = "SSID from known networks (location services disabled)"
        }
        dictionary["currentWiFiNetwork"] = updatedWifiNetwork
        
        dictionary["vpnConnections"] = vpnConnections
        
        // Merge DNS configuration (overwrite the empty one from NetworkInfo)
        if !dnsConfig.isEmpty {
            dictionary["dnsConfiguration"] = dnsConfig
        }
        
        // Merge saved WiFi into wifiInfo
        if var wifiInfo = dictionary["wifiInfo"] as? [String: Any] {
            wifiInfo["knownNetworks"] = savedWifi
            dictionary["wifiInfo"] = wifiInfo
        } else {
            dictionary["wifiInfo"] = [
                "knownNetworks": savedWifi,
                "powerStatus": true
            ]
        }
        
        return BaseModuleData(moduleId: moduleId, data: dictionary)
    }
    
    private func collectNetworkInfo() async throws -> NetworkInfo {
        // Use osquery for interface data, then enhance with bash for VPN/WiFi/activeConnection
        let rawData = try await executeWithFallback(
            osquery: """
            SELECT interface, address, mask, interface_details.type as type, mac 
            FROM interface_addresses 
            JOIN interface_details USING (interface);
            """,
            bash: nil
        )
        
        // Unwrap logic
        var rawInterfaces: [RawNetworkInterface] = []
        var fqdn: String? = nil
        var activeConnection: ActiveConnection? = nil
        var vpnConnections: [VPNConnection] = []
        var wifiInfo: WiFiInfo? = nil
        
        // Check for OSQuery items (wrapped in "items" by BaseModuleProcessor)
        if let osqueryData = rawData["items"] as? [[String: Any]] {
            let jsonData = try JSONSerialization.data(withJSONObject: osqueryData)
            rawInterfaces = try JSONDecoder().decode([RawNetworkInterface].self, from: jsonData)
        } 
        // Check for direct dictionary (Bash/Python)
        else {
            // Try to decode from the rawData itself (it might be the flattened JSON from Bash/Python)
            
            // For Bash/Python, we might have "interfaces" key
            if let interfaceList = rawData["interfaces"] as? [[String: Any]] {
                let jsonData = try JSONSerialization.data(withJSONObject: interfaceList)
                rawInterfaces = try JSONDecoder().decode([RawNetworkInterface].self, from: jsonData)
            } else if let interfaceNames = rawData["interfaces"] as? [String] {
                // Bash simple list
                rawInterfaces = interfaceNames.map { name in
                    RawNetworkInterface(name: name, address: nil, mask: nil, mac: nil, type: nil)
                }
            }
            
            _ = rawData["hostname"] as? String  // hostname is collected but not currently used
            fqdn = rawData["fqdn"] as? String
            
            if let activeDict = rawData["activeConnection"] as? [String: Any] {
                activeConnection = ActiveConnection(
                    interface: activeDict["interface"] as? String ?? "",
                    ipAddress: activeDict["ipAddress"] as? String ?? "",
                    gateway: activeDict["gateway"] as? String,
                    connectionType: activeDict["connectionType"] as? String ?? "Unknown",
                    isPrimary: activeDict["isPrimary"] as? Bool ?? true
                )
            }
            
            if let vpnList = rawData["vpnConnections"] as? [[String: Any]] {
                vpnConnections = vpnList.map { dict in
                    VPNConnection(
                        name: dict["name"] as? String ?? "",
                        status: dict["status"] as? String ?? "",
                        type: dict["type"] as? String ?? "",
                        serverAddress: dict["serverAddress"] as? String,
                        interface: dict["interface"] as? String
                    )
                }
            }
            
            // Parse WiFi info
            if let wifiDict = rawData["wifiInfo"] as? [String: Any] {
                var currentNetwork: WiFiNetwork? = nil
                if let current = wifiDict["currentNetwork"] as? [String: Any] {
                    currentNetwork = WiFiNetwork(
                        ssid: current["ssid"] as? String ?? "",
                        bssid: current["bssid"] as? String,
                        networkName: current["networkName"] as? String,
                        securityType: parseSecurityType(current["security"] as? String),
                        rssi: current["rssi"] as? Int,
                        noise: current["noise"] as? Int,
                        channel: current["channel"] as? Int,
                        channelWidth: current["channelWidth"] as? String,
                        transmitRate: current["txRate"] as? Double
                    )
                }
                
                wifiInfo = WiFiInfo(
                    currentNetwork: currentNetwork,
                    powerStatus: wifiDict["powerEnabled"] as? Bool ?? false,
                    countryCode: wifiDict["countryCode"] as? String
                )
            }
        }
        
        // Filter to only physical interfaces (en*) - exclude bridge, utun, lo, etc.
        let filteredRawInterfaces = rawInterfaces.filter { raw -> Bool in
            let name = raw.name.lowercased()
            // Only keep en* interfaces (physical network interfaces)
            // Exclude enc* which are encrypted tunnel interfaces
            return name.hasPrefix("en") && !name.hasPrefix("enc")
        }
        
        // Get active connection info from default route
        let activeConnectionInfo = try await getActiveConnectionInfo()
        let activeInterfaceName = activeConnectionInfo["interface"] as? String
        let gateway = activeConnectionInfo["gateway"] as? String
        
        // Map RawNetworkInterface to global NetworkInterface
        let interfaces = filteredRawInterfaces.map { raw -> NetworkInterface in
            // Determine if this is the active interface
            let isActive = raw.name == activeInterfaceName
            
            // Determine interface type - en0 is typically WiFi on Mac
            let type: NetworkInterfaceType
            if raw.name == "en0" {
                type = .wifi
            } else if raw.name.hasPrefix("en") {
                type = .ethernet
            } else {
                type = .other
            }
            
            var addresses: [NetworkAddress] = []
            if let addr = raw.address {
                let family: AddressFamily = addr.contains(":") ? .ipv6 : .ipv4
                addresses.append(NetworkAddress(address: addr, netmask: raw.mask, family: family))
            }
            
            // Interface is "up" if it's the active one or has a valid IPv4 address
            let hasIPv4 = raw.address != nil && raw.address!.contains(".") && !raw.address!.hasPrefix("169.254.")
            
            return NetworkInterface(
                name: raw.name,
                type: type,
                macAddress: raw.mac,
                isUp: isActive || hasIPv4,
                addresses: addresses
            )
        }
        
        // Build activeConnection from detected active interface
        // If the active interface is a tunnel (utun/ppp), find the physical interface instead
        var physicalIfaceName = activeInterfaceName
        if let activeIface = activeInterfaceName, 
           (activeIface.hasPrefix("utun") || activeIface.hasPrefix("ppp")) {
            // VPN is active - find the physical interface with an IPv4 address
            // Prefer en0 (WiFi) or en1 (Ethernet)
            if let en0 = filteredRawInterfaces.first(where: { $0.name == "en0" && $0.address?.contains(".") == true }) {
                physicalIfaceName = en0.name
            } else if let en1 = filteredRawInterfaces.first(where: { $0.name == "en1" && $0.address?.contains(".") == true }) {
                physicalIfaceName = en1.name
            } else {
                // Fall back to any en* with IPv4
                physicalIfaceName = filteredRawInterfaces.first(where: { $0.address?.contains(".") == true })?.name
            }
        }
        
        if let physicalIface = physicalIfaceName {
            // Find the first IPv4 address for the active interface
            let activeIfaceData = filteredRawInterfaces.first { $0.name == physicalIface && $0.address?.contains(".") == true }
            
            let connType = physicalIface == "en0" ? "WiFi" : "Ethernet"
            
            activeConnection = ActiveConnection(
                interface: physicalIface,
                ipAddress: activeIfaceData?.address ?? "",
                gateway: gateway,
                connectionType: connType,
                isPrimary: true
            )
        }
        
        return NetworkInfo(
            interfaces: interfaces,
            dnsConfiguration: DNSConfiguration(domainName: fqdn),
            wifiInfo: wifiInfo,
            activeConnection: activeConnection,
            vpnConnections: vpnConnections
        )
    }
    
    /// Get active connection info from default route
    private func getActiveConnectionInfo() async throws -> [String: Any] {
        let output = try await BashService.execute("""
            route -n get default 2>/dev/null | awk '
                /interface:/ { iface=$2 }
                /gateway:/ { gw=$2 }
                END { print "{\\"interface\\": \\"" iface "\\", \\"gateway\\": \\"" gw "\\"}" }
            '
        """)
        
        if let data = output.data(using: String.Encoding.utf8),
           let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            return json
        }
        return [:]
    }
    
    /// Helper to parse WiFi security type string to enum
    private func parseSecurityType(_ security: String?) -> WiFiSecurityType {
        guard let sec = security?.lowercased() else { return .unknown }
        if sec.contains("wpa3") && sec.contains("enterprise") { return .wpa3Enterprise }
        if sec.contains("wpa3") { return .wpa3 }
        if sec.contains("wpa2") && sec.contains("enterprise") { return .wpa2Enterprise }
        if sec.contains("wpa2") { return .wpa2 }
        if sec.contains("wpa") && sec.contains("enterprise") { return .wpaEnterprise }
        if sec.contains("wpa") { return .wpa }
        if sec.contains("wep") { return .wep }
        if sec.contains("none") || sec.contains("open") { return .none }
        return .unknown
    }
    
    /// Returns the Python script for comprehensive network information collection
    private func networkInfoPythonScript() -> String {
        return #"""
import json
import subprocess
import socket
import re
import plistlib
import os

def run_command(cmd, shell=False):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, shell=shell)
        return result.stdout.strip()
    except:
        return ""

def get_saved_wifi_networks():
    """Get list of saved/preferred WiFi networks"""
    networks = []
    
    # Get WiFi interface name
    wifi_interface = None
    try:
        output = run_command(['networksetup', '-listallhardwareports'])
        lines = output.split('\n')
        for i, line in enumerate(lines):
            if 'Wi-Fi' in line or 'AirPort' in line:
                for j in range(i, min(i+3, len(lines))):
                    if 'Device:' in lines[j]:
                        wifi_interface = lines[j].split(':')[1].strip()
                        break
                break
    except:
        wifi_interface = "en0"
    
    if not wifi_interface:
        return networks
    
    # Get preferred/saved networks using networksetup
    try:
        output = run_command(['networksetup', '-listpreferredwirelessnetworks', wifi_interface])
        if output and 'Preferred networks' in output:
            lines = output.split('\n')[1:]  # Skip header line
            for line in lines:
                ssid = line.strip()
                if ssid:
                    networks.append({
                        "ssid": ssid,
                        "security": "Saved Profile",
                        "isConnected": False,
                        "isSaved": True
                    })
    except:
        pass
    
    return networks

def get_wifi_info():
    """Get comprehensive WiFi information including protocol, band, and channel"""
    wifi_info = {
        "powerEnabled": False,
        "currentNetwork": None,
        "countryCode": None,
        "phyMode": None,
        "band": None,
        "channel": None,
        "channelWidth": None,
        "knownNetworks": [],
        "availableNetworks": []
    }
    
    # Get saved WiFi networks
    wifi_info["knownNetworks"] = get_saved_wifi_networks()
    
    # Get WiFi interface name (usually en0 or en1)
    wifi_interface = None
    try:
        output = run_command(['networksetup', '-listallhardwareports'])
        lines = output.split('\n')
        for i, line in enumerate(lines):
            if 'Wi-Fi' in line or 'AirPort' in line:
                for j in range(i, min(i+3, len(lines))):
                    if 'Device:' in lines[j]:
                        wifi_interface = lines[j].split(':')[1].strip()
                        break
                break
    except:
        wifi_interface = "en0"  # Default fallback
    
    wifi_info["interface"] = wifi_interface
    
    if not wifi_interface:
        return wifi_info
    
    # Check if WiFi is powered on
    try:
        power_output = run_command(['networksetup', '-getairportpower', wifi_interface])
        wifi_info["powerEnabled"] = "On" in power_output
    except:
        pass
    
    # Use system_profiler for detailed WiFi info (most reliable)
    try:
        sp_output = run_command(['system_profiler', 'SPAirPortDataType', '-json'])
        if sp_output:
            sp_data = json.loads(sp_output)
            if "SPAirPortDataType" in sp_data:
                for airport in sp_data["SPAirPortDataType"]:
                    # Get country code
                    wifi_info["countryCode"] = airport.get("spairport_country_code")
                    
                    # Check for current network info
                    if "spairport_current_network_information" in airport:
                        net_info = airport["spairport_current_network_information"]
                        
                        # Determine band from channel
                        channel = net_info.get("spairport_network_channel")
                        channel_num = None
                        channel_width = None
                        band = None
                        
                        if channel:
                            # Parse channel string like "36 (5 GHz, 80 MHz)"
                            parts = channel.split()
                            if parts:
                                try:
                                    channel_num = int(parts[0])
                                except:
                                    pass
                            
                            # Determine band from channel number
                            if channel_num:
                                if 1 <= channel_num <= 14:
                                    band = "2.4 GHz"
                                elif 32 <= channel_num <= 177:
                                    band = "5 GHz"
                                elif channel_num > 177:
                                    band = "6 GHz"
                            
                            # Extract channel width from string
                            if "160 MHz" in channel:
                                channel_width = "160 MHz"
                            elif "80 MHz" in channel:
                                channel_width = "80 MHz"
                            elif "40 MHz" in channel:
                                channel_width = "40 MHz"
                            elif "20 MHz" in channel:
                                channel_width = "20 MHz"
                        
                        # Get PHY mode (802.11 protocol) and map to friendly name
                        phy_mode = net_info.get("spairport_network_phymode")
                        wifi_protocol = None
                        if phy_mode:
                            if "802.11be" in phy_mode or "be" in phy_mode.lower():
                                wifi_protocol = "WiFi 7"
                                phy_mode = "802.11be"
                            elif "802.11ax" in phy_mode or "ax" in phy_mode.lower():
                                wifi_protocol = "WiFi 6"
                                phy_mode = "802.11ax"
                            elif "802.11ac" in phy_mode or "ac" in phy_mode.lower():
                                wifi_protocol = "WiFi 5"
                                phy_mode = "802.11ac"
                            elif "802.11n" in phy_mode or "n" in phy_mode.lower():
                                wifi_protocol = "WiFi 4"
                                phy_mode = "802.11n"
                            elif "802.11g" in phy_mode:
                                wifi_protocol = "WiFi 3"
                                phy_mode = "802.11g"
                        
                        # Get transmit rate and format as link speed
                        tx_rate = net_info.get("spairport_network_rate")
                        link_speed = None
                        if tx_rate:
                            try:
                                rate_val = float(str(tx_rate).replace(' Mbps', '').replace('Mbps', '').strip())
                                if rate_val >= 1000:
                                    link_speed = f"{rate_val/1000:.1f} Gbps"
                                else:
                                    link_speed = f"{int(rate_val)} Mbps"
                            except:
                                link_speed = str(tx_rate)
                        
                        current_ssid = net_info.get("_name", "")
                        
                        wifi_info["currentNetwork"] = {
                            "ssid": current_ssid,
                            "bssid": net_info.get("spairport_network_bssid"),
                            "networkName": current_ssid,
                            "security": net_info.get("spairport_security_mode", "Unknown"),
                            "rssi": None,  # Will be filled from airport command
                            "noise": None,
                            "channel": channel_num,
                            "channelWidth": channel_width,
                            "band": band,
                            "phyMode": phy_mode,
                            "wifiProtocol": wifi_protocol,
                            "txRate": tx_rate,
                            "linkSpeed": link_speed
                        }
                        wifi_info["phyMode"] = phy_mode
                        wifi_info["wifiProtocol"] = wifi_protocol
                        wifi_info["band"] = band
                        wifi_info["channel"] = channel_num
                        wifi_info["channelWidth"] = channel_width
                        wifi_info["linkSpeed"] = link_speed
                        
                        # Mark current network as connected in knownNetworks
                        for net in wifi_info["knownNetworks"]:
                            if net["ssid"] == current_ssid:
                                net["isConnected"] = True
                                break
                        
                    # Fallback: try to get interfaces info
                    elif "spairport_airport_interfaces" in airport:
                        for iface in airport.get("spairport_airport_interfaces", []):
                            if iface.get("spairport_status") == "spairport_status_connected":
                                channel = iface.get("spairport_channel")
                                channel_num = None
                                if channel:
                                    try:
                                        channel_num = int(str(channel).split()[0])
                                    except:
                                        pass
                                
                                current_ssid = iface.get("spairport_current_network", "")
                                
                                wifi_info["currentNetwork"] = {
                                    "ssid": current_ssid,
                                    "bssid": iface.get("_name"),
                                    "networkName": current_ssid,
                                    "security": iface.get("spairport_security_type", "Unknown"),
                                    "rssi": None,
                                    "noise": None,
                                    "channel": channel_num,
                                    "channelWidth": iface.get("spairport_channel_width"),
                                    "band": None,
                                    "phyMode": iface.get("spairport_supported_phymodes"),
                                    "txRate": iface.get("spairport_current_network_rate")
                                }
                                
                                # Mark current network as connected
                                for net in wifi_info["knownNetworks"]:
                                    if net["ssid"] == current_ssid:
                                        net["isConnected"] = True
                                        break
    except Exception as e:
        wifi_info["error"] = str(e)
    
    # Try airport command for RSSI/noise (may require location services)
    try:
        airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        if os.path.exists(airport_path):
            airport_output = run_command([airport_path, '-I'])
            if airport_output and wifi_info.get("currentNetwork"):
                for line in airport_output.split('\n'):
                    line = line.strip()
                    if 'agrCtlRSSI:' in line:
                        try:
                            wifi_info["currentNetwork"]["rssi"] = int(line.split(':')[1].strip())
                        except:
                            pass
                    elif 'agrCtlNoise:' in line:
                        try:
                            wifi_info["currentNetwork"]["noise"] = int(line.split(':')[1].strip())
                        except:
                            pass
                    elif 'lastTxRate:' in line and not wifi_info["currentNetwork"].get("txRate"):
                        try:
                            rate = int(line.split(':')[1].strip())
                            wifi_info["currentNetwork"]["txRate"] = rate
                            if rate >= 1000:
                                wifi_info["currentNetwork"]["linkSpeed"] = f"{rate/1000:.1f} Gbps"
                            else:
                                wifi_info["currentNetwork"]["linkSpeed"] = f"{rate} Mbps"
                            wifi_info["linkSpeed"] = wifi_info["currentNetwork"]["linkSpeed"]
                        except:
                            pass
    except:
        pass
    
    return wifi_info

def get_network_info():
    info = {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "interfaces": [],
        "activeConnection": None,
        "vpnConnections": [],
        "wifiInfo": None,
        "dnsServers": [],
        "searchDomains": []
    }
    
    # Get WiFi info (includes saved networks now)
    info["wifiInfo"] = get_wifi_info()
    
    # Get network interfaces with enhanced info
    try:
        result = subprocess.run(['ifconfig', '-a'], capture_output=True, text=True)
        if result.returncode == 0:
            current_iface = None
            for line in result.stdout.split('\n'):
                if line and not line.startswith('\t'):
                    parts = line.split(':')
                    if len(parts) > 0:
                        iface_name = parts[0]
                        flags = ""
                        mtu = 1500
                        
                        # Parse flags and MTU from same line
                        if 'mtu' in line:
                            mtu_match = re.search(r'mtu\s+(\d+)', line)
                            if mtu_match:
                                mtu = int(mtu_match.group(1))
                        
                        if 'flags=' in line:
                            flags_match = re.search(r'flags=\d+<([^>]+)>', line)
                            if flags_match:
                                flags = flags_match.group(1)
                        
                        current_iface = {
                            "interface": iface_name,
                            "type": "unknown",
                            "mtu": mtu,
                            "flags": flags,
                            "isUp": "UP" in flags,
                            "isLoopback": "LOOPBACK" in flags
                        }
                        info["interfaces"].append(current_iface)
                        
                elif line and line.startswith('\t') and current_iface is not None:
                    line = line.strip()
                    if line.startswith('inet '):
                        parts = line.split()
                        if len(parts) >= 2:
                            current_iface["address"] = parts[1]
                            # Parse netmask
                            for i, p in enumerate(parts):
                                if p == 'netmask' and i+1 < len(parts):
                                    current_iface["mask"] = parts[i+1]
                    elif line.startswith('inet6 '):
                        parts = line.split()
                        if len(parts) >= 2:
                            current_iface["ipv6Address"] = parts[1].split('%')[0]
                    elif line.startswith('ether '):
                        parts = line.split()
                        if len(parts) >= 2:
                            current_iface["mac"] = parts[1]
                    elif line.startswith('media: '):
                        current_iface["media"] = line.replace('media: ', '').strip()
                        # Determine type from media
                        if 'autoselect' in line.lower() or 'ethernet' in line.lower():
                            current_iface["type"] = "Ethernet"
                        if '<full-duplex>' in line or '1000baseT' in line:
                            current_iface["linkSpeed"] = "1 Gbps"
                        elif '2500baseT' in line:
                            current_iface["linkSpeed"] = "2.5 Gbps"
                        elif '10GbaseT' in line or '10Gbase' in line:
                            current_iface["linkSpeed"] = "10 Gbps"
                        elif '100baseTX' in line:
                            current_iface["linkSpeed"] = "100 Mbps"
                        elif '10baseT' in line:
                            current_iface["linkSpeed"] = "10 Mbps"
                    elif line.startswith('status: '):
                        current_iface["status"] = line.replace('status: ', '').strip()
    except:
        pass
    
    # Determine interface types and add WiFi-specific info from networksetup
    wifi_interface = info["wifiInfo"].get("interface") if info["wifiInfo"] else None
    try:
        hw_output = run_command(['networksetup', '-listallhardwareports'])
        current_hw = None
        for line in hw_output.split('\n'):
            if 'Hardware Port:' in line:
                current_hw = line.split(':')[1].strip()
            elif 'Device:' in line and current_hw:
                device = line.split(':')[1].strip()
                for iface in info["interfaces"]:
                    if iface["interface"] == device:
                        if 'Wi-Fi' in current_hw or 'AirPort' in current_hw:
                            iface["type"] = "WiFi"
                            # Add WiFi protocol and band info from wifiInfo
                            if info["wifiInfo"] and device == wifi_interface:
                                if info["wifiInfo"].get("wifiProtocol"):
                                    iface["wirelessProtocol"] = info["wifiInfo"]["wifiProtocol"]
                                if info["wifiInfo"].get("band"):
                                    iface["wirelessBand"] = info["wifiInfo"]["band"]
                                if info["wifiInfo"].get("linkSpeed"):
                                    iface["linkSpeed"] = info["wifiInfo"]["linkSpeed"]
                        elif 'Ethernet' in current_hw or 'Thunderbolt' in current_hw:
                            iface["type"] = "Ethernet"
                        elif 'Bluetooth' in current_hw:
                            iface["type"] = "Bluetooth"
                        iface["displayName"] = current_hw
                        break
                current_hw = None
    except:
        pass
        
    # Get active connection with route-based detection
    # Note: This returns the routing interface which may be VPN tunnel
    # We'll also store physical interface info for proper display
    try:
        res = subprocess.run(['route', '-n', 'get', 'default'], capture_output=True, text=True)
        if res.returncode == 0:
            active_iface = ""
            gateway = ""
            for line in res.stdout.split('\n'):
                if 'interface:' in line:
                    active_iface = line.split(':')[1].strip()
                if 'gateway:' in line:
                    gateway = line.split(':')[1].strip()
            
            if active_iface:
                ip_address = ""
                connection_type = "Unknown"
                mac_address = ""
                link_speed = ""
                for iface in info["interfaces"]:
                    if iface["interface"] == active_iface:
                        ip_address = iface.get("address", "")
                        connection_type = iface.get("type", "Unknown")
                        mac_address = iface.get("mac", "")
                        link_speed = iface.get("linkSpeed", "")
                        break
                
                # Check if active interface is VPN tunnel
                is_vpn_tunnel = active_iface.startswith("utun") or active_iface.startswith("ppp")
                
                info["activeConnection"] = {
                    "interface": active_iface,
                    "ipAddress": ip_address,
                    "gateway": gateway,
                    "connectionType": connection_type,
                    "macAddress": mac_address,
                    "linkSpeed": link_speed,
                    "isPrimary": True,
                    "isVpnTunnel": is_vpn_tunnel
                }
                
                # If on VPN, also find primary physical interface for display
                if is_vpn_tunnel:
                    # Find en0 or first physical interface with IP
                    for iface in info["interfaces"]:
                        iface_name = iface["interface"]
                        if iface_name == "en0" or (iface.get("type") in ["Ethernet", "WiFi"] and iface.get("address")):
                            info["activeConnection"]["physicalInterface"] = iface_name
                            info["activeConnection"]["physicalIpAddress"] = iface.get("address", "")
                            info["activeConnection"]["physicalMacAddress"] = iface.get("mac", "")
                            info["activeConnection"]["physicalConnectionType"] = iface.get("type", "Unknown")
                            info["activeConnection"]["physicalLinkSpeed"] = iface.get("linkSpeed", "")
                            break
    except:
        pass

    # Get enhanced VPN connections - filter out Unknown VPN
    try:
        res = subprocess.run(['scutil', '--nc', 'list'], capture_output=True, text=True)
        if res.returncode == 0:
            for line in res.stdout.split('\n'):
                if not line.strip():
                    continue
                    
                status = "Disconnected"
                if "(Connected)" in line:
                    status = "Connected"
                elif "(Connecting)" in line:
                    status = "Connecting"
                elif "(Disconnecting)" in line:
                    status = "Disconnecting"
                
                name = ""
                if '"' in line:
                    parts = line.split('"')
                    if len(parts) >= 2:
                        name = parts[1]
                
                # Skip unnamed/unknown VPNs
                if not name or name == "Unknown VPN":
                    continue
                
                vpn_type = "VPN"
                if '[' in line and ']' in line:
                    vpn_type = line.split('[')[1].split(']')[0]
                
                # Get service ID for more details
                service_id = None
                id_match = re.search(r'\((\w+-\w+-\w+-\w+-\w+)\)', line)
                if id_match:
                    service_id = id_match.group(1)
                
                vpn_entry = {
                    "name": name,
                    "status": status,
                    "type": vpn_type,
                    "serviceId": service_id,
                    "serverAddress": None,
                    "interface": None
                }
                
                # Try to get VPN server details if connected
                if status == "Connected" and service_id:
                    try:
                        show_output = run_command(['scutil', '--nc', 'show', service_id])
                        for show_line in show_output.split('\n'):
                            if 'ServerAddress' in show_line:
                                vpn_entry["serverAddress"] = show_line.split(':')[-1].strip()
                            elif 'InterfaceName' in show_line:
                                vpn_entry["interface"] = show_line.split(':')[-1].strip()
                    except:
                        pass
                
                # Only add if it looks like a VPN
                if any(x in vpn_type for x in ['VPN', 'PPP', 'IPSec', 'IKEv2', 'L2TP']):
                    info["vpnConnections"].append(vpn_entry)
    except:
        pass
    
    # Get DNS configuration
    try:
        dns_output = run_command(['scutil', '--dns'])
        for line in dns_output.split('\n'):
            if 'nameserver[' in line:
                dns = line.split(':')[-1].strip()
                if dns and dns not in info["dnsServers"]:
                    info["dnsServers"].append(dns)
            elif 'search domain[' in line:
                domain = line.split(':')[-1].strip()
                if domain and domain not in info["searchDomains"]:
                    info["searchDomains"].append(domain)
    except:
        pass
    
    return info

print(json.dumps(get_network_info()))
"""#
    }
    
    // MARK: - Extension Tables
    
    private func collectNetworkQuality() async throws -> [String: Any] {
        let osqueryScript = """
            SELECT dl_throughput, ul_throughput, dl_responsiveness, 
                   ul_responsiveness, rating
            FROM network_quality LIMIT 1;
        """
        
        // Actually run networkQuality test - parse output in Swift for reliability
        let bashScript = #"""
command -v networkQuality >/dev/null 2>&1 || { echo "NOT_AVAILABLE"; exit 0; }
networkQuality -s 2>&1
"""#
        
        let result = try await executeWithFallback(osquery: osqueryScript, bash: bashScript)
        
        // If osquery worked, return as-is
        if result["dl_throughput"] != nil || result["items"] != nil {
            return result
        }
        
        // Parse bash output
        if let output = result["output"] as? String {
            if output.contains("NOT_AVAILABLE") {
                return ["error": "Not Available (macOS 12+ required)"]
            }
            
            // Parse networkQuality output
            var parsed: [String: Any] = [:]
            
            // "Downlink capacity: 864.179 Mbps"
            for line in output.components(separatedBy: "\n") {
                if line.contains("Downlink capacity:") {
                    let parts = line.components(separatedBy: ":")
                    if parts.count > 1 {
                        let value = parts[1].trimmingCharacters(in: .whitespaces).components(separatedBy: " ").first ?? "0"
                        parsed["dl_throughput"] = value
                    }
                } else if line.contains("Uplink capacity:") {
                    let parts = line.components(separatedBy: ":")
                    if parts.count > 1 {
                        let value = parts[1].trimmingCharacters(in: .whitespaces).components(separatedBy: " ").first ?? "0"
                        parsed["ul_throughput"] = value
                    }
                } else if line.contains("Downlink Responsiveness:") {
                    // Format: "Downlink Responsiveness: High (48.400 milliseconds | 1239 RPM)"
                    let parts = line.components(separatedBy: ":")
                    if parts.count > 1 {
                        let ratingPart = parts[1].trimmingCharacters(in: .whitespaces)
                        let ratingWord = ratingPart.components(separatedBy: " ").first ?? "Unknown"
                        parsed["dl_rating"] = ratingWord
                    }
                } else if line.contains("Uplink Responsiveness:") {
                    let parts = line.components(separatedBy: ":")
                    if parts.count > 1 {
                        let ratingPart = parts[1].trimmingCharacters(in: .whitespaces)
                        let ratingWord = ratingPart.components(separatedBy: " ").first ?? "Unknown"
                        parsed["ul_rating"] = ratingWord
                    }
                } else if line.contains("Idle Latency:") {
                    let parts = line.components(separatedBy: ":")
                    if parts.count > 1 {
                        let value = parts[1].trimmingCharacters(in: .whitespaces).components(separatedBy: " ").first ?? "0"
                        parsed["idle_latency"] = value
                    }
                }
            }
            
            // Overall rating (lower of dl/ul)
            let dlRating = parsed["dl_rating"] as? String ?? "Unknown"
            let ulRating = parsed["ul_rating"] as? String ?? "Unknown"
            if dlRating == "Low" || ulRating == "Low" {
                parsed["rating"] = "Low"
            } else if dlRating == "Medium" || ulRating == "Medium" {
                parsed["rating"] = "Medium"
            } else if dlRating == "High" && ulRating == "High" {
                parsed["rating"] = "High"
            } else {
                parsed["rating"] = dlRating != "Unknown" ? dlRating : ulRating
            }
            
            return parsed
        }
        
        return ["error": "Failed to run network quality test"]
    }
    
    private func collectWiFiNetwork() async throws -> [String: Any] {
        let osqueryScript = """
            SELECT ssid, bssid, network_name, rssi, noise, channel,
                   channel_width, channel_band, transmit_rate, security_type, mode
            FROM wifi_network LIMIT 1;
        """
        
        // Use system_profiler for WiFi info (simplest cross-version approach)
        // Note: SSID may show "[Location Services Required]" if location services disabled
        let bashScript = #"""
system_profiler SPAirPortDataType -json 2>/dev/null
"""#
        
        let result = try await executeWithFallback(osquery: osqueryScript, bash: bashScript)
        
        // If osquery worked, return as-is (look in items)
        if let items = result["items"] as? [[String: Any]], let first = items.first {
            return first
        }
        
        // Check for error messages
        if let error = result["error"] as? String {
            return ["error": error]
        }
        
        // Parse system_profiler output and enhance with CoreWLAN SSID if available
        var parsed = parseSystemProfilerWiFiData(result)
        
        // Try to get real SSID from CoreWLAN (doesn't require location services)
        if let actualSSID = getCoreWLANSSID(), !actualSSID.isEmpty {
            parsed["ssid"] = actualSSID
            parsed.removeValue(forKey: "note") // Remove location services warning
        }
        
        return parsed
    }
    
    /// Get SSID using CoreWLAN framework (doesn't require location services permission)
    private func getCoreWLANSSID() -> String? {
        ConsoleFormatter.writeDebug("Attempting to get SSID via CoreWLAN...")
        let client = CWWiFiClient.shared()
        ConsoleFormatter.writeDebug("CoreWLAN client: \(client)")
        guard let interface = client.interface() else { 
            ConsoleFormatter.writeDebug("No CoreWLAN interface available")
            return nil 
        }
        ConsoleFormatter.writeDebug("CoreWLAN interface: \(interface.interfaceName ?? "unknown")")
        let ssid = interface.ssid()
        ConsoleFormatter.writeDebug("CoreWLAN SSID: '\(ssid ?? "nil")'")
        return ssid
    }
    
    /// Parse system_profiler WiFi data
    private func parseSystemProfilerWiFiData(_ result: [String: Any]) -> [String: Any] {
        var parsed: [String: Any] = ["ssid": "[Location Services Required]", "note": "SSID requires Location Services permission"]
        
        // If we have SPAirPortDataType, this is the system_profiler JSON output
        if let airportData = result["SPAirPortDataType"] as? [[String: Any]],
           let firstInterface = airportData.first,
           let interfaces = firstInterface["spairport_airport_interfaces"] as? [[String: Any]],
           let wifiInterface = interfaces.first {
            
            // Get current network info from spairport_current_network_info
            if let currentNetwork = wifiInterface["spairport_current_network_info"] as? [String: Any] {
                if let channel = currentNetwork["spairport_network_channel"] as? String {
                    // Format: "165 (6GHz, 160MHz)"
                    let channelParts = channel.components(separatedBy: " ")
                    if let channelNum = Int(channelParts.first ?? "") {
                        parsed["channel"] = "\(channelNum)"
                    }
                    if channel.contains("2GHz") { parsed["channel_band"] = "2.4GHz" }
                    else if channel.contains("5GHz") { parsed["channel_band"] = "5GHz" }
                    else if channel.contains("6GHz") { parsed["channel_band"] = "6GHz" }
                }
                if let mode = currentNetwork["spairport_network_phymode"] as? String {
                    parsed["mode"] = mode
                    if mode.contains("ax") { parsed["wifi_version"] = "WiFi 6" }
                    else if mode.contains("ac") { parsed["wifi_version"] = "WiFi 5" }
                    else if mode.contains("n") { parsed["wifi_version"] = "WiFi 4" }
                }
                if let security = currentNetwork["spairport_security_mode"] as? String {
                    if security.contains("wpa3") { parsed["security"] = "WPA3" }
                    else if security.contains("wpa2") { parsed["security"] = "WPA2" }
                    else if security.contains("wpa") { parsed["security"] = "WPA" }
                    else if security.contains("none") { parsed["security"] = "Open" }
                    else { parsed["security"] = security }
                }
            }
            // Fallback: try first network in other_local_wireless_networks
            else if let networks = wifiInterface["spairport_airport_other_local_wireless_networks"] as? [[String: Any]],
                    let firstNetwork = networks.first {
                if let channel = firstNetwork["spairport_network_channel"] as? String {
                    let channelParts = channel.components(separatedBy: " ")
                    if let channelNum = Int(channelParts.first ?? "") {
                        parsed["channel"] = "\(channelNum)"
                    }
                    if channel.contains("2GHz") { parsed["channel_band"] = "2.4GHz" }
                    else if channel.contains("5GHz") { parsed["channel_band"] = "5GHz" }
                    else if channel.contains("6GHz") { parsed["channel_band"] = "6GHz" }
                }
                if let mode = firstNetwork["spairport_network_phymode"] as? String {
                    parsed["mode"] = mode
                    if mode.contains("ax") { parsed["wifi_version"] = "WiFi 6" }
                    else if mode.contains("ac") { parsed["wifi_version"] = "WiFi 5" }
                    else if mode.contains("n") { parsed["wifi_version"] = "WiFi 4" }
                }
                if let security = firstNetwork["spairport_security_mode"] as? String {
                    if security.contains("wpa3") { parsed["security"] = "WPA3" }
                    else if security.contains("wpa2") { parsed["security"] = "WPA2" }
                    else if security.contains("wpa") { parsed["security"] = "WPA" }
                    else if security.contains("none") { parsed["security"] = "Open" }
                    else { parsed["security"] = security }
                }
            }
            
            // Get country code from interface level
            if let countryCode = wifiInterface["spairport_country_code"] as? String {
                parsed["country_code"] = countryCode
            }
        }
        
        return parsed
    }
    
    private func collectVPNConnections() async throws -> [[String: Any]] {
        let output = try await BashService.execute(#"""
scutil --nc list 2>/dev/null | while IFS= read -r line; do
  [ -z "$line" ] && continue
  name=$(echo "$line" | sed -n 's/.*"\([^"]*\)".*/\1/p')
  [ -z "$name" ] && continue
  [ "$name" = "Unknown VPN" ] && continue
  status="Disconnected"
  case "$line" in *"(Connected)"*) status="Connected";; *"(Connecting)"*) status="Connecting";; esac
  vpn_type=$(echo "$line" | sed -n 's/.*\[\([^]]*\)\].*/\1/p')
  [ -z "$vpn_type" ] && vpn_type="VPN"
  case "$vpn_type" in *VPN*|*PPP*|*IPSec*|*IKEv2*|*L2TP*|*Cisco*)
    printf '%s\t%s\t%s\n' "$name" "$status" "$vpn_type"
  ;; esac
done
"""#)
        
        // Parse tab-separated output
        var vpnList: [[String: Any]] = []
        for line in output.split(separator: "\n") {
            let parts = line.split(separator: "\t", omittingEmptySubsequences: false)
            if parts.count >= 3 {
                vpnList.append([
                    "name": String(parts[0]),
                    "status": String(parts[1]),
                    "type": String(parts[2])
                ])
            }
        }
        return vpnList
    }
    
    private func collectSavedWiFiNetworks() async throws -> [[String: Any]] {
        let output = try await BashService.execute(#"""
wifi_if=$(networksetup -listallhardwareports | awk '/Wi-Fi|AirPort/{getline; print $2}')
[ -z "$wifi_if" ] && wifi_if="en0"
networksetup -listpreferredwirelessnetworks "$wifi_if" 2>/dev/null | tail -n +2 | sed 's/^[[:space:]]*//'
"""#)
        
        // Parse line-by-line output
        var networks: [[String: Any]] = []
        for line in output.split(separator: "\n") {
            let ssid = String(line).trimmingCharacters(in: .whitespaces)
            if !ssid.isEmpty {
                networks.append([
                    "ssid": ssid,
                    "securityType": "Unknown",
                    "isHidden": 0,
                    "captivePortal": 0
                ])
            }
        }
        return networks
    }
    
    private func collectDNSConfiguration() async throws -> [String: Any] {
        // Collect DNS configuration using scutil --dns
        let output = try await BashService.execute(#"""
scutil --dns 2>/dev/null | awk '
    /nameserver\[/ { gsub(/.*: /, ""); dns[NR]=$0 }
    /search domain\[/ { gsub(/.*: /, ""); search[NR]=$0 }
    END {
        printf "NAMESERVERS:"
        for (i in dns) printf "%s,", dns[i]
        printf "\nSEARCHDOMAINS:"
        for (i in search) printf "%s,", search[i]
        printf "\n"
    }
'
"""#)
        
        var nameservers: [String] = []
        var searchDomains: [String] = []
        
        for line in output.split(separator: "\n") {
            let lineStr = String(line)
            if lineStr.hasPrefix("NAMESERVERS:") {
                let servers = lineStr.dropFirst("NAMESERVERS:".count)
                nameservers = servers.split(separator: ",")
                    .map { String($0).trimmingCharacters(in: .whitespaces) }
                    .filter { !$0.isEmpty }
            } else if lineStr.hasPrefix("SEARCHDOMAINS:") {
                let domains = lineStr.dropFirst("SEARCHDOMAINS:".count)
                searchDomains = domains.split(separator: ",")
                    .map { String($0).trimmingCharacters(in: .whitespaces) }
                    .filter { !$0.isEmpty }
            }
        }
        
        // Remove duplicates while preserving order
        nameservers = Array(NSOrderedSet(array: nameservers)) as? [String] ?? nameservers
        searchDomains = Array(NSOrderedSet(array: searchDomains)) as? [String] ?? searchDomains
        
        return [
            "nameservers": nameservers,
            "searchDomains": searchDomains,
            "options": [] as [String],
            "sortList": [] as [String]
        ]
    }
    
    private func collectHostnameInfo() async throws -> [String: Any] {
        // Get hostname (Computer Name), local hostname, and sharing name using scutil
        let output = try await BashService.execute(#"""
printf "HOSTNAME:%s\n" "$(scutil --get ComputerName 2>/dev/null || hostname)"
printf "LOCALHOSTNAME:%s\n" "$(scutil --get LocalHostName 2>/dev/null || hostname -s)"
printf "SHARINGNAME:%s\n" "$(scutil --get ComputerName 2>/dev/null || hostname)"
"""#)
        
        var hostname = ""
        var localHostname = ""
        var sharingName = ""
        
        for line in output.split(separator: "\n") {
            let lineStr = String(line)
            if lineStr.hasPrefix("HOSTNAME:") {
                hostname = String(lineStr.dropFirst("HOSTNAME:".count))
            } else if lineStr.hasPrefix("LOCALHOSTNAME:") {
                localHostname = String(lineStr.dropFirst("LOCALHOSTNAME:".count))
            } else if lineStr.hasPrefix("SHARINGNAME:") {
                sharingName = String(lineStr.dropFirst("SHARINGNAME:".count))
            }
        }
        
        return [
            "hostname": hostname,
            "localHostname": localHostname,
            "sharingName": sharingName
        ]
    }
}