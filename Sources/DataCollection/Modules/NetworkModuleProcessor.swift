import Foundation

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
        // Collect standard network info
        let networkInfo = try await collectNetworkInfo()
        
        // Collect extension-based data in parallel
        async let networkQualityData = collectNetworkQuality()
        async let wifiNetworkData = collectWiFiNetwork()
        
        let networkQuality = try await networkQualityData
        let wifiNetwork = try await wifiNetworkData
        
        // Convert NetworkInfo to [String: Any]
        let jsonData = try JSONEncoder().encode(networkInfo)
        var dictionary = try JSONSerialization.jsonObject(with: jsonData) as? [String: Any] ?? [:]
        
        // Add extension data
        dictionary["networkQuality"] = networkQuality
        dictionary["currentWiFiNetwork"] = wifiNetwork
        
        return BaseModuleData(moduleId: moduleId, data: dictionary)
    }
    
    private func collectNetworkInfo() async throws -> NetworkInfo {
        let rawData = try await executeWithFallback(
            osquery: """
            SELECT interface, address, mask, type, mac 
            FROM interface_addresses 
            JOIN interface_details USING (interface);
            """,
            bash: nil,
            python: networkInfoPythonScript()
        )
        
        // Unwrap logic
        var rawInterfaces: [RawNetworkInterface] = []
        var hostname: String? = nil
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
            
            hostname = rawData["hostname"] as? String
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
        
        // Map RawNetworkInterface to global NetworkInterface
        let interfaces = rawInterfaces.map { raw -> NetworkInterface in
            let type: NetworkInterfaceType
            if let rawType = raw.type {
                let lower = rawType.lowercased()
                if lower.contains("ether") { type = .ethernet }
                else if lower.contains("wifi") || lower.contains("wireless") { type = .wifi }
                else if lower.contains("loop") { type = .loopback }
                else { type = .other }
            } else {
                type = .unknown
            }
            
            var addresses: [NetworkAddress] = []
            if let addr = raw.address {
                let family: AddressFamily = addr.contains(":") ? .ipv6 : .ipv4
                addresses.append(NetworkAddress(address: addr, netmask: raw.mask, family: family))
            }
            
            return NetworkInterface(
                name: raw.name,
                type: type,
                macAddress: raw.mac,
                addresses: addresses
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

def run_command(cmd, shell=False):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, shell=shell)
        return result.stdout.strip()
    except:
        return ""

def get_wifi_info():
    """Get comprehensive WiFi information including protocol, band, and channel"""
    wifi_info = {
        "powerEnabled": False,
        "currentNetwork": None,
        "countryCode": None,
        "phyMode": None,
        "band": None,
        "channel": None,
        "channelWidth": None
    }
    
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
                        
                        # Get PHY mode (802.11 protocol)
                        phy_mode = net_info.get("spairport_network_phymode")
                        if phy_mode:
                            # Clean up PHY mode string
                            if "802.11ax" in phy_mode or "ax" in phy_mode.lower():
                                phy_mode = "802.11ax (WiFi 6)"
                            elif "802.11ac" in phy_mode or "ac" in phy_mode.lower():
                                phy_mode = "802.11ac (WiFi 5)"
                            elif "802.11n" in phy_mode or "n" in phy_mode.lower():
                                phy_mode = "802.11n (WiFi 4)"
                            elif "802.11be" in phy_mode or "be" in phy_mode.lower():
                                phy_mode = "802.11be (WiFi 7)"
                        
                        wifi_info["currentNetwork"] = {
                            "ssid": net_info.get("_name", ""),
                            "bssid": net_info.get("spairport_network_bssid"),
                            "networkName": net_info.get("_name", ""),
                            "security": net_info.get("spairport_security_mode", "Unknown"),
                            "rssi": None,  # Not in system_profiler
                            "noise": None,
                            "channel": channel_num,
                            "channelWidth": channel_width,
                            "band": band,
                            "phyMode": phy_mode,
                            "txRate": net_info.get("spairport_network_rate")
                        }
                        wifi_info["phyMode"] = phy_mode
                        wifi_info["band"] = band
                        wifi_info["channel"] = channel_num
                        wifi_info["channelWidth"] = channel_width
                        
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
                                
                                wifi_info["currentNetwork"] = {
                                    "ssid": iface.get("spairport_current_network", ""),
                                    "bssid": iface.get("_name"),
                                    "networkName": iface.get("spairport_current_network", ""),
                                    "security": iface.get("spairport_security_type", "Unknown"),
                                    "rssi": None,
                                    "noise": None,
                                    "channel": channel_num,
                                    "channelWidth": iface.get("spairport_channel_width"),
                                    "band": None,
                                    "phyMode": iface.get("spairport_supported_phymodes"),
                                    "txRate": iface.get("spairport_current_network_rate")
                                }
    except Exception as e:
        wifi_info["error"] = str(e)
    
    # Try airport command for RSSI/noise (may require location services)
    try:
        airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        if subprocess.run(['test', '-f', airport_path], capture_output=True).returncode == 0:
            airport_output = run_command([airport_path, '-I'])
            if airport_output and wifi_info.get("currentNetwork"):
                for line in airport_output.split('\n'):
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
    
    # Get WiFi info
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
                        elif '100baseTX' in line:
                            current_iface["linkSpeed"] = "100 Mbps"
                        elif '10baseT' in line:
                            current_iface["linkSpeed"] = "10 Mbps"
                    elif line.startswith('status: '):
                        current_iface["status"] = line.replace('status: ', '').strip()
    except:
        pass
    
    # Determine interface types from networksetup
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
                for iface in info["interfaces"]:
                    if iface["interface"] == active_iface:
                        ip_address = iface.get("address", "")
                        connection_type = iface.get("type", "Unknown")
                        break
                
                info["activeConnection"] = {
                    "interface": active_iface,
                    "ipAddress": ip_address,
                    "gateway": gateway,
                    "connectionType": connection_type,
                    "isPrimary": True
                }
    except:
        pass

    # Get enhanced VPN connections
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
                
                name = "Unknown VPN"
                if '"' in line:
                    parts = line.split('"')
                    if len(parts) >= 2:
                        name = parts[1]
                
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
        current_resolver = None
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
        
        let bashScript = """
            if ! command -v networkQuality &> /dev/null; then
                echo '{"error": "Not Available (macOS 12+ required)"}'
                exit 0
            fi
            # Network quality test takes 15-30 seconds and requires active internet
            # Skip for regular collections, run manually if needed
            echo '{"status": "skipped", "reason": "Network quality test takes 15-30 seconds, run manually if needed"}'
        """
        
        return try await executeWithFallback(osquery: osqueryScript, bash: bashScript)
    }
    
    private func collectWiFiNetwork() async throws -> [String: Any] {
        let osqueryScript = """
            SELECT ssid, bssid, network_name, rssi, noise, channel,
                   channel_width, channel_band, transmit_rate, security_type, mode
            FROM wifi_network LIMIT 1;
        """
        
        let bashScript = """
            # Get WiFi interface
            wifi_if=$(networksetup -listallhardwareports | awk '/Wi-Fi|AirPort/{getline; print $2}')
            if [ -z "$wifi_if" ]; then
                echo '{"error": "No WiFi interface"}'
                exit 0
            fi
            
            # Check if connected (has IP address)
            wifi_ip=$(ifconfig "$wifi_if" 2>/dev/null | awk '/inet / {print $2}')
            if [ -z "$wifi_ip" ]; then
                echo '{"error": "Not connected to WiFi"}'
                exit 0
            fi
            
            # Note: SSID access requires Location Services permission on modern macOS
            # For enterprise deployment, grant Location Services to the app or use MDM profile
            ssid="[Location Services Required]"
            
            # Get additional details from system_profiler
            wifi_info=$(system_profiler SPAirPortDataType 2>/dev/null)
            
            # Extract details from the main WiFi section
            phy_mode=$(echo "$wifi_info" | awk '/^[[:space:]]*PHY Mode:/ {print $3; exit}')
            channel=$(echo "$wifi_info" | awk '/^[[:space:]]*Channel:/ {print $2; exit}')
            channel_band=$(echo "$wifi_info" | awk '/^[[:space:]]*Channel:/ {print $3; exit}' | tr -d '()')
            country_code=$(echo "$wifi_info" | awk '/^[[:space:]]*Country Code:/ {print $3; exit}')
            network_type=$(echo "$wifi_info" | awk '/^[[:space:]]*Network Type:/ {print $3; exit}')
            
            # Get router IP as identifier
            router=$(networksetup -getinfo Wi-Fi 2>/dev/null | awk '/Router:/ {print $2}')
            
            echo "{"
            echo "  \\"ssid\\": \\"$ssid\\","
            echo "  \\"bssid\\": \\"$router\\","
            echo "  \\"network_name\\": \\"$ssid\\","
            echo "  \\"channel\\": \\"$channel\\","
            echo "  \\"channel_band\\": \\"$channel_band\\","
            echo "  \\"mode\\": \\"$phy_mode\\","
            echo "  \\"country_code\\": \\"$country_code\\","
            echo "  \\"network_type\\": \\"$network_type\\","
            echo "  \\"note\\": \\"SSID access requires Location Services permission - grant to app or deploy via MDM\\""
            echo "}"
        """
        
        return try await executeWithFallback(osquery: osqueryScript, bash: bashScript)
    }
}