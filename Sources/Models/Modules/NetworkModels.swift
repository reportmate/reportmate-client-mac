import Foundation

/// Network module data models for macOS ReportMate client
/// These models represent network configuration and connectivity information

// MARK: - Network Models

/// Main network information structure
public struct NetworkInfo: Codable, Sendable {
    public let interfaces: [NetworkInterface]
    public let routes: [NetworkRoute]
    public let dnsConfiguration: DNSConfiguration
    public let wifiInfo: WiFiInfo?
    public let listeningPorts: [ListeningPort]
    public let arpCache: [ARPEntry]
    public let networkConnections: [NetworkConnection]
    public let activeConnection: ActiveConnection?
    public let vpnConnections: [VPNConnection]
    
    public init(
        interfaces: [NetworkInterface] = [],
        routes: [NetworkRoute] = [],
        dnsConfiguration: DNSConfiguration,
        wifiInfo: WiFiInfo? = nil,
        listeningPorts: [ListeningPort] = [],
        arpCache: [ARPEntry] = [],
        networkConnections: [NetworkConnection] = [],
        activeConnection: ActiveConnection? = nil,
        vpnConnections: [VPNConnection] = []
    ) {
        self.interfaces = interfaces
        self.routes = routes
        self.dnsConfiguration = dnsConfiguration
        self.wifiInfo = wifiInfo
        self.listeningPorts = listeningPorts
        self.arpCache = arpCache
        self.networkConnections = networkConnections
        self.activeConnection = activeConnection
        self.vpnConnections = vpnConnections
    }
}

/// Network interface information
public struct NetworkInterface: Codable, Sendable {
    public let name: String
    public let displayName: String?
    public let type: NetworkInterfaceType
    public let macAddress: String?
    public let mtu: Int
    public let isUp: Bool
    public let isLoopback: Bool
    public let isPointToPoint: Bool
    public let isBroadcast: Bool
    public let isMulticast: Bool
    public let addresses: [NetworkAddress]
    public let statistics: NetworkInterfaceStatistics?
    
    public init(
        name: String,
        displayName: String? = nil,
        type: NetworkInterfaceType,
        macAddress: String? = nil,
        mtu: Int = 1500,
        isUp: Bool = false,
        isLoopback: Bool = false,
        isPointToPoint: Bool = false,
        isBroadcast: Bool = false,
        isMulticast: Bool = false,
        addresses: [NetworkAddress] = [],
        statistics: NetworkInterfaceStatistics? = nil
    ) {
        self.name = name
        self.displayName = displayName
        self.type = type
        self.macAddress = macAddress
        self.mtu = mtu
        self.isUp = isUp
        self.isLoopback = isLoopback
        self.isPointToPoint = isPointToPoint
        self.isBroadcast = isBroadcast
        self.isMulticast = isMulticast
        self.addresses = addresses
        self.statistics = statistics
    }
}

/// Network interface type enumeration
public enum NetworkInterfaceType: String, Codable, Sendable {
    case ethernet = "Ethernet"
    case wifi = "WiFi"
    case bluetooth = "Bluetooth"
    case cellular = "Cellular"
    case loopback = "Loopback"
    case bridge = "Bridge"
    case tunnel = "Tunnel"
    case virtual = "Virtual"
    case other = "Other"
    case unknown = "Unknown"
}

/// Network address information
public struct NetworkAddress: Codable, Sendable {
    public let address: String
    public let netmask: String?
    public let broadcast: String?
    public let family: AddressFamily
    public let scope: AddressScope?
    
    public init(
        address: String,
        netmask: String? = nil,
        broadcast: String? = nil,
        family: AddressFamily,
        scope: AddressScope? = nil
    ) {
        self.address = address
        self.netmask = netmask
        self.broadcast = broadcast
        self.family = family
        self.scope = scope
    }
}

/// Address family enumeration
public enum AddressFamily: String, Codable, Sendable {
    case ipv4 = "IPv4"
    case ipv6 = "IPv6"
    case unknown = "Unknown"
}

/// Address scope enumeration
public enum AddressScope: String, Codable, Sendable {
    case global = "Global"
    case linkLocal = "Link-Local"
    case siteLocal = "Site-Local"
    case loopback = "Loopback"
    case multicast = "Multicast"
    case unknown = "Unknown"
}

/// Network interface statistics
public struct NetworkInterfaceStatistics: Codable, Sendable {
    public let bytesReceived: Int64
    public let bytesSent: Int64
    public let packetsReceived: Int64
    public let packetsSent: Int64
    public let errorsReceived: Int64
    public let errorsSent: Int64
    public let droppedReceived: Int64
    public let droppedSent: Int64
    public let collisions: Int64
    
    public init(
        bytesReceived: Int64 = 0,
        bytesSent: Int64 = 0,
        packetsReceived: Int64 = 0,
        packetsSent: Int64 = 0,
        errorsReceived: Int64 = 0,
        errorsSent: Int64 = 0,
        droppedReceived: Int64 = 0,
        droppedSent: Int64 = 0,
        collisions: Int64 = 0
    ) {
        self.bytesReceived = bytesReceived
        self.bytesSent = bytesSent
        self.packetsReceived = packetsReceived
        self.packetsSent = packetsSent
        self.errorsReceived = errorsReceived
        self.errorsSent = errorsSent
        self.droppedReceived = droppedReceived
        self.droppedSent = droppedSent
        self.collisions = collisions
    }
}

/// Network route information
public struct NetworkRoute: Codable, Sendable {
    public let destination: String
    public let netmask: String
    public let gateway: String?
    public let interface: String
    public let metric: Int
    public let flags: [String]
    public let type: RouteType
    
    public init(
        destination: String,
        netmask: String,
        gateway: String? = nil,
        interface: String,
        metric: Int = 0,
        flags: [String] = [],
        type: RouteType = .unicast
    ) {
        self.destination = destination
        self.netmask = netmask
        self.gateway = gateway
        self.interface = interface
        self.metric = metric
        self.flags = flags
        self.type = type
    }
}

/// Route type enumeration
public enum RouteType: String, Codable, Sendable {
    case unicast = "Unicast"
    case broadcast = "Broadcast"
    case multicast = "Multicast"
    case blackhole = "Blackhole"
    case reject = "Reject"
    case unknown = "Unknown"
}

/// DNS configuration information
public struct DNSConfiguration: Codable, Sendable {
    public let nameservers: [String]
    public let searchDomains: [String]
    public let domainName: String?
    public let options: [String]
    public let sortList: [String]
    
    public init(
        nameservers: [String] = [],
        searchDomains: [String] = [],
        domainName: String? = nil,
        options: [String] = [],
        sortList: [String] = []
    ) {
        self.nameservers = nameservers
        self.searchDomains = searchDomains
        self.domainName = domainName
        self.options = options
        self.sortList = sortList
    }
}

/// WiFi information structure
public struct WiFiInfo: Codable, Sendable {
    public let currentNetwork: WiFiNetwork?
    public let availableNetworks: [WiFiNetwork]
    public let knownNetworks: [WiFiNetwork]
    public let powerStatus: Bool
    public let countryCode: String?
    
    public init(
        currentNetwork: WiFiNetwork? = nil,
        availableNetworks: [WiFiNetwork] = [],
        knownNetworks: [WiFiNetwork] = [],
        powerStatus: Bool = false,
        countryCode: String? = nil
    ) {
        self.currentNetwork = currentNetwork
        self.availableNetworks = availableNetworks
        self.knownNetworks = knownNetworks
        self.powerStatus = powerStatus
        self.countryCode = countryCode
    }
}

/// WiFi network information
public struct WiFiNetwork: Codable, Sendable {
    public let ssid: String
    public let bssid: String?
    public let networkName: String?
    public let securityType: WiFiSecurityType
    public let rssi: Int? // Signal strength in dBm
    public let noise: Int? // Noise level in dBm
    public let channel: Int?
    public let channelWidth: String?
    public let transmitRate: Double? // in Mbps
    public let lastConnected: Date?
    public let isHidden: Bool
    public let captivePortal: Bool
    
    public init(
        ssid: String,
        bssid: String? = nil,
        networkName: String? = nil,
        securityType: WiFiSecurityType = .none,
        rssi: Int? = nil,
        noise: Int? = nil,
        channel: Int? = nil,
        channelWidth: String? = nil,
        transmitRate: Double? = nil,
        lastConnected: Date? = nil,
        isHidden: Bool = false,
        captivePortal: Bool = false
    ) {
        self.ssid = ssid
        self.bssid = bssid
        self.networkName = networkName
        self.securityType = securityType
        self.rssi = rssi
        self.noise = noise
        self.channel = channel
        self.channelWidth = channelWidth
        self.transmitRate = transmitRate
        self.lastConnected = lastConnected
        self.isHidden = isHidden
        self.captivePortal = captivePortal
    }
    
    public var signalQuality: WiFiSignalQuality {
        guard let rssi = rssi else { return .unknown }
        
        switch rssi {
        case -30...0: return .excellent
        case -67...(-31): return .good
        case -70...(-68): return .fair
        case -80...(-71): return .weak
        default: return .poor
        }
    }
}

/// WiFi security type enumeration
public enum WiFiSecurityType: String, Codable, Sendable {
    case none = "None"
    case wep = "WEP"
    case wpa = "WPA"
    case wpa2 = "WPA2"
    case wpa3 = "WPA3"
    case wpaEnterprise = "WPA Enterprise"
    case wpa2Enterprise = "WPA2 Enterprise"
    case wpa3Enterprise = "WPA3 Enterprise"
    case unknown = "Unknown"
}

/// WiFi signal quality enumeration
public enum WiFiSignalQuality: String, Codable, Sendable {
    case excellent = "Excellent"
    case good = "Good"
    case fair = "Fair"
    case weak = "Weak"
    case poor = "Poor"
    case unknown = "Unknown"
}

/// Listening port information
public struct ListeningPort: Codable, Sendable {
    public let port: Int
    public let networkProtocol: NetworkProtocol
    public let address: String
    public let processId: Int?
    public let processName: String?
    public let processPath: String?
    public let family: AddressFamily
    
    public init(
        port: Int,
        networkProtocol: NetworkProtocol,
        address: String = "0.0.0.0",
        processId: Int? = nil,
        processName: String? = nil,
        processPath: String? = nil,
        family: AddressFamily = .ipv4
    ) {
        self.port = port
        self.networkProtocol = networkProtocol
        self.address = address
        self.processId = processId
        self.processName = processName
        self.processPath = processPath
        self.family = family
    }
}

/// Network protocol enumeration
public enum NetworkProtocol: String, Codable, Sendable {
    case tcp = "TCP"
    case udp = "UDP"
    case icmp = "ICMP"
    case igmp = "IGMP"
    case unknown = "Unknown"
}

/// ARP cache entry
public struct ARPEntry: Codable, Sendable {
    public let ipAddress: String
    public let macAddress: String
    public let interface: String
    public let isPermanent: Bool
    public let isPublished: Bool
    
    public init(
        ipAddress: String,
        macAddress: String,
        interface: String,
        isPermanent: Bool = false,
        isPublished: Bool = false
    ) {
        self.ipAddress = ipAddress
        self.macAddress = macAddress
        self.interface = interface
        self.isPermanent = isPermanent
        self.isPublished = isPublished
    }
}

/// Network connection information
public struct NetworkConnection: Codable, Sendable {
    public let localAddress: String
    public let localPort: Int
    public let remoteAddress: String?
    public let remotePort: Int?
    public let networkProtocol: NetworkProtocol
    public let connectionState: ConnectionState
    public let processId: Int?
    public let processName: String?
    public let family: AddressFamily
    
    public init(
        localAddress: String,
        localPort: Int,
        remoteAddress: String? = nil,
        remotePort: Int? = nil,
        networkProtocol: NetworkProtocol,
        connectionState: ConnectionState = .unknown,
        processId: Int? = nil,
        processName: String? = nil,
        family: AddressFamily = .ipv4
    ) {
        self.localAddress = localAddress
        self.localPort = localPort
        self.remoteAddress = remoteAddress
        self.remotePort = remotePort
        self.networkProtocol = networkProtocol
        self.connectionState = connectionState
        self.processId = processId
        self.processName = processName
        self.family = family
    }
}

/// Connection state enumeration
public enum ConnectionState: String, Codable, Sendable {
    case listen = "Listen"
    case established = "Established"
    case synSent = "SYN_SENT"
    case synReceived = "SYN_RCVD"
    case finWait1 = "FIN_WAIT1"
    case finWait2 = "FIN_WAIT2"
    case timeWait = "TIME_WAIT"
    case closed = "Closed"
    case closedWait = "CLOSE_WAIT"
    case lastAck = "LAST_ACK"
    case closing = "Closing"
    case unknown = "Unknown"
}

/// Active network connection information
public struct ActiveConnection: Codable, Sendable {
    public let interface: String
    public let ipAddress: String
    public let gateway: String?
    public let connectionType: String
    public let isPrimary: Bool
    
    public init(
        interface: String,
        ipAddress: String,
        gateway: String? = nil,
        connectionType: String,
        isPrimary: Bool = true
    ) {
        self.interface = interface
        self.ipAddress = ipAddress
        self.gateway = gateway
        self.connectionType = connectionType
        self.isPrimary = isPrimary
    }
}

/// VPN connection information
public struct VPNConnection: Codable, Sendable {
    public let name: String
    public let status: String
    public let type: String
    public let serverAddress: String?
    public let interface: String?
    
    public init(
        name: String,
        status: String,
        type: String,
        serverAddress: String? = nil,
        interface: String? = nil
    ) {
        self.name = name
        self.status = status
        self.type = type
        self.serverAddress = serverAddress
        self.interface = interface
    }
}