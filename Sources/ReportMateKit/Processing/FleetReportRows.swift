import Foundation

// MARK: - Shared helpers

/// The Apple Silicon chip family names the reports group by.
public enum ChipNames {
    static let table: [(String, String)] = [
        ("m5 ultra", "M5 Ultra"), ("m5 max", "M5 Max"), ("m5 pro", "M5 Pro"), ("m5", "M5"),
        ("m4 ultra", "M4 Ultra"), ("m4 max", "M4 Max"), ("m4 pro", "M4 Pro"), ("m4", "M4"),
        ("m3 ultra", "M3 Ultra"), ("m3 max", "M3 Max"), ("m3 pro", "M3 Pro"), ("m3", "M3"),
        ("m2 ultra", "M2 Ultra"), ("m2 max", "M2 Max"), ("m2 pro", "M2 Pro"), ("m2", "M2"),
        ("m1 ultra", "M1 Ultra"), ("m1 max", "M1 Max"), ("m1 pro", "M1 Pro"), ("m1", "M1"),
    ]

    /// "Apple M3 Pro" -> "M3 Pro"; nil when the name is not Apple Silicon.
    public static func chip(from name: String) -> String? {
        let lower = name.lowercased()
        guard lower.contains("apple") || lower.range(of: #"\bm[1-9]\b"#, options: .regularExpression) != nil else { return nil }
        for (needle, label) in table {
            if needle.contains(" ") { if lower.contains(needle) { return label } }
            else if lower.range(of: "\\b\(needle)\\b", options: .regularExpression) != nil { return label }
        }
        return "Apple Silicon"
    }
}

/// Builds CSV text the way the web export buttons do.
public enum CSVText {
    public static func encode(headers: [String], rows: [[String]]) -> String {
        func esc(_ s: String) -> String { "\"" + s.replacingOccurrences(of: "\"", with: "\"\"") + "\"" }
        return ([headers.map(esc).joined(separator: ",")] + rows.map { $0.map(esc).joined(separator: ",") }).joined(separator: "\n")
    }

    public static func dateStamp(_ date: Date = Date()) -> String {
        let f = DateFormatter(); f.locale = Locale(identifier: "en_US_POSIX"); f.dateFormat = "yyyy-MM-dd"
        return f.string(from: date)
    }
}

// MARK: - Hardware

/// One device in the `/hardware` report, with the groupings `app/hardware/page.tsx` derives.
public struct HardwareReportRow: Sendable, Hashable {
    public var json: JSONValue
    public var architecture: String
    public var processorName: String
    public var processorCores: Int
    public var processorSpeed: String?
    public var performanceCores: Int
    public var efficiencyCores: Int
    public var graphicsCores: Int
    public var graphicsRawName: String?
    public var graphicsCount: Int
    public var npuCores: Int
    public var memoryModuleCount: Int
    public var manufacturer: String?

    public init(json: JSONValue) {
        self.json = json
        let processor = json.first("processor", "cpu")
        let graphics = json.first("graphics", "gpu")
        var arch = json["architecture"].nonEmptyString ?? processor["architecture"].nonEmptyString ?? "Unknown"
        let processorText = (processor.string ?? processor.firstString("name", "model", "brand") ?? "").lowercased()
        let graphicsText = (graphics.string ?? graphics[0].firstString("name", "model") ?? graphics.firstString("name", "model") ?? "").lowercased()
        let isARM = processorText.contains("snapdragon") || processorText.contains("apple m") || processorText.contains("apple silicon") || graphicsText.contains("qualcomm adreno") || graphicsText.contains("apple gpu")
        if isARM {
            arch = "ARM64"
        } else if arch != "Unknown" {
            let n = arch.lowercased().trimmingCharacters(in: .whitespaces)
            if n.contains("arm64") || n.contains("aarch64") { arch = "ARM64" }
            else if n.contains("x64") || n.contains("amd64") || n.contains("x86_64") || n.contains("64-bit") { arch = "x64" }
            else if n.contains("x86"), !n.contains("64") { arch = "x86" }
        }
        architecture = arch
        processorName = processor.string ?? processor.firstString("name", "model", "brand") ?? "Unknown Processor"
        processorCores = json["processorCores"].int ?? processor.first("cores", "core_count", "logicalCores").int ?? 0
        processorSpeed = json["processorSpeed"].nonEmptyString ?? processor.firstString("speed", "frequency", "currentSpeed")
        performanceCores = processor.first("performance_cores", "performanceCores").int ?? 0
        efficiencyCores = processor.first("efficiency_cores", "efficiencyCores").int ?? 0
        let gfx = graphics.array?.first ?? graphics
        graphicsCores = gfx["cores"].int ?? 0
        graphicsRawName = graphics.string ?? gfx.firstString("name", "model", "description")
        graphicsCount = graphics.array?.count ?? (graphics.isNull ? 0 : 1)
        let npu = json["npu"].isNull ? json["modules"]["hardware"]["npu"] : json["npu"]
        npuCores = npu["cores"].int ?? 0
        memoryModuleCount = json["memoryModules"].elements.count
        manufacturer = json["manufacturer"].nonEmptyString
    }

    /// `getDeviceModel`: strip a trailing "(2023)" when the year already appears.
    public var model: String {
        let raw = json["model"].nonEmptyString ?? "Unknown Model"
        if let r = raw.range(of: #"\s*\((\d{4})\)$"#, options: .regularExpression) {
            let year = raw[r].filter(\.isNumber)
            if raw[..<r.lowerBound].contains(year) { return String(raw[..<r.lowerBound]) }
        }
        return raw
    }

    public var deviceType: String {
        let m = model.lowercased()
        for w in ["desktop", "optiplex", "precision", "workstation", "tower", "sff", "imac", "mac pro", "mac studio"] where m.contains(w) { return "Desktop" }
        for w in ["laptop", "book", "thinkpad", "macbook", "pavilion", "inspiron", "latitude", "elitebook", "probook", "yoga", "ideapad", "surface laptop"] where m.contains(w) { return "Laptop" }
        return "Desktop"
    }

    public var chipName: String? { ChipNames.chip(from: processorName) }

    /// `getChipSku`: "M3 Pro (12-core CPU, 18-core GPU, 16-core NPU)".
    public var chipSku: String? {
        guard let chip = chipName else { return nil }
        var parts: [String] = []
        if processorCores > 0 { parts.append("\(processorCores)-core CPU") }
        if graphicsCores > 0 { parts.append("\(graphicsCores)-core GPU") }
        if npuCores > 0 { parts.append("\(npuCores)-core NPU") }
        return parts.isEmpty ? chip : "\(chip) (\(parts.joined(separator: ", ")))"
    }

    /// `getProcessorName`: the family a processor belongs to.
    public var processorGroup: String {
        let lower = processorName.lowercased()
        if lower.contains("intel") {
            for (n, l) in [("core i9", "Intel Core i9"), ("core i7", "Intel Core i7"), ("core i5", "Intel Core i5"), ("core i3", "Intel Core i3"), ("xeon", "Intel Xeon"), ("pentium", "Intel Pentium"), ("celeron", "Intel Celeron")] where lower.contains(n) { return l }
            return "Intel Other"
        }
        if lower.contains("amd") {
            for (n, l) in [("ryzen 9", "AMD Ryzen 9"), ("ryzen 7", "AMD Ryzen 7"), ("ryzen 5", "AMD Ryzen 5"), ("ryzen 3", "AMD Ryzen 3"), ("epyc", "AMD EPYC"), ("threadripper", "AMD Threadripper")] where lower.contains(n) { return l }
            return "AMD Other"
        }
        if let chip = ChipNames.chip(from: processorName) { return chip }
        if lower.contains("qualcomm") || lower.contains("snapdragon") { return "Qualcomm Snapdragon" }
        if lower.contains("virtual") { return "Virtual" }
        return processorName
    }

    /// `getGraphicsName`: the family a GPU belongs to.
    public var graphicsGroup: String {
        let name = graphicsRawName ?? "Unknown Graphics"
        let lower = name.lowercased()
        if lower.contains("nvidia") || lower.contains("geforce") || lower.contains("quadro") || lower.contains("rtx") || lower.contains("gtx") {
            for (n, l) in [("rtx 40", "NVIDIA RTX 40 Series"), ("rtx 30", "NVIDIA RTX 30 Series"), ("rtx 20", "NVIDIA RTX 20 Series"), ("rtx", "NVIDIA RTX Other"), ("gtx 16", "NVIDIA GTX 16 Series"), ("gtx 10", "NVIDIA GTX 10 Series"), ("gtx", "NVIDIA GTX Other"), ("quadro", "NVIDIA Quadro")] where lower.contains(n) { return l }
            return "NVIDIA Other"
        }
        if lower.contains("amd") || lower.contains("radeon") || lower.contains("ati") {
            for (n, l) in [("rx 7000", "AMD RX 7000 Series"), ("rx 6000", "AMD RX 6000 Series"), ("rx 5000", "AMD RX 5000 Series"), ("rx", "AMD RX Other"), ("vega", "AMD Vega")] where lower.contains(n) { return l }
            return "AMD Other"
        }
        if lower.contains("intel") {
            for (n, l) in [("arc", "Intel Arc"), ("iris xe", "Intel Iris Xe"), ("iris", "Intel Iris"), ("uhd", "Intel UHD Graphics"), ("hd graphics", "Intel HD Graphics")] where lower.contains(n) { return l }
            return "Intel Integrated"
        }
        if let chip = ChipNames.chip(from: name) { return chip }
        if lower.contains("qualcomm") || lower.contains("adreno") { return "Qualcomm Adreno" }
        if lower.contains("virtual") || lower.contains("vmware") || lower.contains("hyper-v") || lower.contains("meta virtual") { return "Meta Virtual Monitor" }
        return name
    }

    /// Bytes of physical memory from the many shapes the clients send.
    public var memoryBytes: Double {
        let memory = json["memory"]
        if let obj = memory.object {
            if let f = obj["totalFormatted"]?.string, let r = f.range(of: #"(\d+(?:\.\d+)?)\s*GB"#, options: [.regularExpression, .caseInsensitive]) {
                let n = Double(f[r].filter { $0.isNumber || $0 == "." }) ?? 0
                return n * 1_073_741_824
            }
            for key in ["physical_memory", "physicalMemory", "totalPhysical"] {
                if let v = obj[key], let n = v.double ?? Double(v.string ?? "") { return n }
            }
            return 0
        }
        return memory.double ?? Double(memory.string ?? "") ?? 0
    }

    public var memoryRange: String {
        let gb = memoryBytes / 1_073_741_824
        guard gb > 0 else { return "Unknown" }
        let sizes: [Double] = [2, 4, 8, 12, 16, 24, 32, 36, 48, 64, 96, 128, 192, 256, 384, 512]
        let best = sizes.min { abs(gb - $0) < abs(gb - $1) } ?? sizes[0]
        return "\(Int(best)) GB"
    }

    public var memoryText: String {
        let memory = json["memory"]
        if let f = memory["totalFormatted"].nonEmptyString { return f.replacingOccurrences(of: ".0 GB", with: " GB") }
        let bytes = memoryBytes
        if bytes > 0 {
            if bytes >= 1_000_000_000 {
                let gb = (bytes / 1_073_741_824 * 10).rounded() / 10
                return gb == gb.rounded() ? "\(Int(gb)) GB" : "\(gb) GB"
            }
            return "\(Int((bytes / 1_048_576).rounded())) MB"
        }
        if let s = memory.string { return s.replacingOccurrences(of: ".0 GB", with: " GB") }
        return "Unknown"
    }

    public var storageDrives: [JSONValue] { json["storage"].elements }
    public var storageTotalBytes: Double { storageDrives.reduce(0) { $0 + ($1.first("size", "capacity").double ?? 0) } }
    public var storageFreeBytes: Double { storageDrives.reduce(0) { $0 + ($1.first("free", "available").double ?? 0) } }

    public var storageRange: String {
        guard json["storage"].array != nil else { return "Unknown" }
        let gb = (storageTotalBytes / 1_073_741_824).rounded()
        if gb == 0 { return "Unknown" }
        if gb >= 3500 { return "4 TB" }
        if gb >= 1800 { return "2 TB" }
        if gb >= 900 { return "1 TB" }
        if gb >= 450 { return "512 GB" }
        if gb >= 200 { return "256 GB" }
        if gb >= 100 { return "128 GB" }
        return "64 GB"
    }

    /// `formatStorage`: total label and optional free label.
    public var storageText: (total: String, free: String?) {
        let storage = json["storage"]
        if storage.isNull { return ("No drives", nil) }
        if let s = storage.string { return (s, nil) }
        guard let drives = storage.array else {
            if let n = storage.double { return (n >= 1_000_000_000_000 ? String(format: "%.1f TB", n / 1_099_511_627_776) : "\(Int((n / 1_073_741_824).rounded())) GB", nil) }
            return ("Unknown", nil)
        }
        if drives.isEmpty { return ("No drives", nil) }
        let total = storageTotalBytes, free = storageFreeBytes
        guard total > 0 else { return ("\(drives.count) drives", nil) }
        let gb = total / 1_073_741_824
        let totalText: String
        if gb >= 3500 { totalText = "4 TB" } else if gb >= 1700 { totalText = "2 TB" } else if gb >= 900 { totalText = "1 TB" } else if gb >= 450 { totalText = "512 GB" } else { totalText = "\(Int(gb.rounded())) GB" }
        let freeGB = free / 1_073_741_824
        let freeText: String? = free > 0 ? (freeGB >= 900 ? String(format: "%.1f TB", freeGB / 1024) : "\(Int(freeGB.rounded())) GB") : nil
        return (totalText, freeText)
    }
}

// MARK: - Peripherals

/// One device in the `/peripherals` report.
public struct PeripheralsReportRow: Sendable, Hashable {
    public struct Kind: Sendable, Hashable, Identifiable {
        public var id: String { key }
        public var key: String
        public var label: String
        public var field: String
    }

    public static let kinds: [Kind] = [
        Kind(key: "usb", label: "USB", field: "usbDevices"), Kind(key: "bluetooth", label: "Bluetooth", field: "bluetoothDevices"),
        Kind(key: "printers", label: "Printers", field: "printers"), Kind(key: "cameras", label: "Cameras", field: "cameras"),
        Kind(key: "audio", label: "Audio", field: "audioDevices"), Kind(key: "displays", label: "Displays", field: "displayDevices"),
        Kind(key: "input", label: "Input", field: "inputDevices"), Kind(key: "storage", label: "Storage", field: "storageDevices"),
    ]

    public var json: JSONValue
    public init(json: JSONValue) { self.json = json }

    public func count(_ kind: Kind) -> Int { json[kind.field].elements.count }
    public var total: Int { PeripheralsReportRow.kinds.reduce(0) { $0 + count($1) } }
    public var printerNames: [String] { json["printers"].elements.map { $0.firstString("name", "printerName") ?? "Unknown Printer" } }
    public var usbTypes: [String] { json["usbDevices"].elements.map { $0.firstString("class", "type", "vendor") ?? "Unknown" } }
    /// The web searches the JSON text of these three lists.
    public var searchableText: String {
        [json["usbDevices"], json["bluetoothDevices"], json["printers"]].map { $0.isNull ? "" : $0.prettyPrinted }.joined(separator: " ").lowercased()
    }
}

// MARK: - Network

/// One device in the `/network` report, read through `NetworkInfo`.
public struct NetworkReportRow: Sendable, Hashable {
    public enum Speed: String, Sendable, CaseIterable { case excellent, good, fair, poor, nodata
        public var label: String { self == .nodata ? "No Data" : rawValue.prefix(1).uppercased() + rawValue.dropFirst() }
    }
    public enum Signal: String, Sendable, CaseIterable { case excellent, good, fair, poor, none }
    public enum WirelessState: Sendable { case off, on, connected, unknown }

    public var json: JSONValue
    public var info: NetworkInfo

    public init(json: JSONValue) {
        self.json = json
        let raw = json["raw"].isNull ? json["modules"]["network"] : json["raw"]
        info = NetworkInfo(modules: .object(["network": raw]))
    }

    public var downlink: Double? { info.networkQuality?.downlinkCapacity.flatMap { Double($0.filter { $0.isNumber || $0 == "." }) } }
    public var uplink: Double? { info.networkQuality?.uplinkCapacity.flatMap { Double($0.filter { $0.isNumber || $0 == "." }) } }

    public var speed: Speed {
        guard let dl = downlink else { return .nodata }
        let ul = uplink ?? 0
        if dl >= 500, ul >= 100 { return .excellent }
        if dl >= 100, ul >= 25 { return .good }
        if dl >= 25, ul >= 5 { return .fair }
        return .poor
    }

    public var signalPercent: Double { Double((info.signalStrength ?? "").filter { $0.isNumber || $0 == "." || $0 == "-" }) ?? 0 }
    public var signal: Signal {
        let s = signalPercent
        if s >= 75 { return .excellent }
        if s >= 50 { return .good }
        if s >= 25 { return .fair }
        if s > 0 { return .poor }
        return .none
    }

    public var wirelessState: WirelessState {
        let state = (info.raw["wirelessState"].string ?? info.raw["wireless_state"].string ?? "").lowercased()
        let ct = (info.connectionType ?? "").lowercased()
        if state == "connected" || ct.contains("wireless") || ct.contains("wifi") { return .connected }
        if state == "off" || state == "disabled" { return .off }
        if state == "on" || state == "enabled" || state == "disconnected" { return .on }
        return .unknown
    }

    public var isWired: Bool { let ct = (info.connectionType ?? "").lowercased(); return ct.contains("ethernet") || ct.contains("wired") }
    public var isWireless: Bool { let ct = (info.connectionType ?? "").lowercased(); return ct.contains("wireless") || ct.contains("wifi") }
    public var ssid: String? { info.ssid ?? info.activeWifiSsid ?? info.raw["networkName"].nonEmptyString }

    /// "Wired + SSID" the way the Connection column reads.
    public var connectionDisplay: String? {
        var parts: [String] = []
        if isWired { parts.append("Wired") }
        if ssid != nil || isWireless { parts.append(ssid ?? "Wireless") }
        return parts.isEmpty ? nil : parts.joined(separator: " + ")
    }

    public var protocolBand: String? {
        guard ssid != nil || isWireless else { return nil }
        var pb = info.raw.firstString("protocol", "band", "wirelessStandard", "frequency") ?? info.wifiInterface?.protocolName
        if pb == nil, let active = info.activeInterfaces.first {
            if let p = active.wirelessProtocol, let b = active.wirelessBand { pb = "\(p) - \(b)" } else { pb = active.wirelessProtocol ?? active.wirelessBand }
        }
        guard var text = pb, text != "N/A" else { return nil }
        text = text.replacingOccurrences(of: #"\s+\(([^)]+)\)$"#, with: " - $1", options: .regularExpression)
        return text
    }

    public var ipv4: String? {
        guard let ip = info.ipAddress, ip != "N/A" else { return nil }
        let pattern = #"^(\d{1,3}\.){3}\d{1,3}$"#
        return ip.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.first { $0.range(of: pattern, options: .regularExpression) != nil }
    }

    public func matches(_ q: String) -> Bool {
        let fields: [String?] = [json["deviceName"].string, info.ipAddress, info.macAddress, info.ssid, info.connectionType, info.dnsAddress, info.hostname, json["serialNumber"].string, json["assetTag"].string]
        if fields.contains(where: { $0?.lowercased().contains(q) ?? false }) { return true }
        return info.interfaces.contains { i in i.name.lowercased().contains(q) || (i.ipAddress ?? "").lowercased().contains(q) || (i.macAddress ?? "").lowercased().contains(q) }
    }
}

// MARK: - Security

/// One device in the `/security` report with the labels the widgets group by.
public struct SecurityReportRow: Sendable, Hashable {
    public var json: JSONValue
    public var isWindows: Bool

    public init(json: JSONValue, platform: Platform) {
        self.json = json
        isWindows = platform == .windows
    }

    public var encryptionEnabled: Bool { json["encryptionEnabled"].boolish }
    public var firewallEnabled: Bool { json["firewallEnabled"].boolish }
    public var antivirusName: String? { json["antivirusName"].nonEmptyString }
    public var antivirusEnabled: Bool { json["antivirusEnabled"].boolish }
    public var antivirusUpToDate: Bool { json["antivirusUpToDate"].boolish }
    public var detectionCount: Int { json["detectionCount"].int ?? 0 }
    public var activeThreatCount: Int { json["activeThreatCount"].int ?? detectionCount }
    public var tpmPresent: Bool { json["tpmPresent"].boolish }
    public var tpmEnabled: Bool { json["tpmEnabled"].boolish }
    public var secureBootEnabled: Bool { json["secureBootEnabled"].boolish }
    public var sipEnabled: Bool? { json["sipEnabled"].boolishIfPresent }
    public var firmwarePasswordStatus: String? { json["firmwarePassword"]["statusDisplay"].nonEmptyString }
    public var sshRunning: Bool { json["secureShell"]["isServiceRunning"].boolish }
    public var rdpEnabled: Bool { json["rdpEnabled"].boolish }
    public var expiredCertCount: Int { json["expiredCertCount"].int ?? 0 }
    public var userExpiredCertCount: Int { json["userExpiredCertCount"].int ?? expiredCertCount }
    public var expiringSoonCertCount: Int { json["expiringSoonCertCount"].int ?? 0 }
    public var cveCount: Int { json["cveCount"].int ?? 0 }
    public var criticalCveCount: Int { json["criticalCveCount"].int ?? 0 }
    public var autoLoginUser: String? { json["autoLoginUser"].nonEmptyString }

    public var encryptionLabel: String { encryptionEnabled ? "Encrypted" : "Not Encrypted" }
    public var protectionLabel: String { antivirusEnabled ? (antivirusUpToDate ? "Current" : "Out of Date") : "Disabled" }
    public var detectionLabel: String { activeThreatCount > 0 ? "Threats Detected" : "Clean" }
    public var firewallLabel: String { firewallEnabled ? "Enabled" : "Disabled" }
    public var tamperLabel: String {
        if isWindows { return secureBootEnabled ? "Secured" : "Insecure" }
        return (sipEnabled == true || secureBootEnabled) ? "Secured" : "Insecure"
    }
    public var remoteLabel: String {
        if isWindows {
            if sshRunning, rdpEnabled { return "SSH + RDP" }
            if sshRunning { return "SSH Only" }
            if rdpEnabled { return "RDP Only" }
            return "Disabled"
        }
        return sshRunning ? "SSH Enabled" : "Disabled"
    }
    public var certLabel: String {
        if userExpiredCertCount > 0 { return "Has Expired" }
        if expiringSoonCertCount > 0 { return "Expiring Soon" }
        return "Valid"
    }
    public var cveLabel: String {
        if criticalCveCount > 0 { return "Critical" }
        if cveCount > 0 { return "Has CVEs" }
        return "None"
    }

    /// The tampering summary the CSV export writes.
    public var tamperSummary: String {
        let main = isWindows
            ? "TPM \(tpmPresent && tpmEnabled ? "On" : "Off") / SB \(secureBootEnabled ? "On" : "Off")"
            : "SIP \(sipEnabled == true ? "On" : "Off") / SB \(secureBootEnabled ? "On" : "Off")"
        if firmwarePasswordStatus == "Set" { return main + " / FW On" }
        if firmwarePasswordStatus == "Not Set" { return main + " / FW Off" }
        return main
    }
}

/// One certificate hit from `/security/certificates`, grouped by common name for the search panel.
public struct CertificateSearchGroup: Sendable, Hashable, Identifiable {
    public struct DeviceHit: Sendable, Hashable, Identifiable {
        public var id: String { serialNumber }
        public var serialNumber: String
        public var deviceName: String
        public var notAfter: String?
        public var isExpired: Bool
        public var isExpiringSoon: Bool
    }
    public var id: String { commonName }
    public var commonName: String
    public var issuer: String?
    public var devices: [DeviceHit]
    public var expiredCount: Int
    public var expiringCount: Int
    public var validCount: Int

    public static func group(_ results: [JSONValue]) -> [CertificateSearchGroup] {
        var order: [String] = []
        var groups: [String: CertificateSearchGroup] = [:]
        for cert in results {
            let key = cert["commonName"].nonEmptyString ?? "Unknown"
            if groups[key] == nil {
                groups[key] = CertificateSearchGroup(commonName: key, issuer: cert["issuer"].nonEmptyString, devices: [], expiredCount: 0, expiringCount: 0, validCount: 0)
                order.append(key)
            }
            let serial = cert["serialNumber"].string ?? ""
            if !groups[key]!.devices.contains(where: { $0.serialNumber == serial }) {
                groups[key]!.devices.append(DeviceHit(serialNumber: serial, deviceName: cert["deviceName"].string ?? serial, notAfter: cert["notAfter"].nonEmptyString,
                                                      isExpired: cert["isExpired"].boolish, isExpiringSoon: cert["isExpiringSoon"].boolish))
            }
            if cert["isExpired"].boolish { groups[key]!.expiredCount += 1 } else if cert["isExpiringSoon"].boolish { groups[key]!.expiringCount += 1 } else { groups[key]!.validCount += 1 }
        }
        return order.compactMap { groups[$0] }.sorted { $0.devices.count > $1.devices.count }
    }
}

// MARK: - Management

/// One device in the `/management` report. Port of the mapping in `app/management/page.tsx`.
public struct ManagementReportRow: Sendable, Hashable {
    public var json: JSONValue
    public var provider: String
    public var enrollmentStatus: String
    public var enrollmentType: String
    public var intuneId: String
    public var tenantName: String
    public var isEnrolled: Bool
    public var autopilotActivated: Bool

    public init(json: JSONValue) {
        self.json = json
        var p = json["provider"].nonEmptyString ?? "Unmanaged"
        if p.hasPrefix("Microsoft Intune") { p = "Microsoft Intune" }
        provider = p
        enrollmentStatus = json["enrollmentStatus"].nonEmptyString ?? "Unknown"
        enrollmentType = json["enrollmentType"].nonEmptyString ?? "Unknown"
        intuneId = json["intuneId"].nonEmptyString ?? "N/A"
        tenantName = json["tenantName"].string ?? ""
        isEnrolled = json["isEnrolled"].boolish
        autopilotActivated = json["autopilotConfig"]["activated"].boolish
    }

    /// Provider-based platform guess used when a row carries no platform of its own.
    public static func platformHint(provider: String) -> Platform? {
        let p = provider.lowercased()
        if ["apple", "micromdm", "nanomdm", "mosyle", "kandji"].contains(p) || p.contains("jamf") { return .macOS }
        if p == "microsoft intune" { return .windows }
        return nil
    }

    /// How the device got into MDM: Automated, User Approved, Manual, or nil when not enrolled.
    public var bootstrapMethod: String? {
        if autopilotActivated || enrollmentType == "Automated Device Enrollment" { return "Automated" }
        if enrollmentType == "User Approved Enrollment" { return "User Approved" }
        if enrollmentType == "MDM Enrolled" || (enrollmentStatus == "Enrolled" && enrollmentType != "N/A" && enrollmentType != "Unknown") { return "Manual" }
        return nil
    }

    public var bootstrapHint: String? {
        if autopilotActivated { return "AutoPilot" }
        if enrollmentType == "Automated Device Enrollment" { return "ADE" }
        return nil
    }

    public func matches(_ q: String) -> Bool {
        let fields = [json["deviceName"].string, json["serialNumber"].string, intuneId, provider, json["usage"].string, json["catalog"].string, json["assetTag"].string, json["location"].string, json["department"].string]
        return fields.contains { $0?.lowercased().contains(q) ?? false }
    }
}

// MARK: - Identity

/// One device in the `/identity` report.
public struct IdentityReportRow: Sendable, Hashable {
    public struct SessionSummary: Sendable, Hashable {
        public var totalSessions: Int
        public var uniqueUsers: Int
        public var avgSessionMinutes: Double
        public var medianSessionMinutes: Double
    }

    public var json: JSONValue
    public var platformText: String
    public var totalUsers: Int
    public var adminUsers: Int
    public var disabledUsers: Int
    public var currentlyLoggedIn: Int
    public var secureTokenUsers: Int
    public var secureTokenMissing: Int
    public var hasBootstrapData: Bool
    public var bootstrapEscrowed: Bool
    public var adBound: Bool
    public var ldapBound: Bool
    public var usernames: [String]
    public var adminUsernames: [String]
    public var loggedInUsernames: [String]
    public var enrollmentType: String?
    public var trustStatus: String?
    public var authMethod: String?
    public var sessionSummary: SessionSummary?

    public init(json: JSONValue) {
        self.json = json
        platformText = json["platform"].string ?? ""
        totalUsers = json["totalUsers"].int ?? 0
        adminUsers = json["adminUsers"].int ?? 0
        disabledUsers = json["disabledUsers"].int ?? 0
        currentlyLoggedIn = json["currentlyLoggedIn"].int ?? 0
        secureTokenUsers = json["secureTokenUsers"].int ?? 0
        secureTokenMissing = json["secureTokenMissing"].int ?? 0
        let bt = json["bootstrapToken"]
        hasBootstrapData = bt.object != nil
        bootstrapEscrowed = bt["escrowed"].boolish
        adBound = json["adBound"].boolish
        ldapBound = json["ldapBound"].boolish
        usernames = json["users"].elements.compactMap { $0["username"].nonEmptyString }
        adminUsernames = json["adminUsernames"].elements.compactMap(\.nonEmptyString)
        loggedInUsernames = json["loggedInUsernames"].elements.compactMap(\.nonEmptyString)
        enrollmentType = json["enrollmentType"].nonEmptyString
        trustStatus = json["trustStatus"].nonEmptyString
        authMethod = json["authMethod"].nonEmptyString
        let s = json["sessionSummary"]
        sessionSummary = s.object == nil ? nil : SessionSummary(totalSessions: s["totalSessions"].int ?? 0, uniqueUsers: s["uniqueUsers"].int ?? 0,
                                                                  avgSessionMinutes: s["avgSessionMinutes"].double ?? 0, medianSessionMinutes: s["medianSessionMinutes"].double ?? 0)
    }

    /// Modern (SSO or Hello), Legacy (AD or LDAP without modern auth), Standard.
    public var authLabel: String {
        if authMethod != nil { return "Modern" }
        if adBound || ldapBound { return "Legacy" }
        return "Standard"
    }

    /// Trusted, Broken or Unconfirmed for domain-joined devices.
    public var trustLabel: String? {
        guard enrollmentType == "Domain Joined" else { return nil }
        if trustStatus == "Healthy" { return "Trusted" }
        if trustStatus == "Broken" { return "Broken" }
        return "Unconfirmed"
    }

    public func hasAdmin(_ name: String) -> Bool { adminUsernames.contains { $0.lowercased() == name.lowercased() } }

    public func matches(_ q: String) -> Bool {
        (json["deviceName"].string ?? "").lowercased().contains(q) || (json["serialNumber"].string ?? "").lowercased().contains(q)
            || usernames.contains { $0.lowercased().contains(q) } || loggedInUsernames.contains { $0.lowercased().contains(q) }
    }
}

// MARK: - System

/// One device in the `/system` report (the lean flat shape).
public struct SystemReportRow: Sendable, Hashable {
    public var json: JSONValue
    public var operatingSystem: String
    public var osVersion: String?
    public var buildNumber: String?
    public var displayVersion: String?
    public var edition: String?
    public var architecture: String?
    public var timeZone: String?
    public var locale: String?
    public var uptime: Double?
    public var bootTime: String?
    public var activationStatus: Bool?
    public var licenseSource: String?
    public var hasFirmwareLicense: Bool?
    public var pendingUpdatesCount: Int
    public var deferredUpdatesCount: Int

    public init(json: JSONValue) {
        self.json = json
        operatingSystem = json["operatingSystem"].nonEmptyString ?? ""
        osVersion = json["osVersion"].nonEmptyString
        buildNumber = json["buildNumber"].nonEmptyString
        displayVersion = json["displayVersion"].nonEmptyString
        edition = json["edition"].nonEmptyString
        architecture = json["architecture"].nonEmptyString
        timeZone = json["timeZone"].nonEmptyString
        locale = json["locale"].nonEmptyString
        uptime = json["uptime"].double
        bootTime = json["bootTime"].nonEmptyString
        activationStatus = json["activationStatus"].boolishIfPresent
        licenseSource = json["licenseSource"].nonEmptyString
        hasFirmwareLicense = json["hasFirmwareLicense"].boolishIfPresent
        pendingUpdatesCount = json["pendingUpdatesCount"].int ?? 0
        deferredUpdatesCount = json["deferredUpdatesCount"].int ?? 0
    }

    public var isMac: Bool {
        let p = (json["platform"].string ?? "").lowercased()
        return p == "macos" || operatingSystem.lowercased().contains("mac")
    }

    /// `getOSDisplayName`: "macOS 15 Sequoia" or "Windows 11 24H2".
    public var osDisplayName: String {
        if isMac {
            let major = Int((osVersion ?? "").split(separator: ".").first ?? "") ?? 0
            let name = OSNames.macOSMarketingName(version: osVersion)
            return major > 0 && name != "macOS" ? "macOS \(major) \(name)" : "macOS \(major > 0 ? String(major) : "")".trimmingCharacters(in: .whitespaces)
        }
        if let r = operatingSystem.range(of: #"Windows\s+(\d+)"#, options: .regularExpression) {
            let ver = operatingSystem[r].filter(\.isNumber)
            if let dv = displayVersion { return "Windows \(ver) \(dv)" }
            return "Windows \(ver)"
        }
        return operatingSystem.isEmpty ? "Unknown" : operatingSystem
    }

    /// `formatUptime`: "3d 4h", "5h 12m", "45m".
    public var uptimeText: String? {
        guard let s = uptime, s > 0 else { return nil }
        let days = Int(s / 86_400), hours = Int(s.truncatingRemainder(dividingBy: 86_400) / 3600), mins = Int(s.truncatingRemainder(dividingBy: 3600) / 60)
        if days > 0 { return "\(days)d \(hours)h" }
        if hours > 0 { return "\(hours)h \(mins)m" }
        return "\(mins)m"
    }

    public var activationLabel: String? { activationStatus.map { $0 ? "Activated" : "Not Activated" } }
    public var licenseTypeLabel: String { hasFirmwareLicense == true ? "Has OEM License" : "No OEM License" }
}
