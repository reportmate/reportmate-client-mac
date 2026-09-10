import SwiftUI
import ReportMateKit

/// The device overview: Inventory, System, Hardware, Management, Security
/// and Network widgets in a three-column grid.
struct InfoTabView: View {
    @Environment(AppState.self) private var appState
    let device: DeviceDetail

    private var columns: [GridItem] { [GridItem(.adaptive(minimum: 340, maximum: 600), spacing: 16, alignment: .top)] }

    var body: some View {
        LazyVGrid(columns: columns, alignment: .leading, spacing: 16) {
            InventoryWidget(device: device, settings: appState.settings)
            SystemWidget(device: device)
            HardwareWidget(device: device)
            ManagementWidget(device: device)
            SecurityWidget(device: device, settings: appState.settings)
            NetworkWidget(device: device)
        }
    }
}

// MARK: - Inventory

struct InventoryWidget: View {
    let device: DeviceDetail
    let settings: SettingsDocument

    var body: some View {
        let inventory = device[.inventory].normalizedKeys()
        let rows = InventoryMapping.rows(inventory: device[.inventory], fields: settings.inventory.fields).filter { $0.key != .assetTag }
        let hwSystem = device[.hardware]["system"]
        let name = inventory["deviceName"].nonEmptyString ?? hwSystem.firstString("computer_name", "computerName", "hostname") ?? device.name
        Card {
            VStack(spacing: 0) {
                CardHeader("Inventory", subtitle: "Device identity and assignment details", systemImage: "doc.text", tone: .blue)
                HStack(alignment: .top, spacing: 20) {
                    VStack(alignment: .leading, spacing: 14) {
                        StatRow(label: "Device Name", value: name)
                        if let tag = inventory["assetTag"].nonEmptyString { StatRow(label: "Asset Tag", value: tag, mono: true, copyable: true) }
                        StatRow(label: "Serial Number", value: inventory["serialNumber"].nonEmptyString ?? device.serialNumber, mono: true, copyable: true)
                        if let created = device.createdAt { StatRow(label: "Registered", value: TimeFormatting.relative(created), sublabel: TimeFormatting.medium(created)) }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    if !rows.isEmpty {
                        VStack(alignment: .leading, spacing: 14) {
                            ForEach(rows) { StatRow(label: $0.label, value: $0.value) }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                .padding(16)
            }
        }
    }
}

// MARK: - System

struct SystemWidget: View {
    let device: DeviceDetail

    var body: some View {
        let info = SystemInfo(modules: device.asJSON["modules"], platform: device.platform)
        Card {
            VStack(spacing: 0) {
                CardHeader("System", subtitle: "Operating system details", systemImage: "gearshape", tone: .purple)
                if !info.hasData {
                    EmptyStateView(title: "System information not available")
                } else {
                    let os = info.operatingSystem
                    let label = OSNames.osLabel(name: os.name, isMac: info.isMac)
                    let marketing = info.isMac ? OSNames.macOSMarketingName(version: os.version) : (os.displayVersion ?? "")
                    VStack(alignment: .leading, spacing: 18) {
                        HStack(alignment: .top, spacing: 12) {
                            StatRow(label: label, value: marketing.isEmpty ? "Unknown" : marketing)
                            StatRow(label: "Version", value: OSNames.formattedVersion(os.version, isMac: info.isMac))
                            if info.isMac {
                                StatRow(label: "Build", value: os.build ?? "Unknown")
                            } else {
                                StatRow(label: "Feature", value: os.featureUpdate ?? "Unknown")
                            }
                        }
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Software Update").appFont(.caption).foregroundStyle(.secondary)
                            updateLine(info)
                        }
                        HStack(alignment: .top, spacing: 12) {
                            VStack(alignment: .leading, spacing: 14) {
                                StatRow(label: "Keyboard Layout", value: os.keyboardLayout ?? "Unknown")
                                StatRow(label: "Time Zone", value: os.timeZone ?? "Unknown")
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            VStack(alignment: .leading, spacing: 14) {
                                StatRow(label: "Uptime", value: info.uptime ?? "Unknown")
                                StatRow(label: "Locale", value: os.locale ?? "Unknown")
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                    .padding(16)
                }
            }
        }
    }

    @ViewBuilder
    private func updateLine(_ info: SystemInfo) -> some View {
        switch info.updateStatus {
        case .upToDate:
            Label("Up to Date", systemImage: "checkmark.circle.fill").foregroundStyle(.green).appFont(.callout, weight: .medium)
        case .pending(let count, let deferred, let soonest):
            HStack(spacing: 8) {
                Label("\(count) Pending Update\(count == 1 ? "" : "s")", systemImage: "exclamationmark.triangle.fill").foregroundStyle(.yellow).appFont(.callout, weight: .medium)
                if deferred > 0 {
                    Text("+\(deferred) deferred\(soonest.map { " · \(TimeFormatting.shortDate($0))" } ?? "")").appFont(.caption).foregroundStyle(.orange)
                }
            }
        case .deferredOnly(let count, let soonest):
            VStack(alignment: .leading, spacing: 2) {
                Label("\(count) Update\(count == 1 ? "" : "s") Deferred", systemImage: "clock").foregroundStyle(.orange).appFont(.callout, weight: .medium)
                if let soonest { Text("Available \(TimeFormatting.shortDate(soonest))").appFont(.caption).foregroundStyle(.orange).padding(.leading, 22) }
            }
        }
    }
}

// MARK: - Hardware

struct HardwareWidget: View {
    let device: DeviceDetail

    var body: some View {
        let hw = HardwareInfo(modules: device.asJSON["modules"], platform: device.platform)
        Card {
            VStack(spacing: 0) {
                CardHeader("Hardware", subtitle: "Device specs", systemImage: "cpu", tone: .orange)
                if !hw.hasData {
                    EmptyStateView(title: "Hardware information not available")
                } else if hw.isMac {
                    VStack(alignment: .leading, spacing: 12) {
                        if let model = hw.model { StatRow(label: "Model", value: model, sublabel: hw.modelIdentifier) }
                        StatRow(label: "Chip", value: hw.chipName ?? "Unknown")
                        HStack(alignment: .top, spacing: 12) {
                            VStack(alignment: .leading, spacing: 10) {
                                StatRow(label: "CPU", value: hw.cpuCores > 0 ? coreLabel(hw) : "Unknown")
                                StatRow(label: "GPU", value: hw.gpuCores > 0 ? "\(hw.gpuCores) cores" : hw.cleanGraphicsName)
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            VStack(alignment: .leading, spacing: 10) {
                                StatRow(label: "RAM", value: hw.memoryFormatted)
                                if hw.npuCores > 0 || hw.npuTops != nil {
                                    StatRow(label: "NPU", value: hw.npuTops.map { "\($0) TOPS" } ?? "\(hw.npuCores) cores")
                                }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        StatRow(label: "Storage", value: hw.storageFormatted)
                        if let b = hw.battery, hw.hasBattery {
                            StatRow(label: "Battery", value: batteryLabel(b, cycles: true))
                        }
                    }
                    .padding(16)
                } else {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack(alignment: .top, spacing: 12) {
                            if let m = hw.manufacturer { StatRow(label: "Manufacturer", value: m).frame(maxWidth: 140) }
                            StatRow(label: "Model", value: hw.model ?? "Unknown")
                        }
                        StatRow(label: "Processor", value: hw.cpuCores > 0 ? "\(hw.processorName ?? "Unknown") (\(hw.cpuCores) cores)" : (hw.processorName ?? "Unknown"))
                        StatRow(label: "Graphics", value: hw.gpuCores > 0 ? "\(hw.cleanGraphicsName) (\(hw.gpuCores) cores)" : hw.cleanGraphicsName)
                        StatRow(label: "Memory", value: hw.memoryFormatted)
                        StatRow(label: "Storage", value: hw.totalStorageBytes > 0 ? "\(ByteFormatting.bytes(hw.totalStorageBytes)) (\(ByteFormatting.bytes(hw.freeStorageBytes)) free)" : "Unknown")
                        if let b = hw.battery, hw.hasBattery { StatRow(label: "Battery", value: batteryLabel(b, cycles: false)) }
                    }
                    .padding(16)
                }
            }
        }
    }

    private func batteryLabel(_ b: HardwareInfo.Battery, cycles: Bool) -> String {
        var s = "\(Int(b.chargePercent))%"
        if cycles, b.cycleCount > 0 { s += " · \(b.cycleCount) cycles" }
        if let h = b.health { s += " · \(h)" }
        return s
    }

    private func coreLabel(_ hw: HardwareInfo) -> String {
        let p = hw.performanceCores, e = hw.efficiencyCores
        if p > 0, e > 0, p + e == hw.cpuCores { return "\(hw.cpuCores) cores (\(p)P + \(e)E)" }
        return "\(hw.cpuCores) cores"
    }
}

// MARK: - Management

struct ManagementWidget: View {
    let device: DeviceDetail

    var body: some View {
        let m = ManagementInfo(modules: device.asJSON["modules"], platform: device.platform)
        Card {
            VStack(spacing: 0) {
                CardHeader("Management", subtitle: "Device Management Service", systemImage: "checkmark.shield", tone: .yellow)
                if !m.hasData {
                    EmptyStateView(title: "Management information not available")
                } else {
                    VStack(alignment: .leading, spacing: 12) {
                        if let provider = m.provider {
                            HStack {
                                Text("Provider").appFont(.callout).foregroundStyle(.secondary)
                                Spacer()
                                Text(provider).appFont(.body, weight: .medium)
                            }
                        }
                        StatusBadgeRow(label: "Enrollment", status: m.isEnrolled ? "Enrolled" : "Not Enrolled", tone: m.isEnrolled ? .green : .red)
                        if let type = m.enrollmentType {
                            StatusBadgeRow(label: "Enrollment Type", status: type,
                                           tone: type.contains("Automated") || type.contains("Entra Joined") ? .green : type.contains("User Approved") ? .yellow : .gray)
                        }
                        if m.isMac, let supervised = m.isSupervised {
                            StatusBadgeRow(label: "Supervised", status: supervised ? "Yes" : "No", tone: supervised ? .green : .yellow)
                        }
                        if !m.isMac, let autopilot = m.autopilotActivated {
                            StatusBadgeRow(label: "Autopilot Activated", status: autopilot ? "Yes" : "No", tone: autopilot ? .green : .gray)
                        }
                        if m.isEnrolled {
                            if let host = m.serverHost { StatRow(label: "Server", value: host, copyable: true) }
                            if let exp = m.certificateExpires { StatRow(label: "Certificate Expiry", value: TimeFormatting.shortDate(exp)) }
                            if let org = m.organization { StatRow(label: "Organization", value: org) }
                            VStack(alignment: .leading, spacing: 8) {
                                if !m.providerIsIntune {
                                    idRow("Hardware UUID", device.deviceId)
                                }
                                if !m.isMac, m.providerIsIntune, let id = m.intuneDeviceId { idRow("Intune UUID", id) }
                                if !m.isMac, !m.providerIsIntune, let id = m.entraObjectId { idRow("Object ID", id) }
                            }
                            .padding(.top, 4)
                        }
                    }
                    .padding(16)
                }
            }
        }
    }

    private func idRow(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).appFont(.caption).foregroundStyle(.secondary)
            HStack(spacing: 6) {
                Text(value).appFont(fixed: 11, design: .monospaced).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                CopyButton(value: value)
            }
        }
    }
}

// MARK: - Security

struct SecurityWidget: View {
    let device: DeviceDetail
    let settings: SettingsDocument

    var body: some View {
        let overview = SecurityOverview(device: device, settings: settings)
        Card {
            VStack(spacing: 0) {
                CardHeader("Security", subtitle: "\(overview.platformLabel) protection status", systemImage: "lock", tone: .red)
                if !overview.hasData {
                    EmptyStateView(title: "Security information not available")
                } else {
                    VStack(alignment: .leading, spacing: 10) {
                        ForEach(overview.rows) { row in
                            StatusBadgeRow(label: row.label, status: row.value, tone: tone(row.tone), indented: row.indented)
                        }
                    }
                    .padding(16)
                }
            }
        }
    }

    private func tone(_ t: SecurityOverview.Tone) -> Tone {
        switch t {
        case .success: return .green
        case .warning: return .yellow
        case .error: return .red
        case .info: return .gray
        }
    }
}

// MARK: - Network

struct NetworkWidget: View {
    let device: DeviceDetail

    var body: some View {
        let net = NetworkInfo(modules: device.asJSON["modules"])
        let ethernet = net.ethernetInterface
        let wifi = net.wirelessInterface
        let wifiData = net.wifiInterface
        let primaryIP = ethernet?.ipAddress ?? wifi?.ipAddress ?? net.ipAddress
        Card {
            VStack(spacing: 0) {
                CardHeader("Network", subtitle: "Connectivity and configuration", systemImage: "wifi", tone: .teal)
                if primaryIP == nil {
                    EmptyStateView(title: "Network information not available")
                } else {
                    VStack(alignment: .leading, spacing: 14) {
                        if ethernet != nil, wifi != nil {
                            HStack(alignment: .top, spacing: 12) {
                                StatRow(label: "Hostname", value: net.hostname, mono: true, copyable: true)
                                if let ssid = wifiData?.ssid, ssid != "[Location Services Required]" { StatRow(label: "WiFi Name", value: ssid) }
                            }
                            HStack(alignment: .top, spacing: 12) {
                                VStack(alignment: .leading, spacing: 10) {
                                    StatRow(label: "Wired IP Address", value: ethernet?.ipAddress ?? net.ipAddress, mono: true, copyable: true)
                                    StatRow(label: "Wired MAC Address", value: ethernet?.macAddress ?? net.macAddress, mono: true, copyable: true)
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                                VStack(alignment: .leading, spacing: 10) {
                                    StatRow(label: "WiFi IP Address", value: wifiData?.ipAddress ?? wifi?.ipAddress, mono: true, copyable: true)
                                    StatRow(label: "WiFi MAC Address", value: wifiData?.macAddress ?? wifi?.macAddress, mono: true, copyable: true)
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        } else if let ethernet {
                            StatRow(label: "Connection", value: "Ethernet")
                            StatRow(label: "Hostname", value: net.hostname, mono: true, copyable: true)
                            StatRow(label: "IP Address", value: ethernet.ipAddress ?? net.ipAddress, mono: true, copyable: true)
                            StatRow(label: "MAC Address", value: ethernet.macAddress ?? net.macAddress, mono: true, copyable: true)
                        } else if let wifi {
                            StatRow(label: "Connection", value: "Wireless")
                            StatRow(label: "Hostname", value: net.hostname, mono: true, copyable: true)
                            if let ssid = wifiData?.ssid ?? wifi.ssid, ssid != "[Location Services Required]" {
                                StatRow(label: "SSID", value: (wifiData?.protocolName ?? wifi.wirelessProtocol).map { "\(ssid) (\($0))" } ?? ssid)
                            }
                            StatRow(label: "IP Address", value: wifiData?.ipAddress ?? wifi.ipAddress ?? net.ipAddress, mono: true, copyable: true)
                            StatRow(label: "MAC Address", value: wifiData?.macAddress ?? wifi.macAddress ?? net.macAddress, mono: true, copyable: true)
                        } else {
                            StatRow(label: "Connection", value: net.connectionType ?? "Unknown")
                            if let h = net.hostname { StatRow(label: "Hostname", value: h, mono: true, copyable: true) }
                            StatRow(label: "IP Address", value: net.ipAddress, mono: true, copyable: true)
                            if let mac = net.macAddress { StatRow(label: "MAC Address", value: mac, mono: true, copyable: true) }
                        }
                        if net.vpnActive, let vpn = net.vpnName {
                            StatusBadgeRow(label: "VPN", status: vpn, tone: .blue)
                        }
                        if let q = net.networkQuality, q.hasCapacity {
                            VStack(alignment: .leading, spacing: 8) {
                                SectionLabel("Network Quality")
                                HStack(alignment: .top, spacing: 12) {
                                    VStack(alignment: .leading, spacing: 8) {
                                        if let d = q.downlinkCapacity { StatRow(label: "Download", value: d) }
                                        if let r = q.downlinkResponsiveness ?? q.uplinkResponsiveness { StatRow(label: "Responsiveness", value: r) }
                                    }
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    VStack(alignment: .leading, spacing: 8) {
                                        if let u = q.uplinkCapacity { StatRow(label: "Upload", value: u) }
                                        if let l = q.idleLatency { StatRow(label: "Latency", value: l) }
                                    }
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                }
                            }
                            .padding(.top, 4)
                        }
                    }
                    .padding(16)
                }
            }
        }
    }
}
