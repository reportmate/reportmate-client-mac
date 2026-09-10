import SwiftUI
import ReportMateKit

/// Peripherals: category filter grid, then one section per category with
/// device cards. Port of `PeripheralsTab.tsx`.
struct PeripheralsTabView: View {
    let device: DeviceDetail
    @State private var activeFilter: PeripheralsInfo.Category? = nil

    private static let columns = [GridItem(.adaptive(minimum: 300), spacing: 12, alignment: .top)]

    var body: some View {
        let p = PeripheralsInfo(modules: device.asJSON["modules"])
        VStack(alignment: .leading, spacing: 20) {
            if !p.hasData {
                Card {
                    EmptyStateView(title: "No Peripheral Data",
                                   message: "Peripheral device information is not available for this device. This could be because the device has not reported recently or the peripherals module is not enabled.",
                                   systemImage: "display")
                }
            } else {
                categoryGrid(p)
                if visible(.storage), !p.externalStorage.isEmpty { storage(p.externalStorage) }
                if visible(.printers), !p.printers.isEmpty { printers(p.printers) }
                if visible(.audio), !p.audioOutputs.isEmpty { audio(p.audioOutputs, title: "Audio Output", icon: "speaker.wave.2", tone: .green, fallback: "Audio Output") }
                if visible(.scanners), !p.scanners.isEmpty { scanners(p.scanners) }
                if visible(.microphones), !p.microphones.isEmpty { audio(p.microphones, title: "Microphones", icon: "mic", tone: .pink, fallback: "Microphone") }
                if visible(.usbThunderbolt), !(p.usbDevices.isEmpty && p.thunderboltDevices.isEmpty) { usbThunderbolt(p) }
                if visible(.bluetooth), !p.bluetoothDevices.isEmpty { bluetooth(p.bluetoothDevices) }
                if visible(.input), p.inputCount > 0 { input(p) }
            }
            JSONTreeView(value: device[.peripherals], label: "device.modules.peripherals")
        }
    }

    private func visible(_ c: PeripheralsInfo.Category) -> Bool { activeFilter == nil || activeFilter == c }

    private func categoryGrid(_ p: PeripheralsInfo) -> some View {
        Card {
            LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 8), count: 4), spacing: 8) {
                ForEach(PeripheralsInfo.Category.allCases) { c in
                    let active = activeFilter == c
                    Button {
                        activeFilter = active ? nil : c
                    } label: {
                        HStack {
                            Image(systemName: icon(for: c)).foregroundStyle(active ? Color.white : tone(for: c).color)
                            Text(c.label).appFont(.callout, weight: .medium).lineLimit(1)
                            Spacer()
                            Text("\(p.count(for: c))")
                                .appFont(.caption2, weight: .medium)
                                .padding(.horizontal, 7).padding(.vertical, 2)
                                .background(active ? Color.white.opacity(0.25) : Color.secondary.opacity(0.15), in: Capsule())
                        }
                        .padding(.horizontal, 10).padding(.vertical, 8)
                        .background(active ? Color.blue : Color.subtleBackground, in: RoundedRectangle(cornerRadius: 8))
                        .foregroundStyle(active ? Color.white : Color.primary)
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(12)
        }
    }

    private func icon(for c: PeripheralsInfo.Category) -> String {
        switch c {
        case .storage: return "externaldrive"
        case .usbThunderbolt: return "cable.connector"
        case .audio: return "speaker.wave.2"
        case .input: return "keyboard"
        case .printers: return "printer"
        case .scanners: return "scanner"
        case .microphones: return "mic"
        case .bluetooth: return "dot.radiowaves.left.and.right"
        }
    }

    private func tone(for c: PeripheralsInfo.Category) -> Tone {
        switch c {
        case .storage: return .red
        case .usbThunderbolt: return .blue
        case .audio: return .green
        case .input: return .purple
        case .printers: return .orange
        case .scanners: return .indigo
        case .microphones: return .pink
        case .bluetooth: return .cyan
        }
    }

    // MARK: Sections

    private func sectionTitle(_ text: String, icon: String, tone: Tone) -> some View {
        HStack(spacing: 8) {
            Image(systemName: icon).foregroundStyle(tone.color)
            Text(text).appFont(.title3, weight: .semibold)
        }
    }

    private func subTitle(_ text: String, icon: String, tone: Tone = .gray) -> some View {
        HStack(spacing: 6) {
            Image(systemName: icon).foregroundStyle(tone.color).appFont(.caption)
            Text(text).appFont(.callout, weight: .medium).foregroundStyle(.secondary)
        }
    }

    private func storage(_ items: [PeripheralsInfo.ExternalStorage]) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionTitle("External Storage", icon: "externaldrive", tone: .red)
            LazyVGrid(columns: Self.columns, spacing: 12) {
                ForEach(items) { d in
                    PeripheralCard(title: d.displayName, icon: "externaldrive", badge: d.storageType) {
                        if let fs = d.fileSystem { InfoRow("File System", fs.uppercased()) }
                        if let mp = d.mountPoint { InfoRow("Mount Point", mp) }
                        if let dp = d.devicePath { InfoRow("Device", dp) }
                        if let s = d.totalSize { InfoRow("Size", s) }
                        if let p = d.protocolName { InfoRow("Protocol", p) }
                    }
                }
            }
        }
    }

    private func printers(_ items: [PeripheralsInfo.Printer]) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionTitle("Printers", icon: "printer", tone: .orange)
            ForEach(items) { printer in
                Card {
                    VStack(alignment: .leading, spacing: 10) {
                        HStack {
                            if !printer.name.isEmpty {
                                HStack(spacing: 8) {
                                    Text("Name").appFont(.callout).foregroundStyle(.secondary)
                                    Text(printer.name).appFont(.callout, weight: .medium)
                                }
                            }
                            Spacer()
                            if printer.isDefault { Pill("Default", tone: .green) }
                        }
                        if let uri = printer.uri { CodeRow(label: "Queue", value: uri) }
                        if let ppd = printer.ppd { CodeRow(label: "PostScript Printer Description", value: ppd) }
                        if !printer.cupsFilters.isEmpty {
                            VStack(alignment: .leading, spacing: 6) {
                                Text("CUPS Filters").appFont(.callout, weight: .medium).foregroundStyle(.secondary)
                                ForEach(Array(printer.cupsFilters.enumerated()), id: \.offset) { _, f in
                                    HStack(alignment: .top, spacing: 8) {
                                        VStack(alignment: .leading, spacing: 2) {
                                            HStack(spacing: 6) {
                                                Text(f.name).appFont(.caption, weight: .medium)
                                                if let v = f.version { Text("v\(v)").appFont(.caption).foregroundStyle(.secondary) }
                                            }
                                            if let p = f.path { Text(p).appFont(.caption2, design: .monospaced).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle).help(p) }
                                        }
                                        CopyButton(value: f.path ?? f.name)
                                    }
                                    .padding(.horizontal, 8).padding(.vertical, 4)
                                    .background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 6))
                                }
                            }
                        }
                        Divider()
                        HStack(alignment: .top, spacing: 32) {
                            VStack(alignment: .leading, spacing: 6) {
                                if let m = printer.manufacturer { InfoRow("Manufacturer", m) }
                                if let m = printer.model { InfoRow("Model", m) }
                                if let i = printer.identifier { InfoRow("Identifier", i) }
                                if let c = printer.connectionType { InfoRow("Connection", c) }
                                if let c = printer.cupsVersion { InfoRow("CUPS Version", c) }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            VStack(alignment: .leading, spacing: 6) {
                                if let s = printer.status { InfoRow("Status", s) }
                                if let s = printer.scanningSupport { InfoRow("Scanning", s) }
                                if let f = printer.faxSupport { InfoRow("Fax", f) }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        if !printer.stateReasons.isEmpty {
                            Divider()
                            SectionLabel("State Reasons")
                            FlowLayout(spacing: 6) {
                                ForEach(printer.stateReasons, id: \.self) { Pill($0, tone: .orange) }
                            }
                        }
                    }
                    .padding(16)
                }
            }
        }
    }

    private func audio(_ items: [PeripheralsInfo.AudioDevice], title: String, icon: String, tone: Tone, fallback: String) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionTitle(title, icon: icon, tone: tone)
            LazyVGrid(columns: Self.columns, spacing: 12) {
                ForEach(items) { d in
                    PeripheralCard(title: d.name.isEmpty ? fallback : d.name, icon: icon, badge: d.isDefault ? "Default" : nil) {
                        if let m = d.manufacturer { InfoRow("Manufacturer", m) }
                        if let c = d.connectionType { InfoRow("Connection", c) }
                        if let b = d.isBuiltIn { InfoRow("Type", b ? "Built-in" : "External") }
                    }
                }
            }
        }
    }

    private func scanners(_ items: [PeripheralsInfo.Scanner]) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionTitle("Scanners", icon: "scanner", tone: .indigo)
            LazyVGrid(columns: Self.columns, spacing: 12) {
                ForEach(items) { d in
                    PeripheralCard(title: d.name, icon: "scanner", badge: d.scannerType) {
                        if let m = d.manufacturer { InfoRow("Manufacturer", m) }
                        if let c = d.connectionType { InfoRow("Connection", c) }
                        if let s = d.status { InfoRow("Status", s) }
                    }
                }
            }
        }
    }

    private func usbThunderbolt(_ p: PeripheralsInfo) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionTitle("USB & Thunderbolt", icon: "cable.connector", tone: .blue)
            if !p.thunderboltDevices.isEmpty {
                subTitle("Thunderbolt", icon: "bolt.fill", tone: .yellow)
                LazyVGrid(columns: Self.columns, spacing: 12) {
                    ForEach(p.thunderboltDevices) { d in
                        PeripheralCard(title: d.name, icon: "bolt.fill", badge: d.deviceType) {
                            if let v = d.vendor { InfoRow("Vendor", v) }
                            if let i = d.deviceId { InfoRow("Device ID", i) }
                            if let u = d.uid { InfoRow("UID", u) }
                        }
                    }
                }
            }
            if !p.usbDevices.isEmpty {
                subTitle("USB Devices", icon: "cable.connector", tone: .blue)
                LazyVGrid(columns: Self.columns, spacing: 12) {
                    ForEach(p.usbDevices) { d in
                        PeripheralCard(title: d.name, icon: "cable.connector", badge: d.deviceType) {
                            if let v = d.vendor { InfoRow("Vendor", v) }
                            if let v = d.vendorId { InfoRow("Vendor ID", v) }
                            if let v = d.productId { InfoRow("Product ID", v) }
                            if let v = d.serialNumber { InfoRow("Serial", v) }
                            if let v = d.linkSpeed { InfoRow("Link Speed", v) } else if let v = d.speed { InfoRow("Speed", v) }
                            if let v = d.locationId { InfoRow("Location ID", v) }
                            if let v = d.powerAllocated { InfoRow("Power", v) }
                            if let v = d.usbVersion { InfoRow("USB Version", v) }
                            if let v = d.connectionType { InfoRow("Connection", v) }
                        }
                    }
                }
            }
        }
    }

    private func bluetooth(_ items: [PeripheralsInfo.BluetoothDevice]) -> some View {
        let connected = items.filter(\.isConnected)
        let paired = items.filter { !$0.isConnected }
        return VStack(alignment: .leading, spacing: 12) {
            sectionTitle("Bluetooth Peripherals", icon: "dot.radiowaves.left.and.right", tone: .cyan)
            if !connected.isEmpty {
                subTitle("Connected", icon: "wifi", tone: .green)
                LazyVGrid(columns: Self.columns, spacing: 12) {
                    ForEach(connected) { d in
                        PeripheralCard(title: d.name.isEmpty ? "Bluetooth Device" : d.name, icon: "dot.radiowaves.left.and.right", badge: "Connected", badgeTone: .green) {
                            if let c = d.deviceCategory { InfoRow("Category", c) }
                            if let a = d.address { InfoRow("Address", a) }
                            if let b = d.batteryLevel { InfoRow("Battery", "\(b)%") }
                        }
                    }
                }
            }
            if !paired.isEmpty {
                subTitle("Paired", icon: "wifi.slash")
                LazyVGrid(columns: Self.columns, spacing: 12) {
                    ForEach(paired) { d in
                        PeripheralCard(title: d.name.isEmpty ? "Bluetooth Device" : d.name, icon: "dot.radiowaves.left.and.right", badge: "Paired") {
                            if let c = d.deviceCategory { InfoRow("Category", c) }
                            if let a = d.address { InfoRow("Address", a) }
                        }
                    }
                }
            }
        }
    }

    private func input(_ p: PeripheralsInfo) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionTitle("Input Devices", icon: "keyboard", tone: .purple)
            if p.inputCount == 0 {
                EmptyStateView(title: "No input devices detected", systemImage: "keyboard")
            } else {
                subTitle("Keyboards", icon: "keyboard")
                LazyVGrid(columns: Self.columns, spacing: 12) {
                    ForEach(p.keyboards) { d in
                        PeripheralCard(title: d.name.isEmpty ? "Keyboard" : d.name, icon: "keyboard", badge: d.connectionType) {
                            if let v = d.vendor { InfoRow("Vendor", v) }
                            if let v = d.vendorId { InfoRow("Vendor ID", v) }
                            if let v = d.productId { InfoRow("Product ID", v) }
                            if let v = d.serialNumber { InfoRow("Serial", v) }
                            if let b = d.isBuiltIn { InfoRow("Type", b ? "Built-in" : "External") }
                        }
                    }
                }
            }
            if !p.mice.isEmpty {
                subTitle("Mice", icon: "computermouse")
                LazyVGrid(columns: Self.columns, spacing: 12) {
                    ForEach(p.mice) { d in
                        PeripheralCard(title: d.name.isEmpty ? "Mouse" : d.name, icon: "computermouse", badge: d.connectionType) {
                            if let v = d.vendor { InfoRow("Vendor", v) }
                            if let v = d.vendorId { InfoRow("Vendor ID", v) }
                            if let v = d.productId { InfoRow("Product ID", v) }
                            if let v = d.serialNumber { InfoRow("Serial", v) }
                        }
                    }
                }
            }
            if !p.trackpads.isEmpty {
                subTitle("Trackpads", icon: "hand.point.up.left")
                LazyVGrid(columns: Self.columns, spacing: 12) {
                    ForEach(p.trackpads) { d in
                        PeripheralCard(title: d.name.isEmpty ? "Trackpad" : d.name, icon: nil, badge: d.connectionType) {
                            if let v = d.vendor { InfoRow("Vendor", v) }
                            if let v = d.vendorId { InfoRow("Vendor ID", v) }
                            if let v = d.productId { InfoRow("Product ID", v) }
                            if let v = d.serialNumber { InfoRow("Serial", v) }
                            if let b = d.isBuiltIn { InfoRow("Type", b ? "Built-in" : "External") }
                            if let f = d.supportsForceTouch { InfoRow("Force Touch", f ? "Yes" : "No") }
                        }
                    }
                }
            }
            if !p.tablets.isEmpty {
                subTitle("Pen Input", icon: "pencil.tip")
                LazyVGrid(columns: Self.columns, spacing: 12) {
                    ForEach(p.tablets) { d in
                        PeripheralCard(title: d.name.isEmpty ? "Graphics Tablet" : d.name, icon: "pencil.tip", badge: d.tabletType ?? PeripheralsInfo.penInputLabel) {
                            if let v = d.vendor { InfoRow("Vendor", v) }
                            if let v = d.vendorId { InfoRow("Vendor ID", v) }
                            if let v = d.productId { InfoRow("Product ID", v) }
                            if let v = d.serialNumber { InfoRow("Serial", v) }
                            if let v = d.connectionType { InfoRow("Connection", v) }
                        }
                    }
                }
            }
        }
    }
}

/// One peripheral: titled header with icon and badge, key-value rows below.
struct PeripheralCard<Content: View>: View {
    let title: String
    var icon: String? = nil
    var badge: String? = nil
    var badgeTone: Tone = .gray
    @ViewBuilder var content: Content

    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 0) {
                HStack(spacing: 8) {
                    if let icon { Image(systemName: icon).foregroundStyle(.secondary).appFont(.caption) }
                    Text(title).appFont(.callout, weight: .medium).lineLimit(1).truncationMode(.middle)
                    Spacer()
                    if let badge { Pill(badge, tone: badgeTone) }
                }
                .padding(.horizontal, 14).padding(.vertical, 10)
                .background(Color.subtleBackground)
                Divider()
                VStack(alignment: .leading, spacing: 6) { content }
                    .padding(14)
            }
        }
    }
}

/// Label at a fixed width, value beside it.
struct InfoRow: View {
    let label: String
    let value: String
    init(_ label: String, _ value: String) { self.label = label; self.value = value }
    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Text(label).appFont(.caption).foregroundStyle(.secondary).frame(width: 110, alignment: .leading)
            Text(value).appFont(.caption, weight: .medium).lineLimit(2).truncationMode(.middle).textSelection(.enabled).help(value)
        }
    }
}

/// A monospaced value in a grey box with a copy button.
struct CodeRow: View {
    let label: String
    let value: String
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).appFont(.caption).foregroundStyle(.secondary)
            HStack(spacing: 8) {
                Text(value).appFont(.caption, design: .monospaced).textSelection(.enabled).lineLimit(3)
                CopyButton(value: value)
            }
            .padding(.horizontal, 8).padding(.vertical, 5)
            .background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 6))
        }
    }
}
