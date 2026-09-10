import SwiftUI
import Charts
import ReportMateKit

/// Hardware overview: identity, the chip capsule or discrete spec grid,
/// displays, storage analysis, storage devices, battery and memory modules.
struct HardwareTabView: View {
    let device: DeviceDetail

    var body: some View {
        let hw = HardwareInfo(modules: device.asJSON["modules"], platform: device.platform)
        VStack(alignment: .leading, spacing: 20) {
            header(hw)
            if !hw.hasData {
                Card { EmptyStateView(title: "No Hardware Information", message: "Hardware data is not available for this device.", systemImage: "cpu") }
            } else {
                Card {
                    VStack(alignment: .leading, spacing: 20) {
                        identity(hw)
                        if hw.isUnifiedMemory { unifiedGrid(hw) } else { discreteGrid(hw) }
                    }
                    .padding(20)
                }
                if !hw.displays.isEmpty { displays(hw) }
                storageAnalysis(hw)
                storageDevices(hw)
                if hw.hasBattery, let b = hw.battery { batteryTable(b) }
                if !hw.memoryModules.isEmpty { memoryModules(hw) }
            }
            JSONTreeView(value: device[.hardware], label: "device.modules.hardware")
        }
    }

    private func header(_ hw: HardwareInfo) -> some View {
        HStack {
            HStack(spacing: 12) {
                ZStack {
                    RoundedRectangle(cornerRadius: 10).fill(Color.orange.opacity(0.15))
                    Image(systemName: "cpu").foregroundStyle(.orange).appFont(fixed: 20)
                }
                .frame(width: 44, height: 44)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Hardware Overview").appFont(.title2, weight: .bold)
                    Text("System hardware specifications and components").appFont(.callout).foregroundStyle(.secondary)
                }
            }
            Spacer()
            if let arch = hw.architecture {
                VStack(alignment: .trailing, spacing: 2) {
                    Text("Architecture").appFont(.caption).foregroundStyle(.secondary)
                    Text(arch).appFont(.title2, weight: .bold).foregroundStyle(.orange)
                }
            }
        }
    }

    private func identity(_ hw: HardwareInfo) -> some View {
        HStack(alignment: .top, spacing: 32) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Manufacturer").appFont(.caption).foregroundStyle(.secondary)
                Text(hw.manufacturer ?? "Unknown").appFont(.title3, weight: .bold)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text("Model").appFont(.caption).foregroundStyle(.secondary)
                Text(hw.model ?? "Unknown").appFont(.title3, weight: .bold)
            }
            if let id = hw.modelIdentifier {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Identifier").appFont(.caption).foregroundStyle(.secondary)
                    Text(id).appFont(.title3, weight: .bold, design: .monospaced)
                }
            }
            Spacer()
        }
        .padding(14)
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.cardBorder, lineWidth: 2))
    }

    private var tileColumns: [GridItem] { [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)] }

    private func unifiedGrid(_ hw: HardwareInfo) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text("\(hw.processorName ?? hw.chipName ?? "Apple") Chip").appFont(.title3, weight: .bold)
                Text("Unified Memory Architecture").appFont(.caption).foregroundStyle(.secondary)
            }
            .padding(.leading, 6)
            HStack(alignment: .top, spacing: 16) {
                LazyVGrid(columns: tileColumns, spacing: 12) {
                    SpecTile(icon: "cpu", title: "CPU", tone: .red, value: "\(hw.cpuCores) Cores",
                             detail: hw.hasAppleSilicon ? "\(hw.performanceCores) Performance + \(hw.efficiencyCores) Efficiency" : nil)
                    SpecTile(icon: "memorychip", title: "Memory", tone: .yellow, value: ByteFormatting.bytes(hw.totalMemoryBytes),
                             detail: [hw.memoryType, hw.memoryManufacturer].compactMap { $0 }.filter { $0 != "Unknown" }.joined(separator: " "))
                    SpecTile(icon: "square.3.layers.3d", title: "GPU", tone: .green, value: "\(hw.gpuCores) Cores", detail: hw.graphicsMetalSupport ?? hw.displayGraphicsName)
                    if hw.hasNpu {
                        SpecTile(icon: "brain", title: "NPU", tone: .pink, value: hw.npuTops.map { "\($0) TOPS" } ?? "\(hw.npuCores) Cores",
                                 detail: hw.npuTops != nil ? "\(hw.npuCores) Cores" : nil)
                    }
                }
                .padding(12)
                .background(Color.subtleBackground)
                .clipShape(RoundedRectangle(cornerRadius: 14))
                .overlay(RoundedRectangle(cornerRadius: 14).stroke(style: StrokeStyle(lineWidth: 2, dash: [6, 4])).foregroundStyle(Color.secondary.opacity(0.35)))
                .frame(maxWidth: .infinity)
                LazyVGrid(columns: tileColumns, spacing: 12) {
                    SpecTile(icon: "internaldrive", title: "Storage", tone: .purple, value: ByteFormatting.bytes(hw.totalStorageBytes),
                             detail: hw.totalStorageBytes > 0 ? "\(min(100, Int((hw.freeStorageBytes / hw.totalStorageBytes * 100).rounded())))% Free" : nil)
                    if hw.hasBattery, let b = hw.battery {
                        SpecTile(icon: "battery.75percent", title: "Battery", tone: .green, value: "\(b.cycleCount) Cycles", detail: "\(Int(b.chargePercent.rounded()))% • \(b.health ?? "Unknown")")
                    }
                    if let w = hw.wireless, w.isAvailable {
                        SpecTile(icon: "wifi", title: "Wireless", tone: .teal, value: w.generation ?? "Available", detail: [w.version, w.status].compactMap { $0 }.joined(separator: " • "))
                    }
                    if let b = hw.bluetooth, b.isAvailable {
                        SpecTile(icon: "dot.radiowaves.left.and.right", title: "Bluetooth", tone: .blue, value: b.version ?? "N/A", detail: b.status ?? "Available")
                    }
                }
                .padding(12)
                .frame(maxWidth: .infinity)
            }
        }
    }

    private func discreteGrid(_ hw: HardwareInfo) -> some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 200), spacing: 12)], spacing: 12) {
            SpecTile(icon: "cpu", title: "CPU", tone: .red, value: "\(hw.cpuCores) Cores", detail: hw.processorName,
                     footnote: hw.hasAppleSilicon ? "\(hw.performanceCores) Performance + \(hw.efficiencyCores) Efficiency" : hw.processorMaxSpeed.map { "Max: \($0) GHz" })
            SpecTile(icon: "memorychip", title: "Memory", tone: .yellow, value: ByteFormatting.bytes(hw.totalMemoryBytes),
                     detail: [hw.memoryType, hw.memoryManufacturer].compactMap { $0 }.filter { $0 != "Unknown" }.joined(separator: " "),
                     footnote: hw.memoryModules.isEmpty ? nil : "\(hw.memoryModules.count) Modules")
            SpecTile(icon: "internaldrive", title: "Storage", tone: .purple, value: ByteFormatting.bytes(hw.totalStorageBytes),
                     detail: "\(ByteFormatting.bytes(hw.freeStorageBytes)) Free", footnote: hw.internalDrives.first?.type ?? "Internal")
            if hw.hasBattery, let b = hw.battery {
                SpecTile(icon: "battery.75percent", title: "Battery", tone: .green, value: "\(b.cycleCount) Cycles", detail: "\(Int(b.chargePercent.rounded()))% • \(b.health ?? "Unknown")")
            }
            SpecTile(icon: "square.3.layers.3d", title: "GPU", tone: .green, value: hw.graphicsName ?? "Unknown",
                     detail: [hw.gpuCores > 0 ? "\(hw.gpuCores) Cores" : nil, hw.graphicsMemoryGB > 0 ? "\(Int(hw.graphicsMemoryGB)) GB VRAM" : nil].compactMap { $0 }.joined(separator: " • "),
                     footnote: hw.graphicsManufacturer.map { "\($0) Discrete Card\(hw.graphicsDriverVersion.map { " - Driver \($0)" } ?? "")" } ?? (hw.graphicsMetalSupport ?? "Discrete GPU"))
            if hw.hasNpu {
                SpecTile(icon: "brain", title: "NPU", tone: .pink, value: hw.npuTops.map { "\($0) TOPS" } ?? "\(hw.npuCores) Cores", detail: hw.npuName,
                         footnote: hw.npuTops != nil ? "\(hw.npuCores) Cores" : nil)
            }
            if let w = hw.wireless, w.isAvailable {
                SpecTile(icon: "wifi", title: "Wireless", tone: .cyan, value: w.generation ?? "Available", detail: w.protocolName, footnote: w.name)
            }
            if let b = hw.bluetooth, b.isAvailable {
                SpecTile(icon: "dot.radiowaves.left.and.right", title: "Bluetooth", tone: .blue, value: b.version ?? "N/A", detail: b.status ?? "Available")
            }
        }
    }

    private func displays(_ hw: HardwareInfo) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Displays", systemImage: "display").appFont(.title3, weight: .bold)
            ForEach(hw.displays) { d in
                Card {
                    HStack(spacing: 20) {
                        HStack(spacing: 10) {
                            ZStack {
                                RoundedRectangle(cornerRadius: 8).fill(Color.blue.opacity(0.12))
                                Image(systemName: "display").foregroundStyle(.blue)
                            }
                            .frame(width: 40, height: 40)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(d.name).appFont(.headline)
                                Text("\(d.diagonalInches.map { "\(Int($0))\" " } ?? "")\(d.isInternal ? "Built-in" : "External") \(d.displayType ?? "")").appFont(.caption).foregroundStyle(.secondary)
                            }
                        }
                        .frame(width: 260, alignment: .leading)
                        HStack(alignment: .bottom, spacing: 24) {
                            StatRow(label: "Resolution", value: d.resolution ?? "Unknown")
                            if let ppi = d.ppi { StatRow(label: "Pixel Density", value: "\(ppi) PPI") }
                            if let nits = d.brightnessNits { StatRow(label: "Brightness", value: "\(nits) nits") }
                            if let gamut = d.colorGamut { StatRow(label: "Color Gamut", value: gamut) }
                            StatRow(label: "Serial Number", value: d.serialNumber ?? "N/A", mono: true, copyable: d.serialNumber != nil)
                            if let fw = d.firmwareVersion { StatRow(label: "Firmware", value: fw) }
                        }
                        Spacer()
                        HStack(spacing: 6) {
                            if d.trueTone { Pill("True Tone", tone: .orange) }
                            if let r = d.refreshRate { Pill(r, tone: .purple) }
                            if d.isMainDisplay { Pill("Main Display", tone: .blue) }
                            Pill(d.online ? "Connected" : "Disconnected", tone: d.online ? .green : .gray)
                        }
                    }
                    .padding(16)
                }
            }
        }
    }

    private func storageAnalysis(_ hw: HardwareInfo) -> some View {
        let analysed = hw.storageDevices.filter { $0.capacityBytes > 0 && !$0.rootDirectories.isEmpty }
        return VStack(alignment: .leading, spacing: 10) {
            Label("Storage Analysis", systemImage: "internaldrive").appFont(.title3, weight: .bold)
            if analysed.isEmpty {
                let usable = hw.storageDevices.filter { $0.capacityBytes > 0 && $0.freeBytes > 0 }
                if usable.isEmpty {
                    Text("No storage devices detected").appFont(.callout).foregroundStyle(.secondary).frame(maxWidth: .infinity).padding(20)
                } else {
                    Card {
                        VStack(spacing: 10) {
                            ForEach(usable) { drive in
                                HStack(spacing: 12) {
                                    Text(drive.name).appFont(.body, weight: .medium).frame(width: 160, alignment: .leading).lineLimit(1)
                                    GeometryReader { geo in
                                        ZStack(alignment: .leading) {
                                            Capsule().fill(Color.secondary.opacity(0.12))
                                            Capsule().fill(drive.usedPercent > 90 ? Color.red : drive.usedPercent > 75 ? Color.yellow : Color.green)
                                                .frame(width: geo.size.width * CGFloat(drive.usedPercent) / 100)
                                        }
                                    }
                                    .frame(height: 10)
                                    Text("\(ByteFormatting.bytes(drive.capacityBytes - drive.freeBytes)) used of \(ByteFormatting.bytes(drive.capacityBytes)) · \(100 - drive.usedPercent)% free")
                                        .appFont(.caption).foregroundStyle(.secondary).frame(width: 260, alignment: .trailing)
                                }
                            }
                        }
                        .padding(16)
                    }
                }
            } else {
                StorageAnalysisView(devices: analysed)
            }
        }
    }

    private func storageDevices(_ hw: HardwareInfo) -> some View {
        let drives = hw.storageDevices.filter { $0.capacityBytes > 0 }
        return Group {
            if !drives.isEmpty {
                VStack(alignment: .leading, spacing: 10) {
                    Label("Storage Devices", systemImage: "internaldrive").appFont(.title3, weight: .bold)
                    Card {
                        Table(drives) {
                            TableColumn("Name") { Text($0.name).appFont(.body, weight: .medium) }.width(min: 100, ideal: 140)
                            TableColumn("Model") { Text($0.model ?? "-").appFont(.body).foregroundStyle(.secondary) }.width(min: 120, ideal: 180)
                            TableColumn("Serial Number") { Text($0.serialNumber ?? "-").appFont(.body, design: .monospaced).foregroundStyle(.secondary) }.width(min: 120, ideal: 160)
                            TableColumn("Type") { Text($0.type ?? "-").appFont(.body).foregroundStyle(.secondary) }.width(80)
                            TableColumn("Capacity") { Text(ByteFormatting.bytes($0.capacityBytes)).appFont(.body) }.width(90)
                            TableColumn("Free Space") { d in
                                if d.freeBytes > 0 {
                                    VStack(alignment: .leading, spacing: 4) {
                                        Text("\(ByteFormatting.bytes(d.freeBytes)) (\(100 - d.usedPercent)% free)").appFont(.body)
                                        GeometryReader { geo in
                                            ZStack(alignment: .leading) {
                                                Capsule().fill(Color.secondary.opacity(0.12))
                                                Capsule().fill(d.usedPercent > 90 ? Color.red : d.usedPercent > 75 ? Color.yellow : Color.green).frame(width: geo.size.width * CGFloat(d.usedPercent) / 100)
                                            }
                                        }
                                        .frame(height: 5)
                                    }
                                } else { Text("-").foregroundStyle(.secondary) }
                            }
                            .width(min: 140, ideal: 180)
                            TableColumn("File System") { Text($0.fileSystem ?? "-").appFont(.body).foregroundStyle(.secondary) }.width(90)
                            TableColumn("Health") { d in
                                if let h = d.health { Pill(h, tone: h == "Good" ? .green : h == "Warning" ? .yellow : .red) } else { Text("-").foregroundStyle(.secondary) }
                            }
                            .width(80)
                            TableColumn("Interface") { Text($0.interface ?? "-").appFont(.body).foregroundStyle(.secondary) }.width(90)
                        }
                        .frame(height: CGFloat(drives.count) * 40 + 40)
                    }
                }
            }
        }
    }

    private func batteryTable(_ b: HardwareInfo.Battery) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Battery Information", systemImage: "battery.75percent").appFont(.title3, weight: .bold)
            Card {
                HStack(alignment: .top, spacing: 28) {
                    StatRow(label: "Status", value: b.isCharging ? "Charging" : "Not Charging")
                    if let h = b.health { StatRow(label: "Health", value: h) }
                    if b.cycleCount > 0 {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Cycle Count").appFont(.caption).foregroundStyle(.secondary)
                            Text("\(b.cycleCount) / 1000").appFont(.body, weight: .medium)
                            GeometryReader { geo in
                                ZStack(alignment: .leading) {
                                    Capsule().fill(Color.secondary.opacity(0.12))
                                    Capsule().fill(b.cycleCount > 900 ? Color.red : b.cycleCount > 800 ? Color.yellow : Color.green)
                                        .frame(width: geo.size.width * min(CGFloat(b.cycleCount) / 1000, 1))
                                }
                            }
                            .frame(height: 6)
                        }
                        .frame(width: 160)
                    }
                    if b.chargePercent > 0 { StatRow(label: "Charge", value: "\(Int(b.chargePercent.rounded()))%") }
                    if let r = b.estimatedRuntime { StatRow(label: "Runtime", value: r) }
                    if let d = b.designCapacity { StatRow(label: "Design Capacity", value: "\(Int(d)) mAh") }
                    if let c = b.currentCapacity { StatRow(label: "Current Capacity", value: "\(Int(c)) mAh") }
                    if let condition = b.condition { StatRow(label: "Condition", value: condition) }
                }
                .padding(16)
            }
        }
    }

    private func memoryModules(_ hw: HardwareInfo) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Memory Modules", systemImage: "memorychip").appFont(.title3, weight: .bold)
            Card {
                Table(hw.memoryModules) {
                    TableColumn("Location") { Text($0.location).appFont(.body, weight: .medium) }
                    TableColumn("Type") { Text($0.type.isEmpty ? "-" : $0.type).appFont(.body).foregroundStyle(.secondary) }
                    TableColumn("Capacity") { Text(ByteFormatting.bytes($0.capacityMB * 1024 * 1024)).appFont(.body).foregroundStyle(.secondary) }
                    TableColumn("Speed") { Text($0.speed.map { "\($0) MHz" } ?? "-").appFont(.body).foregroundStyle(.secondary) }
                    TableColumn("Manufacturer") { Text($0.manufacturer.isEmpty ? "-" : $0.manufacturer).appFont(.body).foregroundStyle(.secondary) }
                }
                .frame(height: CGFloat(hw.memoryModules.count) * 32 + 40)
            }
        }
    }
}

/// One hardware fact as a tile: tinted icon and label, value in the tint.
struct SpecTile: View {
    let icon: String
    let title: String
    let tone: Tone
    let value: String
    var detail: String? = nil
    var footnote: String? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                Image(systemName: icon).foregroundStyle(tone.color).appFont(fixed: 14)
                Text(title).appFont(.headline)
            }
            Text(value).appFont(.title2, weight: .bold).foregroundStyle(tone.color).lineLimit(1).minimumScaleFactor(0.7)
            if let detail, !detail.isEmpty { Text(detail).appFont(.callout).lineLimit(2) }
            if let footnote, !footnote.isEmpty { Text(footnote).appFont(.caption).foregroundStyle(.secondary).lineLimit(2) }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14)
        .background(Color.cardBackground)
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.cardBorder))
    }
}

/// Directory breakdown per analysed drive: donut, capacity table and a tree.
struct StorageAnalysisView: View {
    let devices: [HardwareInfo.StorageDevice]
    @State private var selected = 0
    @State private var expandedPaths: Set<String> = []

    private var device: HardwareInfo.StorageDevice { devices[min(selected, devices.count - 1)] }
    private var sorted: [HardwareInfo.StorageDirectory] { device.rootDirectories.sorted { $0.size > $1.size } }

    static func categoryColor(_ category: String, name: String) -> Color {
        if name == "ProgramData" { return .red }
        switch category {
        case "ProgramFiles": return .blue
        case "Users": return .green
        case "System": return .orange
        case "Other": return .purple
        case "ProgramData": return .red
        default: return .gray
        }
    }

    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 16) {
                if devices.count > 1 {
                    Picker("", selection: $selected) { ForEach(Array(devices.enumerated()), id: \.offset) { i, d in Text(d.name).tag(i) } }.pickerStyle(.segmented).fixedSize()
                }
                HStack(alignment: .top, spacing: 28) {
                    VStack(alignment: .leading, spacing: 14) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Storage Analysis").appFont(.title2, weight: .bold)
                            Text("\(device.name) \(device.type ?? "") \(ByteFormatting.bytes(device.capacityBytes)) Total").appFont(.caption).foregroundStyle(.secondary)
                        }
                        HStack(alignment: .top, spacing: 12) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Drive Overview").appFont(.title3, weight: .bold)
                                Text("\(device.health ?? "Unknown") Health").appFont(.caption).foregroundStyle(.secondary)
                            }
                            ZStack {
                                Chart {
                                    ForEach(sorted) { dir in
                                        SectorMark(angle: .value("Size", dir.size), innerRadius: .ratio(0.7), angularInset: 1)
                                            .foregroundStyle(StorageAnalysisView.categoryColor(dir.category, name: dir.name))
                                    }
                                    SectorMark(angle: .value("Free", max(0, device.capacityBytes - sorted.reduce(0) { $0 + $1.size })), innerRadius: .ratio(0.7), angularInset: 1)
                                        .foregroundStyle(Color.secondary.opacity(0.15))
                                }
                                .chartLegend(.hidden)
                                .frame(width: 140, height: 140)
                                VStack(spacing: 0) {
                                    Text("\(device.usedPercent)%").appFont(.title3, weight: .bold)
                                    Text("Used").appFont(.caption).foregroundStyle(.secondary)
                                }
                            }
                        }
                        VStack(spacing: 8) {
                            statLine("Capacity", ByteFormatting.bytes(device.capacityBytes), .blue)
                            statLine("Used", ByteFormatting.bytes(device.capacityBytes - device.freeBytes), .orange)
                            statLine("Free", ByteFormatting.bytes(device.freeBytes), .green)
                            statLine("Usage", "\(device.usedPercent)%", .purple)
                        }
                    }
                    .frame(width: 300)
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Directory Breakdown").appFont(.headline)
                                Text("\(sorted.count) root directories, sorted by size").appFont(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button("Expand All") { expandedPaths = Set(allPaths(sorted)) }.appFont(.caption)
                            Button("Collapse All") { expandedPaths = [] }.appFont(.caption)
                        }
                        ScrollView {
                            VStack(spacing: 2) {
                                ForEach(sorted) { dir in directoryRow(dir, level: 0) }
                            }
                        }
                        .frame(maxHeight: 400)
                    }
                    .frame(maxWidth: .infinity)
                }
            }
            .padding(20)
        }
    }

    private func statLine(_ label: String, _ value: String, _ color: Color) -> some View {
        HStack {
            Text(label).appFont(.headline)
            Spacer()
            Text(value).appFont(.headline).foregroundStyle(color).monospacedDigit()
        }
    }

    private func allPaths(_ dirs: [HardwareInfo.StorageDirectory]) -> [String] {
        dirs.flatMap { [$0.path] + allPaths($0.subdirectories) }
    }

    private func directoryRow(_ dir: HardwareInfo.StorageDirectory, level: Int) -> AnyView {
        let canExpand = !dir.subdirectories.isEmpty && level < 4
        let open = expandedPaths.contains(dir.path)
        return AnyView(VStack(spacing: 2) {
            Button {
                guard canExpand else { return }
                if open { expandedPaths.remove(dir.path) } else { expandedPaths.insert(dir.path) }
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: canExpand ? (open ? "chevron.down" : "chevron.right") : "folder").foregroundStyle(.secondary).appFont(.caption).frame(width: 14)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(dir.name).appFont(.body, weight: .medium).foregroundStyle(StorageAnalysisView.categoryColor(dir.category, name: dir.name))
                        Text(dir.path).appFont(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                    }
                    Spacer()
                    VStack(alignment: .trailing, spacing: 1) {
                        Text(ByteFormatting.bytes(dir.size)).appFont(.body, weight: .semibold).monospacedDigit()
                        Text(String(format: "%.1f%% of drive", dir.percentageOfDrive)).appFont(.caption).foregroundStyle(.secondary)
                    }
                }
                .padding(.vertical, 6).padding(.horizontal, 8)
                .padding(.leading, CGFloat(level) * 18)
                .background(Color.clear)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            if open, canExpand {
                ForEach(dir.subdirectories.sorted { $0.size > $1.size }) { sub in directoryRow(sub, level: level + 1) }
            }
        })
    }
}
