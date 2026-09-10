import SwiftUI
import ReportMateKit

/// ⌘K device finder: fuzzy matches across name, serial, asset tag, hostname
/// and location, Return opens the highlighted device.
struct GlobalSearchView: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss
    @State private var query = ""
    @State private var selectedIndex = 0
    @FocusState private var focused: Bool

    private var results: [DeviceSummary] {
        DeviceSearch.search(appState.devices, query: query, limit: 12)
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Search by name, serial, asset, or hostname", text: $query)
                    .textFieldStyle(.plain)
                    .appFont(.title3)
                    .focused($focused)
                    .onSubmit(openSelected)
                if appState.devicesLoading { ProgressView().controlSize(.small) }
            }
            .padding(14)
            Divider()
            if query.trimmingCharacters(in: .whitespaces).isEmpty {
                Text("\(appState.devices.count) devices loaded")
                    .appFont(.caption).foregroundStyle(.secondary).padding(14)
            } else if results.isEmpty {
                Text("No devices match “\(query)”").appFont(.callout).foregroundStyle(.secondary).padding(14)
            } else {
                ScrollViewReader { proxy in
                    List(Array(results.enumerated()), id: \.element.id, selection: Binding(get: { results.indices.contains(selectedIndex) ? results[selectedIndex].id : nil }, set: { id in
                        if let id, let i = results.firstIndex(where: { $0.id == id }) { selectedIndex = i }
                    })) { index, device in
                        HStack(spacing: 10) {
                            Circle().fill(Tone.forStatus(device.status).color).frame(width: 8, height: 8)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(device.name).appFont(.body, weight: .medium)
                                HStack(spacing: 8) {
                                    Text(device.serialNumber).appFont(.caption, design: .monospaced)
                                    if let tag = device.inventory.assetTag { Text(tag).appFont(.caption, weight: .medium) }
                                    if let host = device.hostname { Text(host).appFont(.caption) }
                                }
                                .foregroundStyle(.secondary)
                            }
                            Spacer()
                            PlatformBadge(platform: device.platform)
                            Image(systemName: "chevron.right").foregroundStyle(.tertiary).appFont(.caption)
                        }
                        .contentShape(Rectangle())
                        .onTapGesture { open(device) }
                        .id(index)
                        .tag(device.id)
                    }
                    .listStyle(.plain)
                    .onChange(of: selectedIndex) { _, i in proxy.scrollTo(i) }
                }
            }
        }
        .frame(width: 560)
        .frame(minHeight: 120, maxHeight: 460)
        .onAppear {
            focused = true
            Task { await appState.loadDevices() }
        }
        .onChange(of: query) { _, _ in selectedIndex = 0 }
        .onKeyPress(.downArrow) { selectedIndex = min(selectedIndex + 1, max(results.count - 1, 0)); return .handled }
        .onKeyPress(.upArrow) { selectedIndex = max(selectedIndex - 1, 0); return .handled }
        .onKeyPress(.escape) { dismiss(); return .handled }
    }

    private func openSelected() {
        if results.indices.contains(selectedIndex) {
            open(results[selectedIndex])
        } else if !query.trimmingCharacters(in: .whitespaces).isEmpty {
            // No suggestion: land on the Devices list filtered by the query.
            appState.section = .devices
            NotificationCenter.default.post(name: .devicesSearch, object: query)
            dismiss()
        }
    }

    private func open(_ device: DeviceSummary) {
        dismiss()
        appState.open(device: device.serialNumber)
    }
}

extension Notification.Name {
    static let devicesSearch = Notification.Name("ReportMate.devicesSearch")
}
