import SwiftUI
import ReportMateKit

/// Tabs on a device page, in the web app's order and colours.
enum DeviceTab: String, CaseIterable, Identifiable, Hashable {
    case info, installs, applications, system, management, identity, hardware, peripherals, security, network, events

    var id: String { rawValue }

    var title: String { rawValue.prefix(1).uppercased() + rawValue.dropFirst() }

    var systemImage: String {
        switch self {
        case .info: return "info.circle"
        case .installs: return "arrow.down.circle"
        case .applications: return "app.badge"
        case .system: return "gearshape"
        case .management: return "checkmark.shield"
        case .identity: return "person.2"
        case .hardware: return "cpu"
        case .peripherals: return "cable.connector"
        case .security: return "lock"
        case .network: return "wifi"
        case .events: return "clock"
        }
    }

    var description: String {
        switch self {
        case .info: return "Device information, management status, and system details"
        case .installs: return "Managed software installations and updates"
        case .applications: return "Installed applications and packages"
        case .system: return "Operating system and system information"
        case .management: return "Device management, enrollment, and configuration profiles"
        case .identity: return "User accounts, sessions, and identity management"
        case .hardware: return "Hardware specifications and performance"
        case .peripherals: return "Displays, printers, and connected peripherals"
        case .security: return "Security status and compliance"
        case .network: return "Network connectivity and settings"
        case .events: return "Event history and activity log"
        }
    }

    var tone: Tone {
        switch self {
        case .info, .events: return .gray
        case .installs: return .emerald
        case .applications: return .blue
        case .system: return .purple
        case .management: return .yellow
        case .identity: return .indigo
        case .hardware: return .orange
        case .peripherals: return .cyan
        case .security: return .red
        case .network: return .teal
        }
    }

    /// The module the tab needs before it can render.
    var module: ModuleName? {
        switch self {
        case .info, .events: return nil
        case .installs: return .installs
        case .applications: return .applications
        case .system: return .system
        case .management: return .management
        case .identity: return .identity
        case .hardware: return .hardware
        case .peripherals: return .peripherals
        case .security: return .security
        case .network: return .network
        }
    }
}

/// Loads a device the way the web page does: the fast `/info` payload first
/// so the header and Info tab render at once, then every other module in the
/// background so tab switches are instant.
@MainActor
@Observable
final class DeviceDetailModel {
    let serial: String
    var device: DeviceDetail?
    var loading = true
    var error: String?
    var notFound = false
    var loadingModules: Set<ModuleName> = []
    var moduleErrors: [ModuleName: String] = [:]
    var events: [FleetEvent] = []
    var eventsLoaded = false
    var eventsLoading = false

    init(serial: String) {
        self.serial = serial
    }

    func load(api: ReportMateAPI, appState: AppState) async {
        loading = device == nil
        error = nil
        notFound = false
        let resolved = await appState.resolveIdentifier(serial) ?? serial
        do {
            if let info = try await api.deviceInfo(resolved) {
                device = info
                loading = false
                await loadRemainingModules(api: api, serial: resolved)
            } else if let full = try await api.device(resolved) {
                device = full
                loading = false
            } else {
                notFound = true
                loading = false
            }
        } catch {
            self.error = error.localizedDescription
            appState.note(error)
            loading = false
        }
    }

    private func loadRemainingModules(api: ReportMateAPI, serial: String) async {
        let needed = ModuleName.fetchable.filter { !(device?.loadedModules.contains($0.rawValue) ?? false) }
        await withTaskGroup(of: (ModuleName, Result<JSONValue, Error>).self) { group in
            for module in needed {
                loadingModules.insert(module)
                group.addTask {
                    do { return (module, .success(try await api.deviceModule(serial, module))) }
                    catch { return (module, .failure(error)) }
                }
            }
            for await (module, result) in group {
                loadingModules.remove(module)
                switch result {
                case .success(let json): device?.setModule(module, json)
                case .failure(let err): moduleErrors[module] = err.localizedDescription
                }
            }
        }
    }

    func reloadModule(_ module: ModuleName, api: ReportMateAPI) async {
        guard let serial = device?.serialNumber else { return }
        loadingModules.insert(module)
        defer { loadingModules.remove(module) }
        do {
            device?.setModule(module, try await api.deviceModule(serial, module))
            moduleErrors[module] = nil
        } catch {
            moduleErrors[module] = error.localizedDescription
        }
    }

    func loadEvents(api: ReportMateAPI) async {
        guard let serial = device?.serialNumber, !eventsLoading else { return }
        eventsLoading = true
        events = (try? await api.deviceEvents(serial, limit: 200)) ?? []
        eventsLoaded = true
        eventsLoading = false
    }
}

struct DeviceDetailView: View {
    @Environment(AppState.self) private var appState
    let serial: String
    var initialTab: DeviceTab?
    var initialFilter: String?

    @State private var model: DeviceDetailModel
    @State private var tab: DeviceTab
    @State private var installsFilter: String?
    @State private var showDeleteConfirm = false
    @State private var adminError: String?

    init(serial: String, initialTab: DeviceTab? = nil, initialFilter: String? = nil) {
        self.serial = serial
        self.initialTab = initialTab
        self.initialFilter = initialFilter
        _model = State(initialValue: DeviceDetailModel(serial: serial))
        _tab = State(initialValue: initialTab ?? .info)
        _installsFilter = State(initialValue: initialFilter)
    }

    var body: some View {
        Group {
            if model.loading, model.device == nil {
                LoadingView(message: "Loading device…")
            } else if model.notFound {
                EmptyStateView(title: "Device not found", message: "No device matches “\(serial)”. It may have been deleted or never registered.", systemImage: "questionmark.circle")
            } else if let error = model.error, model.device == nil {
                ErrorBanner(message: error) { Task { await model.load(api: appState.api, appState: appState) } }.padding()
                Spacer()
            } else if let device = model.device {
                VStack(spacing: 0) {
                    DeviceHeaderView(device: device, model: model, onArchiveToggle: { Task { await toggleArchive(device) } }, onDelete: { showDeleteConfirm = true })
                    tabBar
                    if let adminError { ErrorBanner(message: adminError).padding(.horizontal, 16).padding(.top, 8) }
                    tabContent(device)
                }
            }
        }
        .navigationTitle(model.device?.name ?? serial)
        .task(id: serial) { await model.load(api: appState.api, appState: appState) }
        .onChange(of: appState.refreshRequested) { _, _ in Task { await model.load(api: appState.api, appState: appState) } }
        .confirmationDialog("Delete \(model.device?.name ?? serial)?", isPresented: $showDeleteConfirm, titleVisibility: .visible) {
            Button("Delete Device", role: .destructive) { Task { await deleteDevice() } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This removes the device and all of its collected data from ReportMate. This action cannot be undone. Archive instead if you might want this data back.")
        }
    }

    private var tabBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 2) {
                ForEach(DeviceTab.allCases) { t in
                    let active = tab == t
                    let loading = t.module.map { model.loadingModules.contains($0) } ?? false
                    Button { tab = t } label: {
                        HStack(spacing: 6) {
                            Image(systemName: t.systemImage).appFont(fixed: 12)
                            Text(t.title).appFont(.callout, weight: active ? .semibold : .regular)
                            if loading { ProgressView().controlSize(.mini) }
                        }
                        .padding(.horizontal, 12).padding(.vertical, 9)
                        .foregroundStyle(active ? t.tone.color : Color.secondary)
                        .overlay(alignment: .bottom) {
                            Rectangle().fill(active ? t.tone.color : Color.clear).frame(height: 2)
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .focusable(false)
                    .help(t.description)
                }
            }
            .padding(.horizontal, 12)
        }
        .overlay(alignment: .bottom) { Divider() }
    }

    @ViewBuilder
    private func tabContent(_ device: DeviceDetail) -> some View {
        ScrollView {
            Group {
                switch tab {
                case .info: InfoTabView(device: device)
                case .events: DeviceEventsTabView(model: model)
                default:
                    if let module = tab.module {
                        moduleTab(tab, module: module, device: device)
                    }
                }
            }
            .padding(16)
        }
        .id(tab)
    }

    @ViewBuilder
    private func moduleTab(_ tab: DeviceTab, module: ModuleName, device: DeviceDetail) -> some View {
        if model.loadingModules.contains(module), !device.loadedModules.contains(module.rawValue) {
            LoadingView(message: "Loading \(tab.title.lowercased()) data…")
        } else if let err = model.moduleErrors[module], !device.loadedModules.contains(module.rawValue) {
            ErrorBanner(message: err) { Task { await model.reloadModule(module, api: appState.api) } }
        } else {
            switch tab {
            case .installs: InstallsTabView(device: device, initialFilter: installsFilter)
            case .applications: ApplicationsTabView(device: device)
            case .system: SystemTabView(device: device)
            case .management: ManagementTabView(device: device)
            case .identity: IdentityTabView(device: device)
            case .hardware: HardwareTabView(device: device)
            case .peripherals: PeripheralsTabView(device: device)
            case .security: SecurityTabView(device: device)
            case .network: NetworkTabView(device: device)
            default: EmptyView()
            }
        }
    }

    private func toggleArchive(_ device: DeviceDetail) async {
        do {
            if device.archived { try await appState.api.unarchiveDevice(device.serialNumber) } else { try await appState.api.archiveDevice(device.serialNumber) }
            adminError = nil
            await model.load(api: appState.api, appState: appState)
            await appState.loadDevices(force: true)
        } catch {
            adminError = error.localizedDescription
        }
    }

    private func deleteDevice() async {
        guard let device = model.device else { return }
        do {
            try await appState.api.deleteDevice(device.serialNumber)
            await appState.loadDevices(force: true)
            appState.goBack()
        } catch {
            adminError = error.localizedDescription
        }
    }
}

/// Name, platform badge, identifiers, last-seen and status pills, and the
/// admin menu (archive, delete).
struct DeviceHeaderView: View {
    let device: DeviceDetail
    let model: DeviceDetailModel
    let onArchiveToggle: () -> Void
    let onDelete: () -> Void

    var body: some View {
        HStack(alignment: .center, spacing: 14) {
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 8) {
                    Text(device.name).appFont(.title, weight: .bold).lineLimit(1).truncationMode(.middle)
                    PlatformBadge(platform: device.platform, size: 15)
                }
                HStack(spacing: 12) {
                    if let tag = device.assetTag {
                        HStack(spacing: 4) {
                            Text(tag).appFont(.callout, design: .monospaced)
                            CopyButton(value: tag)
                        }
                    }
                    HStack(spacing: 4) {
                        Text(device.serialNumber).appFont(.callout, design: .monospaced).foregroundStyle(.secondary)
                        CopyButton(value: device.serialNumber)
                    }
                    Pill("Last seen \(TimeFormatting.relative(device.lastSeen))", tone: .gray)
                        .help(TimeFormatting.exact(device.lastSeen))
                    if device.archived {
                        Pill("Archived", tone: .gray)
                    } else if device.status == .stale {
                        Pill("Stale", tone: .yellow)
                    } else if device.status == .missing {
                        Pill("Missing", tone: .red)
                    }
                    if let v = device.clientVersion {
                        Text("Client \(v)").appFont(.caption).foregroundStyle(.tertiary)
                    }
                }
            }
            Spacer()
            if !model.loadingModules.isEmpty {
                HStack(spacing: 6) {
                    ProgressView().controlSize(.small)
                    Text("Loading \(model.loadingModules.count) modules…").appFont(.caption).foregroundStyle(.secondary)
                }
            }
            Menu {
                Button(device.archived ? "Unarchive Device" : "Archive Device", action: onArchiveToggle)
                Divider()
                Button("Delete Device…", role: .destructive, action: onDelete)
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
            .help("Admin actions")
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
        .overlay(alignment: .bottom) { Divider() }
    }
}

/// Per-device event history.
struct DeviceEventsTabView: View {
    @Environment(AppState.self) private var appState
    let model: DeviceDetailModel
    @State private var hidden: Set<EventKind> = []

    var body: some View {
        let bundled = EventBundling.bundle(model.events).filter { !hidden.contains($0.kind) }
        Card {
            VStack(spacing: 0) {
                CardHeader("Events", subtitle: "\(model.events.count) most recent events for this device", systemImage: "clock", tone: .gray) {
                    EventTypeFilterMenu(hidden: $hidden, defaultHidden: [])
                }
                if model.eventsLoading, !model.eventsLoaded {
                    LoadingView(message: "Loading events…").frame(height: 200)
                } else if bundled.isEmpty {
                    EmptyStateView(title: "No events", message: "This device has not reported any events yet.", systemImage: "clock")
                } else {
                    EventsTableView(events: bundled, showDevice: false, autoFetchRows: 100, maxRows: 500)
                }
            }
        }
        .task { await model.loadEvents(api: appState.api) }
    }
}
