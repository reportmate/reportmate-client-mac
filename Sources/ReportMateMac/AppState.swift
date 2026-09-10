import SwiftUI
import ReportMateKit

/// Application-wide state: configuration, the API client, navigation, the
/// global platform filter and the shared device list that powers search.
@MainActor
@Observable
final class AppState {
    // MARK: Configuration

    private(set) var configuration: AppConfiguration
    private(set) var api: ReportMateAPI
    var settings: SettingsDocument = .defaults
    var settingsLoaded = false

    /// Set when the last API call failed with 401/403, shown in the toolbar.
    var authProblem: String?

    // MARK: Navigation

    var section: AppSection = .dashboard {
        didSet { if section != oldValue { path = NavigationPath(); history.append(.section(oldValue)) } }
    }
    var path = NavigationPath()
    var showSearch = false
    var refreshRequested = 0

    private enum HistoryEntry { case section(AppSection) }
    private var history: [HistoryEntry] = []
    var canGoBack: Bool { !path.isEmpty || !history.isEmpty }

    // MARK: Platform filter

    var platformFilter: PlatformFilter {
        didSet { UserDefaults.standard.set(platformFilter.rawValue, forKey: "platformFilter") }
    }

    var includeArchived: Bool {
        didSet { UserDefaults.standard.set(includeArchived, forKey: "includeArchived") }
    }

    // MARK: Devices (shared by search, the Devices list and drill-downs)

    private(set) var devices: [DeviceSummary] = []
    private(set) var devicesLoading = false
    private(set) var devicesError: String?
    private(set) var devicesLoadedAt: Date?
    private var devicesTask: Task<Void, Never>?

    init() {
        let config = AppConfiguration.load()
        configuration = config
        api = ReportMateAPI(configuration: config)
        platformFilter = PlatformFilter(rawValue: UserDefaults.standard.string(forKey: "platformFilter") ?? "") ?? .all
        includeArchived = UserDefaults.standard.bool(forKey: "includeArchived")
    }

    var isConfigured: Bool { configuration.isConfigured }

    func update(configuration: AppConfiguration) throws {
        try configuration.save()
        self.configuration = configuration
        api = ReportMateAPI(configuration: configuration)
        authProblem = nil
        devices = []
        devicesLoadedAt = nil
        settingsLoaded = false
        refreshRequested += 1
    }

    /// Apply a configuration without persisting (used while testing a connection).
    func preview(configuration: AppConfiguration) -> ReportMateAPI {
        ReportMateAPI(configuration: configuration)
    }

    // MARK: Navigation helpers

    func navigate(to section: AppSection) {
        self.section = section
    }

    func open(device serial: String, tab: DeviceTab? = nil, filter: String? = nil) {
        path.append(Route.device(serial: serial, tab: tab, filter: filter))
    }

    func openApplicationUsage(_ appName: String) {
        path.append(Route.applicationUsage(appName: appName))
    }

    func goBack() {
        if !path.isEmpty {
            path.removeLast()
        } else if let last = history.popLast() {
            if case .section(let s) = last {
                // Avoid re-recording this hop.
                let saved = history
                section = s
                history = saved
            }
        }
    }

    // MARK: Devices

    /// Load (or reuse) the fleet device list. Cached for five minutes unless forced.
    func loadDevices(force: Bool = false) async {
        if !force, let at = devicesLoadedAt, Date().timeIntervalSince(at) < 300, !devices.isEmpty { return }
        if let task = devicesTask { await task.value; return }
        let task = Task { [weak self] in
            guard let self else { return }
            devicesLoading = true
            devicesError = nil
            do {
                let list = try await api.allDevices(includeArchived: includeArchived)
                devices = list
                devicesLoadedAt = Date()
                authProblem = nil
            } catch let error as APIError where error.isAuthFailure {
                authProblem = error.localizedDescription
                devicesError = error.localizedDescription
            } catch {
                devicesError = error.localizedDescription
            }
            devicesLoading = false
        }
        devicesTask = task
        await task.value
        devicesTask = nil
    }

    /// Devices visible under the global platform filter.
    var filteredDevices: [DeviceSummary] {
        guard platformFilter != .all else { return devices }
        return devices.filter { platformFilter.includes($0.platform) }
    }

    func device(serial: String) -> DeviceSummary? {
        devices.first { $0.serialNumber == serial }
    }

    /// Resolve a typed identifier (serial, asset tag, name) to a serial.
    func resolveIdentifier(_ identifier: String) async -> String? {
        await loadDevices()
        return DeviceSearch.resolve(identifier, in: devices)?.serialNumber ?? identifier
    }

    /// Name lookup used by event rows when the API gave only a serial.
    var deviceNameMap: [String: String] {
        var map: [String: String] = [:]
        for d in devices where d.name.lowercased() != "unknown" && d.name != d.serialNumber {
            map[d.serialNumber] = d.name
            if d.deviceId != d.serialNumber { map[d.deviceId] = d.name }
            if let tag = d.inventory.assetTag { map[tag] = d.name }
        }
        return map
    }

    // MARK: Settings

    func loadSettings() async {
        guard !settingsLoaded, isConfigured else { return }
        if let response = try? await api.settings() {
            settings = response.value
            settingsLoaded = true
        }
    }

    /// Record an API error, surfacing auth failures in the toolbar.
    func note(_ error: Error) {
        if let apiError = error as? APIError, apiError.isAuthFailure {
            authProblem = apiError.localizedDescription
        }
    }
}
