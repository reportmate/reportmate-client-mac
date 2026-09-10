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
        didSet { if section != oldValue { path = NavigationPath(); history.append(.section(oldValue)); linkQuery = [:] } }
    }
    var path = NavigationPath()
    var showSearch = false
    var refreshRequested = 0
    /// Query from the last `reportmate://` link, consumed by the page it targets.
    var pendingDeepLink: DeepLink?
    /// Filters the visible page contributes to Copy Link.
    var linkQuery: [String: String] = [:]

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
        push(Route.device(serial: serial, tab: tab, filter: filter))
    }

    func openApplicationUsage(_ appName: String, days: Int = 30, usages: [String] = [], catalogs: [String] = [], locations: [String] = []) {
        push(Route.applicationUsage(appName: appName, days: days, usages: usages, catalogs: catalogs, locations: locations))
    }

    func openApplicationCoverage() {
        push(Route.applicationCoverage)
    }

    func openThisMac() {
        push(Route.localDevice)
    }

    /// Follow a `reportmate://` link (or a pasted web URL).
    func open(deepLink link: DeepLink) {
        switch link.target {
        case .dashboard: section = .dashboard
        case .devices: section = .devices; pendingDeepLink = link
        case .device(let serial, let tab):
            if section == .dashboard || section == .devices { section = .devices }
            path = NavigationPath()
            open(device: serial, tab: tab.flatMap(DeviceTab.init(rawValue:)), filter: link.query["filter"])
        case .events, .eventsFailures: section = .events; pendingDeepLink = link
        case .report(let name):
            if let s = AppSection(rawValue: name) { section = s; pendingDeepLink = link }
        case .applicationUsage(let app):
            section = .applications
            let list: (String) -> [String] = { link.query[$0]?.split(separator: ",").map { String($0).trimmingCharacters(in: .whitespaces) } ?? [] }
            openApplicationUsage(app, days: Int(link.query["days"] ?? "") ?? 30, usages: list("usages"), catalogs: list("catalogs"), locations: list("locations"))
        case .applicationCoverage: section = .applications; openApplicationCoverage()
        case .settings: NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
        case .thisMac: section = .devices; openThisMac()
        }
    }

    /// Take the pending link if it targets `section`.
    func consumeDeepLink(for section: AppSection) -> DeepLink? {
        guard let link = pendingDeepLink, self.section == section else { return nil }
        pendingDeepLink = nil
        return link
    }

    /// A link to what is on screen: the pushed route, else the section with its filters.
    var currentDeepLink: DeepLink {
        if let route = currentRoute {
            switch route {
            case .device(let serial, let tab, let filter):
                var q: [String: String] = [:]
                if let filter { q["filter"] = filter }
                return DeepLink(target: .device(serial: serial, tab: tab?.rawValue), query: q)
            case .applicationUsage(let app, let days, let usages, let catalogs, let locations):
                var q = ["days": String(days)]
                if !usages.isEmpty { q["usages"] = usages.joined(separator: ",") }
                if !catalogs.isEmpty { q["catalogs"] = catalogs.joined(separator: ",") }
                if !locations.isEmpty { q["locations"] = locations.joined(separator: ",") }
                return DeepLink(target: .applicationUsage(app: app), query: q)
            case .applicationCoverage: return DeepLink(target: .applicationCoverage)
            case .localDevice: return DeepLink(target: .thisMac)
            }
        }
        switch section {
        case .dashboard: return DeepLink(target: .dashboard)
        case .devices: return DeepLink(target: .devices, query: linkQuery)
        case .events: return DeepLink(target: linkQuery["failures"] == "1" ? .eventsFailures : .events, query: linkQuery.filter { $0.key != "failures" })
        default: return DeepLink(target: .report(section.rawValue), query: linkQuery)
        }
    }

    /// The route on top of the navigation stack, tracked alongside `path`.
    private(set) var currentRoute: Route?
    private var routeStack: [Route] = []

    private func push(_ route: Route) {
        routeStack.append(route)
        currentRoute = route
        path.append(route)
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
