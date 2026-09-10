import SwiftUI
import ReportMateKit

/// The window: the web app's header navigation over the current section,
/// with device pages and drill-downs pushed on a navigation stack.
struct ContentView: View {
    @Environment(AppState.self) private var appState
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        @Bindable var state = appState
        VStack(spacing: 0) {
            TopNavBar()
            NavigationStack(path: $state.path) {
                sectionView
                    .navigationDestination(for: Route.self) { route in
                        switch route {
                        case .device(let serial, let tab, let filter):
                            DeviceDetailView(serial: serial, initialTab: tab, initialFilter: filter)
                        case .applicationUsage(let appName, let days, let usages, let catalogs, let locations):
                            ApplicationUsageDetailView(appName: appName, initialDays: days, usages: usages, catalogs: catalogs, locations: locations)
                        case .applicationCoverage:
                            ApplicationCoverageView()
                        case .localDevice:
                            DeviceDetailView(serial: "this-mac", isLocal: true)
                        }
                    }
            }
        }
        .toolbar {
            ToolbarItemGroup(placement: .navigation) {
                Button { appState.goBack() } label: { Image(systemName: "chevron.left") }
                    .help("Back (⌘[)")
                    .disabled(!appState.canGoBack)
            }
            ToolbarItem(placement: .principal) {
                PlatformToggle()
            }
            ToolbarItemGroup(placement: .primaryAction) {
                CopyLinkMenu()
                Button { appState.showSearch = true } label: {
                    Label("Search", systemImage: "magnifyingglass")
                }
                .help("Find a device by name, serial, asset tag or hostname (⌘K)")
                Button { appState.refreshRequested += 1 } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .help("Refresh (⌘R)")
                if let problem = appState.authProblem {
                    Button { openSettings() } label: {
                        Label("Authentication", systemImage: "lock.trianglebadge.exclamationmark")
                            .foregroundStyle(.red)
                    }
                    .help(problem)
                }
                Button { openSettings() } label: { Label("Settings", systemImage: "gearshape") }
                    .help("Settings (⌘,)")
            }
        }
        .focusedSceneValue(\.appState, appState)
        .onOpenURL { url in
            if let link = DeepLink(url: url) { appState.open(deepLink: link) }
        }
        .sheet(isPresented: $state.showSearch) {
            GlobalSearchView()
                .environment(appState)
        }
        .task(id: appState.configuration) {
            guard appState.isConfigured else { return }
            await appState.loadSettings()
            await appState.loadDevices()
        }
    }

    @ViewBuilder
    private var sectionView: some View {
        if !appState.isConfigured {
            NotConfiguredView()
        } else {
            switch appState.section {
            case .dashboard: DashboardView()
            case .devices: DevicesView()
            case .events: EventsView()
            case .installs: InstallsReportView()
            case .applications: ApplicationsReportView()
            case .system: SystemReportView()
            case .management: ManagementReportView()
            case .identity: IdentityReportView()
            case .hardware: HardwareReportView()
            case .peripherals: PeripheralsReportView()
            case .security: SecurityReportView()
            case .network: NetworkReportView()
            }
        }
    }
}

/// Mac / Windows toggle in the toolbar; clicking the active one returns to All.
struct PlatformToggle: View {
    @Environment(AppState.self) private var appState

    var body: some View {
        HStack(spacing: 2) {
            toggle(.macOS, image: "apple.logo", help: "macOS only")
            toggle(.windows, image: "square.grid.2x2.fill", help: "Windows only")
        }
        .padding(2)
        .background(Color.secondary.opacity(0.1), in: RoundedRectangle(cornerRadius: 7))
    }

    private func toggle(_ filter: PlatformFilter, image: String, help: String) -> some View {
        let active = appState.platformFilter == filter
        return Button {
            appState.platformFilter = active ? .all : filter
        } label: {
            Image(systemName: image)
                .appFont(fixed: 12, weight: .medium)
                .frame(width: 28, height: 20)
                .background(active ? Color.cardBackground : Color.clear, in: RoundedRectangle(cornerRadius: 5))
                .foregroundStyle(active ? Color.primary : Color.secondary)
        }
        .buttonStyle(.plain)
        .focusable(false)
        .help(active ? "Showing \(help), click to show all" : "Filter to \(help)")
    }
}

/// Copy Link: the web handoff URL when a web dashboard is configured (it
/// opens the app when installed and the web page otherwise), plus the raw
/// `reportmate://` and web forms.
struct CopyLinkMenu: View {
    @Environment(AppState.self) private var appState
    @State private var copied = false

    private var link: DeepLink { appState.currentDeepLink }
    private var webBase: URL? { appState.configuration.normalizedWebURL }

    var body: some View {
        Menu {
            if let webBase, let handoff = link.handoffURL(webBase: webBase) {
                Button("Copy Link") { copy(handoff.absoluteString) }
                Button("Copy Web Link") { copy(link.webURL(base: webBase)?.absoluteString ?? handoff.absoluteString) }
                Button("Copy App Link") { copy(link.url.absoluteString) }
            } else {
                Button("Copy App Link") { copy(link.url.absoluteString) }
                Text("Set the web dashboard URL in Settings for links that fall back to the browser.")
            }
        } label: {
            Label(copied ? "Copied" : "Copy Link", systemImage: copied ? "checkmark" : "link")
        } primaryAction: {
            if let webBase, let handoff = link.handoffURL(webBase: webBase) { copy(handoff.absoluteString) } else { copy(link.url.absoluteString) }
        }
        .help("Copy a link to this exact view (⌘⇧C)")
    }

    private func copy(_ s: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(s, forType: .string)
        copied = true
        Task { try? await Task.sleep(for: .seconds(1.5)); copied = false }
    }
}
