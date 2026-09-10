import SwiftUI
import ReportMateKit

struct ContentView: View {
    @Environment(AppState.self) private var appState
    @Environment(\.openSettings) private var openSettings
    @State private var columnVisibility: NavigationSplitViewVisibility = .all

    var body: some View {
        @Bindable var state = appState
        NavigationSplitView(columnVisibility: $columnVisibility) {
            SidebarView()
                .navigationSplitViewColumnWidth(min: 180, ideal: 210, max: 280)
        } detail: {
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

struct SidebarView: View {
    @Environment(AppState.self) private var appState

    var body: some View {
        @Bindable var state = appState
        List(selection: Binding(get: { Optional(appState.section) }, set: { if let s = $0 { appState.section = s } })) {
            Section("Fleet") {
                ForEach(AppSection.fleet) { section in
                    Label(section.title, systemImage: section.systemImage).tag(section)
                }
            }
            Section("Reports") {
                ForEach(AppSection.reports) { section in
                    Label(section.title, systemImage: section.systemImage).tag(section)
                }
            }
        }
        .listStyle(.sidebar)
        .safeAreaInset(edge: .bottom) {
            VStack(alignment: .leading, spacing: 4) {
                Divider()
                HStack(spacing: 6) {
                    Circle().fill(appState.isConfigured ? (appState.authProblem == nil ? Color.green : Color.red) : Color.gray).frame(width: 7, height: 7)
                    Text(appState.isConfigured ? hostLabel : "Not connected")
                        .appFont(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
            }
        }
    }

    private var hostLabel: String {
        URL(string: appState.configuration.normalizedBaseURL)?.host ?? appState.configuration.normalizedBaseURL
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
