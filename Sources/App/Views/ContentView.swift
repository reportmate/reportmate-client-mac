import SwiftUI

enum SidebarItem: String, CaseIterable, Identifiable {
    case runner = "Run Collection"
    case settings = "Settings"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .runner: "play.circle"
        case .settings: "gearshape"
        }
    }
}

struct ContentView: View {

    @State private var selection: SidebarItem = .runner

    var body: some View {
        NavigationSplitView {
            List(SidebarItem.allCases, selection: $selection) { item in
                Label(item.rawValue, systemImage: item.icon)
            }
            .navigationSplitViewColumnWidth(min: 180, ideal: 200)
        } detail: {
            switch selection {
            case .runner:
                RunnerView()
            case .settings:
                SettingsView()
            }
        }
        .navigationTitle("ReportMate")
        .toolbar {
            ToolbarItem(placement: .automatic) {
                Text(appVersion)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var appVersion: String {
        let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "dev"
        return "v\(version)"
    }
}
