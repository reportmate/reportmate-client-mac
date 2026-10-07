//
//  ContentView.swift
//  ReportMate
//
//  Main window with three tabs: Prefs, Run, and Logs. Text-only tab items
//  render as the toolbar capsule in the unified title bar on macOS 26+,
//  matching the other Managed tools.
//

import SwiftUI

struct ContentView: View {
    @Environment(XPCClient.self) private var xpcClient
    @State private var viewModel = SettingsViewModel()
    @State private var logStore = LogFileStore()
    @State private var selectedTab: ContentTab = .prefs

    enum ContentTab: Hashable {
        case prefs, run, logs
    }

    var body: some View {
        TabView(selection: $selectedTab) {
            SettingsView(viewModel: viewModel)
                .environment(xpcClient)
                .tabItem { Text("Prefs") }
                .tag(ContentTab.prefs)

            RunView(viewModel: viewModel)
                .environment(xpcClient)
                .tabItem { Text("Run") }
                .tag(ContentTab.run)

            LogView(store: logStore)
                .tabItem { Text("Logs") }
                .tag(ContentTab.logs)
        }
        .onAppear {
            xpcClient.setup()
            logStore.refresh()
        }
    }
}
