//
//  ContentView.swift
//  ReportMate
//
//  Main window with three tabs: Main, Run, and Logs.
//

import SwiftUI

struct ContentView: View {
    @Environment(XPCClient.self) private var xpcClient
    @State private var viewModel = SettingsViewModel()
    @State private var selectedTab: ContentTab = .main

    enum ContentTab: Hashable {
        case main, run, logs
    }

    var body: some View {
        TabView(selection: $selectedTab) {
            SettingsView(viewModel: viewModel)
                .environment(xpcClient)
                .tabItem { Text("Main") }
                .tag(ContentTab.main)

            RunView(viewModel: viewModel)
                .environment(xpcClient)
                .tabItem { Text("Run") }
                .tag(ContentTab.run)

            LogView()
                .tabItem { Text("Logs") }
                .tag(ContentTab.logs)
        }
        .onAppear {
            xpcClient.checkHelperStatus()
            if xpcClient.helperStatus != .registered {
                xpcClient.registerHelper()
            }
            xpcClient.connect()
        }
    }
}
