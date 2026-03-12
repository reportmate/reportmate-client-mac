//
//  ContentView.swift
//  ReportMate
//
//  Native TabView with liquid glass tabs.
//  Tab order: Run, Logs, Prefs.
//

import SwiftUI

struct ContentView: View {
    @Environment(XPCClient.self) private var xpcClient
    @State private var viewModel = SettingsViewModel()
    @State private var logStore = LogFileStore()

    var body: some View {
        TabView {
            RunView(viewModel: viewModel)
                .environment(xpcClient)
                .tabItem { Label("Run", systemImage: "play.fill") }

            LogView(store: logStore)
                .tabItem { Label("Logs", systemImage: "doc.text") }

            SettingsView(viewModel: viewModel)
                .environment(xpcClient)
                .tabItem { Label("Prefs", systemImage: "gearshape") }
        }
        .onAppear {
            xpcClient.setup()
            logStore.refresh()
        }
    }
}
