//
//  RunView.swift
//  ReportMate
//
//  Dedicated tab for running data collection.
//  Shows module selection in a 5x2 grid, run/stop controls, and real-time console output.
//

import SwiftUI

struct RunView: View {
    @Bindable var viewModel: SettingsViewModel
    @Environment(XPCClient.self) private var xpcClient
    @State private var selectedModules: Set<String> = Set(ModuleDefinition.all.map(\.id))
    @State private var showDebug = false

    private let gridColumns = Array(repeating: GridItem(.flexible(), spacing: 8), count: 5)

    var body: some View {
        VStack(spacing: 0) {
            moduleSelectionArea
                .padding()

            Divider()

            runControlBar
                .padding()

            Divider()

            ConsoleView(outputLines: filteredOutput)
                .padding()
        }
    }

    private var filteredOutput: [XPCClient.OutputLine] {
        showDebug ? xpcClient.outputLines : xpcClient.outputLines.filter { $0.level != .debug }
    }

    // MARK: - Module Selection

    @ViewBuilder
    private var moduleSelectionArea: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Modules")
                    .font(.headline)
                Spacer()
                Button("Select All") { selectedModules = Set(ModuleDefinition.all.map(\.id)) }
                    .buttonStyle(.link)
                    .disabled(xpcClient.isRunning)
                Text("·").foregroundStyle(.secondary)
                Button("Deselect All") { selectedModules = [] }
                    .buttonStyle(.link)
                    .disabled(xpcClient.isRunning)
            }

            LazyVGrid(columns: gridColumns, spacing: 8) {
                ForEach(ModuleDefinition.all) { module in
                    Toggle(isOn: moduleBinding(module.id)) {
                        Label {
                            VStack(alignment: .leading, spacing: 1) {
                                Text(module.displayName)
                                    .lineLimit(1)
                                Text(module.description)
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                            }
                        } icon: {
                            Image(systemName: module.systemImage)
                                .frame(width: 16)
                        }
                    }
                    .toggleStyle(.checkbox)
                    .disabled(xpcClient.isRunning)
                }
            }
        }
    }

    // MARK: - Run Control Bar

    @ViewBuilder
    private var runControlBar: some View {
        HStack(spacing: 12) {
            if xpcClient.isRunning {
                stopButton
            } else {
                runButton
            }

            if xpcClient.isRunning {
                ProgressView()
                    .controlSize(.small)
                Text("Running…")
                    .foregroundStyle(.secondary)
            }

            Spacer()

            statusIndicator

            Toggle("Debug", isOn: $showDebug)
                .toggleStyle(.checkbox)
                .font(.caption)
                .help("Show or hide debug log lines")

            if !xpcClient.outputLines.isEmpty {
                clearButton
            }
        }
    }

    // MARK: - Buttons

    @ViewBuilder
    private var runButton: some View {
        Button {
            startRun()
        } label: {
            Label("Run Collection", systemImage: "play.fill")
        }
        .controlSize(.large)
        .disabled(selectedModules.isEmpty)
    }

    @ViewBuilder
    private var stopButton: some View {
        Button(role: .destructive) {
            xpcClient.stopCollection()
        } label: {
            Label("Stop", systemImage: "stop.fill")
        }
        .controlSize(.large)
    }

    @ViewBuilder
    private var clearButton: some View {
        Button("Clear") {
            xpcClient.outputLines.removeAll()
            xpcClient.lastExitCode = nil
        }
        .controlSize(.small)
    }

    // MARK: - Actions

    private func startRun() {
        viewModel.save(using: xpcClient)
        xpcClient.runCollection(modules: selectedModules.sorted())
    }

    // MARK: - Status Indicator

    @ViewBuilder
    private var statusIndicator: some View {
        if let exitCode = xpcClient.lastExitCode {
            if exitCode == 0 {
                Label("Completed", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
            } else {
                Label("Failed (exit \(exitCode))", systemImage: "xmark.circle.fill")
                    .foregroundStyle(.red)
            }
        }

        if xpcClient.helperStatus == .notRegistered && !xpcClient.isRunning {
            Label("Helper not installed — install via pkg", systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
                .font(.caption)
        } else if xpcClient.helperStatus == .requiresApproval && !xpcClient.isRunning {
            Label("Approve helper in System Settings → Login Items", systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
                .font(.caption)
        }

        if let error = xpcClient.connectionError, !xpcClient.isRunning {
            Label(error, systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.red)
                .font(.caption)
        }
    }

    // MARK: - Helpers

    private func moduleBinding(_ id: String) -> Binding<Bool> {
        Binding(
            get: { selectedModules.contains(id) },
            set: { isOn in
                if isOn { selectedModules.insert(id) }
                else { selectedModules.remove(id) }
            }
        )
    }
}
