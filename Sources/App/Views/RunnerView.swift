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
                .padding(.horizontal)
                .padding(.vertical, 8)

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
                    runModuleCard(module: module)
                }
            }
        }
    }

    @ViewBuilder
    private func runModuleCard(module: ModuleDefinition) -> some View {
        let isSelected = selectedModules.contains(module.id)
        VStack(spacing: 4) {
            Image(systemName: module.systemImage)
                .font(.title3)
                .frame(height: 20)
            Text(module.displayName)
                .font(.caption2)
                .lineLimit(1)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 8)
        .padding(.horizontal, 4)
        .background(
            RoundedRectangle(cornerRadius: 6)
                .fill(isSelected ? Color.primary.opacity(0.1) : Color.clear)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 6)
                .stroke(isSelected ? Color.primary.opacity(0.4) : Color.secondary.opacity(0.2), lineWidth: 1)
        )
        .foregroundStyle(isSelected ? .primary : .secondary)
        .contentShape(Rectangle())
        .onTapGesture {
            guard !xpcClient.isRunning else { return }
            if isSelected { selectedModules.remove(module.id) }
            else { selectedModules.insert(module.id) }
        }
        .opacity(xpcClient.isRunning ? 0.5 : 1.0)
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

        if !xpcClient.helperAvailable && !xpcClient.isRunning {
            if xpcClient.helperStatus == .requiresApproval {
                Label("Approve helper in System Settings > Login Items", systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .font(.caption)
            } else {
                Label("Running without helper (no root)", systemImage: "info.circle")
                    .foregroundStyle(.secondary)
                    .font(.caption)
            }
        }
    }

    // MARK: - Helpers
}
