//
//  LogView.swift
//  ReportMate
//
//  Displays historical log files from /Library/Managed Reports/logs/.
//  Uses a shared LogFileStore that is pre-loaded at app launch.
//

import SwiftUI
import ReportMateXPC

struct LogView: View {
    @Bindable var store: LogFileStore
    @State private var filterText: String = ""

    private let logDirectory = "/Library/Managed Reports/logs"

    var body: some View {
        HSplitView {
            logFileList
                .frame(minWidth: 180, idealWidth: 240, maxWidth: 300, maxHeight: .infinity)

            logDetailView
                .frame(minWidth: 320, maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Log File List

    @ViewBuilder
    private var logFileList: some View {
        VStack(spacing: 0) {
            HStack(spacing: 6) {
                Text("Log Files")
                    .font(.headline)
                Spacer()
                sidebarButton(icon: "arrow.up.forward.square", help: "Open in default editor") {
                    openSelectedLog()
                }
                .disabled(store.selectedLog == nil)
                sidebarButton(icon: "folder", help: "Open log folder in Finder") {
                    openLogFolder()
                }
                sidebarButton(icon: "arrow.clockwise", help: "Refresh log list") {
                    store.refresh()
                }
            }
            .padding(.horizontal)
            .frame(minHeight: 38)

            Divider()

            List(store.logFiles, selection: $store.selectedLog) { file in
                VStack(alignment: .leading, spacing: 2) {
                    Text(file.name)
                        .font(.system(.body, design: .monospaced))
                        .lineLimit(1)
                    HStack {
                        if let date = file.date {
                            Text(LogFileStore.LogFile.displayDateFormatter.string(from: date))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text(file.size)
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                }
                .tag(file)
            }
            .listStyle(.sidebar)
            .frame(maxHeight: .infinity)
            .overlay {
                if store.logFiles.isEmpty {
                    ContentUnavailableView {
                        Label("No Logs Yet", systemImage: "doc.text.magnifyingglass")
                    } description: {
                        Text("Logs are written to \(logDirectory).")
                    }
                }
            }
        }
        .onChange(of: store.selectedLog) { _, newValue in
            if let log = newValue {
                store.loadContent(log)
            }
        }
    }

    @ViewBuilder
    private func sidebarButton(icon: String, help: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: icon)
                .font(.system(size: 12))
        }
        .buttonStyle(.borderless)
        .help(help)
    }

    // MARK: - Log Detail

    @ViewBuilder
    private var logDetailView: some View {
        VStack(spacing: 0) {
            if store.selectedLog != nil {
                HStack {
                    Image(systemName: "line.3.horizontal.decrease")
                        .foregroundStyle(.secondary)
                    TextField("Filter log…", text: $filterText)
                        .textFieldStyle(.roundedBorder)
                }
                .padding(.horizontal)
                .frame(minHeight: 38)

                Divider()

                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 1) {
                        ForEach(filteredLines, id: \.self) { line in
                            Text(line)
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(colorForLogLine(line))
                                .textSelection(.enabled)
                        }
                    }
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .background(.black.opacity(0.85))
            } else if store.logFiles.isEmpty {
                ContentUnavailableView(
                    "No Logs",
                    systemImage: "doc.text",
                    description: Text("There are no logs yet. They appear here after the first run.")
                )
            } else {
                ContentUnavailableView(
                    "No Log Selected",
                    systemImage: "doc.text",
                    description: Text("Select a log file from the sidebar to view its contents.")
                )
            }
        }
    }

    // MARK: - Filtered Lines

    private var filteredLines: [String] {
        let lines = store.logContent.components(separatedBy: "\n")
        guard !filterText.isEmpty else { return lines }
        return lines.filter { $0.localizedCaseInsensitiveContains(filterText) }
    }

    // MARK: - Actions

    private func openSelectedLog() {
        guard let log = store.selectedLog else { return }
        NSWorkspace.shared.open(URL(fileURLWithPath: log.path))
    }

    private func openLogFolder() {
        NSWorkspace.shared.open(URL(fileURLWithPath: logDirectory))
    }

    // MARK: - Log Line Coloring

    /// Log files are written as "[yyyy-MM-dd HH:mm:ss] LEVEL message";
    /// LogLineLevel reads that and the console's "[LEVEL]" tags alike.
    private func colorForLogLine(_ line: String) -> Color {
        switch LogLineLevel.classify(line) {
        case .error: .red
        case .warning: .orange
        case .success: .green
        case .debug: .gray
        case .header: .cyan
        case .info: .white
        }
    }
}
