//
//  LogView.swift
//  ReportMate
//
//  Displays historical log files from /Library/Managed Reports/logs/.
//  Lists available log sessions and shows the selected log's contents.
//

import SwiftUI

struct LogView: View {
    @State private var logFiles: [LogFile] = []
    @State private var selectedLog: LogFile?
    @State private var logContent: String = ""
    @State private var filterText: String = ""
    @State private var isLoading = false

    private let logDirectory = "/Library/Managed Reports/logs"

    nonisolated private static let displayDateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f
    }()

    struct LogFile: Identifiable, Hashable {
        let id: String
        let name: String
        let path: String
        let date: Date?
        let size: String

        var displayDate: String {
            guard let date else { return name }
            return LogView.displayDateFormatter.string(from: date)
        }

        func hash(into hasher: inout Hasher) { hasher.combine(id) }
        static func == (lhs: LogFile, rhs: LogFile) -> Bool { lhs.id == rhs.id }
    }

    var body: some View {
        HSplitView {
            logFileList
                .frame(minWidth: 180, idealWidth: 240, maxWidth: 300)

            logDetailView
        }
        .onAppear { refreshLogFiles() }
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
                .disabled(selectedLog == nil)
                sidebarButton(icon: "folder", help: "Open log folder in Finder") {
                    openLogFolder()
                }
                sidebarButton(icon: "arrow.clockwise", help: "Refresh log list") {
                    refreshLogFiles()
                }
            }
            .padding(.horizontal)
            .frame(minHeight: 38)

            Divider()

            List(logFiles, selection: $selectedLog) { file in
                VStack(alignment: .leading, spacing: 2) {
                    Text(file.name)
                        .font(.system(.body, design: .monospaced))
                        .lineLimit(1)
                    HStack {
                        if let date = file.date {
                            Text(LogView.displayDateFormatter.string(from: date))
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
        }
        .onChange(of: selectedLog) { _, newValue in
            if let log = newValue {
                loadLogContent(log)
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
            if selectedLog != nil {
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
        let lines = logContent.components(separatedBy: "\n")
        guard !filterText.isEmpty else { return lines }
        return lines.filter { $0.localizedCaseInsensitiveContains(filterText) }
    }

    // MARK: - File Operations

    private func refreshLogFiles() {
        let fm = FileManager.default
        guard let files = try? fm.contentsOfDirectory(atPath: logDirectory) else {
            logFiles = []
            return
        }

        logFiles = files
            .filter { $0.hasSuffix(".log") }
            .sorted(by: >)
            .compactMap { name -> LogFile? in
                let path = (logDirectory as NSString).appendingPathComponent(name)
                let attrs = try? fm.attributesOfItem(atPath: path)
                let date = attrs?[.modificationDate] as? Date
                let bytes = attrs?[.size] as? Int64 ?? 0
                let size = ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
                return LogFile(id: name, name: name, path: path, date: date, size: size)
            }

        if selectedLog == nil, let first = logFiles.first {
            selectedLog = first
        }
    }

    private func loadLogContent(_ file: LogFile) {
        isLoading = true
        logContent = (try? String(contentsOfFile: file.path, encoding: .utf8)) ?? "Unable to read log file."
        isLoading = false
    }

    private func openSelectedLog() {
        guard let log = selectedLog else { return }
        NSWorkspace.shared.open(URL(fileURLWithPath: log.path))
    }

    private func openLogFolder() {
        NSWorkspace.shared.open(URL(fileURLWithPath: logDirectory))
    }

    // MARK: - Log Line Coloring

    private func colorForLogLine(_ line: String) -> Color {
        if line.contains("[ERROR]") || line.contains("✗") { return .red }
        if line.contains("[WARNING]") || line.contains("⚠") { return .orange }
        if line.contains("[SUCCESS]") || line.contains("✓") { return .green }
        if line.contains("[DEBUG]") { return .gray }
        if line.hasPrefix("===") { return .cyan }
        return .white
    }
}
