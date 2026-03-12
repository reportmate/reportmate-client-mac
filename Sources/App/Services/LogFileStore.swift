//
//  LogFileStore.swift
//  ReportMate
//
//  Shared store for log files. Pre-loaded at app launch so
//  the Logs tab opens instantly.
//

import Foundation
import Observation

@Observable
final class LogFileStore {

    struct LogFile: Identifiable, Hashable {
        let id: String
        let name: String
        let path: String
        let date: Date?
        let size: String

        nonisolated static let displayDateFormatter: DateFormatter = {
            let f = DateFormatter()
            f.dateStyle = .medium
            f.timeStyle = .short
            return f
        }()

        var displayDate: String {
            guard let date else { return name }
            return Self.displayDateFormatter.string(from: date)
        }

        func hash(into hasher: inout Hasher) { hasher.combine(id) }
        static func == (lhs: LogFile, rhs: LogFile) -> Bool { lhs.id == rhs.id }
    }

    private(set) var logFiles: [LogFile] = []
    var selectedLog: LogFile?
    private(set) var logContent: String = ""

    private let logDirectory = "/Library/Managed Reports/logs"

    func refresh() {
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
            loadContent(first)
        }
    }

    func loadContent(_ file: LogFile) {
        logContent = (try? String(contentsOfFile: file.path, encoding: .utf8)) ?? "Unable to read log file."
    }
}
