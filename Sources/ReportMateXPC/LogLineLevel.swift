//
//  LogLineLevel.swift
//  ReportMate
//
//  Classifies a line of runner output or log file by level, so the Run
//  console and the Logs viewer can colour it. Recognises both formats the
//  runner writes:
//    console:  "[ERROR] message", "[WARN] message", "[OK] message", "[DEBUG] ..."
//    log file: "[yyyy-MM-dd HH:mm:ss] ERROR message"
//

import Foundation

public enum LogLineLevel: Sendable, Equatable {
    case error, warning, success, debug, info, header

    public static func classify(_ line: String) -> LogLineLevel {
        if let level = tagLevel(line) { return level }
        if let level = fileLevel(line) { return level }
        if line.hasPrefix("ERROR:") || line.contains("✗") { return .error }
        if line.hasPrefix("WARNING:") || line.contains("⚠") { return .warning }
        if line.contains("✓") { return .success }
        if line.hasPrefix("===") { return .header }
        return .info
    }

    /// "[stamp] LEVEL message": the word after the first "] ".
    private static func fileLevel(_ line: String) -> LogLineLevel? {
        guard line.hasPrefix("["), let close = line.firstIndex(of: "]") else { return nil }
        let rest = line[line.index(after: close)...].drop(while: { $0 == " " })
        let word = rest.prefix(while: { $0 != " " })
        return level(named: String(word))
    }

    /// "[LEVEL] message" anywhere at the start of the line.
    private static func tagLevel(_ line: String) -> LogLineLevel? {
        let trimmed = line.drop(while: { $0 == " " })
        guard trimmed.hasPrefix("["), let close = trimmed.firstIndex(of: "]") else { return nil }
        let tag = trimmed[trimmed.index(after: trimmed.startIndex)..<close]
        return level(named: String(tag))
    }

    private static func level(named name: String) -> LogLineLevel? {
        switch name.uppercased() {
        case "ERROR", "FATAL", "CRITICAL": .error
        case "WARN", "WARNING": .warning
        case "OK", "SUCCESS": .success
        case "DEBUG", "TRACE": .debug
        case "INFO": .info
        default: nil
        }
    }
}
