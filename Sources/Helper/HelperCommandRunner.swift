//
//  HelperCommandRunner.swift
//  ReportMateHelper
//
//  Implements the XPC protocol: runs the CLI binary with output streaming
//  and manages system-level preferences.
//

import Foundation
import ReportMateXPC

final class HelperCommandRunner: NSObject, HelperXPCProtocol, @unchecked Sendable {
    private let connection: NSXPCConnection
    private var process: Process?

    init(connection: NSXPCConnection) {
        self.connection = connection
    }

    // MARK: - HelperXPCProtocol

    func runCollection(arguments: [String]) {
        let clientProxy = connection.remoteObjectProxy as? HelperXPCClientProtocol

        let task = Process()
        task.executableURL = URL(fileURLWithPath: kReportMateCLIPath)
        task.arguments = arguments

        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = pipe

        process = task

        let handle = pipe.fileHandleForReading
        handle.readabilityHandler = { fileHandle in
            let data = fileHandle.availableData
            guard !data.isEmpty else {
                fileHandle.readabilityHandler = nil
                return
            }
            if let text = String(data: data, encoding: .utf8) {
                for line in text.components(separatedBy: .newlines) where !line.isEmpty {
                    clientProxy?.didReceiveOutput(line)
                }
            }
        }

        task.terminationHandler = { [weak self] proc in
            handle.readabilityHandler = nil
            let remaining = handle.readDataToEndOfFile()
            if !remaining.isEmpty, let text = String(data: remaining, encoding: .utf8) {
                for line in text.components(separatedBy: .newlines) where !line.isEmpty {
                    clientProxy?.didReceiveOutput(line)
                }
            }
            let exitCode = proc.terminationStatus
            clientProxy?.runDidComplete(success: exitCode == 0, exitCode: exitCode)
            self?.process = nil
        }

        do {
            try task.run()
        } catch {
            clientProxy?.didEncounterError("Failed to launch CLI: \(error.localizedDescription)")
            clientProxy?.runDidComplete(success: false, exitCode: -1)
            process = nil
        }
    }

    func stopCollection() {
        cancelRunningProcess()
    }

    func setPreference(key: String, stringValue: String, domain: String, withReply reply: @escaping (Bool) -> Void) {
        CFPreferencesSetValue(
            key as CFString,
            stringValue as CFString,
            domain as CFString,
            kCFPreferencesAnyUser,
            kCFPreferencesCurrentHost
        )
        reply(CFPreferencesSynchronize(domain as CFString, kCFPreferencesAnyUser, kCFPreferencesCurrentHost))
    }

    func setBoolPreference(key: String, boolValue: Bool, domain: String, withReply reply: @escaping (Bool) -> Void) {
        CFPreferencesSetValue(
            key as CFString,
            boolValue as CFPropertyList,
            domain as CFString,
            kCFPreferencesAnyUser,
            kCFPreferencesCurrentHost
        )
        reply(CFPreferencesSynchronize(domain as CFString, kCFPreferencesAnyUser, kCFPreferencesCurrentHost))
    }

    func setIntPreference(key: String, intValue: Int, domain: String, withReply reply: @escaping (Bool) -> Void) {
        CFPreferencesSetValue(
            key as CFString,
            intValue as CFNumber as CFPropertyList,
            domain as CFString,
            kCFPreferencesAnyUser,
            kCFPreferencesCurrentHost
        )
        reply(CFPreferencesSynchronize(domain as CFString, kCFPreferencesAnyUser, kCFPreferencesCurrentHost))
    }

    func setArrayPreference(key: String, arrayValue: [String], domain: String, withReply reply: @escaping (Bool) -> Void) {
        CFPreferencesSetValue(
            key as CFString,
            arrayValue as CFArray as CFPropertyList,
            domain as CFString,
            kCFPreferencesAnyUser,
            kCFPreferencesCurrentHost
        )
        reply(CFPreferencesSynchronize(domain as CFString, kCFPreferencesAnyUser, kCFPreferencesCurrentHost))
    }

    func removePreference(key: String, domain: String, withReply reply: @escaping (Bool) -> Void) {
        CFPreferencesSetValue(
            key as CFString,
            nil,
            domain as CFString,
            kCFPreferencesAnyUser,
            kCFPreferencesCurrentHost
        )
        reply(CFPreferencesSynchronize(domain as CFString, kCFPreferencesAnyUser, kCFPreferencesCurrentHost))
    }

    func getHelperVersion(withReply reply: @escaping (String) -> Void) {
        let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown"
        reply(version)
    }

    // MARK: - Cancellation

    func cancelRunningProcess() {
        process?.terminate()
        process = nil
    }
}
