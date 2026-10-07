//
//  HelperCommandRunner.swift
//  ReportMateHelper
//
//  Implements the XPC protocol: runs the CLI binary with output streaming
//  and manages system-level preferences.
//

import Foundation
import os
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

        guard process == nil else {
            clientProxy?.didEncounterError("A collection is already running.")
            return
        }
        guard HelperPolicy.isAllowedRun(arguments: arguments) else {
            log.error("Refused run with arguments outside the allowed set")
            clientProxy?.didEncounterError("The helper refused these run arguments.")
            clientProxy?.runDidComplete(success: false, exitCode: -1)
            return
        }
        guard HelperPolicy.isTrustedRootPath(kReportMateCLIPath) else {
            log.error("Refused to run \(kReportMateCLIPath, privacy: .public): it, or a folder above it, is a symlink or writable by a non-admin")
            clientProxy?.didEncounterError("The runner binary is not root-owned and protected, so the helper will not run it.")
            clientProxy?.runDidComplete(success: false, exitCode: -1)
            return
        }

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
        reply(write(key: key, value: stringValue as CFString, domain: domain))
    }

    func setBoolPreference(key: String, boolValue: Bool, domain: String, withReply reply: @escaping (Bool) -> Void) {
        reply(write(key: key, value: boolValue as CFPropertyList, domain: domain))
    }

    func setIntPreference(key: String, intValue: Int, domain: String, withReply reply: @escaping (Bool) -> Void) {
        reply(write(key: key, value: intValue as CFNumber as CFPropertyList, domain: domain))
    }

    func setArrayPreference(key: String, arrayValue: [String], domain: String, withReply reply: @escaping (Bool) -> Void) {
        reply(write(key: key, value: arrayValue as CFArray as CFPropertyList, domain: domain))
    }

    func removePreference(key: String, domain: String, withReply reply: @escaping (Bool) -> Void) {
        reply(write(key: key, value: nil, domain: domain))
    }

    /// Writes one key to /Library/Preferences/<domain>.plist (any user, any
    /// host), the file the runner reads below a configuration profile. Only
    /// the keys the Prefs tab edits, in the ReportMate domain, are accepted.
    private func write(key: String, value: CFPropertyList?, domain: String) -> Bool {
        guard HelperPolicy.canWrite(key: key, domain: domain) else {
            log.error("Refused preference write for \(domain, privacy: .public) \(key, privacy: .public)")
            return false
        }
        CFPreferencesSetValue(key as CFString, value, domain as CFString, kCFPreferencesAnyUser, kCFPreferencesAnyHost)
        return CFPreferencesSynchronize(domain as CFString, kCFPreferencesAnyUser, kCFPreferencesAnyHost)
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
