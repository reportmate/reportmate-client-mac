//
//  XPCClient.swift
//  ReportMate
//
//  Manages the NSXPCConnection to the privileged helper daemon.
//  Streams CLI output back to the GUI and handles preference writes.
//

import Foundation
import ReportMateXPC

@Observable
@MainActor
final class XPCClient: NSObject {
    var outputLines: [OutputLine] = []
    var isRunning = false
    var lastExitCode: Int32?
    var helperStatus: HelperStatus = .unknown
    var connectionError: String?
    private(set) var helperAvailable = false

    private var connection: NSXPCConnection?
    private var directProcess: Process?
    private var connectionRetryCount = 0
    private static let maxRetries = 2

    struct OutputLine: Identifiable {
        let id = UUID()
        let text: String
        let level: LogLevel

        enum LogLevel {
            case info, debug, warning, error, success
        }
    }

    enum HelperStatus: String {
        case unknown = "Unknown"
        case registered = "Installed"
        case notRegistered = "Not Installed"
    }

    override init() {
        super.init()
    }

    // MARK: - Setup (called on app launch)

    /// Checks whether the package installed the helper, then connects.
    func setup() {
        checkHelperStatus()
        connect()
    }

    // MARK: - Connection Management

    func connect() {
        guard connection == nil else { return }

        let conn = NSXPCConnection(machServiceName: kHelperMachServiceName, options: .privileged)
        conn.remoteObjectInterface = NSXPCInterface(with: HelperXPCProtocol.self)
        conn.exportedInterface = NSXPCInterface(with: HelperXPCClientProtocol.self)
        conn.exportedObject = self

        conn.invalidationHandler = makeInvalidationHandler()
        conn.interruptionHandler = makeInterruptionHandler()

        conn.resume()
        connection = conn
        connectionError = nil

        // Verify the connection is alive with a version handshake
        helperProxy { proxy in
            proxy.getHelperVersion { [weak self] version in
                Task { @MainActor [weak self] in
                    guard let self else { return }
                    self.helperStatus = .registered
                    self.helperAvailable = true
                    self.connectionError = nil
                    self.connectionRetryCount = 0
                }
            }
        }
    }

    func disconnect() {
        connection?.invalidate()
        connection = nil
    }

    // MARK: - Helper Status

    /// The package installs the helper as a LaunchDaemon, so the app never
    /// registers it and a standard user never has to approve it.
    func checkHelperStatus() {
        helperStatus = FileManager.default.fileExists(atPath: kHelperLaunchDaemonPath) ? .registered : .notRegistered
    }

    // MARK: - Running Collection

    func runCollection(modules: [String], verbose: Bool = true) {
        guard !isRunning else { return }

        isRunning = true
        lastExitCode = nil
        outputLines.removeAll()
        connectionError = nil

        var arguments = ["-vvv"]
        if !modules.isEmpty {
            arguments.append(contentsOf: ["--run-modules", modules.joined(separator: ",")])
        }

        // Try XPC helper if available
        if helperAvailable, connection != nil {
            helperProxy { proxy in
                proxy.runCollection(arguments: arguments)
            }
            return
        }

        // Fallback: run CLI directly as current user
        runCollectionDirect(arguments: arguments)
    }

    func stopCollection() {
        if let proc = directProcess, proc.isRunning {
            proc.terminate()
            directProcess = nil
            isRunning = false
            outputLines.append(OutputLine(text: "[WARNING] Collection stopped by user.", level: .warning))
            return
        }

        helperProxy { proxy in
            proxy.stopCollection()
        }
        isRunning = false
        lastExitCode = nil
        outputLines.append(OutputLine(text: "[WARNING] Collection stopped by user.", level: .warning))
    }

    // MARK: - Direct Execution (fallback when helper unavailable)

    private func runCollectionDirect(arguments: [String]) {
        let cliPath = kReportMateCLIPath
        guard FileManager.default.isExecutableFile(atPath: cliPath) else {
            outputLines.append(OutputLine(text: "[ERROR] CLI binary not found at \(cliPath)", level: .error))
            isRunning = false
            return
        }

        outputLines.append(OutputLine(text: "[INFO] Running collection directly (helper unavailable)", level: .info))

        let task = Process()
        task.executableURL = URL(fileURLWithPath: cliPath)
        task.arguments = arguments

        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = pipe

        directProcess = task

        let handle = pipe.fileHandleForReading
        handle.readabilityHandler = { [weak self] fileHandle in
            let data = fileHandle.availableData
            guard !data.isEmpty else {
                fileHandle.readabilityHandler = nil
                return
            }
            if let text = String(data: data, encoding: .utf8) {
                for line in text.components(separatedBy: .newlines) where !line.isEmpty {
                    let level = Self.parseLogLevel(line)
                    Task { @MainActor [weak self] in
                        self?.outputLines.append(OutputLine(text: line, level: level))
                    }
                }
            }
        }

        task.terminationHandler = { [weak self] proc in
            handle.readabilityHandler = nil
            let remaining = handle.readDataToEndOfFile()
            if !remaining.isEmpty, let text = String(data: remaining, encoding: .utf8) {
                for line in text.components(separatedBy: .newlines) where !line.isEmpty {
                    let level = Self.parseLogLevel(line)
                    Task { @MainActor [weak self] in
                        self?.outputLines.append(OutputLine(text: line, level: level))
                    }
                }
            }
            let exitCode = proc.terminationStatus
            Task { @MainActor [weak self] in
                self?.isRunning = false
                self?.lastExitCode = exitCode
                self?.directProcess = nil
            }
        }

        do {
            try task.run()
        } catch {
            outputLines.append(OutputLine(text: "[ERROR] Failed to launch CLI: \(error.localizedDescription)", level: .error))
            isRunning = false
            directProcess = nil
        }
    }

    // MARK: - Preference Management

    func setStringPreference(key: String, value: String) {
        if helperAvailable {
            connect()
            helperProxy { proxy in
                proxy.setPreference(key: key, stringValue: value, domain: kReportMatePreferenceDomain) { _ in }
            }
        } else {
            writePreferenceDirect(key: key, value: value)
        }
    }

    func setBoolPreference(key: String, value: Bool) {
        if helperAvailable {
            connect()
            helperProxy { proxy in
                proxy.setBoolPreference(key: key, boolValue: value, domain: kReportMatePreferenceDomain) { _ in }
            }
        } else {
            writePreferenceDirect(key: key, value: value ? "true" : "false", type: "-bool")
        }
    }

    func setIntPreference(key: String, value: Int) {
        if helperAvailable {
            connect()
            helperProxy { proxy in
                proxy.setIntPreference(key: key, intValue: value, domain: kReportMatePreferenceDomain) { _ in }
            }
        } else {
            writePreferenceDirect(key: key, value: String(value), type: "-int")
        }
    }

    func setArrayPreference(key: String, value: [String]) {
        if helperAvailable {
            connect()
            helperProxy { proxy in
                proxy.setArrayPreference(key: key, arrayValue: value, domain: kReportMatePreferenceDomain) { _ in }
            }
        } else {
            writeArrayPreferenceDirect(key: key, value: value)
        }
    }

    func removePreference(key: String) {
        if helperAvailable {
            connect()
            helperProxy { proxy in
                proxy.removePreference(key: key, domain: kReportMatePreferenceDomain) { _ in }
            }
        } else {
            deletePreferenceDirect(key: key)
        }
    }

    // MARK: - Direct Preference Writes (user-level fallback)

    private func writePreferenceDirect(key: String, value: String, type: String = "-string") {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["write", kReportMatePreferenceDomain, key, type, value]
        try? task.run()
    }

    private func writeArrayPreferenceDirect(key: String, value: [String]) {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["write", kReportMatePreferenceDomain, key, "-array"] + value
        try? task.run()
    }

    private func deletePreferenceDirect(key: String) {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        task.arguments = ["delete", kReportMatePreferenceDomain, key]
        try? task.run()
    }

    // MARK: - Private

    private nonisolated func makeInvalidationHandler() -> @Sendable () -> Void {
        { [weak self] in
            Task { @MainActor [weak self] in
                guard let self else { return }
                self.connection = nil
                self.helperAvailable = false
                if self.connectionRetryCount < Self.maxRetries {
                    self.connectionRetryCount += 1
                    try? await Task.sleep(for: .seconds(1))
                    self.connect()
                } else {
                    self.connectionError = "Helper unavailable. Collection will run directly."
                }
            }
        }
    }

    private nonisolated func makeInterruptionHandler() -> @Sendable () -> Void {
        { [weak self] in
            Task { @MainActor [weak self] in
                self?.helperAvailable = false
                self?.connectionError = "Connection to helper was interrupted"
                self?.isRunning = false
            }
        }
    }

    private nonisolated func makeErrorHandler() -> @Sendable (any Error) -> Void {
        { [weak self] error in
            Task { @MainActor [weak self] in
                self?.helperAvailable = false
                self?.connectionError = error.localizedDescription
                self?.isRunning = false
            }
        }
    }

    private func helperProxy(block: @escaping (HelperXPCProtocol) -> Void) {
        guard let conn = connection else {
            connectionError = "No connection to helper"
            return
        }
        guard let proxy = conn.remoteObjectProxyWithErrorHandler(makeErrorHandler()) as? HelperXPCProtocol else {
            connectionError = "Failed to get helper proxy"
            return
        }
        block(proxy)
    }
}

// MARK: - HelperXPCClientProtocol

extension XPCClient: HelperXPCClientProtocol {

    nonisolated func didReceiveOutput(_ line: String) {
        let level = Self.parseLogLevel(line)
        Task { @MainActor in
            outputLines.append(OutputLine(text: line, level: level))
        }
    }

    nonisolated func runDidComplete(success: Bool, exitCode: Int32) {
        Task { @MainActor in
            isRunning = false
            lastExitCode = exitCode
        }
    }

    nonisolated func didEncounterError(_ message: String) {
        Task { @MainActor in
            connectionError = message
            outputLines.append(OutputLine(text: "ERROR: \(message)", level: .error))
        }
    }

    private static nonisolated func parseLogLevel(_ line: String) -> OutputLine.LogLevel {
        switch LogLineLevel.classify(line) {
        case .error: .error
        case .warning: .warning
        case .success: .success
        case .debug: .debug
        case .info, .header: .info
        }
    }
}
