//
//  XPCClient.swift
//  ReportMate
//
//  Manages the NSXPCConnection to the privileged helper daemon.
//  Streams CLI output back to the GUI and handles preference writes.
//

import Foundation
import ReportMateXPC
import ServiceManagement

@Observable
@MainActor
final class XPCClient: NSObject {
    var outputLines: [OutputLine] = []
    var isRunning = false
    var lastExitCode: Int32?
    var helperStatus: HelperStatus = .unknown
    var connectionError: String?

    private var connection: NSXPCConnection?

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
        case registered = "Registered"
        case notRegistered = "Not Registered"
        case requiresApproval = "Requires Approval"
    }

    override init() {
        super.init()
    }

    // MARK: - Setup (called on app launch)

    /// Checks helper status, attempts registration if needed, and connects.
    func setup() {
        checkHelperStatus()
        if helperStatus == .notRegistered || helperStatus == .unknown {
            registerHelper()
        }
        if helperStatus == .registered {
            connect()
        }
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

        helperProxy { proxy in
            proxy.getHelperVersion { [weak self] _ in
                Task { @MainActor [weak self] in
                    self?.helperStatus = .registered
                    self?.connectionError = nil
                }
            }
        }
    }

    func disconnect() {
        connection?.invalidate()
        connection = nil
    }

    // MARK: - Helper Registration

    func registerHelper() {
        let service = SMAppService.daemon(plistName: kHelperPlistName)
        do {
            try service.register()
            helperStatus = .registered
        } catch {
            helperStatus = .requiresApproval
            connectionError = "Helper registration failed: \(error.localizedDescription)"
        }
    }

    func checkHelperStatus() {
        let service = SMAppService.daemon(plistName: kHelperPlistName)
        switch service.status {
        case .enabled:
            helperStatus = .registered
        case .requiresApproval:
            helperStatus = .requiresApproval
        case .notRegistered, .notFound:
            helperStatus = .notRegistered
        @unknown default:
            helperStatus = .unknown
        }
    }

    // MARK: - Running Collection

    func runCollection(modules: [String], verbose: Bool = true) {
        guard !isRunning else { return }

        isRunning = true
        lastExitCode = nil
        outputLines.removeAll()
        connectionError = nil

        // Ensure helper is registered and connected
        if helperStatus != .registered {
            checkHelperStatus()
            if helperStatus == .notRegistered || helperStatus == .unknown {
                registerHelper()
            }
        }

        if helperStatus != .registered {
            isRunning = false
            connectionError = "Helper is not registered. Install via the pkg installer."
            outputLines.append(OutputLine(text: "[ERROR] Helper daemon is not available. Install ReportMate via the pkg installer.", level: .error))
            return
        }

        var arguments = ["-vv"]
        if !modules.isEmpty {
            arguments.append(contentsOf: ["--run-modules", modules.joined(separator: ",")])
        }

        connect()

        guard connection != nil else {
            isRunning = false
            connectionError = "Failed to connect to helper daemon"
            outputLines.append(OutputLine(text: "[ERROR] Cannot connect to helper daemon.", level: .error))
            return
        }

        helperProxy { proxy in
            proxy.runCollection(arguments: arguments)
        }
    }

    func stopCollection() {
        helperProxy { proxy in
            proxy.stopCollection()
        }
        isRunning = false
        lastExitCode = nil
        outputLines.append(OutputLine(text: "[WARNING] Collection stopped by user.", level: .warning))
    }

    // MARK: - Preference Management

    func setStringPreference(key: String, value: String) {
        connect()
        helperProxy { proxy in
            proxy.setPreference(key: key, stringValue: value, domain: kReportMatePreferenceDomain) { _ in }
        }
    }

    func setBoolPreference(key: String, value: Bool) {
        connect()
        helperProxy { proxy in
            proxy.setBoolPreference(key: key, boolValue: value, domain: kReportMatePreferenceDomain) { _ in }
        }
    }

    func setIntPreference(key: String, value: Int) {
        connect()
        helperProxy { proxy in
            proxy.setIntPreference(key: key, intValue: value, domain: kReportMatePreferenceDomain) { _ in }
        }
    }

    func setArrayPreference(key: String, value: [String]) {
        connect()
        helperProxy { proxy in
            proxy.setArrayPreference(key: key, arrayValue: value, domain: kReportMatePreferenceDomain) { _ in }
        }
    }

    func removePreference(key: String) {
        connect()
        helperProxy { proxy in
            proxy.removePreference(key: key, domain: kReportMatePreferenceDomain) { _ in }
        }
    }

    // MARK: - Private

    private nonisolated func makeInvalidationHandler() -> @Sendable () -> Void {
        { [weak self] in
            Task { @MainActor [weak self] in
                self?.connection = nil
                self?.connectionError = "Connection to helper was invalidated"
            }
        }
    }

    private nonisolated func makeInterruptionHandler() -> @Sendable () -> Void {
        { [weak self] in
            Task { @MainActor [weak self] in
                self?.connectionError = "Connection to helper was interrupted"
                self?.isRunning = false
            }
        }
    }

    private nonisolated func makeErrorHandler() -> @Sendable (any Error) -> Void {
        { [weak self] error in
            Task { @MainActor [weak self] in
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
        if line.contains("[ERROR]") || line.contains("✗") { return .error }
        if line.contains("[WARNING]") || line.contains("⚠") { return .warning }
        if line.contains("[SUCCESS]") || line.contains("✓") { return .success }
        if line.contains("[DEBUG]") { return .debug }
        return .info
    }
}
