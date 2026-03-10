//
//  HelperXPCProtocol.swift
//  ReportMate
//
//  Shared XPC protocol definitions for communication between the GUI app
//  and the privileged helper daemon.
//

import Foundation

/// Mach service name for the privileged helper
public let kHelperMachServiceName = "com.github.reportmate.helper"

/// Preference domain for ReportMate system-level settings
public let kReportMatePreferenceDomain = "com.github.reportmate"

/// Path to the CLI binary inside the app bundle
public let kReportMateCLIPath = "/Applications/Utilities/ReportMate.app/Contents/MacOS/managedreportsrunner"

/// Helper LaunchDaemon plist name (used by SMAppService)
public let kHelperPlistName = "com.github.reportmate.helper.plist"

/// Protocol exposed by the privileged helper daemon.
/// All methods run with root privileges.
@objc public protocol HelperXPCProtocol: Sendable {
    /// Launch the CLI binary with the given arguments.
    /// Output is streamed back via the client protocol.
    func runCollection(arguments: [String])

    /// Stop the currently running collection process.
    func stopCollection()

    /// Write a string preference at system level (kCFPreferencesAnyUser).
    func setPreference(key: String, stringValue: String, domain: String, withReply reply: @escaping (Bool) -> Void)

    /// Write a boolean preference at system level.
    func setBoolPreference(key: String, boolValue: Bool, domain: String, withReply reply: @escaping (Bool) -> Void)

    /// Write an integer preference at system level.
    func setIntPreference(key: String, intValue: Int, domain: String, withReply reply: @escaping (Bool) -> Void)

    /// Write an array preference at system level.
    func setArrayPreference(key: String, arrayValue: [String], domain: String, withReply reply: @escaping (Bool) -> Void)

    /// Remove a preference key at system level.
    func removePreference(key: String, domain: String, withReply reply: @escaping (Bool) -> Void)

    /// Return the helper's version string for version-mismatch detection.
    func getHelperVersion(withReply reply: @escaping (String) -> Void)
}

/// Callback protocol from the helper back to the GUI client.
@objc public protocol HelperXPCClientProtocol: Sendable {
    /// A single line of output from the running CLI process.
    func didReceiveOutput(_ line: String)

    /// The CLI process finished.
    func runDidComplete(success: Bool, exitCode: Int32)

    /// The helper encountered an error outside of a normal run.
    func didEncounterError(_ message: String)
}
