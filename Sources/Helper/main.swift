//
//  main.swift
//  ReportMateHelper
//
//  Privileged XPC helper daemon. Installed by the package as a LaunchDaemon,
//  runs as root, executes the CLI binary and writes system-level preferences.
//

import Foundation
import os
import Security
import ReportMateXPC

let log = Logger(subsystem: "com.github.reportmate.helper", category: "xpc")

/// The Team ID this helper is signed with. The GUI is signed by the same
/// identity, so the helper trusts exactly its own team and needs no Team ID
/// baked into the source. Nil when the helper is unsigned or ad-hoc signed.
private let ownTeamID: String? = {
    var selfCode: SecCode?
    guard SecCodeCopySelf([], &selfCode) == errSecSuccess, let selfCode else { return nil }
    var staticCode: SecStaticCode?
    guard SecCodeCopyStaticCode(selfCode, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
    var info: CFDictionary?
    guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
          let dict = info as? [String: Any] else { return nil }
    return dict[kSecCodeInfoTeamIdentifier as String] as? String
}()

final class HelperService: NSObject, NSXPCListenerDelegate, Sendable {
    func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection connection: NSXPCConnection
    ) -> Bool {
        // Only our signed GUI, from this helper's own team, may connect.
        guard let teamID = ownTeamID else {
            log.error("Rejecting XPC client pid \(connection.processIdentifier): this helper has no Team ID (unsigned or ad-hoc build)")
            return false
        }
        // The system checks the requirement against the client's audit token on
        // every message, so a recycled PID cannot impersonate the GUI.
        connection.setCodeSigningRequirement(HelperPolicy.clientRequirement(teamID: teamID))
        log.info("Accepted XPC client pid \(connection.processIdentifier) subject to \(kReportMateGUIIdentifier, privacy: .public) from Team ID \(teamID, privacy: .public)")

        let exportedInterface = NSXPCInterface(with: HelperXPCProtocol.self)
        connection.exportedInterface = exportedInterface

        let remoteInterface = NSXPCInterface(with: HelperXPCClientProtocol.self)
        connection.remoteObjectInterface = remoteInterface

        let runner = HelperCommandRunner(connection: connection)
        connection.exportedObject = runner

        connection.invalidationHandler = { [weak runner] in
            runner?.cancelRunningProcess()
        }

        connection.resume()
        return true
    }
}

let delegate = HelperService()
let listener = NSXPCListener(machServiceName: kHelperMachServiceName)
listener.delegate = delegate
listener.resume()
RunLoop.current.run()
