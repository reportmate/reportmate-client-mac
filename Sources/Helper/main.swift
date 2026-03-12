//
//  main.swift
//  ReportMateHelper
//
//  Privileged XPC helper daemon. Runs as root via SMAppService,
//  executes the CLI binary and writes system-level preferences.
//

import Foundation
import ReportMateXPC

final class HelperService: NSObject, NSXPCListenerDelegate, Sendable {
    func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection connection: NSXPCConnection
    ) -> Bool {
        guard validateClient(connection) else { return false }

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

    private func validateClient(_ connection: NSXPCConnection) -> Bool {
        let pid = connection.processIdentifier
        guard pid > 0 else { return false }

        var code: SecCode?
        let attrs = [kSecGuestAttributePid: pid] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attrs, [], &code) == errSecSuccess,
              let secCode = code else {
            return false
        }

        // If we have a team ID, require the connecting process to share it
        if !teamID.isEmpty {
            let requirement = "anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\""
            var reqRef: SecRequirement?
            guard SecRequirementCreateWithString(requirement as CFString, [], &reqRef) == errSecSuccess,
                  let req = reqRef else {
                return false
            }
            return SecCodeCheckValidity(secCode, [], req) == errSecSuccess
        }

        // No team ID (ad-hoc/dev build) — validate the connecting process is
        // signed by the same authority as us by comparing signing identifiers
        var clientStaticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(secCode, [], &clientStaticCode) == errSecSuccess,
              let staticCode = clientStaticCode else {
            return false
        }

        var clientInfo: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, [], &clientInfo) == errSecSuccess,
              let clientDict = clientInfo as? [String: Any],
              let clientIdent = clientDict[kSecCodeInfoIdentifier as String] as? String else {
            return false
        }

        // Accept any ReportMate bundle (com.github.reportmate*)
        return clientIdent.hasPrefix("com.github.reportmate")
    }
}

/// Team ID injected by build.sh; defaults to ad-hoc for development builds.
private let teamID: String = {
    if let envTeam = ProcessInfo.processInfo.environment["REPORTMATE_TEAM_ID"], !envTeam.isEmpty {
        return envTeam
    }
    // Fallback: read from our own code signature
    var code: SecCode?
    guard SecCodeCopySelf([], &code) == errSecSuccess, let secCode = code else {
        return ""
    }
    var staticCode: SecStaticCode?
    guard SecCodeCopyStaticCode(secCode, [], &staticCode) == errSecSuccess, let sCode = staticCode else {
        return ""
    }
    var info: CFDictionary?
    guard SecCodeCopySigningInformation(sCode, [], &info) == errSecSuccess,
          let dict = info as? [String: Any],
          let teamStr = dict[kSecCodeInfoTeamIdentifier as String] as? String else {
        return ""
    }
    return teamStr
}()

let delegate = HelperService()
let listener = NSXPCListener(machServiceName: kHelperMachServiceName)
listener.delegate = delegate
listener.resume()
RunLoop.current.run()
