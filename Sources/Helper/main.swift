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

        // Require the connecting process be signed by our team.
        // The team ID is embedded at build time via build.sh.
        let requirement = "anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\""
        var reqRef: SecRequirement?
        guard SecRequirementCreateWithString(requirement as CFString, [], &reqRef) == errSecSuccess,
              let req = reqRef else {
            return false
        }

        return SecCodeCheckValidity(secCode, [], req) == errSecSuccess
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
