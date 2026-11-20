//
//  HelperDaemon.swift
//
//  Privileged XPC helper daemon. The app registers it as a LaunchDaemon with
//  SMAppService; launchd starts the app's executable with `--helper`, as root,
//  and it runs the collector and writes system-level preferences.
//

import Foundation
import os
import ReportMateXPC

let log = Logger(subsystem: "com.github.reportmate.helper", category: "xpc")

final class HelperService: NSObject, NSXPCListenerDelegate, Sendable {
    func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection connection: NSXPCConnection
    ) -> Bool {
        // Only this app's own signed executable may connect.
        guard let requirement = CodeIdentity.ownDesignatedRequirement else {
            log.error("Rejecting XPC client pid \(connection.processIdentifier): this executable has no Team ID (unsigned or ad-hoc build)")
            return false
        }
        // The system checks the requirement against the client's audit token on
        // every message, so a recycled PID cannot impersonate the window.
        connection.setCodeSigningRequirement(requirement)
        log.info("Accepted XPC client pid \(connection.processIdentifier) subject to \(requirement, privacy: .public)")

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

public enum HelperDaemon {
    /// Serves the helper's Mach service until launchd stops the process.
    public static func run() -> Never {
        let delegate = HelperService()
        let listener = NSXPCListener(machServiceName: kHelperMachServiceName)
        listener.delegate = delegate
        listener.resume()
        while true {
            RunLoop.current.run()
        }
    }
}
