//
//  DaemonRegistration.swift
//
//  Registers the app's LaunchDaemons with SMAppService. Their plists live in
//  Contents/Library/LaunchDaemons and name the app's own executable through
//  BundleProgram, so launchd attributes every job to the app and nothing is
//  copied to /Library/LaunchDaemons. Registering a daemon needs root; the
//  package's postinstall runs `managedreportsrunner --register-daemons`.
//
//  A daemon registered this way also needs approval, which a managed
//  login-items (service management) profile for com.github.reportmate grants
//  silently. Without one it waits in System Settings > General > Login Items
//  & Extensions and does not run.
//

import Foundation
import ReportMateXPC
import ServiceManagement

enum DaemonRegistration {
    /// Registers every daemon afresh. A daemon that reports any registration
    /// is unregistered first and registered again, because the status cannot be
    /// trusted on an upgrade: a job of the same label loaded from
    /// /Library/LaunchDaemons by an earlier release reads as `.enabled`, and once
    /// the postinstall boots that copy out nothing would be loaded at all.
    /// Re-registering also makes launchd load the plists the new bundle carries.
    /// Returns false if any registration failed; a daemon left waiting for
    /// approval is reported but is not a failure, since approval is out of this
    /// tool's hands.
    static func registerAll(plistNames: [String] = kReportMateDaemonPlistNames) -> Bool {
        guard getuid() == 0 else {
            fputs("ERROR: --register-daemons must run as root\n", stderr)
            return false
        }
        var ok = true
        for name in plistNames {
            let service = SMAppService.daemon(plistName: name)
            if service.status != .notRegistered, service.status != .notFound {
                print("\(name): was \(describe(service.status)), re-registering")
                if let error = unregister(service) {
                    print("\(name): unregister before re-register reported: \(error.localizedDescription)")
                }
            }
            do {
                try service.register()
                print("\(name): registered (\(describe(service.status)))")
            } catch {
                if service.status == .requiresApproval {
                    print("\(name): registered, waiting for approval in Login Items & Extensions")
                } else {
                    fputs("\(name): registration failed: \(error.localizedDescription)\n", stderr)
                    ok = false
                }
            }
        }
        return ok
    }

    /// Unregisters every daemon this app registered. launchd stops each job.
    static func unregisterAll(plistNames: [String] = kReportMateDaemonPlistNames) -> Bool {
        guard getuid() == 0 else {
            fputs("ERROR: --unregister-daemons must run as root\n", stderr)
            return false
        }
        var ok = true
        for name in plistNames {
            let service = SMAppService.daemon(plistName: name)
            guard service.status != .notRegistered, service.status != .notFound else {
                print("\(name): not registered")
                continue
            }
            if let error = unregister(service) {
                fputs("\(name): unregister failed: \(error.localizedDescription)\n", stderr)
                ok = false
            } else {
                print("\(name): unregistered")
            }
        }
        return ok
    }

    /// Unregisters one daemon and waits for launchd to finish; nil on success.
    private static func unregister(_ service: SMAppService) -> Error? {
        let done = DispatchSemaphore(value: 0)
        nonisolated(unsafe) var failure: Error?
        service.unregister { error in
            failure = error
            done.signal()
        }
        done.wait()
        return failure
    }

    static func describe(_ status: SMAppService.Status) -> String {
        switch status {
        case .enabled: return "enabled"
        case .requiresApproval: return "waiting for approval"
        case .notRegistered: return "not registered"
        case .notFound: return "plist not found in the app bundle"
        @unknown default: return "unknown"
        }
    }
}
