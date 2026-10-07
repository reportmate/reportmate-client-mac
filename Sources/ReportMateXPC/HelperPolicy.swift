//
//  HelperPolicy.swift
//  ReportMate
//
//  What the privileged helper accepts: which client may connect, which
//  arguments it passes to the CLI, and which preference keys it writes.
//  Kept in the shared library so the rules are unit-tested.
//

import Foundation

/// Signing identifier of the GUI app (the bundle's main executable).
public let kReportMateGUIIdentifier = "com.github.reportmate"

/// Path of the helper's LaunchDaemon plist, installed by the package.
public let kHelperLaunchDaemonPath = "/Library/LaunchDaemons/com.github.reportmate.helper.plist"

public enum HelperPolicy {

    /// Code-signing requirement a client must satisfy: our app, signed by the
    /// helper's own Team ID. Pinning the identifier keeps the CLI and any other
    /// binary from the same team from driving the helper.
    public static func clientRequirement(teamID: String) -> String {
        "anchor apple generic and identifier \"\(kReportMateGUIIdentifier)\" and certificate leaf[subject.OU] = \"\(teamID)\""
    }

    /// Preference keys the GUI's Prefs tab edits. The helper writes nothing else.
    public static let writableKeys: Set<String> = [
        "ApiUrl", "DeviceId", "Passphrase", "ValidateSSL", "CollectionInterval",
        "LogLevel", "StorageMode", "Timeout", "OsqueryPath", "OsqueryExtensionPath",
        "ExtensionEnabled", "UseAltSystemInfo", "EnabledModules",
    ]

    public static func canWrite(key: String, domain: String) -> Bool {
        domain == kReportMatePreferenceDomain && writableKeys.contains(key)
    }

    /// Arguments the helper passes to the CLI: verbosity flags and a module list.
    public static func isAllowedRun(arguments: [String]) -> Bool {
        var index = 0
        while index < arguments.count {
            let argument = arguments[index]
            switch argument {
            case "-v", "-vv", "-vvv":
                index += 1
            case "--run-modules":
                guard index + 1 < arguments.count, isModuleList(arguments[index + 1]) else { return false }
                index += 2
            default:
                return false
            }
        }
        return true
    }

    static func isModuleList(_ value: String) -> Bool {
        let modules = value.split(separator: ",", omittingEmptySubsequences: false)
        guard !modules.isEmpty else { return false }
        return modules.allSatisfy { module in
            !module.isEmpty && module.allSatisfy { $0.isASCII && ($0.isLowercase || $0.isNumber || $0 == "_") }
        }
    }

    /// True when the binary and every folder above it are real (not symlinks),
    /// owned by root and writable only by root. Group write is tolerated for
    /// wheel and admin, since /Applications is root:admin 775 on every Mac and
    /// an admin can already become root.
    public static func isTrustedRootPath(_ path: String, fileManager: FileManager = .default) -> Bool {
        var url = URL(fileURLWithPath: path)
        while url.path != "/" {
            guard let attributes = try? fileManager.attributesOfItem(atPath: url.path),
                  let type = attributes[.type] as? FileAttributeType,
                  let owner = attributes[.ownerAccountID] as? NSNumber,
                  let group = attributes[.groupOwnerAccountID] as? NSNumber,
                  let mode = attributes[.posixPermissions] as? NSNumber,
                  isTrusted(type: type, owner: owner.intValue, group: group.intValue, mode: mode.intValue) else {
                return false
            }
            url.deleteLastPathComponent()
        }
        return true
    }

    static func isTrusted(type: FileAttributeType, owner: Int, group: Int, mode: Int) -> Bool {
        guard type != .typeSymbolicLink, owner == 0, mode & 0o002 == 0 else { return false }
        if mode & 0o020 != 0 { return group == 0 || group == 80 }
        return true
    }
}
