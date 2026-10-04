import Foundation
import Security

/// Decides whether an external binary is safe for this process to execute.
///
/// The runner works as root from LaunchDaemons, so anything it launches runs as root too. A
/// binary qualifies only when nobody but root (or, in an unprivileged run, the current user)
/// could have put it there or changed it since, and — where a signer is known — when its code
/// signature satisfies a pinned requirement.
enum BinaryTrust {
    /// osquery's own Developer ID signature. Every official osquery pkg, including the copy
    /// Fleet's orbit relocates, carries it.
    static let osqueryRequirement =
        #"anchor apple generic and identifier "io.osquery.agent" and certificate leaf[subject.OU] = "3522FA9PXF""#

    /// Owners whose files this process may execute. Root alone when running as root.
    static var allowedOwners: Set<uid_t> {
        let euid = geteuid()
        return euid == 0 ? [0] : [0, euid]
    }

    /// The path with every symlink resolved, when the file and each directory above it are
    /// owned by an allowed owner and writable by nobody else. `nil` otherwise.
    ///
    /// Execute the returned path rather than the one passed in: a symlink is only as
    /// trustworthy as the directory it sits in, and the resolved path is the one checked.
    static func trustedRealPath(_ path: String, allowedOwners: Set<uid_t> = allowedOwners) -> String? {
        guard let resolved = realpath(path, nil) else { return nil }
        defer { free(resolved) }
        let real = String(cString: resolved)

        var info = stat()
        guard lstat(real, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFREG,
              (info.st_mode & S_IXUSR) != 0,
              isSafe(info, allowedOwners: allowedOwners)
        else { return nil }

        var directory = (real as NSString).deletingLastPathComponent
        while true {
            guard lstat(directory, &info) == 0,
                  (info.st_mode & S_IFMT) == S_IFDIR,
                  isSafe(info, allowedOwners: allowedOwners)
            else { return nil }
            if directory == "/" { break }
            directory = (directory as NSString).deletingLastPathComponent
        }
        return real
    }

    private static func isSafe(_ info: stat, allowedOwners: Set<uid_t>) -> Bool {
        allowedOwners.contains(info.st_uid) && (info.st_mode & (S_IWGRP | S_IWOTH)) == 0
    }

    /// Whether the code at `path` is validly signed and meets `requirement`. A main executable
    /// inside an app bundle is checked as the whole bundle, so its resources are sealed too.
    static func satisfies(_ path: String, requirement: String) -> Bool {
        var codePath = path
        if let range = path.range(of: ".app/Contents/MacOS/") {
            codePath = String(path[..<range.lowerBound]) + ".app"
        }

        var staticCode: SecStaticCode?
        var secRequirement: SecRequirement?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: codePath) as CFURL, [], &staticCode) == errSecSuccess,
              let code = staticCode,
              SecRequirementCreateWithString(requirement as CFString, [], &secRequirement) == errSecSuccess,
              let req = secRequirement
        else { return false }

        let flags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate | kSecCSCheckNestedCode)
        return SecStaticCodeCheckValidity(code, flags, req) == errSecSuccess
    }

    /// The Team ID this process is signed with, or `nil` for an unsigned or ad-hoc build.
    static let ownTeamID: String? = {
        var code: SecCode?
        var staticCode: SecStaticCode?
        var info: CFDictionary?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let selfCode = code,
              SecCodeCopyStaticCode(selfCode, [], &staticCode) == errSecSuccess, let selfStatic = staticCode,
              SecCodeCopySigningInformation(selfStatic, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any],
              let team = dict[kSecCodeInfoTeamIdentifier as String] as? String, !team.isEmpty
        else { return nil }
        return team
    }()

    /// A trusted osquery binary: safe path chain and osquery's pinned signature.
    static func trustedOsquery(_ path: String) -> String? {
        guard let real = trustedRealPath(path), satisfies(real, requirement: osqueryRequirement) else { return nil }
        return real
    }

    /// A trusted osquery extension: safe path chain and, when this build is signed, the same
    /// Team ID as this process, since build.sh re-signs the bundled extension with it.
    static func trustedExtension(_ path: String) -> String? {
        guard let real = trustedRealPath(path) else { return nil }
        if let team = ownTeamID {
            guard satisfies(real, requirement: #"anchor apple generic and certificate leaf[subject.OU] = "\#(team)""#) else { return nil }
        }
        return real
    }
}
