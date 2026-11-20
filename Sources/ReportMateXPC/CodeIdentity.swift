//
//  CodeIdentity.swift
//  ReportMate
//
//  The running executable's own code-signing identity. The window, the
//  privileged helper and the collector are one executable, so each end of the
//  helper's XPC connection pins the other to this same requirement.
//

import Foundation
import Security

public enum CodeIdentity {
    /// The designated requirement of the running executable, as text. Nil when
    /// the executable is unsigned or ad-hoc signed: with no Team ID there is
    /// nothing worth pinning, so callers treat that as "trust no one".
    public static let ownDesignatedRequirement: String? = {
        var selfCode: SecCode?
        guard SecCodeCopySelf([], &selfCode) == errSecSuccess, let selfCode else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(selfCode, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any],
              dict[kSecCodeInfoTeamIdentifier as String] is String else { return nil }
        var requirement: SecRequirement?
        guard SecCodeCopyDesignatedRequirement(staticCode, [], &requirement) == errSecSuccess, let requirement else { return nil }
        var text: CFString?
        guard SecRequirementCopyString(requirement, [], &text) == errSecSuccess, let text else { return nil }
        return text as String
    }()
}
