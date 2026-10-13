//
//  AdminAuthorization.swift
//  ReportMate
//
//  Asks for an administrator's name and password when the user saves
//  settings, and hands the helper the resulting authorization, which it
//  checks before writing any machine setting. Each Save asks afresh and the
//  authorization is destroyed once the save finishes, so nothing in the
//  window stays unlocked.
//

import Foundation
import Security
import ReportMateXPC

/// One administrator authorization, held for the length of a single save.
@MainActor
final class AdminAuthorization {
    private var authRef: AuthorizationRef?

    /// The external form the helper accepts.
    let externalForm: Data

    private init(authRef: AuthorizationRef, externalForm: Data) {
        self.authRef = authRef
        self.externalForm = externalForm
    }

    /// Shows the system's administrator prompt. Returns nil when the user
    /// cancels or cannot authenticate as an administrator.
    static func authorize() -> AdminAuthorization? {
        var ref: AuthorizationRef?
        guard AuthorizationCreate(nil, nil, [], &ref) == errAuthorizationSuccess, let ref else { return nil }

        let status = kReportMateAdminRight.withCString { name -> OSStatus in
            var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
            return withUnsafeMutablePointer(to: &item) { itemPointer in
                var rights = AuthorizationRights(count: 1, items: itemPointer)
                return AuthorizationCopyRights(ref, &rights, nil, [.interactionAllowed, .extendRights, .preAuthorize], nil)
            }
        }
        guard status == errAuthorizationSuccess else {
            AuthorizationFree(ref, [])
            return nil
        }

        var form = AuthorizationExternalForm()
        guard AuthorizationMakeExternalForm(ref, &form) == errAuthorizationSuccess else {
            AuthorizationFree(ref, [.destroyRights])
            return nil
        }
        return AdminAuthorization(authRef: ref, externalForm: withUnsafeBytes(of: &form) { Data($0) })
    }

    /// Destroys the authorization, so the next save needs a new prompt.
    func free() {
        if let authRef {
            AuthorizationFree(authRef, [.destroyRights])
        }
        authRef = nil
    }
}
