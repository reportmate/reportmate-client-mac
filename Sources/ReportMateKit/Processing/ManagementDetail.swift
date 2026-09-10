import Foundation

/// Everything the Management tab reads. Port of the derived values at the top
/// of `ManagementTab.tsx`: enrollment, the identity certificate, Autopilot,
/// device details, ADE, domain trust, the profile and managed-preference lists.
public struct ManagementDetail: Sendable, Hashable {
    public struct Certificate: Sendable, Hashable {
        public var pushTopic: String?
        public var scepUrl: String?
        public var name: String?
        public var subject: String?
        public var issuer: String?
        public var expires: String?
        public var enrollmentMethod: String?
        public var identityPayloadType: String?
        public var checkinUrl: String?
        public var serverUrl: String?
        public var provider: String?
        public var hasDetails: Bool { name != nil || issuer != nil }
    }

    public struct Payload: Sendable, Hashable, Identifiable {
        public var id: String { (type ?? "") + (displayName ?? "") + String(index) }
        public var index: Int
        public var displayName: String?
        public var type: String?
        public var settings: [(key: String, value: JSONValue)]
        public var rawData: String?
        public static func == (a: Payload, b: Payload) -> Bool { a.id == b.id && a.rawData == b.rawData && a.settings.map(\.key) == b.settings.map(\.key) }
        public func hash(into hasher: inout Hasher) { hasher.combine(id) }
    }

    public struct Profile: Sendable, Hashable, Identifiable {
        public var id: String { identifier }
        public var identifier: String
        public var name: String
        public var uuid: String?
        public var organization: String?
        public var description: String?
        public var installDate: String?
        public var payloads: [Payload]
        public var payloadCount: Int
        public var scope: String
        public var isVerified: Bool
        public var isRemovalDisallowed: Bool
        public var isLegacyMCX: Bool

        public func matches(_ q: String) -> Bool {
            name.lowercased().contains(q) || identifier.lowercased().contains(q) || (organization ?? "").lowercased().contains(q)
        }
        /// "Jan 5, 2026 at 10:00" style dates keep the date part only.
        public var installDateText: String? {
            guard let d = installDate else { return nil }
            if d.contains(" at ") {
                let head = d.components(separatedBy: " at ").first ?? d
                return head.components(separatedBy: ", ").prefix(2).joined(separator: ", ")
            }
            return d
        }
    }

    public struct PolicyDomain: Sendable, Hashable, Identifiable {
        public var id: String { domain }
        public var domain: String
        public var settings: [(name: String, value: String)]
        public var settingCount: Int
        public static func == (a: PolicyDomain, b: PolicyDomain) -> Bool { a.domain == b.domain && a.settingCount == b.settingCount && a.settings.map(\.name) == b.settings.map(\.name) }
        public func hash(into hasher: inout Hasher) { hasher.combine(domain) }
        public func matches(_ q: String) -> Bool {
            domain.lowercased().contains(q) || settings.contains { $0.name.lowercased().contains(q) || $0.value.lowercased().contains(q) }
        }
    }

    public var management: JSONValue
    public var mdmEnrollment: JSONValue
    public var certificate: Certificate
    public var deviceState: JSONValue
    public var tenantDetails: JSONValue
    public var deviceDetails: JSONValue
    public var adeConfiguration: JSONValue
    public var deviceIdentifiers: JSONValue
    public var autopilot: JSONValue
    public var domainTrust: JSONValue
    public var profiles: [Profile]
    public var managedPolicies: [PolicyDomain]
    public var logs: LogsInfo?
    public var isMac: Bool
    public var isEnrolled: Bool
    public var serverUrl: String?
    public var provider: String?
    public var enrollmentMethod: String?
    public var enrollmentType: String?
    public var tenantName: String?
    public var deviceAuthStatus: String?
    public var compliancePolicyCount: Int
    public var managedAppCount: Int
    public var hasData: Bool

    public init(modules: JSONValue, platform: Platform) {
        management = modules["management"].unwrappingSingleton()
        hasData = !management.isNull && !management.isEmptyContainer
        mdmEnrollment = management.first("mdm_enrollment", "mdmEnrollment")
        certificate = ManagementDetail.parseCertificate(management.first("mdm_certificate", "mdmCertificate"))
        deviceState = management.first("device_state", "deviceState")
        tenantDetails = management.first("tenant_details", "tenantDetails")
        deviceDetails = management.first("device_details", "deviceDetails")
        adeConfiguration = management.first("ade_configuration", "adeConfiguration")
        deviceIdentifiers = management.first("device_identifiers", "deviceIdentifiers")
        autopilot = management.first("autopilot_config", "autopilotConfig")
        domainTrust = management.first("domain_trust", "domainTrust")
        logs = LogsInfo(modules: modules)

        let macFields = ["installed_from_dep", "installedFromDep", "user_approved", "userApproved", "dep_capable", "depCapable",
                         "has_scep_payload", "hasScepPayload", "checkin_url", "checkinUrl"]
        let mdm = mdmEnrollment
        isMac = platform == .macOS || macFields.contains { !mdm[$0].isNull }

        isEnrolled = mdmEnrollment["enrolled"].boolish || mdmEnrollment["is_enrolled"].boolish || mdmEnrollment["isEnrolled"].boolish
        serverUrl = mdmEnrollment.firstString("server_url", "serverUrl", "checkin_url", "checkinUrl")
        provider = ManagementDetail.detectProvider(serverURL: serverUrl, certificate: certificate) ?? mdmEnrollment["provider"].nonEmptyString

        if let m = certificate.enrollmentMethod {
            enrollmentMethod = m
        } else if let tail = certificate.identityPayloadType?.split(separator: ".").last, !tail.isEmpty {
            enrollmentMethod = tail.uppercased()
        } else if mdmEnrollment["has_scep_payload"].boolish || mdmEnrollment["hasScepPayload"].boolish {
            enrollmentMethod = "SCEP"
        } else {
            enrollmentMethod = nil
        }

        if isMac {
            if mdmEnrollment["installed_from_dep"].boolish || mdmEnrollment["installedFromDep"].boolish { enrollmentType = "Automated Device Enrollment" }
            else if mdmEnrollment["user_approved"].boolish || mdmEnrollment["userApproved"].boolish { enrollmentType = "User Approved Enrollment" }
            else if isEnrolled { enrollmentType = "MDM Enrolled" } else { enrollmentType = nil }
        } else {
            enrollmentType = mdmEnrollment.firstString("enrollment_type", "enrollmentType") ?? deviceState["status"].nonEmptyString
        }
        tenantName = tenantDetails.firstString("tenant_name", "tenantName", "organization")
        deviceAuthStatus = deviceDetails.firstString("device_auth_status", "deviceAuthStatus")
        compliancePolicyCount = management.first("compliance_policies", "compliancePolicies").elements.count
        managedAppCount = management.first("managed_apps", "managedApps").elements.count

        let installed = management.first("installed_profiles", "installedProfiles").elements
        if !installed.isEmpty {
            profiles = installed.enumerated().map { i, p in
                let scope = p["user"].nonEmptyString ?? (p["type"].string == "User" ? "User Level" : "System Level")
                return ManagementDetail.profile(p, index: i, scope: scope)
            }
        } else {
            profiles = management.first("configuration_profiles", "configurationProfiles").elements.enumerated().map { i, p in
                let scope = (p["type"].nonEmptyString ?? "Device") == "User" ? "User Level" : "System Level"
                var obj = p.object ?? [:]
                obj["identifier"] = .string(p.firstString("identifier", "uuid", "profile_name", "profileName") ?? "profile-\(i)")
                obj["name"] = .string(p.firstString("profile_name", "profileName", "name") ?? p["identifier"].string ?? "profile-\(i)")
                obj["organization"] = p.first("organization", "source", "category")
                return ManagementDetail.profile(.object(obj), index: i, scope: scope)
            }
        }
        managedPolicies = management.first("managed_policies", "managedPolicies").elements.enumerated().map { i, pol in
            let settings = pol["settings"].elements.map { (name: $0["name"].string ?? "", value: $0["value"].string ?? $0["value"].prettyPrinted) }
            return PolicyDomain(domain: pol["domain"].nonEmptyString ?? "domain-\(i)", settings: settings,
                                settingCount: settings.isEmpty ? (pol["setting_count"].int ?? pol["settingCount"].int ?? 0) : settings.count)
        }
    }

    static func profile(_ p: JSONValue, index: Int, scope: String) -> Profile {
        let identifier = p["identifier"].nonEmptyString ?? "profile-\(index)"
        let payloads = p["payloads"].elements.enumerated().map { i, pl -> Payload in
            let settings = (pl["settings"].object ?? [:]).sorted { $0.key < $1.key }.map { (key: $0.key, value: $0.value) }
            return Payload(index: i, displayName: pl.firstString("display_name", "displayName"), type: pl["type"].nonEmptyString,
                           settings: settings, rawData: pl.firstString("raw_data", "rawData"))
        }
        return Profile(identifier: identifier, name: p["name"].nonEmptyString ?? identifier, uuid: p["uuid"].nonEmptyString,
                       organization: p["organization"].nonEmptyString, description: p["description"].nonEmptyString,
                       installDate: p.firstString("install_date", "installDate"), payloads: payloads,
                       payloadCount: payloads.isEmpty ? (p.first("payload_count", "payloadCount").int ?? 0) : payloads.count,
                       scope: scope, isVerified: p.firstString("verification_state", "verificationState") == "verified",
                       isRemovalDisallowed: p.first("removal_disallowed", "removalDisallowed").boolish,
                       isLegacyMCX: p["method"].string == "Emulated")
    }

    /// `parseMdmCertificate`: the osquery row wraps JSON in `output` with
    /// semicolons leaking inside the quotes.
    static func parseCertificate(_ raw: JSONValue) -> Certificate {
        guard !raw.isNull else { return Certificate() }
        var source = raw
        if let out = raw["output"].string {
            var clean = out
            for (pattern, rep) in [(#"";\\",\s*"#, "\","), (#"";\\"\n"#, "\"\n"), (#"";\s*,"#, "\","), (#"";\s*\n"#, "\"\n"),
                                   (#"\\";\s*,"#, "\","), (#"\\";\s*\n"#, "\"\n"), (#"";""#, "\",\"")] {
                clean = clean.replacingOccurrences(of: pattern, with: rep, options: .regularExpression)
            }
            if let parsed = JSONValue.parse(clean.trimmingCharacters(in: .whitespacesAndNewlines)) { source = parsed }
        }
        return Certificate(
            pushTopic: source.firstString("push_topic", "pushTopic"), scepUrl: source.firstString("scep_url", "scepUrl"),
            name: source.firstString("certificate_name", "certificateName"), subject: source.firstString("certificate_subject", "certificateSubject"),
            issuer: source.firstString("certificate_issuer", "certificateIssuer"), expires: source.firstString("certificate_expires", "certificateExpires"),
            enrollmentMethod: source.firstString("certificate_enrollment_method", "certificateEnrollmentMethod"),
            identityPayloadType: source.firstString("identity_payload_type", "identityPayloadType"),
            checkinUrl: source.firstString("checkin_url", "checkinUrl"), serverUrl: source.firstString("server_url", "serverUrl"),
            provider: source.firstString("mdm_provider", "mdmProvider"))
    }

    /// `detectMdmProvider`: the live server URL wins; the certificate can be
    /// stale after a migration between MDMs.
    public static func detectProvider(serverURL: String?, certificate: Certificate) -> String? {
        if let url = serverURL?.lowercased() {
            if url.contains("micromdm") { return "MicroMDM" }
            if url.contains("nanomdm") { return "NanoMDM" }
            if url.contains("jamf") { return "Jamf Pro" }
            if url.contains("manage.microsoft.com") || url.contains("intune") { return "Microsoft Intune" }
            if url.contains("mosyle") { return "Mosyle" }
            if url.contains("kandji") { return "Kandji" }
            if url.contains("addigy") { return "Addigy" }
            if url.contains("simplemdm") { return "SimpleMDM" }
            if url.contains("airwatch.com") || url.contains("workspaceone") { return "Workspace ONE" }
            if url.contains("meraki") { return "Cisco Meraki" }
            if url.contains("maas360") { return "MaaS360" }
            if url.contains("mobileiron") || url.contains("ivanti") { return "Ivanti" }
        }
        if let p = certificate.provider { return p }
        if let issuer = certificate.issuer?.lowercased() {
            if issuer.contains("micromdm") { return "MicroMDM" }
            if issuer.contains("nanomdm") { return "NanoMDM" }
            if issuer.contains("jamf") { return "Jamf Pro" }
            if issuer.contains("microsoft") || issuer.contains("intune") { return "Microsoft Intune" }
            if issuer.contains("mosyle") { return "Mosyle" }
            if issuer.contains("kandji") { return "Kandji" }
            if issuer.contains("addigy") { return "Addigy" }
            if issuer.contains("simplemdm") { return "SimpleMDM" }
            if issuer.contains("workspace one") || issuer.contains("vmware") { return "Workspace ONE" }
            if issuer.contains("meraki") { return "Cisco Meraki" }
        }
        return nil
    }

    public var enrollmentUrlLabel: String {
        switch enrollmentMethod { case "ACME": return "ACME Directory"; case "SCEP": return "SCEP Server"; default: return "Certificate Enrollment" }
    }

    /// Windows enrollment types read as the joined state.
    public var displayEnrollmentType: String? {
        guard var t = enrollmentType else { return nil }
        if t == "Hybrid Entra Join" { t = "Domain Joined" }
        if t == "Entra Join" { t = "Entra Joined" }
        return t
    }
    public var isDomainJoined: Bool { enrollmentType == "Hybrid Entra Join" || enrollmentType == "Domain Joined" }

    public var profileCount: Int { profiles.isEmpty ? management["profiles"].elements.count : profiles.count }
    public var userScopedProfileCount: Int { profiles.filter { $0.scope == "User Level" }.count }

    /// `user@domain@<tenant-guid>` keeps only the principal name.
    public static func stripTenantSuffix(_ upn: String?) -> String? {
        guard let upn else { return nil }
        if let r = upn.range(of: #"@[0-9a-fA-F-]{36}$"#, options: .regularExpression) { return String(upn[..<r.lowerBound]) }
        return upn
    }

    public var primaryUser: String? { deviceDetails.firstString("primary_user", "primaryUser") }
    public var managementName: String? { deviceDetails.firstString("management_name", "managementName") }
    public var enrolledBy: String? { mdmEnrollment.firstString("user_principal_name", "userPrincipalName") }
    public var intuneDeviceId: String? { deviceDetails.firstString("intune_device_id", "intuneDeviceId") }
    public var entraObjectId: String? { deviceDetails.firstString("entra_object_id", "entraObjectId") }
    public var lastSync: String? { management["last_sync"].nonEmptyString }
    public var hasDeviceDetails: Bool { managementName != nil || primaryUser != nil || enrolledBy != nil || intuneDeviceId != nil || entraObjectId != nil || lastSync != nil }
    /// Intune usually reports the same account for both; show the pair only when they differ.
    public var showPrimaryUser: Bool {
        guard let p = primaryUser else { return false }
        return ManagementDetail.stripTenantSuffix(p)?.lowercased() != ManagementDetail.stripTenantSuffix(enrolledBy)?.lowercased()
    }

    public var hasDeviceIdentifiers: Bool {
        ["uuid", "hardware_serial", "serialNumber", "serial_number", "hardware_model", "model", "asset_tag", "assetTag", "provisioning_udid"].contains { deviceIdentifiers[$0].nonEmptyString != nil }
    }
    public var adeActive: Bool { adeConfiguration["activated"].boolish || adeConfiguration["assigned"].boolish }

    /// Expiry from `[ 2025-03-25 22:47:56.000 UTC -- 2035-03-25 23:17:56.000 UTC ]`.
    public static func validityEnd(_ validity: String?) -> Date? {
        guard let validity, let r = validity.range(of: #"--\s*(\d{4}-\d{2}-\d{2}(?:\s+\d{2}:\d{2}:\d{2}(?:\.\d{3})?)?\s*(?:UTC)?)"#, options: .regularExpression) else { return nil }
        var text = String(validity[r]).dropFirst(2).trimmingCharacters(in: .whitespaces)
        if text.hasSuffix("UTC") { text = String(text.dropLast(3)).trimmingCharacters(in: .whitespaces) }
        if let d = FlexibleDate.parse(text) { return d }
        return FlexibleDate.parse(String(text.prefix(10)))
    }

    public enum ExpiryTone: Sendable { case expired, soon, fine, unknown }
    public static func expiryTone(_ date: Date?, now: Date = Date()) -> ExpiryTone {
        guard let date else { return .unknown }
        let days = Int(ceil(date.timeIntervalSince(now) / 86_400))
        if days < 0 { return .expired }
        if days < 30 { return .soon }
        return .fine
    }
}
