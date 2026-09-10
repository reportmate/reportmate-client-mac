import Foundation

/// MDM enrollment facts for the Info widget and the Management tab.
/// Port of `Management.tsx` (widget) and `modules/management.ts`.
public struct ManagementInfo: Sendable, Hashable {
    public var isEnrolled: Bool
    public var provider: String?
    public var serverURL: String?
    public var serverHost: String?
    public var enrollmentType: String?
    public var isSupervised: Bool?
    public var autopilotActivated: Bool?
    public var certificateExpires: String?
    public var certificateIssuer: String?
    public var pushTopic: String?
    public var intuneDeviceId: String?
    public var entraObjectId: String?
    public var installedFromDep: Bool
    public var userApproved: Bool
    public var depCapable: Bool
    public var organization: String?
    public var tenantName: String?
    public var isMac: Bool
    public var profiles: [JSONValue]
    public var raw: JSONValue

    public var hasData: Bool { !raw.isNull && !(raw.isEmptyContainer) }

    public var providerIsIntune: Bool { (provider ?? "").lowercased().contains("intune") }

    public init(modules: JSONValue, platform: Platform) {
        let management = modules["management"].unwrappingSingleton()
        raw = management
        let mdm = management.first("mdm_enrollment", "mdmEnrollment")
        let cert = ManagementInfo.parseCertificate(management.first("mdm_certificate", "mdmCertificate"))

        isEnrolled = mdm["enrolled"].boolish || mdm["isEnrolled"].boolish || mdm["is_enrolled"].boolish
        serverURL = mdm.firstString("server_url", "serverUrl")
        serverHost = serverURL.map { url in
            var s = url
            for p in ["https://", "http://"] where s.hasPrefix(p) { s = String(s.dropFirst(p.count)) }
            return String(s.split(separator: "/").first ?? "")
        }
        provider = mdm["provider"].nonEmptyString ?? ManagementInfo.detectProvider(serverURL: serverURL, certificate: cert)

        let macFields = ["installed_from_dep", "installedFromDep", "user_approved", "userApproved", "dep_capable", "depCapable",
                         "has_scep_payload", "hasScepPayload", "checkin_url", "checkinUrl"]
        let looksMac = macFields.contains { !mdm[$0].isNull }
        isMac = platform == .macOS || looksMac
        installedFromDep = mdm["installed_from_dep"].boolish || mdm["installedFromDep"].boolish
        userApproved = mdm["user_approved"].boolish || mdm["userApproved"].boolish
        depCapable = mdm["dep_capable"].boolish || mdm["depCapable"].boolish
        if isMac {
            if installedFromDep {
                enrollmentType = "Automated Device Enrollment"
            } else if userApproved {
                enrollmentType = "User Approved Enrollment"
            } else if isEnrolled {
                enrollmentType = "MDM Enrolled"
            }
        } else {
            var t = mdm.firstString("enrollmentType", "enrollment_type")
            if t == "Hybrid Entra Join" { t = "Domain Joined" }
            if t == "Entra Join" { t = "Entra Joined" }
            enrollmentType = t
        }

        let mdmInfo = management.first("mdm_info", "mdmInfo")
        isSupervised = mdmInfo["is_supervised"].boolishIfPresent ?? mdmInfo["isSupervised"].boolishIfPresent
        let autopilot = management.first("autopilot_config", "autopilotConfig")
        autopilotActivated = autopilot.isNull ? nil : autopilot["activated"].boolish

        certificateExpires = cert["certificate_expires"].nonEmptyString
        certificateIssuer = cert["certificate_issuer"].nonEmptyString
        pushTopic = cert["push_topic"].nonEmptyString

        let deviceDetails = management.first("deviceDetails", "device_details")
        intuneDeviceId = deviceDetails.firstString("intuneDeviceId", "intune_device_id")
        entraObjectId = deviceDetails.firstString("entraObjectId", "entra_object_id")

        let ade = management.first("ade_configuration", "adeConfiguration")
        let tenant = management.first("tenant_details", "tenantDetails")
        tenantName = tenant.firstString("tenant_name", "tenantName")
        organization = ade["organization"].nonEmptyString ?? tenantName

        profiles = management.first("installed_profiles", "installedProfiles", "profiles").elements
    }

    /// The osquery MDM certificate row wraps JSON in `output`.
    static func parseCertificate(_ value: JSONValue) -> JSONValue {
        guard !value.isNull else { return .null }
        if let out = value["output"].string, let parsed = JSONValue.parse(out) { return parsed }
        return .object([
            "push_topic": value.first("push_topic", "pushTopic"),
            "scep_url": value.first("scep_url", "scepUrl"),
            "certificate_name": value.first("certificate_name", "certificateName"),
            "certificate_subject": value.first("certificate_subject", "certificateSubject"),
            "certificate_issuer": value.first("certificate_issuer", "certificateIssuer"),
            "certificate_expires": value.first("certificate_expires", "certificateExpires"),
            "mdm_provider": value.first("mdm_provider", "mdmProvider"),
        ])
    }

    /// `detectMdmProvider`: certificate first, then the server URL.
    public static func detectProvider(serverURL: String?, certificate: JSONValue = .null) -> String? {
        if let p = certificate["mdm_provider"].nonEmptyString { return p }
        if let issuer = certificate["certificate_issuer"].nonEmptyString?.lowercased() {
            if issuer.contains("micromdm") { return "MicroMDM" }
            if issuer.contains("nanomdm") { return "NanoMDM" }
            if issuer.contains("jamf") { return "Jamf Pro" }
            if issuer.contains("mosyle") { return "Mosyle" }
            if issuer.contains("kandji") { return "Kandji" }
            if issuer.contains("microsoft") { return "Microsoft Intune" }
        }
        guard let url = serverURL?.lowercased() else { return nil }
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
        if url.contains("hexnode") { return "Hexnode" }
        if url.contains("filewave") { return "FileWave" }
        return nil
    }
}

/// Security posture for the Info widget. Port of `Security.tsx` (widget).
public struct SecurityOverview: Sendable, Hashable {
    public enum Tone: Sendable, Hashable { case success, warning, error, info }

    public struct Row: Sendable, Hashable, Identifiable {
        public var id: String { label }
        public var label: String
        public var value: String
        public var tone: Tone
        public var indented: Bool = false
    }

    public var rows: [Row]
    public var platformLabel: String
    public var hasData: Bool

    public init(device: DeviceDetail, settings: SettingsDocument = .defaults) {
        let modules = device.asJSON["modules"]
        let security = modules["security"].unwrappingSingleton().normalizedKeys()
        let identity = modules["identity"].unwrappingSingleton().normalizedKeys()
        let management = modules["management"].unwrappingSingleton().normalizedKeys()
        hasData = !security.isNull && !security.isEmptyContainer

        let os = modules["system"].first("operatingSystem", "operating_system")
        let platformText = (device.rawPlatform ?? os["platform"].string ?? os["name"].string ?? device.platform.rawValue).lowercased()
        let isWindows = platformText.contains("windows")
        let isMac = platformText.contains("mac") || platformText.contains("darwin") || device.platform == .macOS
        let isLinux = platformText.contains("linux")
        platformLabel = isWindows ? "Windows" : isMac ? "macOS" : isLinux ? "Linux" : "Device"

        let ctx = InventoryMapping.context(inventory: modules["inventory"], fields: settings.inventory.fields)
        func encryptionTone(_ enabled: Bool?) -> Tone {
            switch SecurityEvaluator.evaluate(check: "encryption", enabled: enabled, context: ctx, config: settings.security) {
            case .ok: return .success
            case .danger: return .error
            case .warning: return .warning
            case .neutral: return .info
            case .unknown: return .warning
            }
        }
        func statusTone(_ enabled: Bool?) -> Tone {
            guard let enabled else { return .warning }
            return enabled ? .success : .error
        }

        var out: [Row] = []
        let firewall = security["firewall"]
        let firewallStatus = firewall["statusDisplay"].nonEmptyString ?? (firewall.isNull ? "Unknown" : (firewall["isEnabled"].boolish || firewall["enabled"].boolish ? "Enabled" : "Disabled"))

        if isMac {
            let fv = security["fileVault"]
            let fvEnabled: Bool? = fv.isNull ? nil : (fv["enabled"].boolish || (fv["status"].string ?? "").lowercased() == "on")
            let fvStatus = fv["status"].nonEmptyString ?? (fvEnabled == true ? "Enabled" : "Disabled")
            out.append(Row(label: "FileVault", value: fv.isNull ? "Unknown" : fvStatus, tone: encryptionTone(fvEnabled)))
            if let bt = security["bootstrapToken"]["escrowed"].boolishIfPresent {
                out.append(Row(label: "Bootstrap Token", value: bt ? "Escrowed" : "Not Escrowed", tone: bt ? .success : .error, indented: true))
            }
            if let prk = fv["recoveryKeyEscrowed"].boolishIfPresent {
                out.append(Row(label: "Personal Recovery Key", value: prk ? "Escrowed" : "Not Escrowed", tone: prk ? .success : .error, indented: true))
            }
            let psso = identity["platformSSOUsers"]
            if !psso.isNull {
                let registered = psso["deviceRegistered"].boolish
                out.append(Row(label: "Platform SSO", value: registered ? "Registered" : "Not Registered", tone: statusTone(registered)))
                let user = psso["users"].elements.first { $0["tokensPresent"].boolish } ?? psso["users"].elements.first { $0["registered"].boolish }
                let tokens = user?["tokensPresent"].boolish ?? false
                out.append(Row(label: "Token", value: tokens ? "Present" : "Missing", tone: statusTone(tokens), indented: true))
                out.append(Row(label: "Method", value: psso["method"].nonEmptyString ?? "Unknown", tone: .info, indented: true))
            }
            if !security["gatekeeper"].isNull {
                let on = security["gatekeeper"]["enabled"].boolish
                out.append(Row(label: "Gatekeeper", value: on ? "Enabled" : "Disabled", tone: on ? .success : .error))
            }
            if !security["systemIntegrityProtection"].isNull {
                let on = security["systemIntegrityProtection"]["enabled"].boolish
                out.append(Row(label: "System Integrity Protection", value: on ? "Enabled" : "Disabled", tone: on ? .success : .error))
            }
            if !security["activationLock"].isNull {
                let on = security["activationLock"]["enabled"].boolish
                out.append(Row(label: "Activation Lock", value: on ? "Enabled" : "Disabled", tone: on ? .error : .success))
            }
            out.append(Row(label: "Firewall", value: firewallStatus, tone: .info))
            let remote = management.first("remoteManagement", "remote_management").isNull ? security["remoteManagement"] : management.first("remoteManagement", "remote_management")
            if let ss = remote["screenSharing"].boolishIfPresent ?? remote["screenSharingEnabled"].boolishIfPresent {
                out.append(Row(label: "Screen Sharing", value: ss ? "Enabled" : "Disabled", tone: ss ? .warning : .success))
            }
        } else {
            let av = security["antivirus"]
            let avEnabled = av["isEnabled"].boolishIfPresent
            let avStatus: String
            if av.isNull { avStatus = "Unknown" } else if avEnabled == true, av["isUpToDate"].boolish { avStatus = "Current" } else if avEnabled == true { avStatus = "Enabled" } else { avStatus = "Disabled" }
            let avTone: Tone = avEnabled == true ? .success : avEnabled == false ? .error : .warning
            out.append(Row(label: "Antivirus", value: av["statusDisplay"].nonEmptyString ?? avStatus, tone: avTone))
            if let name = av["name"].nonEmptyString { out.append(Row(label: "Product", value: name, tone: .info, indented: true)) }
            if let v = av["version"].nonEmptyString { out.append(Row(label: "Version", value: v, tone: .info, indented: true)) }
            if let u = av["lastUpdate"].nonEmptyString { out.append(Row(label: "Updated", value: TimeFormatting.medium(u), tone: .info, indented: true)) }
            if let s = av["lastScan"].nonEmptyString {
                let scanType = av["scanType"].nonEmptyString.map { " (\($0))" } ?? ""
                out.append(Row(label: "Last Scan", value: TimeFormatting.medium(s) + scanType, tone: .info, indented: true))
            }
            let enc = security["encryption"]
            let encEnabled: Bool? = isWindows ? enc["bitLocker"]["isEnabled"].boolishIfPresent : isLinux ? enc["luks"]["isEnabled"].boolishIfPresent : nil
            let encStatus = enc["statusDisplay"].nonEmptyString ?? enc["bitLocker"]["status"].nonEmptyString ?? (encEnabled == true ? "Enabled" : encEnabled == false ? "Disabled" : "Unknown")
            out.append(Row(label: isWindows ? "BitLocker" : "Encryption", value: encStatus, tone: encryptionTone(encEnabled)))
            let hello = security["windowsHello"]
            if isWindows, !hello.isNull {
                let providers = hello["credentialProviders"]
                let pin = providers["pinEnabled"].boolish
                let bio = providers["faceRecognitionEnabled"].boolish || providers["fingerprintEnabled"].boolish
                out.append(Row(label: "Windows Hello PIN", value: pin ? "Enabled" : "Disabled", tone: statusTone(pin), indented: true))
                out.append(Row(label: "Windows Hello Biometric", value: bio ? "Enabled" : "Disabled", tone: statusTone(bio), indented: true))
            }
            out.append(Row(label: "Firewall", value: firewall["statusDisplay"].nonEmptyString ?? firewallStatus, tone: .info))
        }
        rows = out
    }
}
