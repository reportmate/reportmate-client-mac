import Foundation

/// Security module reader for the Security tab. Port of the data logic in
/// `SecurityTab.tsx`: the platform flags the six cards read, the certificate
/// table, the CVE table (SOFA on the Mac, MSRC on Windows) and the threat
/// detections table. Card rows that read ad hoc keys go straight to `security`.
public struct SecurityInfo: Sendable, Hashable {
    /// The security module with every key camelCased.
    public var security: JSONValue
    /// Remote management lives in the management module on the Mac.
    public var remoteManagement: JSONValue
    public var isMac: Bool
    public var hasData: Bool
    public var raw: JSONValue
    var inventoryContext: [String: String]
    var config: SecurityConfig

    public init(modules: JSONValue, platform: Platform, settings: SettingsDocument = .defaults) {
        raw = modules["security"].unwrappingSingleton()
        security = raw.normalizedKeys()
        let management = modules["management"].unwrappingSingleton().normalizedKeys()
        let rm = management["remoteManagement"]
        remoteManagement = rm.isNull ? security["remoteManagement"] : rm
        hasData = !security.isNull && !security.isEmptyContainer
        let os = modules["system"].first("operatingSystem", "operating_system")
        let text = (os["platform"].string ?? os["name"].string ?? "").lowercased()
        isMac = platform == .macOS || text.contains("macos") || text.contains("mac os") || text == "darwin"
        inventoryContext = InventoryMapping.context(inventory: modules["inventory"], fields: settings.inventory.fields)
        config = settings.security
    }

    /// Settings-driven severity for a check, on top of the historical defaults.
    public func severity(_ check: String, _ enabled: Bool?) -> Severity {
        SecurityEvaluator.evaluate(check: check, enabled: enabled, context: inventoryContext, config: config)
    }

    public static func on(_ v: JSONValue) -> Bool { v.bool == true || v.int == 1 || v.string?.lowercased() == "true" }

    // MARK: Platform flags

    public var fileVaultEnabled: Bool {
        let fv = security["fileVault"]
        return SecurityInfo.on(fv["enabled"]) || (fv["status"].string ?? "").lowercased() == "on"
    }
    public var sipEnabled: Bool { SecurityInfo.on(security["systemIntegrityProtection"]["enabled"]) }
    public var gatekeeperEnabled: Bool { SecurityInfo.on(security["gatekeeper"]["enabled"]) }
    public var firewallEnabled: Bool {
        let fw = security["firewall"]
        if fw["isEnabled"].boolish || SecurityInfo.on(fw["enabled"]) { return true }
        if let s = fw["globalState"].string { return s.lowercased() == "on" }
        return fw["globalState"].int == 1
    }
    public var sshEnabled: Bool {
        security["ssh"]["enabled"].boolish || remoteManagement["remoteLoginEnabled"].boolish || remoteManagement["remote_login_enabled"].boolish
    }
    public var ardEnabled: Bool { remoteManagement["ardEnabled"].boolish || remoteManagement["ard_enabled"].boolish }
    public var screenSharingEnabled: Bool { ardEnabled || remoteManagement["screenSharingEnabled"].boolish || remoteManagement["screen_sharing_enabled"].boolish }
    public var lastScan: String? { security["antivirus"]["lastScan"].nonEmptyString ?? security["lastSecurityScan"].nonEmptyString }

    // MARK: Certificates

    public enum CertStatus: String, Sendable, Hashable { case valid = "Valid", expiringSoon = "ExpiringSoon", expired = "Expired" }

    public struct Certificate: Sendable, Hashable, Identifiable {
        public var id: String { thumbprint.isEmpty ? commonName + subject + notAfter : thumbprint }
        public var commonName: String
        public var subject: String
        public var issuer: String
        public var notBefore: String
        public var notAfter: String
        public var status: CertStatus
        public var daysUntilExpiry: Int?
        public var thumbprint: String
        public var isSelfSigned: Bool
        public var path: String
        public var store: String
        public var isOsTrustedRoot: Bool

        init(json c: JSONValue) {
            commonName = c["commonName"].string ?? ""
            subject = c["subject"].string ?? ""
            issuer = c["issuer"].string ?? ""
            notBefore = c.firstString("notBefore", "notValidBefore") ?? ""
            notAfter = c.firstString("notAfter", "notValidAfter") ?? ""
            if let s = c["status"].nonEmptyString, let st = CertStatus(rawValue: s) { status = st }
            else if c["isExpired"].boolish { status = .expired } else if c["isExpiringSoon"].boolish { status = .expiringSoon } else { status = .valid }
            daysUntilExpiry = c["daysUntilExpiry"].int
            thumbprint = c.firstString("thumbprint", "sha1") ?? ""
            isSelfSigned = c["isSelfSigned"].boolish || c["selfSigned"].boolish
            path = c["path"].string ?? ""
            let loc = c["storeLocation"].string ?? ""
            store = (loc == "LocalMachine" || loc == "System") ? "System" : "User"
            isOsTrustedRoot = c["isOsTrustedRoot"].boolish
        }

        public var displayName: String {
            if !commonName.isEmpty { return commonName }
            guard !subject.isEmpty else { return "—" }
            let first = subject.split(separator: ",").first.map(String.init) ?? subject
            return first.replacingOccurrences(of: #"^CN\s*=\s*"#, with: "", options: [.regularExpression, .caseInsensitive])
        }
        public var keychainName: String { path.isEmpty ? "—" : (path.split(separator: "/").last.map(String.init) ?? path) }
        public var displayIssuer: String { issuer.count > 50 ? String(issuer.prefix(50)) + "..." : (issuer.isEmpty ? "—" : issuer) }
        public var isExpired: Bool { status == .expired }

        public func matches(_ query: String) -> Bool {
            let q = query.lowercased()
            return commonName.lowercased().contains(q) || subject.lowercased().contains(q) || issuer.lowercased().contains(q) || thumbprint.lowercased().contains(q)
        }
    }

    public var certificates: [Certificate] { security["certificates"].elements.map(Certificate.init(json:)) }

    /// Expired OS roots the client counted, so they can be hidden without losing the number.
    public var osRootExpiredCount: Int {
        let summary = security["certificateSummary"]
        if let n = summary["osRootExpiredCount"].int { return n }
        return certificates.filter { $0.isOsTrustedRoot && $0.isExpired }.count
    }
    public var userExpiredCount: Int? { security["certificateSummary"]["userExpiredCount"].int }

    // MARK: CVEs

    public enum CVESource: String, Sendable, Hashable { case sofa, windows
        public var label: String { self == .sofa ? "SOFA" : "MSRC" }
    }

    public struct CVE: Sendable, Hashable, Identifiable {
        public var id: String { cve + status + (kbArticle ?? "") }
        public var cve: String
        public var osVersion: String
        public var patchedVersion: String
        public var activelyExploited: Bool
        public var severity: String?
        public var url: String?
        public var source: CVESource
        public var status: String
        public var installedDate: String?
        public var kbArticle: String?
    }

    public struct SofaRelease: Sendable, Hashable {
        public var updateName: String?
        public var releaseDate: String?
        public var daysSincePreviousRelease: Int?
        public var securityInfo: String?
        public var osVersion: String?
        public var uniqueCvesCount: Int?
    }

    public var sofaRelease: SofaRelease? {
        let r = security.first("sofaSecurityReleaseInfo", "sofa_security_release_info")
        guard !r.isNull else { return nil }
        return SofaRelease(updateName: r.firstString("updateName", "update_name"), releaseDate: r.firstString("releaseDate", "release_date"),
                           daysSincePreviousRelease: r.first("daysSincePreviousRelease", "days_since_previous_release").int,
                           securityInfo: r.firstString("securityInfo", "security_info"), osVersion: r.firstString("osVersion", "os_version"),
                           uniqueCvesCount: r.first("uniqueCvesCount", "unique_cves_count").int)
    }

    public var cves: [CVE] {
        var out: [CVE] = []
        let sofa = security.first("sofaUnpatchedCves", "sofa_unpatched_cves").elements
        let release = sofaRelease
        for c in sofa {
            let exploited = c.first("activelyExploited", "actively_exploited")
            out.append(CVE(cve: c.firstString("cve", "cveId", "cve_id") ?? "Unknown",
                           osVersion: c.firstString("osVersion", "os_version") ?? release?.osVersion ?? "",
                           patchedVersion: c.firstString("patchedVersion", "patched_version") ?? "",
                           activelyExploited: exploited.boolish, severity: nil, url: c["url"].nonEmptyString,
                           source: .sofa, status: "Unpatched", installedDate: nil, kbArticle: nil))
        }
        let win = security.first("securityCves", "security_cves").elements
        if !win.isEmpty {
            for c in win {
                guard let cveId = c.firstString("cveId", "cve_id", "cve") else { continue }
                let kb = c.firstString("kbArticle", "kb_article")
                out.append(CVE(cve: cveId, osVersion: c.firstString("osVersion", "os_version") ?? "",
                               patchedVersion: kb ?? c["patchedVersion"].string ?? "",
                               activelyExploited: c.first("activelyExploited", "actively_exploited").boolish,
                               severity: c["severity"].nonEmptyString,
                               url: cveId.hasPrefix("CVE-") ? "https://msrc.microsoft.com/update-guide/vulnerability/\(cveId)" : nil,
                               source: .windows, status: c["status"].nonEmptyString ?? "Unpatched",
                               installedDate: c.firstString("installedDate", "installed_date"), kbArticle: kb))
            }
        } else {
            for u in security.first("securityUpdates", "security_updates").elements {
                var ids = u.first("cves", "cve_ids").elements.compactMap(\.string)
                if ids.isEmpty, let one = u["cve"].nonEmptyString { ids = [one] }
                for cveId in ids {
                    out.append(CVE(cve: cveId, osVersion: u.firstString("osVersion", "os_version") ?? "",
                                   patchedVersion: u.firstString("kbArticle", "kb_article", "updateId", "update_id") ?? "",
                                   activelyExploited: u.first("activelyExploited", "actively_exploited").boolish || u["exploited"].boolish,
                                   severity: u.firstString("severity", "msrcSeverity", "msrc_severity"),
                                   url: "https://msrc.microsoft.com/update-guide/vulnerability/\(cveId)",
                                   source: .windows, status: "Unpatched", installedDate: nil, kbArticle: nil))
                }
            }
        }
        return out
    }

    /// Unpatched first, exploited first within, then by id.
    public static func sortCVEs(_ list: [CVE]) -> [CVE] {
        list.sorted { a, b in
            if a.status != b.status { return a.status == "Unpatched" }
            if a.activelyExploited != b.activelyExploited { return a.activelyExploited }
            return a.cve < b.cve
        }
    }

    public var pendingRebootRequired: Bool { security["pendingReboot"]["required"].boolish }

    // MARK: Detections

    public struct Detection: Sendable, Hashable, Identifiable {
        public var id: String { (threatId ?? threatName) + (detectedAt ?? "") + String(index) }
        public var index: Int
        public var threatName: String
        public var severity: String?
        public var category: String?
        public var status: String?
        public var source: String?
        public var detectedAt: String?
        public var threatId: String?
        public var filePath: String?
        public var processName: String?
        public var user: String?
        public var actionTaken: String?
        public var description: String?
        public var eventId: String?

        init(index: Int, json d: JSONValue) {
            self.index = index
            threatName = d["threatName"].nonEmptyString ?? "Unknown Threat"
            severity = d["severity"].nonEmptyString
            category = d["category"].nonEmptyString
            status = d["status"].nonEmptyString
            source = d["source"].nonEmptyString
            detectedAt = d["detectedAt"].nonEmptyString
            threatId = d["threatId"].nonEmptyString
            filePath = d["filePath"].nonEmptyString
            processName = d["processName"].nonEmptyString
            user = d["user"].nonEmptyString
            actionTaken = d["actionTaken"].nonEmptyString
            description = d["description"].nonEmptyString
            eventId = d["eventId"].string
        }
        public var hasDetails: Bool { filePath != nil || processName != nil || user != nil || description != nil || threatId != nil }

        public enum StatusMark: Sendable { case good, attention, bad, unknown }
        public var statusMark: StatusMark {
            switch (status ?? "").lowercased() {
            case "cleaned", "removed", "quarantined", "blocked", "remediated": return .good
            case "detected", "actiontaken": return .attention
            case "allowed", "missed", "remediationfailed": return .bad
            default: return .unknown
            }
        }
    }

    public var detections: [Detection] { security["detections"].elements.enumerated().map { Detection(index: $0.offset, json: $0.element) } }

    public struct DetectionSummary: Sendable, Hashable {
        public var total30d: Int
        public var blocked30d: Int
        public var cleaned30d: Int
        public var allowed30d: Int
        public var hasActiveThreats: Bool
    }
    public var detectionSummary: DetectionSummary {
        let s = security["detectionSummary"]
        return DetectionSummary(total30d: s["totalDetections30d"].int ?? detections.count, blocked30d: s["totalBlocked30d"].int ?? 0,
                                cleaned30d: s["totalCleaned30d"].int ?? 0, allowed30d: s["totalAllowed30d"].int ?? 0,
                                hasActiveThreats: s["hasActiveThreats"].boolish)
    }

    // MARK: EDR (Mac)

    public struct EDRProduct: Sendable, Hashable, Identifiable {
        public var id: String { identifier ?? name }
        public var name: String
        public var identifier: String?
        public var healthy: Bool?
        public var running: Bool?
        public var version: String?
        public var json: JSONValue
        init(json p: JSONValue) {
            self.json = p
            name = p.firstString("name", "vendor") ?? "Unknown EDR"
            identifier = p["identifier"].nonEmptyString
            healthy = p["healthy"].boolishIfPresent
            running = p["running"].boolishIfPresent
            version = p["version"].nonEmptyString
        }
        public var healthLabel: String { healthy == true || running == true ? "Healthy" : healthy == false ? "Issues" : "Unknown" }
    }
    public var edrProducts: [EDRProduct] { security["edrProducts"]["products"].elements.map(EDRProduct.init(json:)) }
    /// Windows: EDR products as a flat list.
    public var windowsEdrProducts: [JSONValue] { security["edrProducts"].elements }

    public var defenderExclusions: [String] {
        let ex = security["defenderExclusions"]
        return ["paths", "processes", "extensions", "ipAddresses"].flatMap { ex[$0].elements.compactMap(\.string) }
    }
    public var defenderExclusionCount: Int { security["defenderExclusions"]["totalCount"].int ?? defenderExclusions.count }
}
