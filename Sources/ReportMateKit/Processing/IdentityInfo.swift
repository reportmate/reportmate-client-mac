import Foundation

/// Identity module reader. Port of `modules/identity.ts` plus the derived
/// facts `IdentityTab.tsx` computes before rendering (Windows admin and
/// group enrichment, the enrollment summary, hidden service accounts).
public struct IdentityInfo: Sendable, Hashable {
    public struct UserAccount: Sendable, Hashable, Identifiable {
        public var id: String { username + String(uid) }
        public var username: String
        public var realName: String?
        public var uid: Int
        public var gid: Int
        public var homeDirectory: String?
        public var shell: String?
        public var uuid: String?
        public var sid: String?
        public var accountType: String?
        public var isAdmin: Bool
        public var isEnabled: Bool
        public var isLocalAccount: Bool?
        public var sshAccess: Bool?
        public var screenSharingAccess: Bool?
        public var autoLoginEnabled: Bool?
        public var passwordHint: String?
        public var creationTime: String?
        public var passwordLastSet: String?
        public var lastLogon: String?
        public var failedLoginCount: Int
        public var lastFailedLogin: String?
        public var linkedAppleId: String?
        public var linkedDate: String?
        public var groupMembership: String?
        public var isDisabled: Bool
        public var isLockout: Bool?

        init(json u: JSONValue) {
            username = u.firstString("username", "user") ?? ""
            realName = u.firstString("realName", "fullName", "description")
            uid = u["uid"].int ?? 0
            gid = u["gid"].int ?? 0
            homeDirectory = u.firstString("homeDirectory", "directory")
            shell = u["shell"].nonEmptyString
            uuid = u["uuid"].nonEmptyString
            sid = u.firstString("sid", "userSid")
            let isLocal = u["isLocal"].boolish
            accountType = u["accountType"].nonEmptyString ?? (isLocal ? "Local" : "Domain")
            isAdmin = u["isAdmin"].boolish
            if let e = u["isEnabled"].boolishIfPresent { isEnabled = e } else if let d = u["isDisabled"].boolishIfPresent { isEnabled = !d } else { isEnabled = true }
            isLocalAccount = u["isLocalAccount"].boolishIfPresent ?? u["isLocal"].boolishIfPresent
            sshAccess = u["sshAccess"].boolishIfPresent
            screenSharingAccess = u["screenSharingAccess"].boolishIfPresent
            autoLoginEnabled = u["autoLoginEnabled"].boolishIfPresent
            passwordHint = u["passwordHint"].nonEmptyString
            creationTime = u.firstString("creationTime", "accountCreated", "createdAt")
            passwordLastSet = u["passwordLastSet"].nonEmptyString
            lastLogon = u.firstString("lastLogon", "time")
            failedLoginCount = u["failedLoginCount"].int ?? 0
            lastFailedLogin = u["lastFailedLogin"].nonEmptyString
            linkedAppleId = u["linkedAppleId"].nonEmptyString
            linkedDate = u["linkedDate"].nonEmptyString
            if let arr = u["groupMemberships"].array {
                groupMembership = arr.compactMap(\.string).joined(separator: ", ")
            } else {
                groupMembership = u["groupMembership"].nonEmptyString
            }
            isDisabled = u["isDisabled"].boolish
            isLockout = u["isLockout"].boolishIfPresent
        }

        public var groups: [String] { (groupMembership ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty } }
    }

    public struct UserGroup: Sendable, Hashable {
        public var groupname: String
        public var gid: Int
        public var sid: String?
        public var members: String?
        public var comment: String?
        public var groupType: String?
        init(json g: JSONValue) {
            groupname = g.firstString("groupname", "groupName", "name") ?? ""
            gid = g["gid"].int ?? 0
            sid = g.firstString("sid", "groupSid")
            if let arr = g["members"].array { members = arr.compactMap(\.string).joined(separator: ", ") } else { members = g["members"].nonEmptyString }
            comment = g.firstString("comment", "description")
            groupType = g["groupType"].nonEmptyString ?? (g["isBuiltIn"].boolish ? "BuiltIn" : "Local")
        }
        public var memberList: [String] { (members ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty } }
    }

    public struct LoggedInUser: Sendable, Hashable, Identifiable {
        public var id: String { user + (tty ?? "") + String(pid ?? 0) }
        public var user: String
        public var tty: String?
        public var host: String?
        public var time: String?
        public var pid: Int?
        public var loginTime: String?
        public var logonType: String?
        public var sessionState: String?
        init(json s: JSONValue) {
            user = s.firstString("user", "username") ?? ""
            tty = s["tty"].nonEmptyString
            host = s.firstString("host", "domain")
            time = s.firstString("time", "loginTime")
            pid = s.first("pid", "sessionId").int
            loginTime = s.firstString("loginTime", "time")
            logonType = s.firstString("logonType", "sessionType", "type")
            sessionState = s["sessionState"].nonEmptyString ?? (s["isActive"].boolish ? "Active" : "Disconnected")
        }
    }

    public struct LoginHistoryEntry: Sendable, Hashable, Identifiable {
        public var id: String { username + (loginTime ?? "") + (eventType ?? "") + (tty ?? "") }
        public var username: String
        public var tty: String?
        public var loginTime: String?
        public var logoutTime: String?
        public var duration: String?
        public var eventType: String?
        public var logonType: String?
        public var sourceIp: String?
        public var eventId: Int?
        init(json e: JSONValue) {
            username = e.firstString("username", "user") ?? ""
            tty = e["tty"].nonEmptyString
            loginTime = e.firstString("loginTime", "time")
            logoutTime = e["logoutTime"].nonEmptyString
            duration = e["duration"].nonEmptyString
            eventType = e.firstString("eventType", "type")
            logonType = e["logonType"].nonEmptyString
            sourceIp = e.firstString("sourceIp", "host")
            eventId = e["eventId"].int
        }
    }

    public struct BTMDBHealth: Sendable, Hashable {
        public var exists: Bool
        public var path: String
        public var sizeBytes: Double
        public var sizeMB: Double
        public var status: String
        public var statusMessage: String
        public var jetsamKillsLast7Days: Int
        public var lastJetsamEvent: String?
        public var registeredItemCount: Int
        public var localUserCount: Int
        init(json b: JSONValue) {
            exists = b["exists"].boolish
            path = b["path"].nonEmptyString ?? "/private/var/db/com.apple.backgroundtaskmanagement"
            sizeBytes = b["sizeBytes"].double ?? 0
            sizeMB = b["sizeMB"].double ?? b["sizeMb"].double ?? 0
            status = b["status"].nonEmptyString ?? "unknown"
            statusMessage = b["statusMessage"].string ?? ""
            jetsamKillsLast7Days = b["jetsamKillsLast7Days"].int ?? 0
            lastJetsamEvent = b["lastJetsamEvent"].nonEmptyString
            registeredItemCount = b["registeredItemCount"].int ?? 0
            localUserCount = b["localUserCount"].int ?? 0
        }
    }

    public struct AzureAD: Sendable, Hashable {
        public var joined: Bool
        public var registered: Bool
        public var tenantId: String?
        public var tenantName: String?
        public var deviceId: String?
        public var thumbprint: String?
        public var deviceCertificateValidity: String?
        public var deviceAuthStatus: String?
    }

    public struct DirectoryServices: Sendable, Hashable {
        public var adBound: Bool
        public var adDomain: String?
        public var ldapBound: Bool
        public var ldapServer: String?
        public var directoryNodes: String?
        public var azureAD: AzureAD?
        public var workgroup: String?

        init(json ds: JSONValue) {
            let ad = ds.first("activeDirectory", "active_directory")
            adBound = ad["bound"].boolish || ad["isDomainJoined"].boolish
            adDomain = ad.firstString("domain", "domainName")
            ldapBound = ds["ldap"]["bound"].boolish
            ldapServer = ds["ldap"]["server"].nonEmptyString
            directoryNodes = ds["directoryNodes"].nonEmptyString
            let entra = ds.first("azureAd", "azureAD", "entraId")
            if !entra.isNull {
                azureAD = AzureAD(
                    joined: entra["joined"].boolish || entra["isAadJoined"].boolish || entra["isEntraJoined"].boolish,
                    registered: entra["registered"].boolish || entra["isAadRegistered"].boolish || entra["isEntraRegistered"].boolish,
                    tenantId: entra["tenantId"].nonEmptyString, tenantName: entra["tenantName"].nonEmptyString,
                    deviceId: entra["deviceId"].nonEmptyString, thumbprint: entra["thumbprint"].nonEmptyString,
                    deviceCertificateValidity: entra["deviceCertificateValidity"].nonEmptyString,
                    deviceAuthStatus: entra["deviceAuthStatus"].nonEmptyString)
            }
            workgroup = ds["workgroup"].nonEmptyString
        }

        /// Anything worth a Directory Services card on the Mac.
        public var hasMacBinding: Bool { adBound || ldapBound || adDomain != nil || ldapServer != nil }
    }

    public struct SsoState: Sendable, Hashable {
        public var entraPrt: Bool
        public var entraPrtUpdateTime: String?
        public var entraPrtExpiryTime: String?
        public var entraPrtAuthority: String?
        public var enterprisePrt: Bool
        public var enterprisePrtAuthority: String?
        public var onPremTgt: Bool
        public var cloudTgt: Bool
        public var kerbTopLevelNames: String?
        init(json s: JSONValue) {
            entraPrt = s["entraPrt"].boolish
            entraPrtUpdateTime = s["entraPrtUpdateTime"].nonEmptyString
            entraPrtExpiryTime = s["entraPrtExpiryTime"].nonEmptyString
            entraPrtAuthority = s["entraPrtAuthority"].nonEmptyString
            enterprisePrt = s["enterprisePrt"].boolish
            enterprisePrtAuthority = s["enterprisePrtAuthority"].nonEmptyString
            onPremTgt = s["onPremTgt"].boolish
            cloudTgt = s["cloudTgt"].boolish
            kerbTopLevelNames = s["kerbTopLevelNames"].nonEmptyString
        }
    }

    public struct DomainTrust: Sendable, Hashable {
        public var secureChannelValid: Bool
        public var domainName: String?
        public var domainController: String?
        public var trustStatus: String
        public var lastChecked: String?
        public var errorMessage: String?
        public var computerAccountExists: Bool
        public var machinePasswordAgeDays: Int?
        init(json t: JSONValue) {
            secureChannelValid = t["secureChannelValid"].boolish
            domainName = t["domainName"].nonEmptyString
            domainController = t["domainController"].nonEmptyString
            trustStatus = t["trustStatus"].nonEmptyString ?? "Unknown"
            lastChecked = t["lastChecked"].nonEmptyString
            errorMessage = t["errorMessage"].nonEmptyString
            computerAccountExists = t["computerAccountExists"].boolish
            machinePasswordAgeDays = t["machinePasswordAgeDays"].int
        }
    }

    public struct SecureToken: Sendable, Hashable {
        public var usersWithToken: [String]
        public var usersWithoutToken: [String]
        public var totalUsersChecked: Int
        public var tokenGrantedCount: Int
        public var tokenMissingCount: Int
        init(json s: JSONValue) {
            usersWithToken = s["usersWithToken"].elements.compactMap(\.string)
            usersWithoutToken = s["usersWithoutToken"].elements.compactMap(\.string)
            totalUsersChecked = s["totalUsersChecked"].int ?? 0
            tokenGrantedCount = s["tokenGrantedCount"].int ?? 0
            tokenMissingCount = s["tokenMissingCount"].int ?? 0
        }
    }

    public struct PlatformSSOUser: Sendable, Hashable {
        public var username: String
        public var uid: Int?
        public var registered: Bool
        public var userPrincipalName: String?
        public var loginUserName: String?
        public var state: String?
        public var lastLoginDate: String?
        public var tokensPresent: Bool
        public var tokenReceived: String?
        public var tokenExpiration: String?
        public var tokenExpired: Bool?
        public var probeStatus: String?
        init(json u: JSONValue) {
            username = u["username"].string ?? ""
            uid = u["uid"].int
            registered = u["registered"].boolish
            userPrincipalName = u["userPrincipalName"].nonEmptyString
            loginUserName = u["loginUserName"].nonEmptyString
            state = u["state"].nonEmptyString
            lastLoginDate = u["lastLoginDate"].nonEmptyString
            tokensPresent = u["tokensPresent"].boolish
            tokenReceived = u["tokenReceived"].nonEmptyString
            tokenExpiration = u["tokenExpiration"].nonEmptyString
            tokenExpired = u["tokenExpired"].boolishIfPresent
            probeStatus = u["probeStatus"].nonEmptyString
        }
        public var displayName: String? { userPrincipalName ?? loginUserName ?? (username.isEmpty ? nil : username) }
    }

    public struct PlatformSSO: Sendable, Hashable {
        public var supported: Bool
        public var deviceRegistered: Bool
        public var provider: String?
        public var method: String?
        public var extensionIdentifier: String?
        public var organizationName: String?
        public var loginFrequency: Int
        public var offlineGracePeriod: String?
        public var registeredUserCount: Int
        public var unregisteredUserCount: Int
        public var tokenPresentCount: Int
        public var nonPlatformSSOAccounts: [String]
        public var users: [PlatformSSOUser]
        init(json p: JSONValue) {
            supported = p["supported"].boolish
            deviceRegistered = p["deviceRegistered"].boolish
            provider = p["provider"].nonEmptyString
            method = p["method"].nonEmptyString
            extensionIdentifier = p["extensionIdentifier"].nonEmptyString
            organizationName = p["organizationName"].nonEmptyString
            loginFrequency = p["loginFrequency"].int ?? 0
            offlineGracePeriod = p["offlineGracePeriod"].nonEmptyString
            registeredUserCount = p["registeredUserCount"].int ?? 0
            unregisteredUserCount = p["unregisteredUserCount"].int ?? 0
            tokenPresentCount = p["tokenPresentCount"].int ?? 0
            nonPlatformSSOAccounts = p["nonPlatformSSOAccounts"].elements.compactMap(\.string)
            users = p["users"].elements.map(PlatformSSOUser.init(json:))
        }
        /// The account holding the registration: tokens first, then registered. Never `users[0]`.
        public var primaryUser: PlatformSSOUser? { users.first { $0.tokensPresent } ?? users.first { $0.registered } }
    }

    public struct EnrollmentInfo: Sendable, Hashable {
        public var enrollmentType: String
        public var entraJoined: Bool
        public var domainJoined: Bool
        public var enterpriseJoined: Bool
        public var tenantId: String?
        public var tenantName: String?
        public var domainName: String?
        public var workgroup: String?
    }

    public struct SessionHistoryEntry: Sendable, Hashable, Identifiable {
        public var id: String { username + timestamp + String(eventId) + String(sessionId ?? 0) }
        public var username: String
        public var timestamp: String
        public var endTime: String?
        public var duration: String?
        public var durationMinutes: Double?
        public var eventId: Int
        public var eventType: String
        public var sessionId: Int?
        public var sourceAddress: String?
        init(json e: JSONValue) {
            username = e.firstString("username", "user") ?? ""
            timestamp = e.firstString("timestamp", "time") ?? ""
            endTime = e["endTime"].nonEmptyString
            duration = e["duration"].nonEmptyString
            durationMinutes = e["durationMinutes"].double
            eventId = e["eventId"].int ?? 0
            eventType = e["eventType"].nonEmptyString ?? "Unknown"
            sessionId = e["sessionId"].int
            sourceAddress = e["sourceAddress"].nonEmptyString
        }
        public var durationText: String {
            if let duration { return duration }
            guard let m = durationMinutes else { return "—" }
            return IdentityInfo.minutes(m)
        }
    }

    public struct SessionSummary: Sendable, Hashable {
        public var totalSessions: Int
        public var uniqueUsers: Int
        public var avgSessionMinutes: Double
        public var medianSessionMinutes: Double
        public var oldestSession: String?
        public var newestSession: String?
        public var sessionsByHour: [String: Int]
        public var sessionsByDayOfWeek: [String: Int]
        init(json s: JSONValue) {
            totalSessions = s["totalSessions"].int ?? 0
            uniqueUsers = s["uniqueUsers"].int ?? 0
            avgSessionMinutes = s["avgSessionMinutes"].double ?? 0
            medianSessionMinutes = s["medianSessionMinutes"].double ?? 0
            oldestSession = s["oldestSession"].nonEmptyString
            newestSession = s["newestSession"].nonEmptyString
            sessionsByHour = (s["sessionsByHour"].object ?? [:]).compactMapValues(\.int)
            sessionsByDayOfWeek = (s["sessionsByDayOfWeek"].object ?? [:]).compactMapValues(\.int)
        }
        /// Top five hours by session count.
        public var peakHours: [(hour: String, count: Int)] {
            sessionsByHour.sorted { $0.value != $1.value ? $0.value > $1.value : $0.key < $1.key }.prefix(5).map { ($0.key, $0.value) }
        }
    }

    public struct Summary: Sendable, Hashable {
        public var totalUsers: Int
        public var adminUsers: Int
        public var disabledUsers: Int
        public var localUsers: Int?
        public var domainUsers: Int?
        public var currentlyLoggedIn: Int
        public var failedLoginsLast7Days: Int?
        public var btmdbStatus: String?
        init(json s: JSONValue) {
            totalUsers = s["totalUsers"].int ?? 0
            adminUsers = s["adminUsers"].int ?? 0
            disabledUsers = s["disabledUsers"].int ?? 0
            localUsers = s["localUsers"].int
            domainUsers = s["domainUsers"].int
            currentlyLoggedIn = s["currentlyLoggedIn"].int ?? 0
            failedLoginsLast7Days = s["failedLoginsLast7Days"].int
            btmdbStatus = s["btmdbStatus"].nonEmptyString
        }
    }

    /// The Windows enrollment summary for the Domains & Tokens card.
    public struct WindowsEnrollment: Sendable, Hashable {
        public var entraJoined: Bool
        public var entraRegistered: Bool
        public var domainJoined: Bool
        public var domainName: String
        public var workgroup: String
        public var enrollmentType: String
        public var tenantName: String
        public var entraDeviceId: String
        public var mdmProvider: String?
        public var mdmEnrolled: Bool
    }

    public var users: [UserAccount]
    public var groups: [UserGroup]
    public var loggedInUsers: [LoggedInUser]
    public var loginHistory: [LoginHistoryEntry]
    public var btmdbHealth: BTMDBHealth?
    public var directoryServices: DirectoryServices?
    public var ssoState: SsoState?
    public var domainTrust: DomainTrust?
    public var secureTokenUsers: SecureToken?
    public var platformSSO: PlatformSSO?
    public var enrollmentInfo: EnrollmentInfo?
    public var sessionHistory: [SessionHistoryEntry]
    public var sessionSummary: SessionSummary?
    public var uac: JSONValue
    public var laps: JSONValue
    public var passwordPolicy: JSONValue
    public var tpmOwnership: JSONValue
    public var autoLogin: JSONValue
    public var windowsHello: JSONValue
    public var summary: Summary
    public var isMac: Bool
    public var hasData: Bool
    /// Cross-module facts the Identity tab shows alongside accounts.
    public var bootstrapToken: JSONValue
    public var activationLock: JSONValue
    public var fileVault: JSONValue
    public var windowsEnrollment: WindowsEnrollment?
    public var raw: JSONValue

    public static let hiddenWindowsAccounts: Set<String> = ["wdagutilityaccount", "administrator", "defaultaccount", "guest"]

    public init(modules: JSONValue, platform: Platform) {
        let rawIdentity = modules["identity"].unwrappingSingleton()
        raw = rawIdentity
        let identity = rawIdentity.normalizedKeys()
        let security = modules["security"].unwrappingSingleton().normalizedKeys()
        let management = modules["management"].unwrappingSingleton().normalizedKeys()
        hasData = !identity.isNull && !identity.isEmptyContainer

        users = identity["users"].elements.map(UserAccount.init(json:))
        groups = identity["groups"].elements.map(UserGroup.init(json:))
        loggedInUsers = identity["loggedInUsers"].elements.map(LoggedInUser.init(json:))
        loginHistory = identity["loginHistory"].elements.map(LoginHistoryEntry.init(json:))
        btmdbHealth = identity["btmdbHealth"].isNull ? nil : BTMDBHealth(json: identity["btmdbHealth"])
        directoryServices = identity["directoryServices"].isNull ? nil : DirectoryServices(json: identity["directoryServices"])
        ssoState = identity["ssoState"].isNull ? nil : SsoState(json: identity["ssoState"])
        domainTrust = identity["domainTrust"].isNull ? nil : DomainTrust(json: identity["domainTrust"])
        secureTokenUsers = identity["secureTokenUsers"].isNull ? nil : SecureToken(json: identity["secureTokenUsers"])
        platformSSO = identity["platformSSOUsers"].isNull ? nil : PlatformSSO(json: identity["platformSSOUsers"])
        sessionHistory = identity["sessionHistory"].elements.map(SessionHistoryEntry.init(json:))
        sessionSummary = identity["sessionSummary"].isNull ? nil : SessionSummary(json: identity["sessionSummary"])
        uac = identity["uac"]
        laps = identity["laps"]
        passwordPolicy = identity["passwordPolicy"]
        tpmOwnership = identity["tpmOwnership"]
        autoLogin = identity["autoLogin"]
        windowsHello = identity["windowsHello"]
        summary = Summary(json: identity["summary"])
        bootstrapToken = security["bootstrapToken"]
        activationLock = security["activationLock"]
        fileVault = security["fileVault"]

        let looksMac = !identity["btmdbHealth"].isNull || !identity["secureTokenUsers"].isNull || !identity["platformSSOUsers"].isNull
        isMac = platform == .macOS || looksMac

        enrollmentInfo = IdentityInfo.enrollment(from: identity["directoryServices"])

        if isMac {
            windowsEnrollment = nil
        } else if let ds = directoryServices, ds.azureAD != nil || ds.adBound || ds.workgroup != nil {
            windowsEnrollment = WindowsEnrollment(
                entraJoined: ds.azureAD?.joined ?? false, entraRegistered: ds.azureAD?.registered ?? false,
                domainJoined: ds.adBound, domainName: ds.adDomain ?? "", workgroup: ds.workgroup ?? "",
                enrollmentType: enrollmentInfo?.enrollmentType ?? "Unknown", tenantName: ds.azureAD?.tenantName ?? "",
                entraDeviceId: ds.azureAD?.deviceId ?? "", mdmProvider: nil, mdmEnrolled: false)
        } else if !management.isNull {
            let deviceState = management["deviceState"]
            let mdm = management["mdmEnrollment"]
            let trust = management["domainTrust"]
            let entraJoined = deviceState["entraJoined"].boolish
            let domainJoined = deviceState["domainJoined"].boolish || trust["secureChannelValid"].boolish
            let type: String
            if entraJoined && domainJoined { type = "Hybrid Entra Join" } else if entraJoined { type = "Entra Joined" } else if domainJoined { type = "Domain Joined" } else { type = "Standalone" }
            windowsEnrollment = WindowsEnrollment(
                entraJoined: entraJoined, entraRegistered: deviceState["enterpriseJoined"].boolish, domainJoined: domainJoined,
                domainName: trust["domainName"].string ?? "", workgroup: "", enrollmentType: type,
                tenantName: management["tenantDetails"]["tenantName"].string ?? "", entraDeviceId: "",
                mdmProvider: mdm["provider"].nonEmptyString, mdmEnrolled: mdm["isEnrolled"].boolish)
        } else {
            windowsEnrollment = nil
        }

        if !isMac { enrichWindowsUsers() }
    }

    static func enrollment(from ds: JSONValue) -> EnrollmentInfo? {
        guard !ds.isNull else { return nil }
        let ad = ds.first("activeDirectory", "active_directory")
        let entra = ds.first("azureAd", "azureAD", "entraId")
        let domainJoined = ad["bound"].boolish || ad["isDomainJoined"].boolish
        let entraJoined = entra["joined"].boolish || entra["isAadJoined"].boolish || entra["isEntraJoined"].boolish
        let enterpriseJoined = entra["registered"].boolish || entra["isAadRegistered"].boolish
        let type: String
        if domainJoined && entraJoined { type = "Hybrid Entra Join" } else if entraJoined { type = "Entra Joined" } else if domainJoined { type = "Domain Joined" } else if ds["workgroup"].nonEmptyString != nil { type = "Workgroup" } else { type = "Standalone" }
        return EnrollmentInfo(enrollmentType: type, entraJoined: entraJoined, domainJoined: domainJoined, enterpriseJoined: enterpriseJoined,
                              tenantId: entra["tenantId"].nonEmptyString, tenantName: entra["tenantName"].nonEmptyString,
                              domainName: ad.firstString("domain", "domainName"), workgroup: ds["workgroup"].nonEmptyString)
    }

    /// Windows: admin status from the Administrators group and group
    /// membership from the groups list, for domain and Entra accounts the
    /// client left blank.
    mutating func enrichWindowsUsers() {
        let adminsGroup = groups.first { $0.groupname.lowercased() == "administrators" || $0.sid == "S-1-5-32-544" }
        let adminNames = Set((adminsGroup?.memberList ?? []).map { IdentityInfo.memberName($0) }.filter { $0.range(of: #"^s-\d+-"#, options: .regularExpression) == nil })
        for i in users.indices {
            let name = users[i].username.lowercased()
            if !users[i].isAdmin, adminNames.contains(name) { users[i].isAdmin = true }
            if (users[i].groupMembership ?? "").trimmingCharacters(in: .whitespaces).isEmpty, !groups.isEmpty {
                let memberOf = groups.filter { g in g.memberList.contains { IdentityInfo.memberName($0) == name } }.map(\.groupname)
                if !memberOf.isEmpty { users[i].groupMembership = memberOf.joined(separator: ", ") }
            }
        }
    }

    static func memberName(_ member: String) -> String {
        let parts = member.split(separator: "\\", maxSplits: 1).map(String.init)
        return (parts.count > 1 ? parts[1] : parts.first ?? "").lowercased()
    }

    /// Sessions with a real user, not orphaned TTYs.
    public var activeUserSessions: [LoggedInUser] { loggedInUsers.filter { !$0.user.trimmingCharacters(in: .whitespaces).isEmpty } }
    public var uniqueLoggedInUsers: [String] {
        var seen = Set<String>(); var out: [String] = []
        for s in activeUserSessions where !seen.contains(s.user) { seen.insert(s.user); out.append(s.user) }
        return out
    }

    /// Accounts worth listing: Windows service accounts are noise.
    public var visibleUsers: [UserAccount] {
        isMac ? users : users.filter { !IdentityInfo.hiddenWindowsAccounts.contains($0.username.lowercased()) }
    }

    public func isLoggedIn(_ user: UserAccount) -> Bool {
        if LoginTime.parse(user.lastLogon).isActive { return true }
        if !isMac { return uniqueLoggedInUsers.contains { $0.lowercased() == user.username.lowercased() } }
        return false
    }

    public func hasSecureToken(_ user: UserAccount) -> Bool { secureTokenUsers?.usersWithToken.contains(user.username) ?? false }

    public static func minutes(_ m: Double) -> String {
        m > 60 ? String(format: "%.1fh", m / 60) : "\(Int(m.rounded()))m"
    }
}

/// `formatDate` from the Identity tab: UNIX seconds or millis, ISO strings,
/// `Jan 22 09:08` without a year, and a `still` suffix marking an open session.
public enum LoginTime {
    public struct Parsed: Sendable, Hashable {
        public var text: String
        public var isActive: Bool
        public var date: Date?
    }

    public static func parse(_ value: String?, now: Date = Date()) -> Parsed {
        guard let value, !value.isEmpty else { return Parsed(text: "Unknown", isActive: false, date: nil) }
        var cleaned = value
        var active = false
        if value.lowercased().contains("still") {
            active = true
            cleaned = value.replacingOccurrences(of: #"\s*still\s*"#, with: "", options: [.regularExpression, .caseInsensitive]).trimmingCharacters(in: .whitespaces)
        }
        var date: Date?
        if cleaned.range(of: #"^\d{10,}$"#, options: .regularExpression) != nil, let n = Double(cleaned) {
            date = Date(timeIntervalSince1970: n > 9_999_999_999 ? n / 1000 : n)
        } else if cleaned.range(of: #"^[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}$"#, options: .regularExpression) != nil {
            let year = Calendar.current.component(.year, from: now)
            let f = DateFormatter(); f.locale = Locale(identifier: "en_US_POSIX"); f.dateFormat = "MMM d HH:mm yyyy"
            date = f.date(from: "\(cleaned) \(year)")
        } else {
            date = FlexibleDate.parse(cleaned)
        }
        guard let date else { return Parsed(text: value, isActive: active, date: nil) }
        return Parsed(text: TimeFormatting.exact(date), isActive: active, date: date)
    }
}
