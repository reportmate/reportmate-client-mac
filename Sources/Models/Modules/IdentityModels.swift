import Foundation

// MARK: - Identity Module Models

/// Complete identity data collection result
public struct IdentityInfo: Codable, Sendable {
    public let users: [UserAccount]
    public let groups: [UserGroup]
    public let loggedInUsers: [LoggedInUser]
    public let loginHistory: [LoginHistoryEntry]
    public let btmdbHealth: BTMDBHealth
    public let directoryServices: DirectoryServicesInfo
    public let secureTokenUsers: SecureTokenInfo
    public let platformSSOUsers: PlatformSSOUsersInfo
    public let summary: IdentitySummary
    
    public init(
        users: [UserAccount] = [],
        groups: [UserGroup] = [],
        loggedInUsers: [LoggedInUser] = [],
        loginHistory: [LoginHistoryEntry] = [],
        btmdbHealth: BTMDBHealth = BTMDBHealth(),
        directoryServices: DirectoryServicesInfo = DirectoryServicesInfo(),
        secureTokenUsers: SecureTokenInfo = SecureTokenInfo(),
        platformSSOUsers: PlatformSSOUsersInfo = PlatformSSOUsersInfo(),
        summary: IdentitySummary = IdentitySummary()
    ) {
        self.users = users
        self.groups = groups
        self.loggedInUsers = loggedInUsers
        self.loginHistory = loginHistory
        self.btmdbHealth = btmdbHealth
        self.directoryServices = directoryServices
        self.secureTokenUsers = secureTokenUsers
        self.platformSSOUsers = platformSSOUsers
        self.summary = summary
    }
}

// MARK: - User Account

/// Represents a local user account with comprehensive attributes
public struct UserAccount: Codable, Sendable, Identifiable {
    public var id: String { username }
    
    public let username: String
    public let realName: String?
    public let uid: Int
    public let gid: Int
    public let homeDirectory: String?
    public let shell: String?
    public let uuid: String?
    public let isAdmin: Bool
    public let sshAccess: Bool
    public let screenSharingAccess: Bool
    public let autoLoginEnabled: Bool
    public let passwordHint: String?
    public let creationTime: String?
    public let passwordLastSet: String?
    public let lastLogon: String?
    public let failedLoginCount: Int
    public let lastFailedLogin: String?
    public let linkedAppleId: String?
    public let linkedDate: String?
    public let groupMembership: String?
    public let isDisabled: Bool
    
    public init(
        username: String,
        realName: String? = nil,
        uid: Int = 0,
        gid: Int = 20,
        homeDirectory: String? = nil,
        shell: String? = nil,
        uuid: String? = nil,
        isAdmin: Bool = false,
        sshAccess: Bool = false,
        screenSharingAccess: Bool = false,
        autoLoginEnabled: Bool = false,
        passwordHint: String? = nil,
        creationTime: String? = nil,
        passwordLastSet: String? = nil,
        lastLogon: String? = nil,
        failedLoginCount: Int = 0,
        lastFailedLogin: String? = nil,
        linkedAppleId: String? = nil,
        linkedDate: String? = nil,
        groupMembership: String? = nil,
        isDisabled: Bool = false
    ) {
        self.username = username
        self.realName = realName
        self.uid = uid
        self.gid = gid
        self.homeDirectory = homeDirectory
        self.shell = shell
        self.uuid = uuid
        self.isAdmin = isAdmin
        self.sshAccess = sshAccess
        self.screenSharingAccess = screenSharingAccess
        self.autoLoginEnabled = autoLoginEnabled
        self.passwordHint = passwordHint
        self.creationTime = creationTime
        self.passwordLastSet = passwordLastSet
        self.lastLogon = lastLogon
        self.failedLoginCount = failedLoginCount
        self.lastFailedLogin = lastFailedLogin
        self.linkedAppleId = linkedAppleId
        self.linkedDate = linkedDate
        self.groupMembership = groupMembership
        self.isDisabled = isDisabled
    }
}

// MARK: - User Group

/// Represents a local group
public struct UserGroup: Codable, Sendable, Identifiable {
    public var id: String { groupname }
    
    public let groupname: String
    public let gid: Int
    public let members: String?
    public let comment: String?
    
    public init(
        groupname: String,
        gid: Int = 0,
        members: String? = nil,
        comment: String? = nil
    ) {
        self.groupname = groupname
        self.gid = gid
        self.members = members
        self.comment = comment
    }
}

// MARK: - Logged In User

/// Represents a currently logged-in user session
public struct LoggedInUser: Codable, Sendable, Identifiable {
    public var id: String { "\(user)-\(tty ?? "")" }
    
    public let user: String
    public let tty: String?
    public let host: String?
    public let time: String?
    public let pid: Int?
    public let loginTime: String?
    
    public init(
        user: String,
        tty: String? = nil,
        host: String? = nil,
        time: String? = nil,
        pid: Int? = nil,
        loginTime: String? = nil
    ) {
        self.user = user
        self.tty = tty
        self.host = host
        self.time = time
        self.pid = pid
        self.loginTime = loginTime
    }
}

// MARK: - Login History Entry

/// Represents a historical login event
public struct LoginHistoryEntry: Codable, Sendable, Identifiable {
    public var id: String { "\(username)-\(loginTime ?? UUID().uuidString)" }
    
    public let username: String
    public let tty: String?
    public let loginTime: String?
    public let duration: String?
    public let type: String?
    public let pid: Int?
    
    public init(
        username: String,
        tty: String? = nil,
        loginTime: String? = nil,
        duration: String? = nil,
        type: String? = nil,
        pid: Int? = nil
    ) {
        self.username = username
        self.tty = tty
        self.loginTime = loginTime
        self.duration = duration
        self.type = type
        self.pid = pid
    }
}

// MARK: - BTMDB Health

/// Background Task Management Database health status
/// Critical for shared Mac environments where BTMDB corruption causes loginwindow deadlocks
public struct BTMDBHealth: Codable, Sendable {
    public let exists: Bool
    public let path: String
    public let sizeBytes: Int64
    public let sizeMB: Double
    public let status: BTMDBStatus
    public let statusMessage: String
    public let jetsamKillsLast7Days: Int
    public let lastJetsamEvent: String?
    public let registeredItemCount: Int
    public let localUserCount: Int
    public let thresholds: BTMDBThresholds
    
    public init(
        exists: Bool = false,
        path: String = "/private/var/db/com.apple.backgroundtaskmanagement",
        sizeBytes: Int64 = 0,
        sizeMB: Double = 0.0,
        status: BTMDBStatus = .healthy,
        statusMessage: String = "Database not found or not accessible",
        jetsamKillsLast7Days: Int = 0,
        lastJetsamEvent: String? = nil,
        registeredItemCount: Int = 0,
        localUserCount: Int = 0,
        thresholds: BTMDBThresholds = BTMDBThresholds()
    ) {
        self.exists = exists
        self.path = path
        self.sizeBytes = sizeBytes
        self.sizeMB = sizeMB
        self.status = status
        self.statusMessage = statusMessage
        self.jetsamKillsLast7Days = jetsamKillsLast7Days
        self.lastJetsamEvent = lastJetsamEvent
        self.registeredItemCount = registeredItemCount
        self.localUserCount = localUserCount
        self.thresholds = thresholds
    }
}

public enum BTMDBStatus: String, Codable, Sendable {
    case healthy = "healthy"
    case warning = "warning"
    case critical = "critical"
    case unknown = "unknown"
}

public struct BTMDBThresholds: Codable, Sendable {
    public let warningMB: Double
    public let criticalMB: Double
    public let failureMB: Double
    
    public init(
        warningMB: Double = 3.0,
        criticalMB: Double = 3.5,
        failureMB: Double = 4.0
    ) {
        self.warningMB = warningMB
        self.criticalMB = criticalMB
        self.failureMB = failureMB
    }
}

// MARK: - Directory Services

/// Directory service binding information
public struct DirectoryServicesInfo: Codable, Sendable {
    public let activeDirectory: ADBindingInfo
    public let ldap: LDAPBindingInfo
    public let directoryNodes: String?
    
    public init(
        activeDirectory: ADBindingInfo = ADBindingInfo(),
        ldap: LDAPBindingInfo = LDAPBindingInfo(),
        directoryNodes: String? = nil
    ) {
        self.activeDirectory = activeDirectory
        self.ldap = ldap
        self.directoryNodes = directoryNodes
    }
}

public struct ADBindingInfo: Codable, Sendable {
    public let bound: Bool
    public let domain: String?
    
    public init(bound: Bool = false, domain: String? = nil) {
        self.bound = bound
        self.domain = domain
    }
}

public struct LDAPBindingInfo: Codable, Sendable {
    public let bound: Bool
    public let server: String?
    
    public init(bound: Bool = false, server: String? = nil) {
        self.bound = bound
        self.server = server
    }
}

// MARK: - Secure Token

/// Secure Token user information for MDM bootstrap token workflows
public struct SecureTokenInfo: Codable, Sendable {
    public let usersWithToken: [String]
    public let usersWithoutToken: [String]
    public let totalUsersChecked: Int
    public let tokenGrantedCount: Int
    public let tokenMissingCount: Int
    
    public init(
        usersWithToken: [String] = [],
        usersWithoutToken: [String] = [],
        totalUsersChecked: Int = 0,
        tokenGrantedCount: Int = 0,
        tokenMissingCount: Int = 0
    ) {
        self.usersWithToken = usersWithToken
        self.usersWithoutToken = usersWithoutToken
        self.totalUsersChecked = totalUsersChecked
        self.tokenGrantedCount = tokenGrantedCount
        self.tokenMissingCount = tokenMissingCount
    }
}

// MARK: - Platform SSO Users

/// Platform SSO registration status for all users (macOS 13+ Ventura)
public struct PlatformSSOUsersInfo: Codable, Sendable {
    public let supported: Bool
    public let deviceRegistered: Bool
    public let registeredUserCount: Int
    public let unregisteredUserCount: Int
    public let users: [PlatformSSOUser]
    
    public init(
        supported: Bool = false,
        deviceRegistered: Bool = false,
        registeredUserCount: Int = 0,
        unregisteredUserCount: Int = 0,
        users: [PlatformSSOUser] = []
    ) {
        self.supported = supported
        self.deviceRegistered = deviceRegistered
        self.registeredUserCount = registeredUserCount
        self.unregisteredUserCount = unregisteredUserCount
        self.users = users
    }
}

/// Individual user's Platform SSO registration status
public struct PlatformSSOUser: Codable, Sendable, Identifiable {
    public var id: String { username }
    
    public let username: String
    public let registered: Bool
    public let userPrincipalName: String?
    
    public init(
        username: String,
        registered: Bool = false,
        userPrincipalName: String? = nil
    ) {
        self.username = username
        self.registered = registered
        self.userPrincipalName = userPrincipalName
    }
}

// MARK: - Summary

/// Identity module summary statistics
public struct IdentitySummary: Codable, Sendable {
    public let totalUsers: Int
    public let adminUsers: Int
    public let disabledUsers: Int
    public let currentlyLoggedIn: Int
    public let btmdbStatus: String
    
    public init(
        totalUsers: Int = 0,
        adminUsers: Int = 0,
        disabledUsers: Int = 0,
        currentlyLoggedIn: Int = 0,
        btmdbStatus: String = "unknown"
    ) {
        self.totalUsers = totalUsers
        self.adminUsers = adminUsers
        self.disabledUsers = disabledUsers
        self.currentlyLoggedIn = currentlyLoggedIn
        self.btmdbStatus = btmdbStatus
    }
}
