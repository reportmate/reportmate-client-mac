import Foundation

/// Security module data models for macOS ReportMate client
/// These models represent security configuration and status information

// MARK: - Security Models

/// Main security information structure
public struct SecurityInfo: Codable, Sendable {
    public let systemIntegrityProtection: SIPStatus
    public let gatekeeper: GatekeeperStatus
    public let firewall: FirewallStatus
    public let fileVault: FileVaultStatus
    public let secureBoot: SecureBootStatus
    public let certificates: [Certificate]
    public let keychainItems: [KeychainItem]
    public let authorizationRights: [AuthorizationRight]
    public let trustedExecutables: [TrustedExecutable]
    public let firmwarePassword: FirmwarePasswordStatus?
    public let ssh: SSHStatus?
    public let tcc: [TCCEntry]
    
    public init(
        systemIntegrityProtection: SIPStatus,
        gatekeeper: GatekeeperStatus,
        firewall: FirewallStatus,
        fileVault: FileVaultStatus,
        secureBoot: SecureBootStatus,
        certificates: [Certificate] = [],
        keychainItems: [KeychainItem] = [],
        authorizationRights: [AuthorizationRight] = [],
        trustedExecutables: [TrustedExecutable] = [],
        firmwarePassword: FirmwarePasswordStatus? = nil,
        ssh: SSHStatus? = nil,
        tcc: [TCCEntry] = []
    ) {
        self.systemIntegrityProtection = systemIntegrityProtection
        self.gatekeeper = gatekeeper
        self.firewall = firewall
        self.fileVault = fileVault
        self.secureBoot = secureBoot
        self.certificates = certificates
        self.keychainItems = keychainItems
        self.authorizationRights = authorizationRights
        self.trustedExecutables = trustedExecutables
        self.firmwarePassword = firmwarePassword
        self.ssh = ssh
        self.tcc = tcc
    }
}

/// System Integrity Protection status
public struct SIPStatus: Codable, Sendable {
    public let enabled: Bool
    public let configFlags: [String: Bool]
    public let details: String
    
    public init(enabled: Bool, configFlags: [String: Bool] = [:], details: String = "") {
        self.enabled = enabled
        self.configFlags = configFlags
        self.details = details
    }
}

/// Gatekeeper status and configuration
public struct GatekeeperStatus: Codable, Sendable {
    public let enabled: Bool
    public let assessmentsEnabled: Bool
    public let developerIdEnabled: Bool
    public let version: String?
    public let opaqueVersion: String?
    
    public init(
        enabled: Bool,
        assessmentsEnabled: Bool = false,
        developerIdEnabled: Bool = false,
        version: String? = nil,
        opaqueVersion: String? = nil
    ) {
        self.enabled = enabled
        self.assessmentsEnabled = assessmentsEnabled
        self.developerIdEnabled = developerIdEnabled
        self.version = version
        self.opaqueVersion = opaqueVersion
    }
}

/// Firewall status and configuration
public struct FirewallStatus: Codable, Sendable {
    public let enabled: Bool
    public let stealthMode: Bool
    public let globalState: String
    public let loggingEnabled: Bool
    public let blockAllIncoming: Bool
    public let allowSignedSoftware: Bool
    public let allowDownloadedSignedSoftware: Bool
    public let applications: [FirewallApplication]
    
    public init(
        enabled: Bool = false,
        stealthMode: Bool = false,
        globalState: String = "off",
        loggingEnabled: Bool = false,
        blockAllIncoming: Bool = false,
        allowSignedSoftware: Bool = true,
        allowDownloadedSignedSoftware: Bool = true,
        applications: [FirewallApplication] = []
    ) {
        self.enabled = enabled
        self.stealthMode = stealthMode
        self.globalState = globalState
        self.loggingEnabled = loggingEnabled
        self.blockAllIncoming = blockAllIncoming
        self.allowSignedSoftware = allowSignedSoftware
        self.allowDownloadedSignedSoftware = allowDownloadedSignedSoftware
        self.applications = applications
    }
}

/// Firewall application configuration
public struct FirewallApplication: Codable, Sendable {
    public let bundleId: String
    public let name: String
    public let path: String
    public let state: FirewallApplicationState
    public let incomingAllowed: Bool
    public let outgoingAllowed: Bool
    
    public init(
        bundleId: String,
        name: String,
        path: String,
        state: FirewallApplicationState,
        incomingAllowed: Bool = false,
        outgoingAllowed: Bool = true
    ) {
        self.bundleId = bundleId
        self.name = name
        self.path = path
        self.state = state
        self.incomingAllowed = incomingAllowed
        self.outgoingAllowed = outgoingAllowed
    }
}

/// Firewall application state enumeration
public enum FirewallApplicationState: String, Codable, Sendable {
    case allowed = "Allowed"
    case blocked = "Blocked"
    case ask = "Ask"
    case unknown = "Unknown"
}

/// FileVault disk encryption status
public struct FileVaultStatus: Codable, Sendable {
    public let enabled: Bool
    public let status: String
    public let encryptedVolumes: [EncryptedVolume]
    public let masterKeyEnabled: Bool
    public let institutionalRecoveryKeyEnabled: Bool
    
    public init(
        enabled: Bool = false,
        status: String = "Off",
        encryptedVolumes: [EncryptedVolume] = [],
        masterKeyEnabled: Bool = false,
        institutionalRecoveryKeyEnabled: Bool = false
    ) {
        self.enabled = enabled
        self.status = status
        self.encryptedVolumes = encryptedVolumes
        self.masterKeyEnabled = masterKeyEnabled
        self.institutionalRecoveryKeyEnabled = institutionalRecoveryKeyEnabled
    }
}

/// Encrypted volume information
public struct EncryptedVolume: Codable, Sendable {
    public let name: String
    public let uuid: String
    public let encryptionType: String
    public let conversionStatus: String
    public let percentage: Double
    public let users: [FileVaultUser]
    
    public init(
        name: String,
        uuid: String,
        encryptionType: String = "XTS-AES 128",
        conversionStatus: String = "Complete",
        percentage: Double = 100.0,
        users: [FileVaultUser] = []
    ) {
        self.name = name
        self.uuid = uuid
        self.encryptionType = encryptionType
        self.conversionStatus = conversionStatus
        self.percentage = percentage
        self.users = users
    }
}

/// FileVault enabled user
public struct FileVaultUser: Codable, Sendable {
    public let uuid: String
    public let username: String
    public let displayName: String?
    
    public init(uuid: String, username: String, displayName: String? = nil) {
        self.uuid = uuid
        self.username = username
        self.displayName = displayName
    }
}

/// Secure Boot status
public struct SecureBootStatus: Codable, Sendable {
    public let secureBootEnabled: Bool
    public let externalBootAllowed: Bool
    public let mdmControlled: Bool
    public let securityLevel: String?
    
    public init(
        secureBootEnabled: Bool = false,
        externalBootAllowed: Bool = false,
        mdmControlled: Bool = false,
        securityLevel: String? = nil
    ) {
        self.secureBootEnabled = secureBootEnabled
        self.externalBootAllowed = externalBootAllowed
        self.mdmControlled = mdmControlled
        self.securityLevel = securityLevel
    }
}

/// Certificate information
public struct Certificate: Codable, Sendable {
    public let commonName: String
    public let subject: String
    public let issuer: String
    public let serialNumber: String
    public let isCA: Bool
    public let isSelfSigned: Bool
    public let notValidBefore: Date
    public let notValidAfter: Date
    public let keyAlgorithm: String
    public let keyStrength: Int?
    public let signatureAlgorithm: String
    public let keyUsage: [String]
    public let extendedKeyUsage: [String]
    public let sha1Fingerprint: String?
    public let sha256Fingerprint: String?
    
    public init(
        commonName: String,
        subject: String,
        issuer: String,
        serialNumber: String,
        isCA: Bool = false,
        isSelfSigned: Bool = false,
        notValidBefore: Date,
        notValidAfter: Date,
        keyAlgorithm: String,
        keyStrength: Int? = nil,
        signatureAlgorithm: String,
        keyUsage: [String] = [],
        extendedKeyUsage: [String] = [],
        sha1Fingerprint: String? = nil,
        sha256Fingerprint: String? = nil
    ) {
        self.commonName = commonName
        self.subject = subject
        self.issuer = issuer
        self.serialNumber = serialNumber
        self.isCA = isCA
        self.isSelfSigned = isSelfSigned
        self.notValidBefore = notValidBefore
        self.notValidAfter = notValidAfter
        self.keyAlgorithm = keyAlgorithm
        self.keyStrength = keyStrength
        self.signatureAlgorithm = signatureAlgorithm
        self.keyUsage = keyUsage
        self.extendedKeyUsage = extendedKeyUsage
        self.sha1Fingerprint = sha1Fingerprint
        self.sha256Fingerprint = sha256Fingerprint
    }
    
    public var isExpired: Bool {
        return Date() > notValidAfter
    }
    
    public var isValid: Bool {
        let now = Date()
        return now >= notValidBefore && now <= notValidAfter
    }
}

/// Keychain item information (non-sensitive data only)
public struct KeychainItem: Codable, Sendable {
    public let label: String
    public let itemClass: KeychainItemClass
    public let description: String?
    public let comment: String?
    public let creationDate: Date?
    public let modificationDate: Date?
    public let accessGroup: String?
    
    public init(
        label: String,
        itemClass: KeychainItemClass,
        description: String? = nil,
        comment: String? = nil,
        creationDate: Date? = nil,
        modificationDate: Date? = nil,
        accessGroup: String? = nil
    ) {
        self.label = label
        self.itemClass = itemClass
        self.description = description
        self.comment = comment
        self.creationDate = creationDate
        self.modificationDate = modificationDate
        self.accessGroup = accessGroup
    }
}

/// Keychain item class enumeration
public enum KeychainItemClass: String, Codable, Sendable {
    case genericPassword = "GenericPassword"
    case internetPassword = "InternetPassword"
    case certificate = "Certificate"
    case key = "Key"
    case identity = "Identity"
    case unknown = "Unknown"
}

/// Authorization right information
public struct AuthorizationRight: Codable, Sendable {
    public let name: String
    public let ruleClass: String
    public let comment: String?
    public let isAllowed: Bool
    public let requiresAdmin: Bool
    public let timeout: TimeInterval?
    public let version: Int?
    public let maxTries: Int?
    public let authenticateUser: Bool
    
    public init(
        name: String,
        ruleClass: String,
        comment: String? = nil,
        isAllowed: Bool = false,
        requiresAdmin: Bool = false,
        timeout: TimeInterval? = nil,
        version: Int? = nil,
        maxTries: Int? = nil,
        authenticateUser: Bool = false
    ) {
        self.name = name
        self.ruleClass = ruleClass
        self.comment = comment
        self.isAllowed = isAllowed
        self.requiresAdmin = requiresAdmin
        self.timeout = timeout
        self.version = version
        self.maxTries = maxTries
        self.authenticateUser = authenticateUser
    }
}

/// Trusted executable information
public struct TrustedExecutable: Codable, Sendable {
    public let path: String
    public let bundleId: String?
    public let teamId: String?
    public let signingIdentity: String?
    public let codeSignatureStatus: CodeSignatureStatus
    public let notarized: Bool
    public let quarantineStatus: QuarantineStatus
    
    public init(
        path: String,
        bundleId: String? = nil,
        teamId: String? = nil,
        signingIdentity: String? = nil,
        codeSignatureStatus: CodeSignatureStatus,
        notarized: Bool = false,
        quarantineStatus: QuarantineStatus = .none
    ) {
        self.path = path
        self.bundleId = bundleId
        self.teamId = teamId
        self.signingIdentity = signingIdentity
        self.codeSignatureStatus = codeSignatureStatus
        self.notarized = notarized
        self.quarantineStatus = quarantineStatus
    }
}

/// Code signature status enumeration
public enum CodeSignatureStatus: String, Codable, Sendable {
    case valid = "Valid"
    case invalid = "Invalid"
    case unsigned = "Unsigned"
    case adhoc = "Ad-hoc"
    case unknown = "Unknown"
}

/// Quarantine status enumeration
public enum QuarantineStatus: String, Codable, Sendable {
    case none = "None"
    case quarantined = "Quarantined"
    case approved = "Approved"
    case unknown = "Unknown"
}

/// Firmware Password status
public struct FirmwarePasswordStatus: Codable, Sendable {
    public let enabled: Bool
    public let details: String?
    
    public init(enabled: Bool, details: String? = nil) {
        self.enabled = enabled
        self.details = details
    }
}

/// SSH status
public struct SSHStatus: Codable, Sendable {
    public let enabled: Bool
    public let details: String?
    
    public init(enabled: Bool, details: String? = nil) {
        self.enabled = enabled
        self.details = details
    }
}

/// TCC Entry information
public struct TCCEntry: Codable, Sendable {
    public let service: String
    public let client: String
    public let allowed: Bool
    public let promptCount: Int?
    
    public init(service: String, client: String, allowed: Bool, promptCount: Int? = nil) {
        self.service = service
        self.client = client
        self.allowed = allowed
        self.promptCount = promptCount
    }
}
