import Foundation

/// @deprecated This module has been deprecated.
/// Profiles functionality has been integrated into the Management module.
/// See ManagementModuleProcessor for profile collection.
///
/// Profiles module data model for macOS - encompasses configuration profiles and system policies
@available(*, deprecated, message: "Profiles now part of Management module")
public struct ProfilesData: ModuleDataModel, Sendable {
    public var moduleId: String { "profiles" }
    public let collectionTimestamp: Date
    public let success: Bool
    public let errorMessage: String?
    
    // Additional profiles-specific properties
    public let deviceId: String
    
    // Mac configuration profile systems
    public let configurationProfiles: [ConfigurationProfile]
    public let systemPreferences: [SystemPreference]
    public let mdmPolicies: [MDMPolicy]
    public let securityPolicies: [SecurityPolicy]
    public let restrictionPolicies: [RestrictionPolicy]
    public let payloadTypes: [PayloadType]
    
    // Summary statistics
    public let totalProfiles: Int
    public let lastProfileUpdate: Date?
    public let profileCountsBySource: [String: Int]
    
    public init(
        deviceId: String,
        collectionTimestamp: Date = Date(),
        success: Bool = true,
        errorMessage: String? = nil,
        configurationProfiles: [ConfigurationProfile] = [],
        systemPreferences: [SystemPreference] = [],
        mdmPolicies: [MDMPolicy] = [],
        securityPolicies: [SecurityPolicy] = [],
        restrictionPolicies: [RestrictionPolicy] = [],
        payloadTypes: [PayloadType] = [],
        totalProfiles: Int = 0,
        lastProfileUpdate: Date? = nil,
        profileCountsBySource: [String: Int] = [:]
    ) {
        self.deviceId = deviceId
        self.collectionTimestamp = collectionTimestamp
        self.success = success
        self.errorMessage = errorMessage
        self.configurationProfiles = configurationProfiles
        self.systemPreferences = systemPreferences
        self.mdmPolicies = mdmPolicies
        self.securityPolicies = securityPolicies
        self.restrictionPolicies = restrictionPolicies
        self.payloadTypes = payloadTypes
        self.totalProfiles = totalProfiles
        self.lastProfileUpdate = lastProfileUpdate
        self.profileCountsBySource = profileCountsBySource
    }
}

/// Configuration profile information (MDM profiles)
public struct ConfigurationProfile: Codable, Sendable {
    public let identifier: String
    public let uuid: String
    public let displayName: String
    public let description: String
    public let organization: String
    public let version: Int
    public let payloadType: String
    public let payloadVersion: Int
    public let installDate: Date?
    public let lastModified: Date?
    public let isSystem: Bool
    public let isUser: Bool
    public let isRemovalAllowed: Bool
    public let isManaged: Bool
    public let source: String // MDM, Manual, System, etc.
    public let scope: String // System, User
    public let payloads: [ProfilePayload]
    public let verificationState: String
    public let hasRemovalPasscode: Bool
    
    public init(
        identifier: String = "",
        uuid: String = "",
        displayName: String = "",
        description: String = "",
        organization: String = "",
        version: Int = 1,
        payloadType: String = "",
        payloadVersion: Int = 1,
        installDate: Date? = nil,
        lastModified: Date? = nil,
        isSystem: Bool = false,
        isUser: Bool = false,
        isRemovalAllowed: Bool = true,
        isManaged: Bool = false,
        source: String = "",
        scope: String = "",
        payloads: [ProfilePayload] = [],
        verificationState: String = "",
        hasRemovalPasscode: Bool = false
    ) {
        self.identifier = identifier
        self.uuid = uuid
        self.displayName = displayName
        self.description = description
        self.organization = organization
        self.version = version
        self.payloadType = payloadType
        self.payloadVersion = payloadVersion
        self.installDate = installDate
        self.lastModified = lastModified
        self.isSystem = isSystem
        self.isUser = isUser
        self.isRemovalAllowed = isRemovalAllowed
        self.isManaged = isManaged
        self.source = source
        self.scope = scope
        self.payloads = payloads
        self.verificationState = verificationState
        self.hasRemovalPasscode = hasRemovalPasscode
    }
}

/// Profile payload information
public struct ProfilePayload: Codable, Sendable {
    public let identifier: String
    public let uuid: String
    public let displayName: String
    public let description: String
    public let type: String
    public let version: Int
    public let settings: [String: String] // Simplified - actual payloads can have complex nested structures
    
    public init(
        identifier: String = "",
        uuid: String = "",
        displayName: String = "",
        description: String = "",
        type: String = "",
        version: Int = 1,
        settings: [String: String] = [:]
    ) {
        self.identifier = identifier
        self.uuid = uuid
        self.displayName = displayName
        self.description = description
        self.type = type
        self.version = version
        self.settings = settings
    }
}

/// System preference information
public struct SystemPreference: Codable, Sendable {
    public let domain: String
    public let key: String
    public let value: String
    public let type: String
    public let scope: String // System, User, Host
    public let isManaged: Bool
    public let source: String
    public let category: String
    public let lastModified: Date?
    
    public init(
        domain: String = "",
        key: String = "",
        value: String = "",
        type: String = "",
        scope: String = "",
        isManaged: Bool = false,
        source: String = "",
        category: String = "",
        lastModified: Date? = nil
    ) {
        self.domain = domain
        self.key = key
        self.value = value
        self.type = type
        self.scope = scope
        self.isManaged = isManaged
        self.source = source
        self.category = category
        self.lastModified = lastModified
    }
}

/// MDM policy information
public struct MDMPolicy: Codable, Sendable {
    public let policyId: String
    public let policyName: String
    public let policyType: String
    public let platform: String
    public let assignedDate: Date?
    public let lastSync: Date?
    public let status: String
    public let enforcementState: String
    public let settings: [PolicySetting]
    public let configuration: [String: String]
    
    public init(
        policyId: String = "",
        policyName: String = "",
        policyType: String = "",
        platform: String = "macOS",
        assignedDate: Date? = nil,
        lastSync: Date? = nil,
        status: String = "",
        enforcementState: String = "",
        settings: [PolicySetting] = [],
        configuration: [String: String] = [:]
    ) {
        self.policyId = policyId
        self.policyName = policyName
        self.policyType = policyType
        self.platform = platform
        self.assignedDate = assignedDate
        self.lastSync = lastSync
        self.status = status
        self.enforcementState = enforcementState
        self.settings = settings
        self.configuration = configuration
    }
}

/// Security policy information
public struct SecurityPolicy: Codable, Sendable {
    public let policyName: String
    public let policyArea: String // FileVault, Gatekeeper, SIP, Firewall, etc.
    public let setting: String
    public let value: String
    public let source: String
    public let lastApplied: Date?
    public let complianceStatus: String
    public let severity: String
    public let details: [String: String]
    
    public init(
        policyName: String = "",
        policyArea: String = "",
        setting: String = "",
        value: String = "",
        source: String = "",
        lastApplied: Date? = nil,
        complianceStatus: String = "",
        severity: String = "",
        details: [String: String] = [:]
    ) {
        self.policyName = policyName
        self.policyArea = policyArea
        self.setting = setting
        self.value = value
        self.source = source
        self.lastApplied = lastApplied
        self.complianceStatus = complianceStatus
        self.severity = severity
        self.details = details
    }
}

/// Restriction policy information (parental controls, managed preferences)
public struct RestrictionPolicy: Codable, Sendable {
    public let identifier: String
    public let name: String
    public let type: String // Application, System, User
    public let restrictionType: String
    public let isActive: Bool
    public let affectedUsers: [String]
    public let affectedApplications: [String]
    public let restrictions: [String: String]
    public let exemptions: [String]
    public let source: String
    
    public init(
        identifier: String = "",
        name: String = "",
        type: String = "",
        restrictionType: String = "",
        isActive: Bool = false,
        affectedUsers: [String] = [],
        affectedApplications: [String] = [],
        restrictions: [String: String] = [:],
        exemptions: [String] = [],
        source: String = ""
    ) {
        self.identifier = identifier
        self.name = name
        self.type = type
        self.restrictionType = restrictionType
        self.isActive = isActive
        self.affectedUsers = affectedUsers
        self.affectedApplications = affectedApplications
        self.restrictions = restrictions
        self.exemptions = exemptions
        self.source = source
    }
}

/// Policy setting information
public struct PolicySetting: Codable, Sendable {
    public let name: String
    public let displayName: String
    public let value: String
    public let type: String
    public let category: String
    public let isEnabled: Bool
    public let description: String
    public let attributes: [String: String]
    
    public init(
        name: String = "",
        displayName: String = "",
        value: String = "",
        type: String = "",
        category: String = "",
        isEnabled: Bool = false,
        description: String = "",
        attributes: [String: String] = [:]
    ) {
        self.name = name
        self.displayName = displayName
        self.value = value
        self.type = type
        self.category = category
        self.isEnabled = isEnabled
        self.description = description
        self.attributes = attributes
    }
}

/// Payload type information
public struct PayloadType: Codable, Sendable {
    public let type: String
    public let displayName: String
    public let description: String
    public let isSupported: Bool
    public let version: String
    public let category: String
    public let requiredKeys: [String]
    public let optionalKeys: [String]
    
    public init(
        type: String = "",
        displayName: String = "",
        description: String = "",
        isSupported: Bool = true,
        version: String = "",
        category: String = "",
        requiredKeys: [String] = [],
        optionalKeys: [String] = []
    ) {
        self.type = type
        self.displayName = displayName
        self.description = description
        self.isSupported = isSupported
        self.version = version
        self.category = category
        self.requiredKeys = requiredKeys
        self.optionalKeys = optionalKeys
    }
}