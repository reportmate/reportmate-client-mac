import Foundation

/// Management module data models for macOS ReportMate client
/// These models represent management status, MDM enrollment, and compliance

public struct ManagementData: ModuleDataModel, Sendable {
    public var moduleId: String { "management" }
    public let collectionTimestamp: Date
    public let success: Bool
    public let errorMessage: String?
    
    public let mdmStatus: MDMStatus
    public let profiles: [ManagementProfile]
    public let complianceStatus: ComplianceStatus
    public let remoteManagement: RemoteManagementInfo?
    
    public init(
        collectionTimestamp: Date = Date(),
        success: Bool = true,
        errorMessage: String? = nil,
        mdmStatus: MDMStatus = MDMStatus(),
        profiles: [ManagementProfile] = [],
        complianceStatus: ComplianceStatus = ComplianceStatus(),
        remoteManagement: RemoteManagementInfo? = nil
    ) {
        self.collectionTimestamp = collectionTimestamp
        self.success = success
        self.errorMessage = errorMessage
        self.mdmStatus = mdmStatus
        self.profiles = profiles
        self.complianceStatus = complianceStatus
        self.remoteManagement = remoteManagement
    }
}

public struct MDMStatus: Codable, Sendable {
    public let isEnrolled: Bool
    public let authority: String?
    public let enrollmentDate: Date?
    public let isSupervised: Bool
    public let depEnrolled: Bool
    
    public init(isEnrolled: Bool = false, authority: String? = nil, enrollmentDate: Date? = nil, isSupervised: Bool = false, depEnrolled: Bool = false) {
        self.isEnrolled = isEnrolled
        self.authority = authority
        self.enrollmentDate = enrollmentDate
        self.isSupervised = isSupervised
        self.depEnrolled = depEnrolled
    }
}

public struct ManagementProfile: Codable, Sendable {
    public let identifier: String
    public let displayName: String
    public let organization: String?
    public let description: String?
    public let isVerified: Bool
    public let isEncrypted: Bool
    public let installDate: Date?
    
    public init(identifier: String, displayName: String, organization: String? = nil, description: String? = nil, isVerified: Bool, isEncrypted: Bool, installDate: Date? = nil) {
        self.identifier = identifier
        self.displayName = displayName
        self.organization = organization
        self.description = description
        self.isVerified = isVerified
        self.isEncrypted = isEncrypted
        self.installDate = installDate
    }
}

public struct ComplianceStatus: Codable, Sendable {
    public let fileVaultEnabled: Bool
    public let firewallEnabled: Bool
    public let gatekeeperEnabled: Bool
    public let sipEnabled: Bool
    public let automaticUpdatesEnabled: Bool
    
    public init(fileVaultEnabled: Bool = false, firewallEnabled: Bool = false, gatekeeperEnabled: Bool = false, sipEnabled: Bool = false, automaticUpdatesEnabled: Bool = false) {
        self.fileVaultEnabled = fileVaultEnabled
        self.firewallEnabled = firewallEnabled
        self.gatekeeperEnabled = gatekeeperEnabled
        self.sipEnabled = sipEnabled
        self.automaticUpdatesEnabled = automaticUpdatesEnabled
    }
}

public struct RemoteManagementInfo: Codable, Sendable {
    public let isEnabled: Bool
    public let users: [String]
    public let privileges: [String]
    
    public init(isEnabled: Bool, users: [String], privileges: [String]) {
        self.isEnabled = isEnabled
        self.users = users
        self.privileges = privileges
    }
}
