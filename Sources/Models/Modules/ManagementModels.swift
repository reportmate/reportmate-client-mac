import Foundation

/// Management module data models for macOS ReportMate client
/// These models represent management status, MDM enrollment, and compliance
/// Aligned with Windows client structure for API compatibility

public struct ManagementData: ModuleDataModel, Sendable {
    public var moduleId: String { "management" }
    public let collectionTimestamp: Date
    public let success: Bool
    public let errorMessage: String?
    
    // Primary management sections - aligned with Windows structure
    public let deviceState: DeviceState
    public let deviceDetails: DeviceDetails
    public let tenantDetails: TenantDetails
    public let mdmEnrollment: MDMEnrollmentInfo
    public let profiles: [MDMProfile]
    public let compliancePolicies: [CompliancePolicy]
    public let remoteManagement: RemoteManagementInfo?
    public let lastSync: Date?
    public let ownershipType: String?
    
    public init(
        collectionTimestamp: Date = Date(),
        success: Bool = true,
        errorMessage: String? = nil,
        deviceState: DeviceState = DeviceState(),
        deviceDetails: DeviceDetails = DeviceDetails(),
        tenantDetails: TenantDetails = TenantDetails(),
        mdmEnrollment: MDMEnrollmentInfo = MDMEnrollmentInfo(),
        profiles: [MDMProfile] = [],
        compliancePolicies: [CompliancePolicy] = [],
        remoteManagement: RemoteManagementInfo? = nil,
        lastSync: Date? = nil,
        ownershipType: String? = nil
    ) {
        self.collectionTimestamp = collectionTimestamp
        self.success = success
        self.errorMessage = errorMessage
        self.deviceState = deviceState
        self.deviceDetails = deviceDetails
        self.tenantDetails = tenantDetails
        self.mdmEnrollment = mdmEnrollment
        self.profiles = profiles
        self.compliancePolicies = compliancePolicies
        self.remoteManagement = remoteManagement
        self.lastSync = lastSync
        self.ownershipType = ownershipType
    }
}

// MARK: - Device State (macOS equivalent of Windows DeviceState)
public struct DeviceState: Codable, Sendable {
    public let mdmEnrolled: Bool           // Is device enrolled in MDM
    public let adeEnrolled: Bool           // Enrolled via ADE (Automated Device Enrollment, formerly DEP)
    public let userApproved: Bool          // User-approved MDM enrollment
    public let supervised: Bool            // Device is supervised
    public let adBound: Bool               // Bound to Active Directory
    public let status: String              // Simplified status string

    public init(
        mdmEnrolled: Bool = false,
        adeEnrolled: Bool = false,
        userApproved: Bool = false,
        supervised: Bool = false,
        adBound: Bool = false,
        status: String = "Not Enrolled"
    ) {
        self.mdmEnrolled = mdmEnrolled
        self.adeEnrolled = adeEnrolled
        self.userApproved = userApproved
        self.supervised = supervised
        self.adBound = adBound
        self.status = status
    }
}

// MARK: - Device Details
public struct DeviceDetails: Codable, Sendable {
    public let deviceId: String?           // MDM device ID
    public let enrollmentId: String?       // Enrollment identifier
    public let udid: String?               // Unique Device Identifier
    public let serialNumber: String?       // Hardware serial
    
    public init(
        deviceId: String? = nil,
        enrollmentId: String? = nil,
        udid: String? = nil,
        serialNumber: String? = nil
    ) {
        self.deviceId = deviceId
        self.enrollmentId = enrollmentId
        self.udid = udid
        self.serialNumber = serialNumber
    }
}

// MARK: - Tenant Details (MDM Server Info)
public struct TenantDetails: Codable, Sendable {
    public let serverUrl: String?          // MDM server URL
    public let serverName: String?         // Extracted server hostname
    public let organizationName: String?   // Organization from profiles
    public let checkInUrl: String?         // MDM check-in URL
    
    public init(
        serverUrl: String? = nil,
        serverName: String? = nil,
        organizationName: String? = nil,
        checkInUrl: String? = nil
    ) {
        self.serverUrl = serverUrl
        self.serverName = serverName
        self.organizationName = organizationName
        self.checkInUrl = checkInUrl
    }
}

// MARK: - MDM Enrollment Info
public struct MDMEnrollmentInfo: Codable, Sendable {
    public let isEnrolled: Bool
    public let enrollmentType: String?     // "ADE Enrolled", "User Approved", "Unenrolled"
    public let provider: String?           // Intune, Jamf, Mosyle, etc.
    public let userPrincipalName: String?  // Enrolled user
    public let enrollmentDate: Date?
    public let serverUrl: String?
    
    public init(
        isEnrolled: Bool = false,
        enrollmentType: String? = nil,
        provider: String? = nil,
        userPrincipalName: String? = nil,
        enrollmentDate: Date? = nil,
        serverUrl: String? = nil
    ) {
        self.isEnrolled = isEnrolled
        self.enrollmentType = enrollmentType
        self.provider = provider
        self.userPrincipalName = userPrincipalName
        self.enrollmentDate = enrollmentDate
        self.serverUrl = serverUrl
    }
}

// MARK: - MDM Profile
public struct MDMProfile: Codable, Sendable {
    public let identifier: String
    public let displayName: String
    public let organization: String?
    public let description: String?
    public let profileType: String?        // Configuration, MDM, Certificate, etc.
    public let isVerified: Bool
    public let isEncrypted: Bool
    public let isRemovable: Bool
    public let installDate: Date?
    public let payloadTypes: [String]?     // Payload types in profile
    
    public init(
        identifier: String,
        displayName: String,
        organization: String? = nil,
        description: String? = nil,
        profileType: String? = nil,
        isVerified: Bool = false,
        isEncrypted: Bool = false,
        isRemovable: Bool = true,
        installDate: Date? = nil,
        payloadTypes: [String]? = nil
    ) {
        self.identifier = identifier
        self.displayName = displayName
        self.organization = organization
        self.description = description
        self.profileType = profileType
        self.isVerified = isVerified
        self.isEncrypted = isEncrypted
        self.isRemovable = isRemovable
        self.installDate = installDate
        self.payloadTypes = payloadTypes
    }
}

// MARK: - Compliance Policy
public struct CompliancePolicy: Codable, Sendable {
    public let name: String
    public let status: String              // Compliant, Non-Compliant, Unknown
    public let lastEvaluated: Date?
    public let details: String?
    
    public init(
        name: String,
        status: String = "Unknown",
        lastEvaluated: Date? = nil,
        details: String? = nil
    ) {
        self.name = name
        self.status = status
        self.lastEvaluated = lastEvaluated
        self.details = details
    }
}

// MARK: - Remote Management Info (ARD)
public struct RemoteManagementInfo: Codable, Sendable {
    public let isEnabled: Bool
    public let users: [String]
    public let privileges: [String]
    public let allUsers: Bool
    
    public init(
        isEnabled: Bool = false,
        users: [String] = [],
        privileges: [String] = [],
        allUsers: Bool = false
    ) {
        self.isEnabled = isEnabled
        self.users = users
        self.privileges = privileges
        self.allUsers = allUsers
    }
}

// Legacy compatibility aliases
public typealias MDMStatus = MDMEnrollmentInfo
public typealias ManagementProfile = MDMProfile
public typealias ComplianceStatus = CompliancePolicy

