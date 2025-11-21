import Foundation

/// Inventory module data models for macOS ReportMate client
/// These models represent file system inventory and asset tracking

public struct InventoryData: ModuleDataModel, Sendable {
    public var moduleId: String { "inventory" }
    public let collectionTimestamp: Date
    public let success: Bool
    public let errorMessage: String?
    
    public let logicalDrives: [LogicalDrive]
    public let sharedFolders: [SharedFolder]
    public let userAccounts: [UserAccount]
    public let groups: [UserGroup]
    public let certificates: [CertificateInfo]
    
    public init(
        collectionTimestamp: Date = Date(),
        success: Bool = true,
        errorMessage: String? = nil,
        logicalDrives: [LogicalDrive] = [],
        sharedFolders: [SharedFolder] = [],
        userAccounts: [UserAccount] = [],
        groups: [UserGroup] = [],
        certificates: [CertificateInfo] = []
    ) {
        self.collectionTimestamp = collectionTimestamp
        self.success = success
        self.errorMessage = errorMessage
        self.logicalDrives = logicalDrives
        self.sharedFolders = sharedFolders
        self.userAccounts = userAccounts
        self.groups = groups
        self.certificates = certificates
    }
}

public struct LogicalDrive: Codable, Sendable {
    public let deviceId: String
    public let volumeName: String
    public let fileSystem: String
    public let size: Int64
    public let freeSpace: Int64
    public let isBootVolume: Bool
    
    public init(deviceId: String, volumeName: String, fileSystem: String, size: Int64, freeSpace: Int64, isBootVolume: Bool) {
        self.deviceId = deviceId
        self.volumeName = volumeName
        self.fileSystem = fileSystem
        self.size = size
        self.freeSpace = freeSpace
        self.isBootVolume = isBootVolume
    }
}

public struct SharedFolder: Codable, Sendable {
    public let name: String
    public let path: String
    public let description: String?
    
    public init(name: String, path: String, description: String? = nil) {
        self.name = name
        self.path = path
        self.description = description
    }
}

public struct UserAccount: Codable, Sendable {
    public let username: String
    public let fullName: String
    public let uid: Int
    public let gid: Int
    public let homeDirectory: String
    public let shell: String
    public let isAdmin: Bool
    
    public init(username: String, fullName: String, uid: Int, gid: Int, homeDirectory: String, shell: String, isAdmin: Bool) {
        self.username = username
        self.fullName = fullName
        self.uid = uid
        self.gid = gid
        self.homeDirectory = homeDirectory
        self.shell = shell
        self.isAdmin = isAdmin
    }
}

public struct UserGroup: Codable, Sendable {
    public let name: String
    public let gid: Int
    public let members: [String]
    
    public init(name: String, gid: Int, members: [String]) {
        self.name = name
        self.gid = gid
        self.members = members
    }
}

public struct CertificateInfo: Codable, Sendable {
    public let commonName: String
    public let issuer: String
    public let serialNumber: String
    public let notBefore: Date
    public let notAfter: Date
    public let isRoot: Bool
    
    public init(commonName: String, issuer: String, serialNumber: String, notBefore: Date, notAfter: Date, isRoot: Bool) {
        self.commonName = commonName
        self.issuer = issuer
        self.serialNumber = serialNumber
        self.notBefore = notBefore
        self.notAfter = notAfter
        self.isRoot = isRoot
    }
}
