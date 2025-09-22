import Foundation

/// Installs module data model for macOS - encompasses software installation and package management systems
public struct InstallsData: ModuleDataModel, Sendable {
    public var moduleId: String { "installs" }
    public let collectionTimestamp: Date
    public let success: Bool
    public let errorMessage: String?
    
    // Additional installs-specific properties
    public let deviceId: String
    
    // Mac package management systems
    public let homebrewInfo: HomebrewInfo
    public let macPortsInfo: MacPortsInfo
    public let applications: [InstalledApplication]
    public let systemPackages: [SystemPackage]
    public let recentInstalls: [RecentInstall]
    public let packageManagers: [PackageManager]
    
    // Summary statistics
    public let totalApplications: Int
    public let totalPackages: Int
    public let lastInstallActivity: Date?
    
    public init(
        deviceId: String,
        collectionTimestamp: Date = Date(),
        success: Bool = true,
        errorMessage: String? = nil,
        homebrewInfo: HomebrewInfo = HomebrewInfo(),
        macPortsInfo: MacPortsInfo = MacPortsInfo(),
        applications: [InstalledApplication] = [],
        systemPackages: [SystemPackage] = [],
        recentInstalls: [RecentInstall] = [],
        packageManagers: [PackageManager] = [],
        totalApplications: Int = 0,
        totalPackages: Int = 0,
        lastInstallActivity: Date? = nil
    ) {
        self.deviceId = deviceId
        self.collectionTimestamp = collectionTimestamp
        self.success = success
        self.errorMessage = errorMessage
        self.homebrewInfo = homebrewInfo
        self.macPortsInfo = macPortsInfo
        self.applications = applications
        self.systemPackages = systemPackages
        self.recentInstalls = recentInstalls
        self.packageManagers = packageManagers
        self.totalApplications = totalApplications
        self.totalPackages = totalPackages
        self.lastInstallActivity = lastInstallActivity
    }
}

/// Homebrew package manager information
public struct HomebrewInfo: Codable, Sendable {
    public let isInstalled: Bool
    public let version: String
    public let prefix: String
    public let repository: String
    public let lastUpdated: Date?
    public let totalPackages: Int
    public let outdatedPackages: Int
    public let caskPackages: Int
    public let tapRepositories: [String]
    public let installedFormulae: [HomebrewPackage]
    public let installedCasks: [HomebrewCask]
    
    public init(
        isInstalled: Bool = false,
        version: String = "",
        prefix: String = "/usr/local",
        repository: String = "",
        lastUpdated: Date? = nil,
        totalPackages: Int = 0,
        outdatedPackages: Int = 0,
        caskPackages: Int = 0,
        tapRepositories: [String] = [],
        installedFormulae: [HomebrewPackage] = [],
        installedCasks: [HomebrewCask] = []
    ) {
        self.isInstalled = isInstalled
        self.version = version
        self.prefix = prefix
        self.repository = repository
        self.lastUpdated = lastUpdated
        self.totalPackages = totalPackages
        self.outdatedPackages = outdatedPackages
        self.caskPackages = caskPackages
        self.tapRepositories = tapRepositories
        self.installedFormulae = installedFormulae
        self.installedCasks = installedCasks
    }
}

/// Homebrew package/formula information
public struct HomebrewPackage: Codable, Sendable {
    public let name: String
    public let version: String
    public let description: String
    public let homepage: String
    public let installedVersion: String
    public let availableVersion: String
    public let isOutdated: Bool
    public let installDate: Date?
    public let dependencies: [String]
    public let size: String
    
    public init(
        name: String = "",
        version: String = "",
        description: String = "",
        homepage: String = "",
        installedVersion: String = "",
        availableVersion: String = "",
        isOutdated: Bool = false,
        installDate: Date? = nil,
        dependencies: [String] = [],
        size: String = ""
    ) {
        self.name = name
        self.version = version
        self.description = description
        self.homepage = homepage
        self.installedVersion = installedVersion
        self.availableVersion = availableVersion
        self.isOutdated = isOutdated
        self.installDate = installDate
        self.dependencies = dependencies
        self.size = size
    }
}

/// Homebrew cask (application) information
public struct HomebrewCask: Codable, Sendable {
    public let name: String
    public let version: String
    public let description: String
    public let homepage: String
    public let appName: String
    public let artifactPath: String
    public let installDate: Date?
    public let size: String
    
    public init(
        name: String = "",
        version: String = "",
        description: String = "",
        homepage: String = "",
        appName: String = "",
        artifactPath: String = "",
        installDate: Date? = nil,
        size: String = ""
    ) {
        self.name = name
        self.version = version
        self.description = description
        self.homepage = homepage
        self.appName = appName
        self.artifactPath = artifactPath
        self.installDate = installDate
        self.size = size
    }
}

/// MacPorts package manager information
public struct MacPortsInfo: Codable, Sendable {
    public let isInstalled: Bool
    public let version: String
    public let prefix: String
    public let lastSynced: Date?
    public let totalPorts: Int
    public let outdatedPorts: Int
    public let activePorts: Int
    public let installedPorts: [MacPortsPackage]
    
    public init(
        isInstalled: Bool = false,
        version: String = "",
        prefix: String = "/opt/local",
        lastSynced: Date? = nil,
        totalPorts: Int = 0,
        outdatedPorts: Int = 0,
        activePorts: Int = 0,
        installedPorts: [MacPortsPackage] = []
    ) {
        self.isInstalled = isInstalled
        self.version = version
        self.prefix = prefix
        self.lastSynced = lastSynced
        self.totalPorts = totalPorts
        self.outdatedPorts = outdatedPorts
        self.activePorts = activePorts
        self.installedPorts = installedPorts
    }
}

/// MacPorts package information
public struct MacPortsPackage: Codable, Sendable {
    public let name: String
    public let version: String
    public let revision: String
    public let variants: [String]
    public let description: String
    public let homepage: String
    public let isActive: Bool
    public let isOutdated: Bool
    public let installDate: Date?
    public let dependencies: [String]
    
    public init(
        name: String = "",
        version: String = "",
        revision: String = "",
        variants: [String] = [],
        description: String = "",
        homepage: String = "",
        isActive: Bool = false,
        isOutdated: Bool = false,
        installDate: Date? = nil,
        dependencies: [String] = []
    ) {
        self.name = name
        self.version = version
        self.revision = revision
        self.variants = variants
        self.description = description
        self.homepage = homepage
        self.isActive = isActive
        self.isOutdated = isOutdated
        self.installDate = installDate
        self.dependencies = dependencies
    }
}

/// Installed application information (from /Applications and ~/Applications)
public struct InstalledApplication: Codable, Sendable {
    public let name: String
    public let displayName: String
    public let bundleIdentifier: String
    public let version: String
    public let buildVersion: String
    public let path: String
    public let size: Int64
    public let installDate: Date?
    public let lastModified: Date?
    public let developer: String
    public let category: String
    public let isSystemApp: Bool
    public let isMacAppStore: Bool
    public let copyright: String
    public let minimumSystemVersion: String
    public let architectures: [String]
    public let codeSignature: CodeSignatureInfo?
    
    public init(
        name: String = "",
        displayName: String = "",
        bundleIdentifier: String = "",
        version: String = "",
        buildVersion: String = "",
        path: String = "",
        size: Int64 = 0,
        installDate: Date? = nil,
        lastModified: Date? = nil,
        developer: String = "",
        category: String = "",
        isSystemApp: Bool = false,
        isMacAppStore: Bool = false,
        copyright: String = "",
        minimumSystemVersion: String = "",
        architectures: [String] = [],
        codeSignature: CodeSignatureInfo? = nil
    ) {
        self.name = name
        self.displayName = displayName
        self.bundleIdentifier = bundleIdentifier
        self.version = version
        self.buildVersion = buildVersion
        self.path = path
        self.size = size
        self.installDate = installDate
        self.lastModified = lastModified
        self.developer = developer
        self.category = category
        self.isSystemApp = isSystemApp
        self.isMacAppStore = isMacAppStore
        self.copyright = copyright
        self.minimumSystemVersion = minimumSystemVersion
        self.architectures = architectures
        self.codeSignature = codeSignature
    }
}

/// Code signature information
public struct CodeSignatureInfo: Codable, Sendable {
    public let isSigned: Bool
    public let isValid: Bool
    public let authority: String
    public let teamIdentifier: String
    public let entitlements: [String: String]
    
    public init(
        isSigned: Bool = false,
        isValid: Bool = false,
        authority: String = "",
        teamIdentifier: String = "",
        entitlements: [String: String] = [:]
    ) {
        self.isSigned = isSigned
        self.isValid = isValid
        self.authority = authority
        self.teamIdentifier = teamIdentifier
        self.entitlements = entitlements
    }
}

/// System package information (framework, kext, etc.)
public struct SystemPackage: Codable, Sendable {
    public let name: String
    public let version: String
    public let identifier: String
    public let path: String
    public let packageType: String // PKG, framework, kext, etc.
    public let installDate: Date?
    public let size: Int64
    public let receipt: String?
    public let isApple: Bool
    
    public init(
        name: String = "",
        version: String = "",
        identifier: String = "",
        path: String = "",
        packageType: String = "",
        installDate: Date? = nil,
        size: Int64 = 0,
        receipt: String? = nil,
        isApple: Bool = false
    ) {
        self.name = name
        self.version = version
        self.identifier = identifier
        self.path = path
        self.packageType = packageType
        self.installDate = installDate
        self.size = size
        self.receipt = receipt
        self.isApple = isApple
    }
}

/// Recent install activity
public struct RecentInstall: Codable, Sendable {
    public let name: String
    public let version: String
    public let installDate: Date
    public let source: String // App Store, Homebrew, MacPorts, DMG, PKG, etc.
    public let installer: String
    public let status: String // Success, Failed, Partial
    public let size: Int64
    
    public init(
        name: String = "",
        version: String = "",
        installDate: Date = Date(),
        source: String = "",
        installer: String = "",
        status: String = "",
        size: Int64 = 0
    ) {
        self.name = name
        self.version = version
        self.installDate = installDate
        self.source = source
        self.installer = installer
        self.status = status
        self.size = size
    }
}

/// Package manager information
public struct PackageManager: Codable, Sendable {
    public let name: String
    public let version: String
    public let path: String
    public let isActive: Bool
    public let lastUsed: Date?
    public let totalPackages: Int
    public let configFile: String?
    
    public init(
        name: String = "",
        version: String = "",
        path: String = "",
        isActive: Bool = false,
        lastUsed: Date? = nil,
        totalPackages: Int = 0,
        configFile: String? = nil
    ) {
        self.name = name
        self.version = version
        self.path = path
        self.isActive = isActive
        self.lastUsed = lastUsed
        self.totalPackages = totalPackages
        self.configFile = configFile
    }
}