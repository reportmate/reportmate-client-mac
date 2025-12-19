import Foundation

/// System module data models for macOS ReportMate client
/// These models represent system information collected from the macOS system

// MARK: - System Models

/// System module information structure (comprehensive system data for module processing)
public struct SystemModuleInfo: Codable, Sendable {
    public let operatingSystem: OSVersionInfo
    public let systemDetails: SystemDetails
    public let uptime: Int
    public let uptimeString: String
    public let kernelInfo: KernelInfo
    public let scheduledTasks: [StartupItem]
    public let services: [LaunchdService]
    public let environment: [String: String]
    public let systemConfiguration: SystemConfiguration
    
    public init(
        osVersion: OSVersionInfo,
        systemDetails: SystemDetails,
        uptimeInfo: UptimeInfo,
        kernelInfo: KernelInfo,
        startupItems: [StartupItem] = [],
        launchdServices: [LaunchdService] = [],
        environmentVariables: [String: String] = [:],
        systemConfiguration: SystemConfiguration
    ) {
        self.operatingSystem = osVersion
        self.systemDetails = systemDetails
        self.uptime = uptimeInfo.totalSeconds
        self.uptimeString = uptimeInfo.displayString
        self.kernelInfo = kernelInfo
        self.scheduledTasks = startupItems
        self.services = launchdServices
        self.environment = environmentVariables
        self.systemConfiguration = systemConfiguration
    }
}

/// Operating system version information
public struct OSVersionInfo: Codable, Sendable {
    public let name: String
    public let version: String
    public let majorVersion: Int
    public let minorVersion: Int
    public let patchVersion: Int
    public let buildNumber: String
    public let platform: String
    public let architecture: String
    public let kernelVersion: String
    
    public init(
        name: String,
        version: String,
        majorVersion: Int,
        minorVersion: Int,
        patchVersion: Int,
        buildNumber: String,
        platform: String,
        architecture: String,
        kernelVersion: String
    ) {
        self.name = name
        self.version = version
        self.majorVersion = majorVersion
        self.minorVersion = minorVersion
        self.patchVersion = patchVersion
        self.buildNumber = buildNumber
        self.platform = platform
        self.architecture = architecture
        self.kernelVersion = kernelVersion
    }
    
    public var fullVersionString: String {
        return "\(name) \(version) (\(buildNumber))"
    }
}

/// System details information
public struct SystemDetails: Codable, Sendable {
    public let hostname: String
    public let computerName: String
    public let localHostname: String
    public let systemUUID: String
    public let currentUser: String
    public let bootTime: String  // ISO8601 string for flexibility
    public let timeZone: String
    public let locale: String
    public let systemIntegrityProtection: Bool
    public let secureBootLevel: String?
    public let keyboardLayouts: [String]?
    public let rosetta2Installed: Bool?
    public let rosetta2Status: String?
    
    public init(
        hostname: String,
        computerName: String,
        localHostname: String,
        systemUUID: String,
        currentUser: String,
        bootTime: String,
        timeZone: String,
        locale: String,
        systemIntegrityProtection: Bool,
        secureBootLevel: String? = nil,
        keyboardLayouts: [String]? = nil,
        rosetta2Installed: Bool? = nil,
        rosetta2Status: String? = nil
    ) {
        self.hostname = hostname
        self.computerName = computerName
        self.localHostname = localHostname
        self.systemUUID = systemUUID
        self.currentUser = currentUser
        self.bootTime = bootTime
        self.timeZone = timeZone
        self.locale = locale
        self.systemIntegrityProtection = systemIntegrityProtection
        self.secureBootLevel = secureBootLevel
        self.keyboardLayouts = keyboardLayouts
        self.rosetta2Installed = rosetta2Installed
        self.rosetta2Status = rosetta2Status
    }
}

/// System uptime information
public struct UptimeInfo: Codable, Sendable {
    public let totalSeconds: Int
    public let days: Int
    public let hours: Int
    public let minutes: Int
    public let seconds: Int
    public let bootTime: Date
    public let lastWakeTime: Date?
    
    public init(
        totalSeconds: Int,
        bootTime: Date,
        lastWakeTime: Date? = nil
    ) {
        self.totalSeconds = totalSeconds
        self.bootTime = bootTime
        self.lastWakeTime = lastWakeTime
        
        // Calculate breakdown
        let totalSecondsInt = totalSeconds
        self.days = totalSecondsInt / 86400
        let remainingAfterDays = totalSecondsInt % 86400
        self.hours = remainingAfterDays / 3600
        let remainingAfterHours = remainingAfterDays % 3600
        self.minutes = remainingAfterHours / 60
        self.seconds = remainingAfterHours % 60
    }
    
    public var displayString: String {
        if days > 0 {
            return "\(days) days, \(hours) hours, \(minutes) minutes"
        } else if hours > 0 {
            return "\(hours) hours, \(minutes) minutes"
        } else {
            return "\(minutes) minutes, \(seconds) seconds"
        }
    }
}

/// Kernel information
public struct KernelInfo: Codable, Sendable {
    public let version: String
    public let release: String
    public let machine: String
    public let arguments: [String]
    public let bootPath: String?
    public let loadAddress: String?
    public let uuid: String?
    
    public init(
        version: String,
        release: String,
        machine: String,
        arguments: [String] = [],
        bootPath: String? = nil,
        loadAddress: String? = nil,
        uuid: String? = nil
    ) {
        self.version = version
        self.release = release
        self.machine = machine
        self.arguments = arguments
        self.bootPath = bootPath
        self.loadAddress = loadAddress
        self.uuid = uuid
    }
}

/// Startup item information
public struct StartupItem: Codable, Sendable {
    public let name: String
    public let path: String
    public let arguments: [String]
    public let type: StartupItemType
    public let source: String
    public let status: StartupItemStatus
    public let runAtLoad: Bool
    public let username: String?
    
    public init(
        name: String,
        path: String,
        arguments: [String] = [],
        type: StartupItemType,
        source: String,
        status: StartupItemStatus,
        runAtLoad: Bool = false,
        username: String? = nil
    ) {
        self.name = name
        self.path = path
        self.arguments = arguments
        self.type = type
        self.source = source
        self.status = status
        self.runAtLoad = runAtLoad
        self.username = username
    }
}

/// Startup item type enumeration
public enum StartupItemType: String, Codable, Sendable {
    case launchAgent = "LaunchAgent"
    case launchDaemon = "LaunchDaemon"
    case loginItem = "LoginItem"
    case kernel_extension = "KernelExtension"
    case system_extension = "SystemExtension"
    case unknown = "Unknown"
}

/// Startup item status enumeration
public enum StartupItemStatus: String, Codable, Sendable {
    case enabled = "Enabled"
    case disabled = "Disabled"
    case loaded = "Loaded"
    case unloaded = "Unloaded"
    case error = "Error"
    case unknown = "Unknown"
}

/// Launch daemon/agent service information
public struct LaunchdService: Codable, Sendable {
    public let label: String
    public let path: String
    public let status: LaunchdStatus
    public let pid: Int?
    public let program: String?
    public let programArguments: [String]
    public let runAtLoad: Bool
    public let keepAlive: Bool
    public let onDemand: Bool
    public let disabled: Bool
    public let username: String?
    public let groupname: String?
    public let workingDirectory: String?
    public let rootDirectory: String?
    public let standardOutPath: String?
    public let standardErrorPath: String?
    public let exitTimeout: Int?
    public let startInterval: Int?
    public let watchPaths: [String]
    public let queueDirectories: [String]
    
    public init(
        label: String,
        path: String,
        status: LaunchdStatus,
        pid: Int? = nil,
        program: String? = nil,
        programArguments: [String] = [],
        runAtLoad: Bool = false,
        keepAlive: Bool = false,
        onDemand: Bool = false,
        disabled: Bool = false,
        username: String? = nil,
        groupname: String? = nil,
        workingDirectory: String? = nil,
        rootDirectory: String? = nil,
        standardOutPath: String? = nil,
        standardErrorPath: String? = nil,
        exitTimeout: Int? = nil,
        startInterval: Int? = nil,
        watchPaths: [String] = [],
        queueDirectories: [String] = []
    ) {
        self.label = label
        self.path = path
        self.status = status
        self.pid = pid
        self.program = program
        self.programArguments = programArguments
        self.runAtLoad = runAtLoad
        self.keepAlive = keepAlive
        self.onDemand = onDemand
        self.disabled = disabled
        self.username = username
        self.groupname = groupname
        self.workingDirectory = workingDirectory
        self.rootDirectory = rootDirectory
        self.standardOutPath = standardOutPath
        self.standardErrorPath = standardErrorPath
        self.exitTimeout = exitTimeout
        self.startInterval = startInterval
        self.watchPaths = watchPaths
        self.queueDirectories = queueDirectories
    }
}

/// Launch daemon status enumeration
public enum LaunchdStatus: String, Codable, Sendable {
    case loaded = "Loaded"
    case unloaded = "Unloaded"
    case running = "Running"
    case stopped = "Stopped"
    case error = "Error"
    case disabled = "Disabled"
    case unknown = "Unknown"
}

/// System configuration information
public struct SystemConfiguration: Codable, Sendable {
    public let softwareUpdateSettings: SoftwareUpdateSettings
    public let energySettings: EnergySettings
    public let dateTimeSettings: DateTimeSettings
    public let regionSettings: RegionSettings
    public let accessibilitySettings: AccessibilitySettings?
    public let screenSaverSettings: ScreenSaverSettings
    
    public init(
        softwareUpdateSettings: SoftwareUpdateSettings,
        energySettings: EnergySettings,
        dateTimeSettings: DateTimeSettings,
        regionSettings: RegionSettings,
        accessibilitySettings: AccessibilitySettings? = nil,
        screenSaverSettings: ScreenSaverSettings
    ) {
        self.softwareUpdateSettings = softwareUpdateSettings
        self.energySettings = energySettings
        self.dateTimeSettings = dateTimeSettings
        self.regionSettings = regionSettings
        self.accessibilitySettings = accessibilitySettings
        self.screenSaverSettings = screenSaverSettings
    }
}

/// Software update settings
public struct SoftwareUpdateSettings: Codable, Sendable {
    public let automaticCheckEnabled: Bool
    public let automaticDownloadEnabled: Bool
    public let automaticInstallOSUpdates: Bool
    public let automaticInstallAppUpdates: Bool
    public let automaticInstallSecurityUpdates: Bool
    public let automaticInstallConfigDataUpdates: Bool
    public let lastCheckDate: String?  // ISO8601 string
    public let lastCheckTime: String?  // Alternate field name from Python
    public let lastFullCheckTime: String?  // From Python script
    public let pendingUpdates: [[String: AnyCodable]]?  // From Python script
    
    public init(
        automaticCheckEnabled: Bool = true,
        automaticDownloadEnabled: Bool = false,
        automaticInstallOSUpdates: Bool = false,
        automaticInstallAppUpdates: Bool = false,
        automaticInstallSecurityUpdates: Bool = false,
        automaticInstallConfigDataUpdates: Bool = false,
        lastCheckDate: String? = nil,
        lastCheckTime: String? = nil,
        lastFullCheckTime: String? = nil,
        pendingUpdates: [[String: AnyCodable]]? = nil
    ) {
        self.automaticCheckEnabled = automaticCheckEnabled
        self.automaticDownloadEnabled = automaticDownloadEnabled
        self.automaticInstallOSUpdates = automaticInstallOSUpdates
        self.automaticInstallAppUpdates = automaticInstallAppUpdates
        self.automaticInstallSecurityUpdates = automaticInstallSecurityUpdates
        self.automaticInstallConfigDataUpdates = automaticInstallConfigDataUpdates
        self.lastCheckDate = lastCheckDate
        self.lastCheckTime = lastCheckTime
        self.lastFullCheckTime = lastFullCheckTime
        self.pendingUpdates = pendingUpdates
    }
}

/// Energy/power management settings
public struct EnergySettings: Codable, Sendable {
    public let computerSleepTime: Int // in minutes
    public let displaySleepTime: Int // in minutes
    public let disableSleep: Bool
    public let wakeOnNetworkAccess: Bool
    public let restartAfterPowerFailure: Bool
    public let powerNapEnabled: Bool?
    public let standbyDelay: Int? // in seconds
    
    public init(
        computerSleepTime: Int = 0,
        displaySleepTime: Int = 0,
        disableSleep: Bool = false,
        wakeOnNetworkAccess: Bool = false,
        restartAfterPowerFailure: Bool = false,
        powerNapEnabled: Bool? = nil,
        standbyDelay: Int? = nil
    ) {
        self.computerSleepTime = computerSleepTime
        self.displaySleepTime = displaySleepTime
        self.disableSleep = disableSleep
        self.wakeOnNetworkAccess = wakeOnNetworkAccess
        self.restartAfterPowerFailure = restartAfterPowerFailure
        self.powerNapEnabled = powerNapEnabled
        self.standbyDelay = standbyDelay
    }
}

/// Date and time settings
public struct DateTimeSettings: Codable, Sendable {
    public let timeZone: String
    public let ntpEnabled: Bool
    public let ntpServer: String?
    public let is24HourFormat: Bool
    public let dateFormat: String
    public let automaticTimeZone: Bool
    
    public init(
        timeZone: String,
        ntpEnabled: Bool = true,
        ntpServer: String? = nil,
        is24HourFormat: Bool = false,
        dateFormat: String = "MM/dd/yyyy",
        automaticTimeZone: Bool = true
    ) {
        self.timeZone = timeZone
        self.ntpEnabled = ntpEnabled
        self.ntpServer = ntpServer
        self.is24HourFormat = is24HourFormat
        self.dateFormat = dateFormat
        self.automaticTimeZone = automaticTimeZone
    }
}

/// Region and localization settings
public struct RegionSettings: Codable, Sendable {
    public let country: String
    public let locale: String
    public let language: String
    public let currency: String
    public let measurementUnits: String
    public let calendarType: String
    
    public init(
        country: String,
        locale: String,
        language: String,
        currency: String,
        measurementUnits: String = "Metric",
        calendarType: String = "Gregorian"
    ) {
        self.country = country
        self.locale = locale
        self.language = language
        self.currency = currency
        self.measurementUnits = measurementUnits
        self.calendarType = calendarType
    }
}

/// Accessibility settings
public struct AccessibilitySettings: Codable, Sendable {
    public let voiceOverEnabled: Bool
    public let zoomEnabled: Bool
    public let stickyKeysEnabled: Bool
    public let slowKeysEnabled: Bool
    public let mouseKeysEnabled: Bool
    public let fullKeyboardAccessEnabled: Bool
    public let switchControlEnabled: Bool
    
    public init(
        voiceOverEnabled: Bool = false,
        zoomEnabled: Bool = false,
        stickyKeysEnabled: Bool = false,
        slowKeysEnabled: Bool = false,
        mouseKeysEnabled: Bool = false,
        fullKeyboardAccessEnabled: Bool = false,
        switchControlEnabled: Bool = false
    ) {
        self.voiceOverEnabled = voiceOverEnabled
        self.zoomEnabled = zoomEnabled
        self.stickyKeysEnabled = stickyKeysEnabled
        self.slowKeysEnabled = slowKeysEnabled
        self.mouseKeysEnabled = mouseKeysEnabled
        self.fullKeyboardAccessEnabled = fullKeyboardAccessEnabled
        self.switchControlEnabled = switchControlEnabled
    }
}

/// Screen saver settings
public struct ScreenSaverSettings: Codable, Sendable {
    public let enabled: Bool
    public let timeout: Int // in minutes
    public let moduleName: String?
    public let askForPasswordDelay: Int // in minutes
    public let showClock: Bool
    
    public init(
        enabled: Bool = true,
        timeout: Int = 20,
        moduleName: String? = nil,
        askForPasswordDelay: Int = 0,
        showClock: Bool = false
    ) {
        self.enabled = enabled
        self.timeout = timeout
        self.moduleName = moduleName
        self.askForPasswordDelay = askForPasswordDelay
        self.showClock = showClock
    }
}