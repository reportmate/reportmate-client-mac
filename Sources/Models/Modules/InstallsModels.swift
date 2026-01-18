import Foundation

/// Installs module data model for macOS - encompasses software installation and package management systems
public struct InstallsData: ModuleDataModel, Sendable {
    public var moduleId: String { "installs" }
    public let collectionTimestamp: Date
    public let success: Bool
    public let errorMessage: String?
    
    public let deviceId: String
    
    // Cimian Integration (cross-platform: macOS and Windows)
    public var cimian: CimianInfo?
    public var cacheStatus: [String: AnyCodable] = [:]
    public var cimianSnapshot: [String: AnyCodable]?
    public var bootstrapModeActive: Bool = false
    
    // Munki Integration (macOS only - via macadmins osquery extension)
    public var munki: MunkiInfo?
    
    public init(
        deviceId: String,
        collectionTimestamp: Date = Date(),
        success: Bool = true,
        errorMessage: String? = nil,
        cimian: CimianInfo? = nil,
        munki: MunkiInfo? = nil
    ) {
        self.deviceId = deviceId
        self.collectionTimestamp = collectionTimestamp
        self.success = success
        self.errorMessage = errorMessage
        self.cimian = cimian
        self.munki = munki
    }
}

// MARK: - Munki Models (macOS only - via macadmins osquery extension)

/// Munki managed software information from macadmins osquery extension
/// Reference: https://github.com/macadmins/osquery-extension
/// Tables: munki_info, munki_installs
public struct MunkiInfo: Codable, Sendable {
    // Core installation status
    public var isInstalled: Bool = false
    public var version: String = ""
    public var status: String = "Unknown"  // Active, Inactive, Error
    
    // Munki configuration (from munki_info table)
    public var clientIdentifier: String?
    public var manifestName: String?
    public var softwareRepoURL: String?
    
    // Run state (from munki_info table)
    public var lastRun: Date?
    public var lastRunSuccess: Bool = false
    public var consoleUser: String?
    public var startTime: String?
    public var endTime: String?
    
    // Run errors/warnings (from munki_info table)
    public var errors: String?
    public var warnings: String?
    public var problemInstalls: String?
    
    // Managed items (from munki_installs table)
    public var items: [MunkiItem] = []
    
    // Computed properties for dashboard compatibility
    public var pendingPackages: [String] {
        items.filter { $0.status == "Pending" }.map { $0.name }
    }
    
    public var installedItems: [MunkiItem] {
        items.filter { $0.status == "Installed" }
    }
    
    // Reports metadata
    public var reports: [String: MunkiReportFileInfo] = [:]
    public var logs: [String] = []
    
    public init() {}
}

/// Munki package item from munki_installs table
/// Maps directly to macadmins osquery extension munki_installs columns
public struct MunkiItem: Codable, Sendable {
    public var id: String = ""
    public var name: String = ""
    public var displayName: String = ""
    public var version: String = ""            // Version Munki wants to install
    public var installedVersion: String = ""    // Currently installed version
    public var status: String = "Unknown"       // Installed, Pending, Removed (mapped from 'installed' column)
    public var installedSize: Int = 0
    public var endTime: String = ""            // Last Munki run end time for this item
    
    // Enhanced fields for ReportMate dashboard compatibility
    public var type: String = "munki"
    public var lastUpdate: String = ""
    public var itemSize: String?
    
    // Error, warning, and pending reason messages (matches Windows CimianItem pattern)
    public var lastError: String = ""          // Last error message for this item
    public var lastWarning: String = ""        // Last warning message for this item
    public var pendingReason: String = ""      // Why the package is pending (e.g., "Update available: 1.0 → 2.0")
    
    public init() {}
    
    public init(name: String, displayName: String? = nil, version: String = "", installedVersion: String = "", installed: Bool = false) {
        self.id = name.lowercased().replacingOccurrences(of: " ", with: "-")
        self.name = name
        self.displayName = displayName ?? name
        self.version = version
        self.installedVersion = installedVersion
        self.status = installed ? "Installed" : "Pending"
        self.type = "munki"
        
        // Derive pending reason for new items
        if !installed && !version.isEmpty {
            if installedVersion.isEmpty || installedVersion == "Unknown" {
                self.pendingReason = "Not yet installed"
            } else if version != installedVersion {
                self.pendingReason = "Update available: \(installedVersion) → \(version)"
            }
        }
    }
}

/// Munki report file info for metadata tracking
public struct MunkiReportFileInfo: Codable, Sendable {
    public var size: String?
    public var mtime: String?
    
    public init() {}
}

public struct CimianInfo: Codable, Sendable {
    public var services: [String] = []
    public var status: String = "Unknown"
    public var isInstalled: Bool = false
    public var activeProcesses: [String] = []
    public var registryConfig: [String: String] = [:]
    public var bootstrapFlagPresent: Bool = false
    public var totalSessions: Int = 0
    public var lastSessionTime: Date?
    public var version: String?
    public var lastRun: Date?
    public var reports: [String: CimianReportFileInfo] = [:]
    public var config: [String: AnyCodable] = [:]
    public var sessions: [CimianSession] = []
    public var items: [CimianItem] = []
    public var events: [CimianEvent] = []
    
    public init() {}
}

public struct CimianReportFileInfo: Codable, Sendable {
    public var size: String?
    public var mtime: String?
    
    public init() {}
}

public struct CimianItem: Codable, Sendable {
    public var id: String?
    public var itemName: String = "Unknown"
    public var displayName: String?
    public var currentStatus: String = "Unknown"
    public var mappedStatus: String?
    public var latestVersion: String = "Unknown"
    public var installedVersion: String = "Unknown"
    public var lastSeenInSession: String?
    public var lastError: String = ""
    public var lastWarning: String = ""
    public var pendingReason: String = ""      // Why the package is pending (e.g., "Update available: 1.0 → 2.0")
    public var installCount: Int = 0
    public var updateCount: Int = 0
    public var failureCount: Int = 0
    public var type: String = "cimian"
    public var lastUpdate: Date?
    
    public init() {}
}

public struct CimianSession: Codable, Sendable {
    public var sessionId: String = ""
    public var runType: String = ""
    public var status: String = ""
    public var startTime: Date?
    public var endTime: Date?
    public var duration: TimeInterval?
    public var durationSeconds: Int = 0
    public var hostname: String = ""
    public var user: String = ""
    public var processId: Int = 0
    public var logVersion: String = ""
    
    public var totalActions: Int = 0
    public var installs: Int = 0
    public var updates: Int = 0
    public var removals: Int = 0
    public var successes: Int = 0
    public var failures: Int = 0
    
    public var totalPackagesManaged: Int = 0
    public var packagesInstalled: Int = 0
    public var packagesPending: Int = 0
    public var packagesFailed: Int = 0
    public var cacheSizeMb: Double = 0.0
    
    public var packagesHandled: [String] = []
    public var environment: [String: String] = [:]
    public var systemInfo: [String: String] = [:]
    public var flags: [String: Bool] = [:]
    public var performanceMetrics: [String: String] = [:]
    public var failedItems: [String] = []
    public var blockingApplications: [String: [String]] = [:]
    public var config: [String: String] = [:]
    
    public init() {}
}

public struct CimianEvent: Codable, Sendable {
    public var eventId: String = ""
    public var sessionId: String = ""
    public var level: String = ""
    public var eventType: String = ""
    public var action: String = ""
    public var status: String = ""
    public var message: String = ""
    public var timestamp: Date?
    public var package: String = ""
    public var version: String = ""
    public var error: String = ""
    public var progress: Int = 0
    public var duration: TimeInterval?
    
    public var sourceFile: String = ""
    public var sourceFunction: String = ""
    public var sourceLine: Int = 0
    public var context: [String: String] = [:]
    
    public var batchId: String = ""
    public var installerType: String = ""
    public var installerPath: String = ""
    public var installerOutput: String = ""
    public var checkOnlyMode: Bool = false
    public var systemContext: [String: String] = [:]
    public var performanceCounters: [String: String] = [:]
    
    public init() {}
}

// Helper for AnyCodable
public struct AnyCodable: Codable, @unchecked Sendable {
    public let value: Any
    
    public init(_ value: Any) {
        self.value = value
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let x = try? container.decode(Bool.self) { value = x }
        else if let x = try? container.decode(Int.self) { value = x }
        else if let x = try? container.decode(Double.self) { value = x }
        else if let x = try? container.decode(String.self) { value = x }
        else if let x = try? container.decode([AnyCodable].self) { value = x.map { $0.value } }
        else if let x = try? container.decode([String: AnyCodable].self) { value = x.mapValues { $0.value } }
        else {
            value = "unknown"
        }
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        if let x = value as? Bool { try container.encode(x) }
        else if let x = value as? Int { try container.encode(x) }
        else if let x = value as? Double { try container.encode(x) }
        else if let x = value as? String { try container.encode(x) }
        else if let x = value as? [Any] { try container.encode(x.map { AnyCodable($0) }) }
        else if let x = value as? [String: Any] { try container.encode(x.mapValues { AnyCodable($0) }) }
        else {
            try container.encode(String(describing: value))
        }
    }
}











