import Foundation

/// Configuration manager for ReportMate macOS client
/// Handles configuration hierarchy: CLI args > Environment > Config Profiles > System plist > User plist > Defaults
public class ConfigurationManager {
    public private(set) var configuration: ReportMateConfiguration
    private var overrides: [String: Any] = [:]
    
    public init() throws {
        self.configuration = try Self.loadConfiguration()
    }
    
    /// Set runtime override for configuration value
    public func setOverride(key: String, value: Any) {
        overrides[key] = value
        // Refresh configuration with new overrides
        do {
            self.configuration = try Self.loadConfiguration(overrides: overrides)
        } catch {
            print("Warning: Failed to apply configuration override: \(error)")
        }
    }
    
    /// Save system-wide configuration
    public func setSystemConfiguration(
        apiUrl: String,
        deviceId: String? = nil,
        apiKey: String? = nil
    ) throws {
        
        let systemConfigPath = "/Library/Managed Reports/reportmate.plist"
        
        // Ensure directory exists
        let systemConfigDir = URL(fileURLWithPath: systemConfigPath).deletingLastPathComponent()
        try FileManager.default.createDirectory(at: systemConfigDir, withIntermediateDirectories: true)
        
        // Create configuration dictionary
        var configDict: [String: Any] = [
            "ApiUrl": apiUrl,
            "CollectionInterval": 3600,
            "LogLevel": "info",
            "EnabledModules": [
                "hardware", "system", "network", "security", 
                "applications", "management", "inventory"
            ]
        ]
        
        if let deviceId = deviceId {
            configDict["DeviceId"] = deviceId
        }
        
        if let apiKey = apiKey {
            configDict["ApiKey"] = apiKey
        }
        
        // Write plist file
        let plistData = try PropertyListSerialization.data(
            fromPropertyList: configDict,
            format: .xml,
            options: 0
        )
        
        try plistData.write(to: URL(fileURLWithPath: systemConfigPath))
    }
    
    // MARK: - Private Configuration Loading
    
    private static func loadConfiguration(overrides: [String: Any] = [:]) throws -> ReportMateConfiguration {
        var config = ReportMateConfiguration()
        
        // 1. Load defaults (already set in init)
        
        // 2. Load user plist (~/<user>/Library/Managed Reports/reportmate.plist)
        if let userConfig = loadUserPlist() {
            config.merge(with: userConfig)
        }
        
        // 3. Load system plist (/Library/Managed Reports/reportmate.plist)
        if let systemConfig = loadSystemPlist() {
            config.merge(with: systemConfig)
        }
        
        // 4. Load global preferences plist (/Library/Preferences/com.github.reportmate.plist)
        // Read directly as a file — UserDefaults(suiteName:) maps to the CURRENT USER's home
        // domain (/var/root/Library/Preferences/ when running as root/daemon), not this global
        // file. Direct file I/O is the correct approach for daemon-context admin tools.
        if let globalConfig = loadGlobalPreferencesPlist() {
            config.merge(with: globalConfig)
        }
        
        // 5. Load MDM-managed Configuration Profiles (highest external authority)
        // UserDefaults correctly surfaces managed preferences regardless of user context.
        if let profileConfig = loadConfigurationProfiles() {
            config.merge(with: profileConfig)
        }
        
        // 6. Load environment variables
        config.merge(with: loadEnvironmentVariables())
        
        // 7. Apply runtime overrides
        config.merge(with: overrides)
        
        return config
    }
    
    private static func loadUserPlist() -> [String: Any]? {
        let userConfigPath = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Managed Reports/reportmate.plist")
        
        return loadPlist(at: userConfigPath)
    }
    
    private static func loadSystemPlist() -> [String: Any]? {
        let systemConfigPath = URL(fileURLWithPath: "/Library/Managed Reports/reportmate.plist")
        return loadPlist(at: systemConfigPath)
    }

    private static func loadGlobalPreferencesPlist() -> [String: Any]? {
        // /Library/Preferences/com.github.reportmate.plist is written by the postinstall
        // script and by `defaults write /Library/Preferences/com.github.reportmate ...`.
        // It must be read as a raw file because UserDefaults(suiteName:) maps to the current
        // user's HOME preferences domain — which is /var/root/Library/Preferences/ for root/
        // daemon processes, not this global path.
        let globalPrefsPath = URL(fileURLWithPath: "/Library/Preferences/com.github.reportmate.plist")
        return loadPlist(at: globalPrefsPath)
    }
    
    private static func loadConfigurationProfiles() -> [String: Any]? {
        // Use CFPreferencesCopyAppValue instead of UserDefaults(suiteName:).
        // UserDefaults(suiteName: bundleID) triggers an OS warning ("does not make
        // sense and will not work") when the suite name matches the process's own
        // bundle identifier. CFPreferences reads the same MDM-managed preferences
        // domain without that restriction.
        let appID = "com.github.reportmate" as CFString

        let keys = ["ApiUrl", "DeviceId", "Passphrase", "CollectionInterval", "LogLevel", "EnabledModules"]
        var config: [String: Any] = [:]

        for key in keys {
            if let value = CFPreferencesCopyAppValue(key as CFString, appID) {
                config[key] = value
            }
        }

        return config.isEmpty ? nil : config
    }
    
    private static func loadEnvironmentVariables() -> [String: Any] {
        var config: [String: Any] = [:]
        let environment = ProcessInfo.processInfo.environment
        
        // Map environment variables to configuration keys
        let envMappings: [String: String] = [
            "REPORTMATE_API_URL": "ApiUrl",
            "REPORTMATE_DEVICE_ID": "DeviceId",
            "REPORTMATE_PASSPHRASE": "Passphrase",
            "REPORTMATE_COLLECTION_INTERVAL": "CollectionInterval",
            "REPORTMATE_LOG_LEVEL": "LogLevel"
        ]
        
        for (envKey, configKey) in envMappings {
            if let value = environment[envKey] {
                // Convert string values to appropriate types
                switch configKey {
                case "CollectionInterval":
                    if let intValue = Int(value) {
                        config[configKey] = intValue
                    }
                case "EnabledModules":
                    config[configKey] = value.components(separatedBy: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                default:
                    config[configKey] = value
                }
            }
        }
        
        return config
    }
    
    private static func loadPlist(at url: URL) -> [String: Any]? {
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        
        do {
            let data = try Data(contentsOf: url)
            let plist = try PropertyListSerialization.propertyList(
                from: data,
                options: [],
                format: nil
            )
            return plist as? [String: Any]
        } catch {
            print("Warning: Failed to load plist at \(url.path): \(error)")
            return nil
        }
    }
}

/// ReportMate configuration structure
/// Storage analysis depth for hardware module
public enum StorageMode: String {
    case quick  // Drive totals only (fast)
    case deep   // Full directory analysis (slow)
    case auto   // Deep first run, use cache on subsequent runs
}

public struct ReportMateConfiguration {
    public var apiUrl: String?
    public var deviceId: String?
    /// Client passphrase for API authentication (X-Client-Passphrase header)
    /// Configured via REPORTMATE_PASSPHRASE environment variable or Passphrase plist key
    public var passphrase: String?
    public var storageMode: StorageMode = .auto
    public var collectionInterval: Int = 3600 // 1 hour default
    public var logLevel: String = "info"
    public var enabledModules: [String] = [
        "hardware", "system", "network", "security", 
        "applications", "management", "inventory"
    ]
    public var osqueryPath: String = "/usr/local/bin/osqueryi"
    
    /// Path to macadmins osquery extension binary
    /// Default: bundled extension in Resources or /usr/local/bin
    public var osqueryExtensionPath: String?
    
    /// Enable automatic extension loading (default: true)
    /// When enabled, OSQueryService will load macadmins_extension.ext if available
    /// This provides: mdm, macos_profiles, alt_system_info, and other macOS tables
    public var extensionEnabled: Bool = true
    
    /// Use alt_system_info table instead of system_info (macOS 15+ compatibility)
    /// When true, queries will prefer alt_system_info to avoid network permission prompts
    public var useAltSystemInfo: Bool = true
    
    public var validateSSL: Bool = true
    public var timeout: Int = 300 // 5 minutes
    
    /// Merge configuration with another dictionary
    mutating func merge(with other: [String: Any]) {
        if let apiUrl = other["ApiUrl"] as? String { self.apiUrl = apiUrl }
        if let deviceId = other["DeviceId"] as? String { self.deviceId = deviceId }
        if let passphrase = other["Passphrase"] as? String { self.passphrase = passphrase }
        if let interval = other["CollectionInterval"] as? Int { self.collectionInterval = interval }
        if let logLevel = other["LogLevel"] as? String { self.logLevel = logLevel }
        if let modules = other["EnabledModules"] as? [String] { self.enabledModules = modules }
        if let osqueryPath = other["OsqueryPath"] as? String { self.osqueryPath = osqueryPath }
        if let extensionPath = other["OsqueryExtensionPath"] as? String { self.osqueryExtensionPath = extensionPath }
        if let extensionEnabled = other["ExtensionEnabled"] as? Bool { self.extensionEnabled = extensionEnabled }
        if let useAltSystemInfo = other["UseAltSystemInfo"] as? Bool { self.useAltSystemInfo = useAltSystemInfo }
        if let validateSSL = other["ValidateSSL"] as? Bool { self.validateSSL = validateSSL }
        if let timeout = other["Timeout"] as? Int { self.timeout = timeout }
        if let storageModeStr = other["StorageMode"] as? String,
           let mode = StorageMode(rawValue: storageModeStr.lowercased()) {
            self.storageMode = mode
        }
    }
}