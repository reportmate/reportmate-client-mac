import Foundation

/// Configuration manager for ReportMate macOS client
/// Handles configuration hierarchy: CLI args > Environment > UserDefaults (com.github.reportmate) > Defaults
/// Configuration can be set via:
/// - Configuration Profiles (MDM)
/// - /Library/Preferences/com.github.reportmate.plist (system-wide)
/// - ~/Library/Preferences/com.github.reportmate.plist (user-specific)
/// - `defaults write com.github.reportmate <key> <value>`
/// - Environment variables (REPORTMATE_*)
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
    
    /// Save system-wide configuration to standard macOS preferences
    /// Uses /Library/Preferences/com.github.reportmate.plist via UserDefaults
    public func setSystemConfiguration(
        apiUrl: String,
        passphrase: String? = nil,
        deviceId: String? = nil
    ) throws {
        // Use standard macOS preferences location via UserDefaults
        // This writes to /Library/Preferences/com.github.reportmate.plist when run as root
        guard let defaults = UserDefaults(suiteName: "com.github.reportmate") else {
            throw ConfigurationError.failedToAccessPreferences
        }
        
        defaults.set(apiUrl, forKey: "ApiUrl")
        defaults.set(3600, forKey: "CollectionInterval")
        defaults.set("info", forKey: "LogLevel")
        defaults.set([
            "hardware", "system", "network", "security",
            "applications", "management", "inventory"
        ], forKey: "EnabledModules")
        
        if let passphrase = passphrase {
            defaults.set(passphrase, forKey: "Passphrase")
        }
        
        if let deviceId = deviceId {
            defaults.set(deviceId, forKey: "DeviceId")
        }
        
        defaults.synchronize()
    }
    
    public enum ConfigurationError: Error {
        case failedToAccessPreferences
    }
    
    // MARK: - Private Configuration Loading
    
    private static func loadConfiguration(overrides: [String: Any] = [:]) throws -> ReportMateConfiguration {
        var config = ReportMateConfiguration()
        
        // 1. Load defaults (already set in init)
        
        // 2. Load Configuration Profiles / UserDefaults (includes /Library/Preferences/com.github.reportmate.plist)
        if let profileConfig = loadConfigurationProfiles() {
            config.merge(with: profileConfig)
        }
        
        // 3. Load environment variables
        config.merge(with: loadEnvironmentVariables())
        
        // 4. Apply runtime overrides
        config.merge(with: overrides)
        
        return config
    }
    
    private static func loadConfigurationProfiles() -> [String: Any]? {
        // Check for Configuration Profile managed preferences
        let profileDefaults = UserDefaults(suiteName: "com.github.reportmate")
        
        guard let profileDefaults = profileDefaults else { return nil }
        
        var config: [String: Any] = [:]
        
        // Map Configuration Profile keys to internal configuration
        // Passphrase is for device-to-api authentication
        let keyMappings: [String: String] = [
            "ApiUrl": "ApiUrl",
            "DeviceId": "DeviceId", 
            "Passphrase": "Passphrase",
            "CollectionInterval": "CollectionInterval",
            "LogLevel": "LogLevel",
            "EnabledModules": "EnabledModules"
        ]
        
        for (profileKey, configKey) in keyMappings {
            if let value = profileDefaults.object(forKey: profileKey) {
                config[configKey] = value
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
}

/// Storage analysis mode for hardware module
public enum StorageAnalysisMode: String {
    case quick = "quick"   // Drive totals only (capacity, free space)
    case deep = "deep"     // Full directory analysis with per-folder sizes
    case auto = "auto"     // Deep if cache expired (>24h), otherwise use cache
}

/// ReportMate configuration structure
public struct ReportMateConfiguration {
    public var apiUrl: String?
    public var deviceId: String?
    /// Client passphrase for API authentication (X-Client-Passphrase header)
    /// Configured via REPORTMATE_PASSPHRASE environment variable or Passphrase plist key
    public var passphrase: String?
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
    
    /// Storage analysis mode: quick, deep, or auto (default: auto)
    /// - quick: Drive totals only (fast, ~1 second)
    /// - deep: Full directory analysis with per-folder sizes (slow, ~minutes to hours depending on drive size)
    /// - auto: Use cached deep analysis if available and <24h old, otherwise run deep analysis
    public var storageMode: StorageAnalysisMode = .auto
    
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
        if let storageMode = other["StorageMode"] as? String, 
           let mode = StorageAnalysisMode(rawValue: storageMode) { self.storageMode = mode }
    }
}