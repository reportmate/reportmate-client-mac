import Foundation

/// Configuration manager for ReportMate macOS client
/// Handles configuration hierarchy: CLI args > Environment > plist file > Defaults
/// Configuration can be set via:
/// - Configuration Profiles (MDM) → /Library/Managed Preferences/com.github.reportmate.plist
/// - System plist (written as root) → /Library/Preferences/com.github.reportmate.plist
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
    
    /// Save system-wide configuration to /Library/Preferences/com.github.reportmate.plist
    /// Writes directly via NSDictionary to avoid the UserDefaults(suiteName: bundleId) restriction.
    public func setSystemConfiguration(
        apiUrl: String,
        passphrase: String? = nil,
        deviceId: String? = nil
    ) throws {
        let plistPath = "/Library/Preferences/com.github.reportmate.plist"

        // Load existing values so we don't clobber unrelated keys
        var dict: [String: Any] = (NSDictionary(contentsOfFile: plistPath) as? [String: Any]) ?? [:]

        dict["ApiUrl"] = apiUrl
        dict["CollectionInterval"] = 3600
        dict["LogLevel"] = "info"
        dict["EnabledModules"] = [
            "hardware", "system", "network", "security",
            "applications", "management", "inventory"
        ]
        if let passphrase = passphrase { dict["Passphrase"] = passphrase }
        if let deviceId = deviceId { dict["DeviceId"] = deviceId }

        let nsd = NSDictionary(dictionary: dict)
        guard nsd.write(toFile: plistPath, atomically: true) else {
            throw ConfigurationError.failedToAccessPreferences
        }
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
        // Read directly from the plist file rather than via UserDefaults(suiteName:).
        // Using the app's own bundle identifier as a suite name is explicitly rejected by
        // macOS ("will not work"), so UserDefaults-based reading is unreliable here.
        // Reading the file directly works regardless of which user context the runner executes under.
        let plistPaths = [
            "/Library/Managed Preferences/com.github.reportmate.plist", // MDM-pushed (highest priority)
            "/Library/Preferences/com.github.reportmate.plist",          // system-wide (written as root)
        ]

        var merged: [String: Any] = [:]
        for path in plistPaths {
            if let dict = NSDictionary(contentsOfFile: path) as? [String: Any] {
                merged.merge(dict) { _, new in new }
            }
        }

        return merged.isEmpty ? nil : merged
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