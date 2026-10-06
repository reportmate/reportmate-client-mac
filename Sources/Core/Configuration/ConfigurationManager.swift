import Foundation

/// Configuration manager for ReportMate macOS client
/// Handles configuration hierarchy: CLI args > Config Profiles > System plist > Environment > User plist > Defaults
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
        
        let systemConfigPath = "/Library/Preferences/com.github.reportmate.plist"
        
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
                "applications", "management", "inventory",
                "identity", "peripherals", "installs"
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

    /// Preference domain read for machine settings and configuration-profile policy.
    public static let preferencesDomain = "com.github.reportmate"

    /// Every key ReportMateConfiguration.merge understands. Each one can be set by a
    /// configuration profile, and a profile-forced value beats every other source.
    public static let settingKeys = [
        "ApiUrl", "DeviceId", "Passphrase", "ApiKey",
        "CollectionInterval", "LogLevel", "EnabledModules",
        "OsqueryPath", "OsqueryExtensionPath", "ExtensionEnabled", "UseAltSystemInfo",
        "ValidateSSL", "Timeout", "CompressPayload", "MaxRetryAttempts",
        "QueryTimeoutSeconds", "ExtensionQueryTimeoutSeconds", "ModuleTimeoutSeconds",
        "StorageMode",
    ]

    private static func loadConfiguration(overrides: [String: Any] = [:]) throws -> ReportMateConfiguration {
        resolve(
            userPlist: loadUserPlist(),
            environment: loadEnvironmentVariables(),
            systemPlist: loadSystemPlist(),
            policy: loadConfigurationProfiles(),
            overrides: overrides
        )
    }

    /// Layers the configuration sources, lowest first:
    /// defaults < user plist < environment < /Library/Preferences < configuration profile < one-off overrides.
    /// Overrides are the explicit command-line flags for this run (--api-url, --device-id, --storage-mode).
    /// Environment variables sit with the machine settings and never beat a profile.
    static func resolve(
        userPlist: [String: Any]?,
        environment: [String: Any],
        systemPlist: [String: Any]?,
        policy: [String: Any]?,
        overrides: [String: Any]
    ) -> ReportMateConfiguration {
        var config = ReportMateConfiguration()
        if let userPlist { config.merge(with: userPlist) }
        config.merge(with: environment)
        if let systemPlist { config.merge(with: systemPlist) }
        if let policy { config.merge(with: policy) }
        config.merge(with: overrides)
        return config
    }

    private static func loadUserPlist() -> [String: Any]? {
        let userConfigPath = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Managed Reports/reportmate.plist")

        return loadPlist(at: userConfigPath)
    }

    private static func loadSystemPlist() -> [String: Any]? {
        let systemConfigPath = URL(fileURLWithPath: "/Library/Preferences/com.github.reportmate.plist")
        return loadPlist(at: systemConfigPath)
    }

    /// Values a configuration profile forces, for every setting key.
    private static func loadConfigurationProfiles() -> [String: Any]? {
        policyValues(
            isForced: { CFPreferencesAppValueIsForced($0 as CFString, preferencesDomain as CFString) },
            read: { CFPreferencesCopyAppValue($0 as CFString, preferencesDomain as CFString) }
        )
    }

    /// Collects the forced value of every setting key; nil when a profile forces none.
    static func policyValues(isForced: (String) -> Bool, read: (String) -> Any?) -> [String: Any]? {
        var config: [String: Any] = [:]
        for key in settingKeys where isForced(key) {
            if let value = read(key) {
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
            "REPORTMATE_API_KEY": "ApiKey",
            "REPORTMATE_COLLECTION_INTERVAL": "CollectionInterval",
            "REPORTMATE_LOG_LEVEL": "LogLevel",
            "REPORTMATE_QUERY_TIMEOUT": "QueryTimeoutSeconds",
            "REPORTMATE_EXTENSION_QUERY_TIMEOUT": "ExtensionQueryTimeoutSeconds",
            "REPORTMATE_MODULE_TIMEOUT": "ModuleTimeoutSeconds"
        ]

        for (envKey, configKey) in envMappings {
            if let value = environment[envKey] {
                // Convert string values to appropriate types
                switch configKey {
                case "CollectionInterval":
                    if let intValue = Int(value) {
                        config[configKey] = intValue
                    }
                case "QueryTimeoutSeconds", "ExtensionQueryTimeoutSeconds", "ModuleTimeoutSeconds":
                    if let doubleValue = Double(value) {
                        config[configKey] = doubleValue
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

/// Controls how storage deep analysis is executed
public enum StorageMode: String {
    case quick
    case deep
    case auto
}

/// ReportMate configuration structure
public struct ReportMateConfiguration {
    public var apiUrl: String?
    public var deviceId: String?
    /// Client passphrase for API authentication (X-Client-Passphrase header)
    /// Configured via REPORTMATE_PASSPHRASE environment variable or Passphrase plist key
    public var passphrase: String?
    /// Scoped API key for API authentication (X-API-Key header)
    /// Configured via REPORTMATE_API_KEY environment variable or ApiKey plist key.
    /// Sent alongside the passphrase; the API falls through to the passphrase if the
    /// key is absent or invalid, so this is safe to roll out incrementally.
    public var apiKey: String?
    public var collectionInterval: Int = 3600 // 1 hour default
    public var logLevel: String = "info"
    public var enabledModules: [String] = [
        "hardware", "system", "network", "security",
        "applications", "management", "inventory",
        "identity", "peripherals", "installs"
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

    /// Gzip the check-in body before sending. Set CompressPayload to false in
    /// the managed profile to put a machine back on uncompressed check-ins
    /// without shipping a new client.
    public var compressPayload: Bool = true

    /// Attempts per check-in, counting the first. A transport failure or a
    /// transient server error is resent with backoff until this is spent.
    public var maxRetryAttempts: Int = 3

    /// Per-query timeout for built-in osquery tables. Kills the osqueryi process
    /// if it does not return within this bound, so a single misbehaving table
    /// cannot block the rest of a module's collection.
    public var queryTimeoutSeconds: Double = 30

    /// Per-query timeout for macadmins extension tables. Higher than the built-in
    /// bound because the extension path includes a 7s startup sleep plus the
    /// extension's own registration time. Tables that do online I/O (e.g.
    /// sofa_unpatched_cves fetching the SOFA feed) are the usual offenders.
    public var extensionQueryTimeoutSeconds: Double = 60

    /// Per-module wall-clock timeout. Defensive layer in case the sum of a
    /// module's queries exceeds a useful budget; the module returns whatever
    /// partial data it has and the runner moves on to the next module.
    public var moduleTimeoutSeconds: Double = 120

    /// Controls whether deep storage directory analysis runs on each collection cycle
    public var storageMode: StorageMode = .auto

    /// Merge configuration with another dictionary
    mutating func merge(with other: [String: Any]) {
        if let apiUrl = other["ApiUrl"] as? String { self.apiUrl = apiUrl }
        if let deviceId = other["DeviceId"] as? String { self.deviceId = deviceId }
        if let passphrase = other["Passphrase"] as? String { self.passphrase = passphrase }
        if let apiKey = other["ApiKey"] as? String { self.apiKey = apiKey }
        if let interval = other["CollectionInterval"] as? Int { self.collectionInterval = interval }
        if let logLevel = other["LogLevel"] as? String { self.logLevel = logLevel }
        if let modules = other["EnabledModules"] as? [String] { self.enabledModules = modules }
        if let osqueryPath = other["OsqueryPath"] as? String { self.osqueryPath = osqueryPath }
        if let extensionPath = other["OsqueryExtensionPath"] as? String { self.osqueryExtensionPath = extensionPath }
        if let extensionEnabled = other["ExtensionEnabled"] as? Bool { self.extensionEnabled = extensionEnabled }
        if let useAltSystemInfo = other["UseAltSystemInfo"] as? Bool { self.useAltSystemInfo = useAltSystemInfo }
        if let validateSSL = other["ValidateSSL"] as? Bool { self.validateSSL = validateSSL }
        if let timeout = other["Timeout"] as? Int { self.timeout = timeout }
        if let compressPayload = other["CompressPayload"] as? Bool { self.compressPayload = compressPayload }
        if let maxRetryAttempts = other["MaxRetryAttempts"] as? Int { self.maxRetryAttempts = maxRetryAttempts }
        if let queryTimeout = other["QueryTimeoutSeconds"] as? Double { self.queryTimeoutSeconds = queryTimeout }
        else if let queryTimeoutInt = other["QueryTimeoutSeconds"] as? Int { self.queryTimeoutSeconds = Double(queryTimeoutInt) }
        if let extQueryTimeout = other["ExtensionQueryTimeoutSeconds"] as? Double { self.extensionQueryTimeoutSeconds = extQueryTimeout }
        else if let extQueryTimeoutInt = other["ExtensionQueryTimeoutSeconds"] as? Int { self.extensionQueryTimeoutSeconds = Double(extQueryTimeoutInt) }
        if let moduleTimeout = other["ModuleTimeoutSeconds"] as? Double { self.moduleTimeoutSeconds = moduleTimeout }
        else if let moduleTimeoutInt = other["ModuleTimeoutSeconds"] as? Int { self.moduleTimeoutSeconds = Double(moduleTimeoutInt) }
        if let storageModeStr = other["StorageMode"] as? String,
           let mode = StorageMode(rawValue: storageModeStr) { self.storageMode = mode }
    }
}