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
        
        // 2. Load user plist
        if let userConfig = loadUserPlist() {
            config.merge(with: userConfig)
        }
        
        // 3. Load system plist  
        if let systemConfig = loadSystemPlist() {
            config.merge(with: systemConfig)
        }
        
        // 4. Load Configuration Profiles
        if let profileConfig = loadConfigurationProfiles() {
            config.merge(with: profileConfig)
        }
        
        // 5. Load environment variables
        config.merge(with: loadEnvironmentVariables())
        
        // 6. Apply runtime overrides
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
    
    private static func loadConfigurationProfiles() -> [String: Any]? {
        // Check for Configuration Profile managed preferences
        let profileDefaults = UserDefaults(suiteName: "com.github.reportmate")
        
        guard let profileDefaults = profileDefaults else { return nil }
        
        var config: [String: Any] = [:]
        
        // Map Configuration Profile keys to internal configuration
        let keyMappings: [String: String] = [
            "ApiUrl": "ApiUrl",
            "DeviceId": "DeviceId", 
            "ApiKey": "ApiKey",
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
            "REPORTMATE_API_KEY": "ApiKey", 
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
public struct ReportMateConfiguration {
    public var apiUrl: String?
    public var deviceId: String?
    public var apiKey: String?
    public var collectionInterval: Int = 3600 // 1 hour default
    public var logLevel: String = "info"
    public var enabledModules: [String] = [
        "hardware", "system", "network", "security", 
        "applications", "management", "inventory"
    ]
    public var osqueryPath: String = "/usr/local/bin/osqueryi"
    public var validateSSL: Bool = true
    public var timeout: Int = 300 // 5 minutes
    
    /// Merge configuration with another dictionary
    mutating func merge(with other: [String: Any]) {
        if let apiUrl = other["ApiUrl"] as? String { self.apiUrl = apiUrl }
        if let deviceId = other["DeviceId"] as? String { self.deviceId = deviceId }
        if let apiKey = other["ApiKey"] as? String { self.apiKey = apiKey }
        if let interval = other["CollectionInterval"] as? Int { self.collectionInterval = interval }
        if let logLevel = other["LogLevel"] as? String { self.logLevel = logLevel }
        if let modules = other["EnabledModules"] as? [String] { self.enabledModules = modules }
        if let osqueryPath = other["OsqueryPath"] as? String { self.osqueryPath = osqueryPath }
        if let validateSSL = other["ValidateSSL"] as? Bool { self.validateSSL = validateSSL }
        if let timeout = other["Timeout"] as? Int { self.timeout = timeout }
    }
}