import Foundation

/// API client for communicating with ReportMate backend
public class APIClient {
    private let configuration: ReportMateConfiguration
    private let session = URLSession.shared
    
    public init(configuration: ReportMateConfiguration) {
        self.configuration = configuration
    }
    
    /// Test connectivity to the API
    public func testConnectivity() async throws -> Bool {
        guard let apiUrl = configuration.apiUrl,
              let url = URL(string: apiUrl) else {
            throw APIError.invalidConfiguration("API URL not configured")
        }
        
        var request = URLRequest(url: url.appendingPathComponent("health"))
        request.httpMethod = "GET"
        request.timeoutInterval = TimeInterval(configuration.timeout)
        
        do {
            let (_, response) = try await session.data(for: request)
            
            if let httpResponse = response as? HTTPURLResponse {
                return httpResponse.statusCode >= 200 && httpResponse.statusCode < 300
            }
            
            return false
        } catch {
            throw APIError.networkError(error)
        }
    }
    
    /// Transmit device data to the API
    public func transmitData(_ payload: [String: Any]) async throws -> Result<TransmissionResponse, APIError> {
        guard let apiUrl = configuration.apiUrl,
              let url = URL(string: apiUrl) else {
            return .failure(.invalidConfiguration("API URL not configured"))
        }
        
        var request = URLRequest(url: url.appendingPathComponent("api/events"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.timeoutInterval = TimeInterval(configuration.timeout)
        
        // Add authentication header
        if let passphrase = configuration.passphrase {
            request.setValue(passphrase, forHTTPHeaderField: "X-Client-Passphrase")
        }
        
        do {
            // Encode as JSON dictionary
            request.httpBody = try JSONSerialization.data(withJSONObject: payload)
            
            let (data, response) = try await session.data(for: request)
            
            guard let httpResponse = response as? HTTPURLResponse else {
                return .failure(.invalidResponse("Invalid response type"))
            }
            
            if httpResponse.statusCode >= 200 && httpResponse.statusCode < 300 {
                // Try to parse the response, but don't fail if format differs
                // The API might return different response formats
                let decoder = JSONDecoder()
                decoder.dateDecodingStrategy = .iso8601
                
                // First try the expected format
                if let transmissionResponse = try? decoder.decode(TransmissionResponse.self, from: data) {
                    return .success(transmissionResponse)
                }
                
                // If that fails, try to parse as generic success response
                if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                    // Check for various success indicators
                    let isSuccess = (json["success"] as? Bool) ?? 
                                   (json["status"] as? String == "success" ? true : nil) ??
                                   (json["ok"] as? Bool) ?? 
                                   true // Assume success if 2xx status
                    
                    let message = (json["message"] as? String) ?? 
                                 (json["detail"] as? String) ?? 
                                 String(data: data, encoding: .utf8)
                    
                    return .success(TransmissionResponse(
                        success: isSuccess,
                        recordsProcessed: (json["recordsProcessed"] as? Int) ?? 1,
                        message: message,
                        timestamp: Date()
                    ))
                }
                
                // Fallback: treat any 2xx as success
                return .success(TransmissionResponse(
                    success: true,
                    recordsProcessed: 1,
                    message: String(data: data, encoding: .utf8),
                    timestamp: Date()
                ))
            } else {
                let errorMessage = String(data: data, encoding: .utf8) ?? "Unknown error"
                return .failure(.httpError(httpResponse.statusCode, errorMessage))
            }
            
        } catch {
            return .failure(.networkError(error))
        }
    }
}

// MARK: - Supporting Types

public struct TransmissionResponse: Codable {
    public let success: Bool
    public let recordsProcessed: Int
    public let message: String?
    public let timestamp: Date
    
    public init(success: Bool, recordsProcessed: Int, message: String?, timestamp: Date) {
        self.success = success
        self.recordsProcessed = recordsProcessed
        self.message = message
        self.timestamp = timestamp
    }
}

public enum APIError: Error, LocalizedError {
    case invalidConfiguration(String)
    case networkError(Error)
    case invalidResponse(String)
    case httpError(Int, String)
    case encodingError(Error)
    case decodingError(Error)
    
    public var errorDescription: String? {
        switch self {
        case .invalidConfiguration(let message):
            return "Invalid API configuration: \(message)"
        case .networkError(let error):
            return "Network error: \(error.localizedDescription)"
        case .invalidResponse(let message):
            return "Invalid response: \(message)"
        case .httpError(let statusCode, let message):
            return "HTTP error \(statusCode): \(message)"
        case .encodingError(let error):
            return "Encoding error: \(error.localizedDescription)"
        case .decodingError(let error):
            return "Decoding error: \(error.localizedDescription)"
        }
    }
}

/// System information service for collecting basic system data
public class SystemInfoService {
    
    public func gatherSystemInfo(configuration: ReportMateConfiguration) async -> SystemInfo {
        let processInfo = ProcessInfo.processInfo
        
        // Get basic system information
        let deviceName = processInfo.hostName
        let osName = "macOS"
        let osVersion = processInfo.operatingSystemVersionString
        let architecture = await getMachineArchitecture()
        
        // Try to get hardware model and serial number
        var deviceModel = "Unknown"
        var serialNumber = "Unknown"
        
        do {
            let hardwareInfo = try await BashService.executeSystemProfiler("SPHardwareDataType")
            if let hardwareArray = hardwareInfo["SPHardwareDataType"] as? [[String: Any]],
               let hardware = hardwareArray.first {
                deviceModel = hardware["machine_model"] as? String ?? "Unknown"
                serialNumber = hardware["serial_number"] as? String ?? "Unknown"
            }
        } catch {
            print("Warning: Could not get hardware information: \(error)")
        }
        
        // Determine configuration source
        let configurationSource = determineConfigurationSource(configuration)
        
        return SystemInfo(
            deviceName: deviceName,
            deviceModel: deviceModel,
            osName: osName,
            osVersion: osVersion,
            architecture: architecture,
            serialNumber: serialNumber,
            reportMateVersion: AppVersion.current,
            configurationSource: configurationSource
        )
    }
    
    private func getMachineArchitecture() async -> String {
        var size = 0
        sysctlbyname("hw.machine", nil, &size, nil, 0)
        
        var machine = [CChar](repeating: 0, count: size)
        sysctlbyname("hw.machine", &machine, &size, nil, 0)
        
        let machineBytes: [UInt8] = machine.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        return String(decoding: machineBytes, as: UTF8.self)
    }
    
    private func determineConfigurationSource(_ configuration: ReportMateConfiguration) -> String {
        // Check if configuration comes from environment variables
        let environment = ProcessInfo.processInfo.environment
        if environment["REPORTMATE_API_URL"] != nil {
            return "Environment Variables"
        }
        
        // Check if configuration comes from Configuration Profiles
        let profileDefaults = UserDefaults(suiteName: "com.github.reportmate")
        if profileDefaults?.object(forKey: "ApiUrl") != nil {
            return "Configuration Profiles"
        }
        
        // Check if system plist exists
        let systemConfigPath = "/Library/Managed Reports/reportmate.plist"
        if FileManager.default.fileExists(atPath: systemConfigPath) {
            return "System Configuration"
        }
        
        // Check if user plist exists
        let userConfigPath = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Managed Reports/reportmate.plist")
        if FileManager.default.fileExists(atPath: userConfigPath.path) {
            return "User Configuration"
        }
        
        return "Default Configuration"
    }
}

/// Cache service for managing collection timestamps and cached data
/// Enhanced to match Windows client architecture: per-module JSON files with timestamps
public class CacheService {
    private let baseCacheDirectory: URL
    private var currentCacheDirectory: URL?
    
    public init() {
        // Use system-wide cache directory matching Munki: /Library/Managed Reports/cache
        self.baseCacheDirectory = URL(fileURLWithPath: "/Library/Managed Reports/cache")
        
        // Create base cache directory if it doesn't exist
        try? FileManager.default.createDirectory(at: baseCacheDirectory, withIntermediateDirectories: true)
    }
    
    // MARK: - Timestamped Directory Management (matches Windows architecture)
    
    /// Create a new timestamped cache directory for this collection run
    /// Returns the directory URL for saving module files
    public func createTimestampedCacheDirectory() -> URL {
        let now = Date()
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd-HHmmss"
        let timestamp = formatter.string(from: now)
        
        let timestampedDir = baseCacheDirectory.appendingPathComponent(timestamp)
        try? FileManager.default.createDirectory(at: timestampedDir, withIntermediateDirectories: true)
        
        self.currentCacheDirectory = timestampedDir
        return timestampedDir
    }
    
    /// Get the current timestamped cache directory, creating one if needed
    public func getCurrentCacheDirectory() -> URL {
        if let current = currentCacheDirectory {
            return current
        }
        return createTimestampedCacheDirectory()
    }
    
    /// Save module data to its own JSON file in the current timestamped directory
    /// Matches Windows pattern: each module gets its own file (e.g., security.json, hardware.json)
    public func saveModuleData(_ data: [String: Any], for moduleId: String) async throws {
        let cacheDir = getCurrentCacheDirectory()
        let moduleFile = cacheDir.appendingPathComponent("\(moduleId).json")
        
        let jsonData = try JSONSerialization.data(withJSONObject: data, options: [.prettyPrinted, .sortedKeys])
        try jsonData.write(to: moduleFile)
        
        print("Saved module data: \(moduleFile.lastPathComponent)")
    }
    
    /// Load module data from the latest timestamped cache directory
    public func loadModuleData(for moduleId: String) async -> [String: Any]? {
        guard let latestDir = getLatestCacheDirectory() else {
            return nil
        }
        
        let moduleFile = latestDir.appendingPathComponent("\(moduleId).json")
        
        guard FileManager.default.fileExists(atPath: moduleFile.path) else {
            return nil
        }
        
        do {
            let data = try Data(contentsOf: moduleFile)
            return try JSONSerialization.jsonObject(with: data) as? [String: Any]
        } catch {
            print("Warning: Could not load module data for \(moduleId): \(error)")
            return nil
        }
    }
    
    /// Get the latest timestamped cache directory
    public func getLatestCacheDirectory() -> URL? {
        do {
            let contents = try FileManager.default.contentsOfDirectory(
                at: baseCacheDirectory,
                includingPropertiesForKeys: [.isDirectoryKey],
                options: [.skipsHiddenFiles]
            )
            
            // Filter to only timestamped directories (format: YYYY-MM-DD-HHmmss)
            let timestampDirs = contents.filter { url in
                var isDirectory: ObjCBool = false
                FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory)
                guard isDirectory.boolValue else { return false }
                
                // Check if name matches timestamp pattern
                let name = url.lastPathComponent
                return name.range(of: #"^\d{4}-\d{2}-\d{2}-\d{6}$"#, options: .regularExpression) != nil
            }
            
            // Sort by name (which is chronological due to timestamp format) and get latest
            return timestampDirs.sorted { $0.lastPathComponent > $1.lastPathComponent }.first
        } catch {
            print("Warning: Could not list cache directories: \(error)")
            return nil
        }
    }
    
    /// Save the unified event.json payload to the current cache directory
    public func saveEventPayload(_ payload: [String: Any]) async throws {
        let cacheDir = getCurrentCacheDirectory()
        let eventFile = cacheDir.appendingPathComponent("event.json")
        
        let jsonData = try JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys])
        try jsonData.write(to: eventFile)
        
        print("Saved event payload: \(eventFile.path)")
    }
    
    /// Load the event.json from the latest cache directory
    public func loadEventPayload() async -> [String: Any]? {
        guard let latestDir = getLatestCacheDirectory() else {
            return nil
        }
        
        let eventFile = latestDir.appendingPathComponent("event.json")
        
        guard FileManager.default.fileExists(atPath: eventFile.path) else {
            return nil
        }
        
        do {
            let data = try Data(contentsOf: eventFile)
            return try JSONSerialization.jsonObject(with: data) as? [String: Any]
        } catch {
            print("Warning: Could not load event payload: \(error)")
            return nil
        }
    }
    
    // MARK: - Legacy Methods (for backwards compatibility)
    
    /// Get the timestamp of the last data collection
    public func getLastCollectionTimestamp() async -> Date? {
        let timestampFile = baseCacheDirectory.appendingPathComponent("last_collection.timestamp")
        
        guard FileManager.default.fileExists(atPath: timestampFile.path) else {
            return nil
        }
        
        do {
            let timestampString = try String(contentsOf: timestampFile)
            let timestamp = TimeInterval(timestampString) ?? 0
            return Date(timeIntervalSince1970: timestamp)
        } catch {
            print("Warning: Could not read last collection timestamp: \(error)")
            return nil
        }
    }
    
    /// Set the timestamp of the last data collection
    public func setLastCollectionTimestamp(_ timestamp: Date) async {
        let timestampFile = baseCacheDirectory.appendingPathComponent("last_collection.timestamp")
        let timestampString = String(timestamp.timeIntervalSince1970)
        
        do {
            try timestampString.write(to: timestampFile, atomically: true, encoding: .utf8)
        } catch {
            print("Warning: Could not write last collection timestamp: \(error)")
        }
    }
    
    /// Cache all collected data (legacy method - now also saves to event.json)
    public func setCachedData(_ data: [String: Any]) async {
        // Create timestamped directory and save as event.json
        _ = getCurrentCacheDirectory()
        
        do {
            try await saveEventPayload(data)
            
            // Also save individual module files from the payload
            if let modules = data["modules"] as? [String: Any] {
                for (moduleId, moduleData) in modules {
                    if let moduleDict = moduleData as? [String: Any] {
                        try await saveModuleData(moduleDict, for: moduleId)
                    }
                }
            }
            
            // Save top-level module data if present (for flat payload structure)
            let moduleNames = ["hardware", "system", "security", "network", "applications", 
                            "management", "inventory", "installs", "displays", "printers", "identity"]
            for moduleName in moduleNames {
                if let moduleData = data[moduleName] as? [String: Any] {
                    try await saveModuleData(moduleData, for: moduleName)
                }
            }
        } catch {
            print("Warning: Could not cache collected data: \(error)")
        }
    }
    
    /// Get all cached data (legacy method - reads from latest event.json)
    public func getCachedData() async -> [String: Any]? {
        return await loadEventPayload()
    }
    
    /// Clean up old cache directories (keeps last N directories)
    public func cleanupOldCache(keepLast count: Int = 5) async {
        do {
            let contents = try FileManager.default.contentsOfDirectory(
                at: baseCacheDirectory,
                includingPropertiesForKeys: [.isDirectoryKey],
                options: [.skipsHiddenFiles]
            )
            
            // Filter to only timestamped directories
            let timestampDirs = contents.filter { url in
                var isDirectory: ObjCBool = false
                FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory)
                guard isDirectory.boolValue else { return false }
                
                let name = url.lastPathComponent
                return name.range(of: #"^\d{4}-\d{2}-\d{2}-\d{6}$"#, options: .regularExpression) != nil
            }
            
            // Sort by name (chronological) and remove oldest if over count
            let sorted = timestampDirs.sorted { $0.lastPathComponent > $1.lastPathComponent }
            
            if sorted.count > count {
                for dir in sorted.dropFirst(count) {
                    try FileManager.default.removeItem(at: dir)
                    print("Cleaned up old cache directory: \(dir.lastPathComponent)")
                }
            }
        } catch {
            print("Warning: Could not clean up cache directories: \(error)")
        }
    }
}

/// Build service for packaging and code signing
public class BuildService {
    public init() {}
    
    public func executeBuild(
        sign: Bool = false,
        version: String? = nil,
        identity: String? = nil
    ) async throws -> BuildInfo {
        
        // This would implement actual build and signing logic
        // For now, return a mock result
        let outputPath = "/tmp/ReportMate-build"
        
        var buildInfo = BuildInfo(
            version: version,
            signed: sign,
            signingIdentity: identity,
            outputPath: outputPath
        )
        
        if sign {
            // Mock signing process
            buildInfo.signed = true
            buildInfo.signingIdentity = identity ?? "Default Developer ID"
        }
        
        return buildInfo
    }
}