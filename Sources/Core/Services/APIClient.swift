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
        
        var request = URLRequest(url: url.appendingPathComponent("devices/data"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.timeoutInterval = TimeInterval(configuration.timeout)
        
        // Add authentication if available
        if let apiKey = configuration.apiKey {
            request.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
        }
        
        do {
            // Encode as JSON dictionary
            request.httpBody = try JSONSerialization.data(withJSONObject: payload)
            
            let (data, response) = try await session.data(for: request)
            
            guard let httpResponse = response as? HTTPURLResponse else {
                return .failure(.invalidResponse("Invalid response type"))
            }
            
            if httpResponse.statusCode >= 200 && httpResponse.statusCode < 300 {
                let decoder = JSONDecoder()
                decoder.dateDecodingStrategy = .iso8601
                let transmissionResponse = try decoder.decode(TransmissionResponse.self, from: data)
                return .success(transmissionResponse)
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
            reportMateVersion: "1.0.0",
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
        let profileDefaults = UserDefaults(suiteName: "com.reportmate.client")
        if profileDefaults?.object(forKey: "ApiUrl") != nil {
            return "Configuration Profiles"
        }
        
        // Check if system plist exists
        let systemConfigPath = "/Library/Application Support/ReportMate/reportmate.plist"
        if FileManager.default.fileExists(atPath: systemConfigPath) {
            return "System Configuration"
        }
        
        // Check if user plist exists
        let userConfigPath = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/ReportMate/reportmate.plist")
        if FileManager.default.fileExists(atPath: userConfigPath.path) {
            return "User Configuration"
        }
        
        return "Default Configuration"
    }
}

/// Cache service for managing collection timestamps and cached data
public class CacheService {
    private let cacheDirectory: URL
    
    public init() {
        let appSupportDir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        self.cacheDirectory = appSupportDir.appendingPathComponent("ReportMate/cache")
        
        // Create cache directory if it doesn't exist
        try? FileManager.default.createDirectory(at: cacheDirectory, withIntermediateDirectories: true)
    }
    
    /// Get the timestamp of the last data collection
    public func getLastCollectionTimestamp() async -> Date? {
        let timestampFile = cacheDirectory.appendingPathComponent("last_collection.timestamp")
        
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
        let timestampFile = cacheDirectory.appendingPathComponent("last_collection.timestamp")
        let timestampString = String(timestamp.timeIntervalSince1970)
        
        do {
            try timestampString.write(to: timestampFile, atomically: true, encoding: .utf8)
        } catch {
            print("Warning: Could not write last collection timestamp: \(error)")
        }
    }
    
    /// Cache collected data
    public func cacheData(_ payload: [String: Any], for moduleId: String) async {
        let cacheFile = cacheDirectory.appendingPathComponent("\(moduleId)_cache.json")
        
        do {
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            encoder.outputFormatting = .prettyPrinted
            
            let data = try JSONSerialization.data(withJSONObject: payload)
            try data.write(to: cacheFile)
        } catch {
            print("Warning: Could not cache data for module \(moduleId): \(error)")
        }
    }
    
    /// Load cached data for a module
    public func loadCachedData(for moduleId: String) async -> [String: Any]? {
        let cacheFile = cacheDirectory.appendingPathComponent("\(moduleId)_cache.json")
        
        guard FileManager.default.fileExists(atPath: cacheFile.path) else {
            return nil
        }
        
        do {
            let data = try Data(contentsOf: cacheFile)
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            
            return try JSONSerialization.jsonObject(with: data) as? [String: Any]
        } catch {
            print("Warning: Could not load cached data for module \(moduleId): \(error)")
            return nil
        }
    }
    
    /// Clean up old cache files
    public func cleanupOldCache(olderThan interval: TimeInterval = 86400) async { // 24 hours default
        let cutoffDate = Date().addingTimeInterval(-interval)
        
        do {
            let cacheFiles = try FileManager.default.contentsOfDirectory(at: cacheDirectory, includingPropertiesForKeys: [.contentModificationDateKey])
            
            for file in cacheFiles {
                let attributes = try file.resourceValues(forKeys: [.contentModificationDateKey])
                if let modificationDate = attributes.contentModificationDate,
                   modificationDate < cutoffDate {
                    try FileManager.default.removeItem(at: file)
                    print("Cleaned up old cache file: \(file.lastPathComponent)")
                }
            }
        } catch {
            print("Warning: Could not clean up cache directory: \(error)")
        }
    }
}