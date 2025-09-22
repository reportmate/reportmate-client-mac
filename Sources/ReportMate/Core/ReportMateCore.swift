import Foundation
import Logging

/// Main ReportMate client coordinator
public class ReportMateCore {
    private let logger = Logger(label: "reportmate.core")
    private let configurationManager: ConfigurationManager
    private let dataCollectionService: DataCollectionService
    private let apiClient: APIClient
    
    public init() async throws {
        logger.info("Initializing ReportMate Core...")
        
        // Initialize configuration manager
        self.configurationManager = try ConfigurationManager()
        
        // Initialize services
        self.apiClient = APIClient(configuration: configurationManager.configuration)
        self.dataCollectionService = DataCollectionService(
            configuration: configurationManager.configuration
        )
        
        logger.info("ReportMate Core initialized successfully")
    }
    
    // MARK: - Data Collection
    
    /// Execute complete data collection and transmission
    public func executeDataCollection(
        force: Bool = false,
        deviceId: String? = nil,
        apiUrl: String? = nil,
        verbose: Bool = false
    ) async -> Result<CollectionSummary, ReportMateError> {
        
        logger.info("Starting data collection...")
        
        do {
            // Update configuration if overrides provided
            if let deviceId = deviceId {
                configurationManager.setOverride(key: "deviceId", value: deviceId)
            }
            if let apiUrl = apiUrl {
                configurationManager.setOverride(key: "apiUrl", value: apiUrl)
            }
            
            // Check if we should skip collection due to recent cache
            let shouldSkip = await shouldSkipCollection()
            if !force && shouldSkip {
                logger.info("Skipping collection - recent cache available")
                return .success(CollectionSummary(moduleCount: 0, recordCount: 0, cached: true))
            }
            
            // Execute data collection
            let collectedData = try await dataCollectionService.collectAllModules()
            let moduleResults = collectedData["modules"] as? [String: Any] ?? [:]
            logger.info("Collected data from \(moduleResults.count) modules")
            
            // Transmit data to API
            let transmissionResult = try await apiClient.transmitData(collectedData)
            
            switch transmissionResult {
            case .success(let response):
                logger.info("Data transmitted successfully: \(response.recordsProcessed) records")
                
                // Update cache timestamp
                await updateLastCollectionTimestamp()
                
                return .success(CollectionSummary(
                    moduleCount: moduleResults.count,
                    recordCount: response.recordsProcessed,
                    cached: false
                ))
                
            case .failure(let error):
                logger.error("Data transmission failed: \(error)")
                return .failure(.apiError(error))
            }
            
        } catch {
            logger.error("Data collection failed: \(error)")
            return .failure(.collectionError(error))
        }
    }
    
    // MARK: - Configuration Testing
    
    /// Test configuration and connectivity
    public func testConfiguration(verbose: Bool = false) async -> Result<DiagnosticInfo, ReportMateError> {
        logger.info("Running configuration test...")
        
        do {
            let config = configurationManager.configuration
            
            // Test osquery availability
            let osqueryService = OSQueryService(configuration: config)
            let osqueryAvailable = await osqueryService.isAvailable()
            
            // Test API connectivity
            let apiConnectivity = try await apiClient.testConnectivity()
            
            let diagnostics = DiagnosticInfo(
                apiUrl: config.apiUrl ?? "Not configured",
                deviceId: config.deviceId ?? "Auto-generated",
                enabledModules: config.enabledModules,
                osqueryAvailable: osqueryAvailable,
                apiConnectivity: apiConnectivity
            )
            
            logger.info("Configuration test completed")
            return .success(diagnostics)
            
        } catch {
            logger.error("Configuration test failed: \(error)")
            return .failure(.configurationError(error))
        }
    }
    
    // MARK: - System Information
    
    /// Get system and configuration information
    public func getSystemInfo() async -> SystemInfo {
        logger.debug("Gathering system information...")
        
        let systemInfoService = SystemInfoService()
        return await systemInfoService.gatherSystemInfo(
            configuration: configurationManager.configuration
        )
    }
    
    // MARK: - Configuration
    
    /// Configure ReportMate client
    public func configure(
        apiUrl: String,
        deviceId: String? = nil,
        apiKey: String? = nil
    ) async -> Result<Void, ReportMateError> {
        
        logger.info("Configuring ReportMate client...")
        
        do {
            try configurationManager.setSystemConfiguration(
                apiUrl: apiUrl,
                deviceId: deviceId,
                apiKey: apiKey
            )
            
            logger.info("Configuration saved successfully")
            return .success(())
            
        } catch {
            logger.error("Configuration failed: \(error)")
            return .failure(.configurationError(error))
        }
    }
    
    // MARK: - Private Methods
    
    private func shouldSkipCollection() async -> Bool {
        let cacheService = CacheService()
        let lastCollection = await cacheService.getLastCollectionTimestamp()
        let cacheInterval = configurationManager.configuration.collectionInterval
        
        guard let lastCollection = lastCollection else {
            return false // No previous collection
        }
        
        let timeSinceLastCollection = Date().timeIntervalSince(lastCollection)
        return timeSinceLastCollection < TimeInterval(cacheInterval)
    }
    
    private func updateLastCollectionTimestamp() async {
        let cacheService = CacheService()
        await cacheService.setLastCollectionTimestamp(Date())
    }
}

// MARK: - Supporting Types

public struct CollectionSummary {
    public let moduleCount: Int
    public let recordCount: Int
    public let cached: Bool
}

public struct DiagnosticInfo: Codable {
    public let apiUrl: String
    public let deviceId: String
    public let enabledModules: [String]
    public let osqueryAvailable: Bool
    public let apiConnectivity: Bool
}

/// Basic system information for CLI display and core functionality
public struct SystemInfo: Codable {
    public let deviceName: String
    public let deviceModel: String
    public let osName: String
    public let osVersion: String
    public let architecture: String
    public let serialNumber: String
    public let reportMateVersion: String
    public let configurationSource: String
}

// MARK: - Error Types

public enum ReportMateError: Error, LocalizedError {
    case configurationError(Error)
    case collectionError(Error)
    case apiError(Error)
    case osqueryError(String)
    case systemError(String)
    
    public var errorDescription: String? {
        switch self {
        case .configurationError(let error):
            return "Configuration error: \(error.localizedDescription)"
        case .collectionError(let error):
            return "Data collection error: \(error.localizedDescription)"
        case .apiError(let error):
            return "API error: \(error.localizedDescription)"
        case .osqueryError(let message):
            return "OSQuery error: \(message)"
        case .systemError(let message):
            return "System error: \(message)"
        }
    }
}