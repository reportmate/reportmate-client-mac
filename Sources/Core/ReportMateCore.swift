import Foundation
import Logging

/// Main ReportMate client coordinator
public class ReportMateCore {
    private let logger = Logger(label: "reportmate.core")
    private let configurationManager: ConfigurationManager
    private let dataCollectionService: DataCollectionService
    private let apiClient: APIClient
    private let cacheService: CacheService
    private let buildService: BuildService
    
    public init() async throws {
        logger.info("Initializing ReportMate Core...")
        
        // Initialize configuration manager
        self.configurationManager = try ConfigurationManager()
        
        // Initialize services
        self.apiClient = APIClient(configuration: configurationManager.configuration)
        self.dataCollectionService = DataCollectionService(
            configuration: configurationManager.configuration
        )
        self.cacheService = CacheService()
        self.buildService = BuildService()
        
        logger.info("ReportMate Core initialized successfully")
    }
    
    // MARK: - Data Collection
    
    /// Execute complete data collection and transmission
    public func executeDataCollection(
        force: Bool = false,
        collectOnly: Bool = false,
        transmitOnly: Bool = false,
        modulesToRun: [String]? = nil,
        deviceId: String? = nil,
        apiUrl: String? = nil,
        verboseLevel: VerboseLevel = .error
    ) async -> Result<CollectionSummary, ReportMateError> {
        
        // Configure logging level based on verbose setting
        configureLogging(level: verboseLevel)
        
        logger.info("Starting data collection...")
        
        do {
            // Update configuration if overrides provided
            if let deviceId = deviceId {
                configurationManager.setOverride(key: "deviceId", value: deviceId)
            }
            if let apiUrl = apiUrl {
                configurationManager.setOverride(key: "apiUrl", value: apiUrl)
            }
            
            var collectedData: [String: Any] = [:]
            var moduleCount = 0
            
            // Handle transmit-only mode
            if transmitOnly {
                logger.info("Transmit-only mode: loading cached data...")
                if let cachedData = await cacheService.getCachedData() {
                    collectedData = cachedData
                    moduleCount = (cachedData["modules"] as? [String: Any])?.count ?? 0
                    logger.info("Loaded cached data from \(moduleCount) modules")
                } else {
                    logger.warning("No cached data available for transmission")
                    return .failure(.systemError("No cached data available for transmission"))
                }
            } else {
                // Normal collection mode
                
                // Check if we should skip collection due to recent cache
                let shouldSkip = await shouldSkipCollection()
                if !force && shouldSkip && !collectOnly {
                    logger.info("Skipping collection - recent cache available")
                    return .success(CollectionSummary(moduleCount: 0, recordCount: 0, cached: true))
                }
                
                // Execute data collection (specific modules or all)
                if let modules = modulesToRun {
                    collectedData = try await dataCollectionService.collectSpecificModules(modules)
                    logger.info("Collected data from specified modules: \(modules.joined(separator: ", "))")
                } else {
                    collectedData = try await dataCollectionService.collectAllModules()
                    logger.info("Collected data from all enabled modules")
                }
                
                let moduleResults = collectedData["modules"] as? [String: Any] ?? [:]
                moduleCount = moduleResults.count
                
                // Cache the collected data
                await cacheService.setCachedData(collectedData)
            }
            
            // Handle collect-only mode
            if collectOnly {
                logger.info("Collect-only mode: data cached without transmission")
                return .success(CollectionSummary(
                    moduleCount: moduleCount,
                    recordCount: 0,
                    cached: true
                ))
            }
            
            // Transmit data to API
            let transmissionResult = try await apiClient.transmitData(collectedData)
            
            switch transmissionResult {
            case .success(let response):
                logger.info("Data transmitted successfully: \(response.recordsProcessed) records")
                
                // Update cache timestamp
                await updateLastCollectionTimestamp()
                
                return .success(CollectionSummary(
                    moduleCount: moduleCount,
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
    public func testConfiguration(verboseLevel: VerboseLevel = .error) async -> Result<DiagnosticInfo, ReportMateError> {
        // Configure logging level
        configureLogging(level: verboseLevel)
        
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
    
    // MARK: - Build Operations
    
    /// Execute build and signing operations
    public func executeBuild(
        sign: Bool = false,
        version: String? = nil,
        identity: String? = nil,
        verboseLevel: VerboseLevel = .error
    ) async -> Result<BuildInfo, ReportMateError> {
        
        // Configure logging level
        configureLogging(level: verboseLevel)
        
        logger.info("Starting build process...")
        
        do {
            let buildService = BuildService()
            let buildInfo = try await buildService.executeBuild(
                sign: sign,
                version: version,
                identity: identity
            )
            
            logger.info("Build process completed successfully")
            return .success(buildInfo)
            
        } catch {
            logger.error("Build process failed: \(error)")
            return .failure(.systemError("Build failed: \(error.localizedDescription)"))
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
                passphrase: apiKey,
                deviceId: deviceId
            )
            
            logger.info("Configuration saved successfully")
            return .success(())
            
        } catch {
            logger.error("Configuration failed: \(error)")
            return .failure(.configurationError(error))
        }
    }
    
    // MARK: - Private Methods
    
    private func configureLogging(level: VerboseLevel) {
        // Configure the logging system based on verbose level
        // Note: In a real implementation, this would configure the global logging system
        // For now, we'll just acknowledge the level parameter
        _ = level.logLevel // Acknowledge the parameter to avoid unused warning
        // Swift Logging framework configuration would go here
    }
    
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

public struct BuildInfo {
    public let version: String?
    public var signed: Bool
    public var signingIdentity: String?
    public let outputPath: String
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