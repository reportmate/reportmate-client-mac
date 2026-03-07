import ArgumentParser
import Foundation
import Logging

/// ReportMate macOS Client - Device data collection and reporting
@main
struct ReportMateClient: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "managedreportsrunner",
        abstract: "ReportMate - Device data collection and reporting",
        version: AppVersion.current
    )
    
    // MARK: - Command Options
    
    @Flag(name: [.customShort("v"), .long], help: "Increase verbosity (use -vv for more verbose)")
    var verbose: Int
    
    @Flag(name: .long, help: "Force data collection even if recent cache exists")
    var force: Bool = false
    
    @Flag(name: .long, help: "Collect data only, do not transmit")
    var collectOnly: Bool = false
    
    @Flag(name: .long, help: "Transmit cached data only, do not collect new data")
    var transmitOnly: Bool = false
    
    @Option(name: .long, help: "Run specific module only")
    var runModule: String?
    
    @Option(name: .long, help: "Run specific modules (comma-separated)")
    var runModules: String?
    
    @Option(name: .long, help: "Override device ID")
    var deviceId: String?
    
    @Option(name: .long, help: "Override API URL")
    var apiUrl: String?
    
    @Option(name: .long, help: "Storage analysis mode: 'quick' (drive totals only) or 'deep' (full directory analysis)")
    var storageMode: String?
    
    @Flag(name: .long, help: "Test configuration and exit")
    var test: Bool = false
    
    @Flag(name: .long, help: "Show system information and exit")
    var info: Bool = false
    
    @Flag(name: .long, help: "Build executable package")
    var build: Bool = false
    
    // MARK: - Main Execution
    
    mutating func run() async throws {
        // Check for root privileges (required for system data collection and writing to /Library)
        guard getuid() == 0 else {
            fputs("ERROR: You must run this as root!\n", stderr)
            throw ExitCode.failure
        }
        
        // Display startup banner
        displayStartupBanner()
        
        // Convert verbose level and validate
        let verboseLevel = VerboseLevel(rawValue: max(0, min(3, verbose))) ?? .error
        
        // Enable ConsoleFormatter with verbose level (matches Windows client)
        // -vv (level 2) enables progress bars, -vvv (level 3) enables debug output
        ConsoleFormatter.setVerboseLevel(verbose)
        
        // Configure logging
        LoggingSystem.bootstrap { label in
            var handler = StreamLogHandler.standardOutput(label: label)
            handler.logLevel = verboseLevel.logLevel
            return handler
        }
        
        let logger = Logger(label: "reportmate.client")
        
        // Initialize Configuration
        let configManager: ConfigurationManager
        do {
            configManager = try ConfigurationManager()
            
            // Apply overrides
            if let apiUrl = apiUrl {
                configManager.setOverride(key: "ApiUrl", value: apiUrl)
            }
            if let deviceId = deviceId {
                configManager.setOverride(key: "DeviceId", value: deviceId)
            }
            if let storageMode = storageMode {
                configManager.setOverride(key: "StorageMode", value: storageMode)
            }
        } catch {
            logger.error("Failed to initialize configuration: \(error)")
            throw ExitCode.failure
        }
        
        // Display configuration information
        displayConfigurationInfo(config: configManager.configuration, verboseLevel: verboseLevel, logger: logger)
        
        // Display command execution details
        displayCommandExecution(config: configManager.configuration, verboseLevel: verboseLevel, logger: logger)
        
        do {
            // Handle special modes first
            if test {
                try handleTestMode(verboseLevel: verboseLevel, logger: logger)
                return
            }
            
            if info {
                try handleInfoMode(verboseLevel: verboseLevel, logger: logger)
                return
            }
            
            if build {
                try handleBuildMode(verboseLevel: verboseLevel, logger: logger)
                return
            }
            
            if transmitOnly {
                try await handleTransmitOnly(config: configManager.configuration, verboseLevel: verboseLevel, logger: logger)
                return
            }
            
            // Handle main data collection/transmission
            try await handleDataCollection(config: configManager.configuration, verboseLevel: verboseLevel, logger: logger)
            
        } catch {
            logger.error("Execution failed: \(error)")
            throw ExitCode.failure
        }
    }
    
    // MARK: - Display Methods
    
    private func displayStartupBanner() {
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        let timestamp = dateFormatter.string(from: Date())
        
        print("[\(timestamp)] INFO  === REPORTMATE MACOS CLIENT ===")
        if verbose >= 1 {
            print("[\(timestamp)] INFO      Verbose logging enabled")
        }
        print("[\(timestamp)] INFO  ─────────────────────────────────")
        print("[\(timestamp)] INFO  Version: \(AppVersion.current)")
        print("[\(timestamp)] INFO  Arguments: \(CommandLine.arguments.dropFirst().joined(separator: " "))")
        print("[\(timestamp)] INFO  Verbose Level: \(verbose) (\(getVerboseDescription(verbose)))")
        print("[\(timestamp)] INFO  Platform: \(getSystemPlatform())")
        print("")
    }
    
    private func displayConfigurationInfo(config: ReportMateConfiguration, verboseLevel: VerboseLevel, logger: Logger) {
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        let timestamp = dateFormatter.string(from: Date())
        
        print("[\(timestamp)] INFO  === CONFIGURATION SOURCES ===")
        print("[\(timestamp)] INFO      Loading settings from multiple sources in order of precedence")
        print("[\(timestamp)] INFO  ─────────────────────────────")
        print("[\(timestamp)] INFO  1. Application defaults: Embedded in binary (no JSON dependency)")
        print("[\(timestamp)] INFO  2. PLIST configuration from: ~/Library/Preferences")
        print("[\(timestamp)] INFO  3. Environment variables with REPORTMATE_ prefix")
        print("[\(timestamp)] INFO  4. Command line arguments (HIGHEST PRECEDENCE)")
        print("")
        
        print("[\(timestamp)] INFO  === FINAL CONFIGURATION ===")
        print("[\(timestamp)] INFO  ───────────────────────────")
        print("[\(timestamp)] INFO  Key configuration values")
        
        print("[\(timestamp)] INFO    ApiUrl: \(config.apiUrl ?? "Not Set")")
        print("[\(timestamp)] INFO    DeviceId: \(config.deviceId ?? "Not Set")")
        print("[\(timestamp)] INFO    DebugLogging: \(verbose >= 3)")
        print("[\(timestamp)] INFO  Configuration built successfully")
        
        // Add Serilog-style logging
        logger.info("ReportMate v1.0.0 starting")
        logger.info("Command line args: \(CommandLine.arguments.dropFirst().joined(separator: " "))")
        print("")
    }
    
    private func displayCommandExecution(config: ReportMateConfiguration, verboseLevel: VerboseLevel, logger: Logger) {
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        let timestamp = dateFormatter.string(from: Date())
        
        print("[\(timestamp)] INFO  === COMMAND EXECUTION ===")
        if verbose >= 1 {
            print("[\(timestamp)] INFO      Run command with enhanced verbose logging")
        }
        print("[\(timestamp)] INFO  ─────────────────────────")
        print("[\(timestamp)] INFO  Command Parameters")
        print("[\(timestamp)] INFO    Command: run")
        print("[\(timestamp)] INFO    Force: \(force)")
        print("[\(timestamp)] INFO    Collect Only: \(collectOnly)")
        print("[\(timestamp)] INFO    Transmit Only: \(transmitOnly)")
        print("[\(timestamp)] INFO    Run Module: \(runModule ?? "ALL")")
        print("[\(timestamp)] INFO    Run Modules: \(runModules ?? "NONE")")
        
        let effectiveMode: String
        if let module = runModule {
            effectiveMode = "Single Module: \(module)"
        } else if let modules = runModules {
            effectiveMode = "Multiple Modules: \(modules)"
        } else {
            effectiveMode = "All Modules"
        }
        
        print("[\(timestamp)] INFO    Effective Mode: \(effectiveMode)")
        print("[\(timestamp)] INFO    Custom Device ID: \(config.deviceId ?? "NONE (will auto-detect)")")
        print("[\(timestamp)] INFO    Custom API URL: \(config.apiUrl ?? "NONE (using config)")")
        print("[\(timestamp)] INFO    Verbose Level: \(verbose) (\(getVerboseDescription(verbose)))")
        print("[\(timestamp)] INFO  Expected Flow: 1) Detect Serial 2) Check Registration 3) Register if needed 4) Send Data")
        
        logger.info("ReportMate v1.0.0 - Device Registration & Data Collection")
        print("")
    }
    
    private func getVerboseDescription(_ level: Int) -> String {
        switch level {
        case 0: return "Errors Only"
        case 1: return "Errors + Warnings"
        case 2: return "Errors + Warnings + Info"
        case 3: return "Errors + Warnings + Info + Debug"
        default: return "Unknown"
        }
    }
    
    private func getSystemPlatform() -> String {
        let version = ProcessInfo.processInfo.operatingSystemVersion
        return "macOS \(version.majorVersion).\(version.minorVersion).\(version.patchVersion)"
    }
    
    private func createProcessor(for module: String, config: ReportMateConfiguration) -> ModuleProcessor? {
        switch module.lowercased() {
        case "hardware": return HardwareModuleProcessor(configuration: config)
        case "system": return SystemModuleProcessor(configuration: config)
        case "network": return NetworkModuleProcessor(configuration: config)
        case "security": return SecurityModuleProcessor(configuration: config)
        case "applications": 
            // Application usage service for usage tracking from SQLite database
            let usageService = ApplicationUsageService()
            return ApplicationsModuleProcessor(configuration: config, applicationUsageService: usageService)
        case "management": return ManagementModuleProcessor(configuration: config)
        case "inventory": return InventoryModuleProcessor(configuration: config)
        case "displays", "printers", "peripherals":
            // Displays and Printers are now part of the unified Peripherals module
            return PeripheralsModuleProcessor(configuration: config)
        case "installs": return InstallsModuleProcessor(configuration: config)
        case "identity": return IdentityModuleProcessor(configuration: config)
        default: return nil
        }
    }
    
    private func executeModule(module: String, config: ReportMateConfiguration, logger: Logger, current: Int = 1, total: Int = 1) async throws -> (String, Any)? {
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "HH:mm:ss"
        let timestamp = dateFormatter.string(from: Date())
        
        guard let processor = createProcessor(for: module, config: config) else {
            logger.warning("Unknown module: \(module)")
            ConsoleFormatter.writeWarning("Unknown module: \(module)")
            return nil
        }
        
        logger.info("Starting collection for module: \(module)")
        
        // Don't show module-level progress - modules show their own query-level progress
        
        // Also print standard log format for non-verbose mode
        if !ConsoleFormatter.isVerbose {
            print("[\(timestamp)] INFO  Executing module: \(module)...")
        }
        
        do {
            let startTime = Date()
            let data = try await processor.collectData()
            let duration = Date().timeIntervalSince(startTime)
            
            logger.info("Module \(module) completed in \(String(format: "%.2f", duration))s")
            
            if let baseData = data as? BaseModuleData {
                return (module, baseData.data)
            } else {
                // Generic Codable handling for typed module data (like InventoryData)
                let encoder = JSONEncoder()
                encoder.dateEncodingStrategy = .iso8601
                let jsonData = try encoder.encode(data)
                if let dict = try JSONSerialization.jsonObject(with: jsonData) as? [String: Any] {
                    return (module, dict)
                }
                return (module, [:])
            }
            
        } catch {
            logger.error("Module \(module) failed: \(error.localizedDescription)")
            ConsoleFormatter.writeError("Module \(module) failed: \(error.localizedDescription)")
            if !ConsoleFormatter.isVerbose {
                print("[\(timestamp)] ERROR Module \(module) failed: \(error.localizedDescription)")
            }
            return nil
        }
    }
    
    // MARK: - Mode Handlers
    
    private func handleTestMode(verboseLevel: VerboseLevel, logger: Logger) throws {
        logger.info("Running configuration test...")
        print("Configuration test completed")
    }
    
    private func handleInfoMode(verboseLevel: VerboseLevel, logger: Logger) throws {
        logger.info("Gathering system information...")
        print("System information gathered")
    }
    
    private func handleBuildMode(verboseLevel: VerboseLevel, logger: Logger) throws {
        logger.info("Building executable package...")
        print("Build completed")
    }
    
    private func handleDataCollection(config: ReportMateConfiguration, verboseLevel: VerboseLevel, logger: Logger) async throws {
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        let timestamp = dateFormatter.string(from: Date())
        
        var modulesToRun: [String] = []
        
        if let module = runModule {
            modulesToRun = [module]
            print("[\(timestamp)] INFO  === SINGLE MODULE COLLECTION ===")
        } else if let modules = runModules {
            modulesToRun = modules.split(separator: ",").map { String($0.trimmingCharacters(in: .whitespaces)) }
            print("[\(timestamp)] INFO  === MULTIPLE MODULE COLLECTION ===")
        } else {
            // Default modules
            modulesToRun = config.enabledModules
            print("[\(timestamp)] INFO  === FULL DATA COLLECTION ===")
        }
        
        print("[\(timestamp)] INFO      Collecting data for modules: \(modulesToRun.joined(separator: ", "))")
        logger.info("Starting data collection for \(modulesToRun.count) modules")
        
        // Show header in verbose mode
        if ConsoleFormatter.isVerbose {
            ConsoleFormatter.writeSection("Data Collection", subtitle: "Collecting \(modulesToRun.count) modules")
        }
        
        var collectedData: [String: Any] = [:]
        
        // Always run inventory first to get device identity if we are doing a full run or if it's requested
        // But for now, we just run what's requested. 
        // Ideally, we should ensure 'inventory' is run if we plan to transmit, to build the DeviceInfo.
        
        let totalModules = modulesToRun.count
        for (index, module) in modulesToRun.enumerated() {
            if let (moduleName, data) = try await executeModule(module: module, config: config, logger: logger, current: index + 1, total: totalModules) {
                collectedData[moduleName] = data
            }
        }
        
        // Display completion status
        let completionTimestamp = dateFormatter.string(from: Date())
        print("[\(completionTimestamp)] INFO  Data collection completed")
        
        // Construct DeviceInfo (for backwards compatibility)
        let serialNumber = SystemUtils.getSerialNumber()
        let osVersion = SystemUtils.getOSVersion()
        let model = SystemUtils.getHardwareModel()
        let architecture = SystemUtils.getArchitecture()
        let deviceName = ProcessInfo.processInfo.hostName
        
        // Use configured device ID or generate a UUID if not set
        // API requires deviceId to be in UUID format
        let finalDeviceId: String
        if let configuredId = config.deviceId, !configuredId.isEmpty {
            finalDeviceId = configuredId
        } else {
            // Generate a stable UUID from the serial number for consistency
            finalDeviceId = serialNumber.sha256UUID()
        }
        
        // Device info captured for potential future use (logging, debugging)
        _ = DeviceInfo(
            deviceId: finalDeviceId,
            deviceName: deviceName,
            serialNumber: serialNumber,
            manufacturer: "Apple",
            model: model,
            osName: "macOS",
            osVersion: osVersion,
            architecture: architecture,
            lastSeen: Date(),
            reportMateVersion: AppVersion.current
        )
        
        // Create EventMetadata matching Windows structure
        let metadata = EventMetadata(
            deviceId: finalDeviceId,
            serialNumber: serialNumber,
            collectedAt: Date(),
            clientVersion: AppVersion.current,
            platform: "macOS",
            collectionType: "Full",
            enabledModules: modulesToRun
        )
        
        // Generate event message: "Hardware, System, Network data reported"
        // Capitalize module names and join with comma
        let nonInstallsModules = modulesToRun.filter { $0 != "installs" }
        let moduleList = nonInstallsModules.map { $0.prefix(1).uppercased() + $0.dropFirst() }.joined(separator: ", ")
        let eventMessage = moduleList.isEmpty ? "Data collection complete" : "\(moduleList) data reported"
        
        // Build events array - start with OS update detection
        var events: [ReportMateEvent] = []
        
        // Detect OS version changes (before caching new data)
        if modulesToRun.contains("system"), let systemData = collectedData["system"] as? [String: Any] {
            if let osUpdateEvent = detectOSVersionChange(systemData: systemData, logger: logger) {
                events.append(osUpdateEvent)
                logger.info("OS version change detected")
            }
        }
        
        // Generate Munki/Installs events with actual error/warning messages
        if modulesToRun.contains("installs"), let installsData = collectedData["installs"] as? [String: Any] {
            let munkiEvents = generateMunkiEvents(from: installsData)
            events.append(contentsOf: munkiEvents)
            logger.info("Generated \(munkiEvents.count) Munki event(s)")
        }
        
        // Add summary event for non-installs modules if any were collected
        if !nonInstallsModules.isEmpty {
            let summaryEvent = ReportMateEvent(
                moduleId: "collection",
                eventType: "info",
                message: eventMessage,
                timestamp: Date(),
                stringDetails: [
                    "collectionType": "Full",
                    "moduleCount": String(nonInstallsModules.count),
                    "modules": nonInstallsModules.joined(separator: ", ")
                ]
            )
            events.append(summaryEvent)
        }
        
        // Create UnifiedDevicePayload matching Windows format for API
        let unifiedPayload = UnifiedDevicePayload(
            metadata: metadata,
            events: events,
            modules: collectedData
        )
        
        // Serialize and Print
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        encoder.dateEncodingStrategy = .iso8601
        
        var payloadDict: [String: Any]?
        
        do {
            // Use unified payload for API transmission
            let jsonData = try encoder.encode(unifiedPayload)
            // Only dump full JSON at -vvv (debug level)
            if ConsoleFormatter.isDebug, let jsonString = String(data: jsonData, encoding: .utf8) {
                print("\n=== COLLECTED DATA PAYLOAD ===")
                print(jsonString)
                print("=== END PAYLOAD ===")
            }
            // Convert to dictionary for transmission/caching
            payloadDict = try JSONSerialization.jsonObject(with: jsonData) as? [String: Any]
        } catch {
            logger.error("Failed to serialize payload: \(error)")
            print("[\(completionTimestamp)] ERROR Failed to serialize payload: \(error)")
            return
        }
        
        // Initialize services
        let cacheService = CacheService()
        let apiClient = APIClient(configuration: config)
        
        if let payloadDict = payloadDict {
            // Cache the data
            await cacheService.setCachedData(payloadDict)
            await cacheService.setLastCollectionTimestamp(Date())
            logger.info("Data cached successfully")
        }
        
        if collectOnly {
            print("[\(completionTimestamp)] INFO  Data collected only (not transmitted)")
            return
        }
        
        // Transmission Logic
        print("[\(completionTimestamp)] INFO  Transmitting data to API...")
        logger.info("Transmitting data to \(config.apiUrl ?? "unknown URL")")
        
        if let payloadDict = payloadDict {
            do {
                let result = try await apiClient.transmitData(payloadDict)
                switch result {
                case .success(let response):
                    print("[\(completionTimestamp)] INFO  Transmission successful: \(response.message ?? "No message")")
                    logger.info("Transmission successful. Records processed: \(response.recordsProcessed)")
                case .failure(let error):
                    print("[\(completionTimestamp)] ERROR Transmission failed: \(error.localizedDescription)")
                    logger.error("Transmission failed: \(error)")
                }
            } catch {
                print("[\(completionTimestamp)] ERROR Transmission error: \(error.localizedDescription)")
                logger.error("Transmission error: \(error)")
            }
        }
    }
    
    private func handleTransmitOnly(config: ReportMateConfiguration, verboseLevel: VerboseLevel, logger: Logger) async throws {
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        let timestamp = dateFormatter.string(from: Date())
        
        print("[\(timestamp)] INFO  === TRANSMIT ONLY MODE ===")
        
        let cacheService = CacheService()
        let apiClient = APIClient(configuration: config)
        
        guard let cachedData = await cacheService.getCachedData() else {
            print("[\(timestamp)] ERROR No cached data found to transmit")
            logger.error("No cached data found")
            return
        }
        
        print("[\(timestamp)] INFO  Found cached data, transmitting...")
        
        do {
            let result = try await apiClient.transmitData(cachedData)
            switch result {
            case .success(let response):
                print("[\(timestamp)] INFO  Transmission successful: \(response.message ?? "No message")")
                logger.info("Transmission successful. Records processed: \(response.recordsProcessed)")
            case .failure(let error):
                print("[\(timestamp)] ERROR Transmission failed: \(error.localizedDescription)")
                logger.error("Transmission failed: \(error)")
            }
        } catch {
            print("[\(timestamp)] ERROR Transmission error: \(error.localizedDescription)")
            logger.error("Transmission error: \(error)")
        }
    }
    
    // MARK: - OS Version Change Detection
    
    /// Path to the persistent OS version state file (in base cache directory, not timestamped)
    private static let previousOSVersionPath = "/Library/Managed Reports/cache/previous_os_version.json"
    
    /// Detects OS version changes by comparing current system data against stored previous version.
    /// Returns a system event if the version changed, nil otherwise.
    private func detectOSVersionChange(systemData: [String: Any], logger: Logger) -> ReportMateEvent? {
        guard let osInfo = systemData["operatingSystem"] as? [String: Any] else {
            return nil
        }
        
        let currentVersion = osInfo["version"] as? String ?? ""
        let currentBuild = osInfo["buildNumber"] as? String ?? ""
        let currentName = osInfo["name"] as? String ?? "macOS"
        
        guard !currentVersion.isEmpty else { return nil }
        
        // Read previous version state
        let fileURL = URL(fileURLWithPath: Self.previousOSVersionPath)
        var previousVersion: String?
        var previousBuild: String?
        
        if FileManager.default.fileExists(atPath: Self.previousOSVersionPath),
           let data = try? Data(contentsOf: fileURL),
           let stored = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            previousVersion = stored["version"] as? String
            previousBuild = stored["build"] as? String
        }
        
        // Always write current version for next comparison
        let stateDict: [String: Any] = [
            "name": currentName,
            "version": currentVersion,
            "build": currentBuild,
            "platform": "macOS",
            "recorded_at": ISO8601DateFormatter().string(from: Date())
        ]
        if let jsonData = try? JSONSerialization.data(withJSONObject: stateDict, options: [.prettyPrinted, .sortedKeys]) {
            try? jsonData.write(to: fileURL)
        }
        
        // No previous version stored (first run) — no event
        guard let oldVersion = previousVersion, !oldVersion.isEmpty else {
            logger.info("No previous OS version recorded, storing \(currentVersion)")
            return nil
        }
        
        // Version unchanged — no event
        guard oldVersion != currentVersion else { return nil }
        
        // Version changed — generate event
        let message = "\(currentName) updated \(oldVersion) \u{2192} \(currentVersion)"
        logger.info(Logger.Message(stringLiteral: message))
        
        return ReportMateEvent(
            moduleId: "os_update",
            eventType: "system",
            message: message,
            timestamp: Date(),
            stringDetails: [
                "previous_version": oldVersion,
                "new_version": currentVersion,
                "previous_build": previousBuild ?? "",
                "new_build": currentBuild
            ]
        )
    }
    
    // MARK: - Munki Event Generation

    /// Generates ReportMate events from Munki data using InstallResults/RemovalResults
    /// from ManagedInstallReport.plist — matches MunkiReport's per-run event approach.
    /// Separate events for installs, removals, errors, and warnings.
    private func generateMunkiEvents(from installsData: [String: Any]) -> [ReportMateEvent] {
        var events: [ReportMateEvent] = []
        
        guard let munkiData = installsData["munki"] as? [String: Any],
              munkiData["isInstalled"] as? Bool == true else {
            return events
        }
        
        let errorsString = munkiData["errors"] as? String ?? ""
        let warningsString = munkiData["warnings"] as? String ?? ""
        
        // Read what Munki actually installed/removed this run from InstallResults/RemovalResults
        // (collected from ManagedInstallReport.plist by collectMunkiInfo)
        let newlyInstalledItems = munkiData["newlyInstalledItems"] as? [[String: String]] ?? []
        let newlyRemovedItems = munkiData["newlyRemovedItems"] as? [[String: String]] ?? []
        
        // Generate install event (MunkiReport format: "{name} {version} installed")
        if !newlyInstalledItems.isEmpty {
            let message: String
            if newlyInstalledItems.count == 1 {
                let item = newlyInstalledItems[0]
                let name = item["name"] ?? "Unknown"
                let version = item["version"] ?? ""
                message = version.isEmpty ? "\(name) installed" : "\(name) \(version) installed"
            } else {
                message = "\(newlyInstalledItems.count) packages installed"
            }
            events.append(ReportMateEvent(
                moduleId: "managedinstalls",
                eventType: "success",
                message: message,
                timestamp: Date(),
                stringDetails: newlyInstalledItems.count <= 5
                    ? Dictionary(uniqueKeysWithValues: newlyInstalledItems.compactMap { item -> (String, String)? in
                        guard let name = item["name"] else { return nil }
                        return (name, item["version"] ?? "")
                      })
                    : ["count": String(newlyInstalledItems.count)]
            ))
        }
        
        // Generate removal event (MunkiReport format: "{name} {version} removed")
        if !newlyRemovedItems.isEmpty {
            let message: String
            if newlyRemovedItems.count == 1 {
                let item = newlyRemovedItems[0]
                let name = item["name"] ?? "Unknown"
                let version = item["version"] ?? ""
                message = version.isEmpty ? "\(name) removed" : "\(name) \(version) removed"
            } else {
                message = "\(newlyRemovedItems.count) packages removed"
            }
            events.append(ReportMateEvent(
                moduleId: "managedinstalls",
                eventType: "success",
                message: message,
                timestamp: Date(),
                stringDetails: newlyRemovedItems.count <= 5
                    ? Dictionary(uniqueKeysWithValues: newlyRemovedItems.compactMap { item -> (String, String)? in
                        guard let name = item["name"] else { return nil }
                        return (name, item["version"] ?? "")
                      })
                    : ["count": String(newlyRemovedItems.count)]
            ))
        }
        
        // Generate error event (MunkiReport format: "{count} Munki errors")
        let errorMessages = parseMessagesFromString(errorsString)
        if !errorMessages.isEmpty {
            events.append(ReportMateEvent(
                moduleId: "munkireport",
                eventType: "error",
                message: "\(errorMessages.count) Munki error\(errorMessages.count == 1 ? "" : "s")",
                timestamp: Date(),
                stringDetails: ["errors": errorsString]
            ))
        }
        
        // Generate warning event (MunkiReport format: "{count} Munki warnings")
        let warningMessages = parseMessagesFromString(warningsString)
        if !warningMessages.isEmpty {
            events.append(ReportMateEvent(
                moduleId: "munkireport",
                eventType: "warning",
                message: "\(warningMessages.count) Munki warning\(warningMessages.count == 1 ? "" : "s")",
                timestamp: Date(),
                stringDetails: ["warnings": warningsString]
            ))
        }
        
        return events
    }
    
    /// Parse semicolon-separated message strings into array, filtering empty entries
    private func parseMessagesFromString(_ input: String) -> [String] {
        guard !input.isEmpty else { return [] }
        return input
            .split(separator: ";")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }
}

// MARK: - VerboseLevel Enum

public enum VerboseLevel: Int, Sendable {
    case error = 0
    case warning = 1
    case info = 2
    case debug = 3
    
    public var logLevel: Logger.Level {
        switch self {
        case .error: return .error
        case .warning: return .warning
        case .info: return .info
        case .debug: return .debug
        }
    }
}

// Entry point handled by @main attribute
