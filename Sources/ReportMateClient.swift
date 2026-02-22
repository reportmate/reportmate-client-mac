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
        
        // Build events array - start with Munki events if installs module is present
        var events: [ReportMateEvent] = []
        
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
    
    // MARK: - Munki Event Generation
    
    /// Generates ReportMate events from Munki data with actual error/warning messages
    /// Mirrors the Windows InstallsModuleProcessor.GenerateEventsFromDataAsync pattern
    private func generateMunkiEvents(from installsData: [String: Any]) -> [ReportMateEvent] {
        var events: [ReportMateEvent] = []
        
        guard let munkiData = installsData["munki"] as? [String: Any],
              munkiData["isInstalled"] as? Bool == true else {
            // Munki not installed - no events to generate
            return events
        }
        
        // Parse errors and warnings from semicolon-separated strings
        let errorsString = munkiData["errors"] as? String ?? ""
        let warningsString = munkiData["warnings"] as? String ?? ""
        let problemInstalls = munkiData["problemInstalls"] as? String ?? ""
        
        // Get item counts for context - count items with per-item messages (set by attachMessagesToItems)
        let items = munkiData["items"] as? [[String: Any]] ?? []
        let newlyInstalledCount = munkiData["newlyInstalledCount"] as? Int ?? 0
        let pendingCount = items.filter { ($0["status"] as? String) == "Pending" }.count
        let failedItems = items.filter { !($0["lastError"] as? String ?? "").isEmpty }
        let warningItems = items.filter { !($0["lastWarning"] as? String ?? "").isEmpty }
        
        // Use per-item messages as the source of truth (consolidated at collection time)
        // Fall back to raw semicolon strings only if no items have per-item messages
        let errorMessages: [String]
        let warningMessages: [String]
        let problemItems = parseMessagesFromString(problemInstalls)
        if !failedItems.isEmpty || !warningItems.isEmpty {
            // Per-item messages exist — derive message arrays from items (one per item)
            errorMessages = failedItems.compactMap { $0["lastError"] as? String }.filter { !$0.isEmpty }
            warningMessages = warningItems.compactMap { $0["lastWarning"] as? String }.filter { !$0.isEmpty }
        } else {
            // Legacy fallback — parse from semicolon-separated strings
            errorMessages = parseMessagesFromString(errorsString)
            warningMessages = parseMessagesFromString(warningsString)
        }
        
        // Build details dictionary
        var details: [String: EventDetailValue] = [
            "module_id": .string("installs"),
            "total_managed_items": .int(items.count),
            "installed_count": .int(newlyInstalledCount),
            "pending_count": .int(pendingCount)
        ]
        
        // Determine event type and message based on priority
        // PRIORITY 1: ERRORS (failed installs or Munki errors)
        if !errorMessages.isEmpty || !failedItems.isEmpty {
            let failedCount = max(errorMessages.count, failedItems.count)
            var messageParts: [String] = []
            
            // Primary message: error count with first error text
            if let firstError = errorMessages.first {
                // Show the actual error message for single errors
                if errorMessages.count == 1 {
                    messageParts.append(firstError)
                } else {
                    messageParts.append("\(failedCount) Munki error\(failedCount == 1 ? "" : "s")")
                }
            } else if !failedItems.isEmpty {
                messageParts.append("\(failedItems.count) failed install\(failedItems.count == 1 ? "" : "s")")
            }
            
            // Add warning count if any
            if !warningMessages.isEmpty || !warningItems.isEmpty {
                let warnCount = max(warningMessages.count, warningItems.count)
                messageParts.append("\(warnCount) warning\(warnCount == 1 ? "" : "s")")
            }
            
            // Add newly installed count if any actual activity this run
            if newlyInstalledCount > 0 {
                messageParts.append("\(newlyInstalledCount) installed")
            }
            
            // Include error details in payload for expansion
            details["error_count"] = .int(errorMessages.count)
            details["error_messages"] = .stringArray(errorMessages)
            details["module_status"] = .string("error")
            
            if !warningMessages.isEmpty {
                details["warning_count"] = .int(warningMessages.count)
                details["warning_messages"] = .stringArray(warningMessages)
            }
            
            if !problemItems.isEmpty {
                details["problem_installs"] = .stringArray(problemItems)
            }
            
            // Include failed item details
            if !failedItems.isEmpty {
                let failedItemDetails = failedItems.prefix(10).map { item -> [String: String] in
                    [
                        "name": item["name"] as? String ?? "Unknown",
                        "displayName": item["displayName"] as? String ?? item["name"] as? String ?? "Unknown",
                        "error": item["lastError"] as? String ?? ""
                    ]
                }
                details["failed_items"] = .dictArray(failedItemDetails)
            }
            
            let message = messageParts.joined(separator: ", ")
            events.append(ReportMateEvent(
                moduleId: "installs",
                eventType: "error",
                message: message,
                timestamp: Date(),
                details: details
            ))
        }
        // PRIORITY 2: WARNINGS (Munki warnings without errors)
        else if !warningMessages.isEmpty || !warningItems.isEmpty {
            let warnCount = max(warningMessages.count, warningItems.count)
            var messageParts: [String] = []
            
            // Show actual warning message for single warnings
            if let firstWarning = warningMessages.first, warningMessages.count == 1 {
                messageParts.append(firstWarning)
            } else {
                messageParts.append("\(warnCount) Munki warning\(warnCount == 1 ? "" : "s")")
            }
            
            // Add newly installed count if any
            if newlyInstalledCount > 0 {
                messageParts.append("\(newlyInstalledCount) installed")
            }
            
            details["warning_count"] = .int(warningMessages.count)
            details["warning_messages"] = .stringArray(warningMessages)
            details["module_status"] = .string("warning")
            
            // Include warning item details
            if !warningItems.isEmpty {
                let warningItemDetails = warningItems.prefix(10).map { item -> [String: String] in
                    [
                        "name": item["name"] as? String ?? "Unknown",
                        "displayName": item["displayName"] as? String ?? item["name"] as? String ?? "Unknown",
                        "warning": item["lastWarning"] as? String ?? ""
                    ]
                }
                details["warning_items"] = .dictArray(warningItemDetails)
            }
            
            let message = messageParts.joined(separator: ", ")
            events.append(ReportMateEvent(
                moduleId: "installs",
                eventType: "warning",
                message: message,
                timestamp: Date(),
                details: details
            ))
        }
        // PRIORITY 3: SUCCESS (items actually installed this run, no errors or warnings)
        else if newlyInstalledCount > 0 {
            var messageParts: [String] = []
            
            messageParts.append("\(newlyInstalledCount) package\(newlyInstalledCount == 1 ? "" : "s") installed")
            
            if pendingCount > 0 {
                messageParts.append("\(pendingCount) pending")
            }
            
            details["module_status"] = .string("success")
            
            let message = messageParts.joined(separator: ", ")
            events.append(ReportMateEvent(
                moduleId: "installs",
                eventType: "success",
                message: message,
                timestamp: Date(),
                details: details
            ))
        }
        // NO CHANGES: Munki is running normally, nothing to report - no event needed
        // Matches Windows behavior: don't generate events for steady-state "all managed" status
        else {
            // No event generated - normal operation
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
