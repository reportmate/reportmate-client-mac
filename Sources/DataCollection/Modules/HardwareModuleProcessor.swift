import Foundation

/// Hardware module processor for collecting comprehensive hardware information
/// Uses osquery as primary data source with bash fallback - NO Python
/// Reference: https://github.com/munkireport/machine for MunkiReport patterns
/// osquery tables: system_info, memory_devices, virtual_memory_info, mounts, battery
public class HardwareModuleProcessor: BaseModuleProcessor, @unchecked Sendable {
    
    public init(configuration: ReportMateConfiguration) {
        super.init(moduleId: "hardware", configuration: configuration)
    }
    
    public override func collectData() async throws -> ModuleData {
        print("=== HARDWARE MODULE COLLECTION ===")
        print("Collecting comprehensive hardware data for macOS...")
        print("Using osquery + bash (no Python)")
        print("─────────────────────────────────")
        
        let startTime = Date()
        let hardwareData = try await collectComprehensiveHardwareData()
        let duration = Date().timeIntervalSince(startTime)
        
        print("Hardware data collection completed in \(String(format: "%.2f", duration)) seconds")
        return BaseModuleData(moduleId: moduleId, data: hardwareData)
    }
    
    public func collectComprehensiveHardwareData() async throws -> [String: Any] {
        print("Starting comprehensive hardware collection...")
        
        // Collect all hardware data first
        var rawData: [String: Any] = [:]
        
        // Collect system information (osquery: system_info + bash fallback)
        print("  [1/9] Collecting system information...")
        let systemInfo = try await collectSystemInfo()
        rawData["system"] = systemInfo
        
        // Collect processor information (osquery: system_info + bash sysctl)
        print("  [2/9] Collecting processor information...")
        let processorInfo = try await collectProcessorInfo()
        rawData["processor_raw"] = processorInfo
        
        // Collect memory information (osquery: memory_devices, virtual_memory_info + bash)
        print("  [3/9] Collecting memory information...")
        let memoryInfo = try await collectMemoryInfo()
        rawData["memory_raw"] = memoryInfo
        
        // Collect storage information (osquery: mounts + bash diskutil)
        print("  [4/9] Collecting storage information...")
        let storageInfo = try await collectStorageInfo()
        rawData["storage_raw"] = storageInfo
        
        // Collect graphics information (bash: system_profiler)
        print("  [5/9] Collecting graphics information...")
        let graphicsInfo = try await collectGraphicsInfo()
        rawData["graphics_raw"] = graphicsInfo
        
        // Collect battery information (osquery: battery + bash pmset)
        print("  [6/9] Collecting battery information...")
        let batteryInfo = try await collectBatteryInfo()
        rawData["battery"] = batteryInfo
        
        // Collect wireless (Wi-Fi) information (bash: system_profiler + airport)
        print("  [7/9] Collecting wireless information...")
        let wirelessInfo = try await collectWirelessInfo()
        rawData["wireless"] = wirelessInfo
        
        // Collect Bluetooth information (bash: system_profiler)
        print("  [8/9] Collecting Bluetooth information...")
        let bluetoothInfo = try await collectBluetoothInfo()
        rawData["bluetooth"] = bluetoothInfo
        
        // Collect thermal information (bash: pmset)
        print("  [9/9] Collecting thermal information...")
        rawData["thermal"] = try await collectThermalInfo()
        
        // Collect NPU information (bash: sysctl for Apple Silicon detection)
        if let npuInfo = try await collectNPUInfo() {
            rawData["npu"] = npuInfo
        }
        
        // ============================================================
        // Build ordered output with Windows-compatible fields
        // Order: collectedAt, model, model_identifier, manufacturer,
        //        processor, graphics, memory, storage, battery, wireless, bluetooth
        // ============================================================
        
        var hardwareData: [String: Any] = [:]
        
        // 1. collectedAt - ISO 8601 timestamp
        let isoFormatter = ISO8601DateFormatter()
        hardwareData["collectedAt"] = isoFormatter.string(from: Date())
        
        // 2. model (friendly name like "Mac mini (2024)")
        // 3. model_identifier (technical ID like "Mac16,11")
        // 4. manufacturer (cleaned to "Apple")
        // 5. formFactor ("desktop" or "laptop")
        if let systemDict = systemInfo as? [String: Any] {
            // Get model identifier (e.g., "Mac16,11")
            let modelId = systemDict["hardware_model"] as? String ?? ""
            
            // Get friendly model name (e.g., "Mac mini" or "Mac mini (2024)")
            let modelName = systemDict["model_name"] as? String ?? ""
            
            // Check if model_name already includes a year (e.g., "Mac mini (2024)")
            let hasYearPattern = modelName.range(of: "\\(\\d{4}\\)", options: .regularExpression) != nil
            
            // Set model
            if !modelName.isEmpty && modelName != "Mac" {
                // If ioreg already provided the year, use it as-is
                if hasYearPattern {
                    hardwareData["model"] = modelName
                } else {
                    // Otherwise, try to add year from our mapping
                    let modelYear = getModelYear(from: modelId)
                    if !modelYear.isEmpty {
                        hardwareData["model"] = "\(modelName) (\(modelYear))"
                    } else {
                        hardwareData["model"] = modelName
                    }
                }
            } else {
                hardwareData["model"] = modelId
            }
            
            // Set model_identifier
            hardwareData["model_identifier"] = modelId
            
            // Manufacturer - clean to just "Apple" (not "Apple Inc.")
            let vendor = systemDict["hardware_vendor"] as? String ?? "Apple Inc."
            hardwareData["manufacturer"] = vendor.replacingOccurrences(of: " Inc.", with: "")
            
            // Determine form factor (desktop vs laptop)
            hardwareData["formFactor"] = determineFormFactor(modelIdentifier: modelId, modelName: modelName)
        }
        
        // 5. processor - Enhanced with performance/efficiency cores
        if let procDict = processorInfo as? [String: Any] {
            var windowsProcessor: [String: Any] = [:]
            
            // Get chip type name (e.g., "Apple M4 Pro")
            let cpuBrand = procDict["cpu_brand"] as? String ?? "Unknown"
            windowsProcessor["name"] = cpuBrand
            
            // Handle cores
            if let coresStr = procDict["cpu_physical_cores"] as? String, let cores = Int(coresStr) {
                windowsProcessor["cores"] = cores
            } else if let cores = procDict["cpu_physical_cores"] as? Int {
                windowsProcessor["cores"] = cores
            }
            
            // Handle logical processors
            if let logicalStr = procDict["cpu_logical_cores"] as? String, let logical = Int(logicalStr) {
                windowsProcessor["logicalProcessors"] = logical
            } else if let logical = procDict["cpu_logical_cores"] as? Int {
                windowsProcessor["logicalProcessors"] = logical
            }
            
            // Parse performance/efficiency cores from system_profiler (format: "proc 14:10:4")
            // This is only available on Apple Silicon
            if let numberProcs = procDict["number_processors"] as? String {
                // Format: "proc total:performance:efficiency"
                let pattern = "proc (\\d+):(\\d+):(\\d+)"
                if let regex = try? NSRegularExpression(pattern: pattern),
                   let match = regex.firstMatch(in: numberProcs, range: NSRange(numberProcs.startIndex..., in: numberProcs)) {
                    if let totalRange = Range(match.range(at: 1), in: numberProcs),
                       let perfRange = Range(match.range(at: 2), in: numberProcs),
                       let effRange = Range(match.range(at: 3), in: numberProcs) {
                        windowsProcessor["cores"] = Int(numberProcs[totalRange])
                        windowsProcessor["performanceCores"] = Int(numberProcs[perfRange])
                        windowsProcessor["efficiencyCores"] = Int(numberProcs[effRange])
                    }
                }
            }
            
            // Clean up architecture: "arm64e" -> "ARM64"
            let rawArch = procDict["cpu_type"] as? String ?? "arm64"
            if rawArch.hasPrefix("arm64") {
                windowsProcessor["architecture"] = "ARM64"
            } else if rawArch == "x86_64" {
                windowsProcessor["architecture"] = "x64"
            } else {
                windowsProcessor["architecture"] = rawArch
            }
            
            windowsProcessor["manufacturer"] = "Apple"
            hardwareData["processor"] = windowsProcessor
        }
        
        // 6. graphics - Enhanced with Metal support, bus, device type
        if let graphDict = graphicsInfo as? [String: Any] {
            var windowsGraphics: [String: Any] = [:]
            
            // Extract GPU info from SPDisplaysDataType array
            if let gpuArray = graphDict["SPDisplaysDataType"] as? [[String: Any]], let firstGpu = gpuArray.first {
                windowsGraphics["name"] = firstGpu["sppci_model"] as? String ?? firstGpu["_name"] as? String ?? "Unknown"
                windowsGraphics["manufacturer"] = "Apple"
                
                // Get GPU cores if available
                if let coresStr = firstGpu["sppci_cores"] as? String, let cores = Int(coresStr) {
                    windowsGraphics["cores"] = cores
                }
                
                // Bus type (e.g., "spdisplays_builtin" -> "Built-in")
                if let bus = firstGpu["sppci_bus"] as? String {
                    windowsGraphics["bus"] = bus.replacingOccurrences(of: "spdisplays_", with: "").capitalized
                }
                
                // Device type (e.g., "spdisplays_gpu" -> "GPU")
                if let deviceType = firstGpu["sppci_device_type"] as? String {
                    windowsGraphics["deviceType"] = deviceType.replacingOccurrences(of: "spdisplays_", with: "").uppercased()
                }
                
                // Metal support (e.g., "spdisplays_metal4" -> "Metal 4")
                if let metalSupport = firstGpu["spdisplays_mtlgpufamilysupport"] as? String {
                    // Convert "spdisplays_metal4" to "Metal 4"
                    let metalVersion = metalSupport.replacingOccurrences(of: "spdisplays_metal", with: "")
                    windowsGraphics["metalSupport"] = "Metal \(metalVersion)"
                }
                
                // Vendor (e.g., "sppci_vendor_Apple" -> "Apple")
                if let vendor = firstGpu["sppci_vendor"] as? String {
                    windowsGraphics["vendor"] = vendor.replacingOccurrences(of: "sppci_vendor_", with: "")
                }
            }
            
            hardwareData["graphics"] = windowsGraphics
        }
        
        // 7. displays - Array of connected displays
        if let graphDict = graphicsInfo as? [String: Any],
           let gpuArray = graphDict["SPDisplaysDataType"] as? [[String: Any]] {
            var displaysArray: [[String: Any]] = []
            
            // Iterate through all GPUs to find displays
            for gpu in gpuArray {
                if let displays = gpu["spdisplays_ndrvs"] as? [[String: Any]] {
                    for display in displays {
                        var displayInfo: [String: Any] = [:]
                        
                        // Display name
                        displayInfo["name"] = display["_name"] as? String ?? "Unknown Display"
                        
                        // Serial number - use human-readable serial (spdisplays_display-serial-number)
                        // NOT the hex version (_spdisplays_display-serial-number)
                        if let serial = display["spdisplays_display-serial-number"] as? String, !serial.isEmpty {
                            displayInfo["serialNumber"] = serial
                        }
                        
                        // Display type (Retina LCD, etc.)
                        if let displayType = display["spdisplays_display_type"] as? String {
                            // Clean up "spdisplays_retinaLCD" -> "Retina LCD"
                            var cleanType = displayType.replacingOccurrences(of: "spdisplays_", with: "")
                            // Add space before LCD
                            cleanType = cleanType.replacingOccurrences(of: "retinaLCD", with: "Retina LCD")
                            cleanType = cleanType.replacingOccurrences(of: "retina", with: "Retina")
                            displayInfo["displayType"] = cleanType
                        }
                        
                        // Resolution - use pixel resolution for display (e.g., "5120 x 2880")
                        displayInfo["resolution"] = display["_spdisplays_pixels"] as? String ?? "Unknown"
                        
                        // Scaled resolution (e.g., "2560 x 1440 @ 60.00Hz")
                        displayInfo["scaledResolution"] = display["_spdisplays_resolution"] as? String
                        
                        // Firmware version (e.g., "Version 17.0 (Build 21A329)")
                        if let firmware = display["spdisplays_display-fw-version"] as? String, !firmware.isEmpty {
                            displayInfo["firmwareVersion"] = firmware
                        }
                        
                        // Is main display
                        let isMain = display["spdisplays_main"] as? String == "spdisplays_yes"
                        displayInfo["isMainDisplay"] = isMain
                        
                        // Mirror status
                        let isMirrored = display["spdisplays_mirror"] as? String == "spdisplays_on"
                        displayInfo["mirror"] = isMirrored
                        
                        // Online status
                        let isOnline = display["spdisplays_online"] as? String == "spdisplays_yes"
                        displayInfo["online"] = isOnline
                        
                        // Ambient brightness support
                        let hasAmbient = display["spdisplays_ambient_brightness"] as? String == "spdisplays_yes"
                        displayInfo["ambientBrightnessEnabled"] = hasAmbient
                        
                        // Connection type (if available)
                        if let connType = display["spdisplays_connection_type"] as? String {
                            displayInfo["connectionType"] = connType.replacingOccurrences(of: "spdisplays_", with: "")
                        }
                        
                        // Display type (internal/external) - Studio Display is external, built-in is internal
                        let displayName = displayInfo["name"] as? String ?? ""
                        displayInfo["type"] = displayName.contains("Built-in") ? "internal" : "external"
                        
                        displaysArray.append(displayInfo)
                    }
                }
            }
            
            if !displaysArray.isEmpty {
                hardwareData["displays"] = displaysArray
            }
        }
        
        // 8. memory - Enhanced with type and manufacturer
        if let memDict = memoryInfo as? [String: Any] {
            var windowsMemory: [String: Any] = [:]
            
            // Handle physical_memory
            if let memStr = memDict["physical_memory"] as? String, let memBytes = Int64(memStr) {
                windowsMemory["totalPhysical"] = memBytes
            } else if let memBytes = memDict["physical_memory"] as? Int64 {
                windowsMemory["totalPhysical"] = memBytes
            } else if let memBytes = memDict["physical_memory"] as? Int {
                windowsMemory["totalPhysical"] = Int64(memBytes)
            }
            
            // Memory type (e.g., "LPDDR5")
            if let memType = memDict["dimm_type"] as? String {
                windowsMemory["type"] = memType
            } else {
                windowsMemory["type"] = memDict["memory_type"] as? String ?? "Unknown"
            }
            
            // Memory manufacturer (e.g., "Hynix", "Samsung")
            if let manufacturer = memDict["dimm_manufacturer"] as? String {
                windowsMemory["manufacturer"] = manufacturer
            }
            
            hardwareData["memory"] = windowsMemory
        }
        
        // 9. storage - Enhanced with physical drive info, SMART status, internal/external
        // Use system_profiler SPStorageDataType for rich physical drive details
        var windowsStorage: [[String: Any]] = []
        var processedDrives: Set<String> = []  // Dedupe by device name
        
        // First, try to get enhanced storage info from system_profiler
        let spStorageScript = """
            system_profiler SPStorageDataType -json 2>/dev/null
        """
        
        if let spStorageJson = try? await BashService.execute(spStorageScript),
           let spStorageData = spStorageJson.data(using: .utf8),
           let spStorage = try? JSONSerialization.jsonObject(with: spStorageData) as? [String: Any],
           let spVolumes = spStorage["SPStorageDataType"] as? [[String: Any]] {
            
            for volume in spVolumes {
                let mountPoint = volume["mount_point"] as? String ?? ""
                
                // Skip non-standard mount points (keep /, /System/Volumes/Data, and /Volumes/*)
                if mountPoint.isEmpty { continue }
                if !mountPoint.hasPrefix("/") && !mountPoint.hasPrefix("/Volumes/") && mountPoint != "/" { continue }
                
                // Skip system volumes like Recovery, Preboot, VM
                let volumeName = volume["_name"] as? String ?? ""
                let skipNames = ["Recovery", "Preboot", "VM", "Update", "xART", "iSCPreboot", "Hardware"]
                if skipNames.contains(where: { volumeName.contains($0) }) { continue }
                
                // Get physical drive info
                guard let physicalDrive = volume["physical_drive"] as? [String: Any] else { continue }
                let deviceName = physicalDrive["device_name"] as? String ?? "Unknown"
                
                // Skip if we've already processed this device
                if processedDrives.contains(deviceName) { continue }
                processedDrives.insert(deviceName)
                
                var drive: [String: Any] = [:]
                
                // Volume/drive name
                drive["name"] = volumeName.isEmpty ? "Unknown" : volumeName
                
                // Device name (actual hardware name like "APPLE SSD AP2048Z")
                drive["deviceName"] = deviceName
                
                // Capacity and free space
                if let sizeBytes = volume["size_in_bytes"] as? Int64 {
                    drive["capacity"] = sizeBytes
                }
                if let freeBytes = volume["free_space_in_bytes"] as? Int64 {
                    drive["freeSpace"] = freeBytes
                }
                
                // File system
                drive["fileSystem"] = volume["file_system"] as? String ?? "Unknown"
                
                // Physical drive details
                // Medium type (ssd, hdd, etc.)
                let mediumType = physicalDrive["medium_type"] as? String ?? "ssd"
                drive["type"] = mediumType.uppercased()
                
                // Protocol/interface (Apple Fabric, USB, SATA, etc.)
                drive["interface"] = physicalDrive["protocol"] as? String ?? "Unknown"
                
                // Internal vs External
                let isInternal = physicalDrive["is_internal_disk"] as? String == "yes"
                drive["isInternal"] = isInternal
                
                // SMART status (Verified, Failing, etc.)
                let smartStatus = physicalDrive["smart_status"] as? String ?? "Unknown"
                if smartStatus == "Verified" {
                    drive["health"] = "Good"
                    drive["smartStatus"] = "Verified"
                } else if smartStatus == "N/A" || smartStatus == "Unknown" {
                    drive["health"] = "Unknown"
                    drive["smartStatus"] = "Not Supported"
                } else {
                    drive["health"] = smartStatus
                    drive["smartStatus"] = smartStatus
                }
                
                // Detachable
                if let detachable = physicalDrive["detachable_drive"] as? String {
                    drive["detachable"] = detachable == "yes"
                }
                
                windowsStorage.append(drive)
            }
        }
        
        // Fallback to basic osquery mounts if system_profiler didn't work
        if windowsStorage.isEmpty, let storageDict = storageInfo as? [String: Any] {
            if let items = storageDict["items"] as? [[String: Any]] {
                for item in items {
                    let path = item["path"] as? String ?? ""
                    
                    // Only include root volume "/"
                    if path == "/" {
                        var drive: [String: Any] = [:]
                        
                        let blocks = Int64(item["blocks"] as? String ?? "0") ?? (item["blocks"] as? Int64 ?? 0)
                        let blocksFree = Int64(item["blocks_available"] as? String ?? item["blocks_free"] as? String ?? "0") ?? 
                                        (item["blocks_available"] as? Int64 ?? item["blocks_free"] as? Int64 ?? 0)
                        let blockSize = Int64(item["blocks_size"] as? String ?? "4096") ?? (item["blocks_size"] as? Int64 ?? 4096)
                        
                        drive["name"] = "Macintosh HD"
                        drive["capacity"] = blocks * blockSize
                        drive["freeSpace"] = blocksFree * blockSize
                        drive["type"] = "SSD"
                        drive["interface"] = item["type"] as? String ?? "APFS"
                        drive["health"] = "Good"
                        drive["isInternal"] = true
                        
                        windowsStorage.append(drive)
                        break
                    }
                }
            }
        }
        
        // Add storage directory analysis for the primary (internal) drive
        // This provides the directory breakdown visualization like Windows
        if !windowsStorage.isEmpty {
            // Find the primary internal storage device (root volume "/")
            for i in 0..<windowsStorage.count {
                if windowsStorage[i]["isInternal"] as? Bool == true {
                    // Collect directory analysis for this drive
                    do {
                        print("  [*] Analyzing storage directories for breakdown visualization...")
                        let directoryAnalysis = try await collectStorageDirectoryAnalysis(forDrivePath: "/")
                        addStorageAnalysisToDevice(&windowsStorage[i], directoryAnalysis: directoryAnalysis)
                    } catch {
                        print("  [!] Storage directory analysis failed: \(error.localizedDescription)")
                        // Continue without directory analysis - storage will still work, just no breakdown
                        windowsStorage[i]["storageAnalysisEnabled"] = false
                    }
                    break  // Only analyze the first internal drive
                }
            }
            hardwareData["storage"] = windowsStorage
        }
        
        // 10. battery
        hardwareData["battery"] = batteryInfo
        
        // 11. displays (already added above if present)
        
        // 12. wireless - Wi-Fi adapter info
        if let wireless = wirelessInfo {
            hardwareData["wireless"] = wireless
        }
        
        // 13. bluetooth - Bluetooth adapter info
        if let bluetooth = bluetoothInfo {
            hardwareData["bluetooth"] = bluetooth
        }
        
        // Keep additional raw data for reference (system, thermal, npu)
        // These are at the end, after the main hardware fields
        hardwareData["system"] = systemInfo
        hardwareData["thermal"] = rawData["thermal"]
        if let npu = rawData["npu"] {
            hardwareData["npu"] = npu
        }
        
        print("Hardware collection completed successfully")
        return hardwareData
    }
    
    // MARK: - Form Factor Detection
    
    private func determineFormFactor(modelIdentifier: String, modelName: String) -> String {
        // Desktop models: Mac mini, Mac Studio, Mac Pro, iMac
        // Laptop models: MacBook, MacBook Air, MacBook Pro
        
        let lowercasedName = modelName.lowercased()
        let lowercasedId = modelIdentifier.lowercased()
        
        // Check by model name first (most reliable)
        if lowercasedName.contains("macbook") {
            return "laptop"
        }
        if lowercasedName.contains("mac mini") || lowercasedName.contains("mac studio") || 
           lowercasedName.contains("mac pro") || lowercasedName.contains("imac") {
            return "desktop"
        }
        
        // Fallback to model identifier patterns
        // MacBook identifiers: MacBookPro*, MacBookAir*, MacBook*
        if lowercasedId.hasPrefix("macbookpro") || lowercasedId.hasPrefix("macbookair") || 
           lowercasedId.hasPrefix("macbook") {
            return "laptop"
        }
        
        // Mac mini: Macmini*, Mac14,3, Mac14,12, Mac16,10, Mac16,11
        // Mac Studio: Mac13,1, Mac13,2, Mac14,13, Mac14,14
        // Mac Pro: MacPro*, Mac14,8
        // iMac: iMac*, Mac15,4, Mac15,5
        if lowercasedId.hasPrefix("macmini") || lowercasedId.hasPrefix("macpro") || 
           lowercasedId.hasPrefix("imac") {
            return "desktop"
        }
        
        // Modern Mac identifiers (Mac##,##) - check specific ranges
        if lowercasedId.hasPrefix("mac") {
            // Mac mini M4: Mac16,10, Mac16,11
            // Mac mini M2: Mac14,3, Mac14,12
            // Mac Studio: Mac13,1, Mac13,2, Mac14,13, Mac14,14
            // Mac Pro: Mac14,8
            // iMac: Mac15,4, Mac15,5
            // These are all desktops
            let desktopIds = ["mac16,10", "mac16,11", "mac14,3", "mac14,12", 
                             "mac13,1", "mac13,2", "mac14,13", "mac14,14", "mac14,8",
                             "mac15,4", "mac15,5"]
            if desktopIds.contains(lowercasedId) {
                return "desktop"
            }
            
            // MacBook Pro M4: Mac16,1, Mac16,2, Mac16,5, Mac16,6, Mac16,7, Mac16,8
            // MacBook Air M3: Mac15,12, Mac15,13
            // MacBook Air M2: Mac14,2, Mac14,15
            // MacBook Pro M3: Mac15,3, Mac15,6, Mac15,7, Mac15,8, Mac15,9, Mac15,10, Mac15,11
            // These are all laptops
            let laptopIds = ["mac16,1", "mac16,2", "mac16,5", "mac16,6", "mac16,7", "mac16,8",
                            "mac15,12", "mac15,13", "mac14,2", "mac14,15",
                            "mac15,3", "mac15,6", "mac15,7", "mac15,8", "mac15,9", "mac15,10", "mac15,11"]
            if laptopIds.contains(lowercasedId) {
                return "laptop"
            }
        }
        
        // Default to "unknown" if we can't determine
        return "unknown"
    }
    
    // MARK: - System Info (osquery: system_info)
    
    private func collectSystemInfo() async throws -> [String: Any] {
        // osquery system_info provides: hostname, hardware_serial, hardware_vendor, hardware_model,
        // computer_name, cpu_brand, uuid, hardware_version
        let osqueryScript = """
            SELECT 
                hostname, hardware_serial, hardware_vendor, hardware_model,
                computer_name, hardware_version, uuid
            FROM system_info;
        """
        
        // bash fallback using system_profiler and ioreg
        let bashScript = """
            # Get model identifier from sysctl
            model_id=$(sysctl -n hw.model 2>/dev/null)
            
            # Get hardware serial
            serial=$(ioreg -l | grep IOPlatformSerialNumber | awk -F'"' '{print $4}')
            
            # Get UUID
            hw_uuid=$(ioreg -d2 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}')
            
            # Get chip type for hardware_version
            chip=$(sysctl -n machdep.cpu.brand_string 2>/dev/null)
            
            # Get friendly model name - different methods for Intel vs Apple Silicon
            cpu_arch=$(uname -m 2>/dev/null)
            if [ "$cpu_arch" = "arm64" ]; then
                # Apple Silicon: Use ioreg product-name with plutil and base64 decode (e.g., "Mac mini (2024)")
                # The product-name is base64 encoded in the plist XML
                model_name=$(ioreg -ar -k product-name -d1 2>/dev/null | plutil -extract 0.product-name raw -o - - 2>/dev/null | base64 -d 2>/dev/null | tr -d '\0')
            else
                # Intel: Try SIMachineAttributes.plist
                if [ -f "/System/Library/PrivateFrameworks/ServerInformation.framework/Resources/en.lproj/SIMachineAttributes.plist" ]; then
                    model_name=$(defaults read /System/Library/PrivateFrameworks/ServerInformation.framework/Resources/en.lproj/SIMachineAttributes "$model_id" 2>/dev/null | grep marketingModel | awk -F'"' '{print $2}')
                fi
            fi
            
            # Fallback to system_profiler if ioreg didn't work
            if [ -z "$model_name" ]; then
                sp_json=$(system_profiler SPHardwareDataType -json 2>/dev/null)
                if [ -n "$sp_json" ]; then
                    model_name=$(echo "$sp_json" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('SPHardwareDataType', [{}])[0].get('machine_name', 'Mac'))" 2>/dev/null)
                fi
            fi
            
            # If still empty, default to "Mac"
            model_name=${model_name:-Mac}
            
            echo "{"
            echo "  \\"hostname\\": \\"$(hostname -s)\\","
            echo "  \\"hardware_serial\\": \\"$serial\\","
            echo "  \\"hardware_vendor\\": \\"Apple Inc.\\","
            echo "  \\"hardware_model\\": \\"$model_id\\","
            echo "  \\"computer_name\\": \\"$(scutil --get ComputerName 2>/dev/null || hostname -s)\\","
            echo "  \\"hardware_version\\": \\"$chip\\","
            echo "  \\"uuid\\": \\"$hw_uuid\\","
            echo "  \\"model_name\\": \\"$model_name\\"" 
            echo "}"
        """
        
        var result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript,
            python: nil
        )
        
        // osquery doesn't have model_name, so we add it by extracting from ioreg
        // This works around osquery's limitation - friendly model name is only in ioreg
        if var resultDict = result as? [String: Any], resultDict["model_name"] == nil {
            // Simple inline script to get model name
            let modelNameCommand = "ioreg -ar -k product-name -d1 2>/dev/null | plutil -extract 0.product-name raw -o - - 2>/dev/null | base64 -d 2>/dev/null | tr -d '\\0'"
            
            if let modelName = try? await BashService.execute(modelNameCommand).trimmingCharacters(in: .whitespacesAndNewlines),
               !modelName.isEmpty {
                resultDict["model_name"] = modelName
                result = resultDict
            }
        }
        
        return result
    }
    
    // MARK: - Model Year Mapping
    
    private func getModelYear(from modelIdentifier: String) -> String {
        // Map model identifiers to release years
        // Source: https://support.apple.com/en-us/HT201300
        let modelYearMap: [String: String] = [
            // Mac mini
            "Mac16,11": "2024",  // Mac mini (M4 Pro, 2024)
            "Mac16,10": "2024",  // Mac mini (M4, 2024)
            "Mac14,12": "2023",  // Mac mini (M2 Pro, 2023)
            "Mac14,3": "2023",   // Mac mini (M2, 2023)
            "Macmini9,1": "2020", // Mac mini (M1, 2020)
            
            // MacBook Pro
            "Mac16,1": "2024",   // MacBook Pro 14-inch (M4, 2024)
            "Mac16,2": "2024",   // MacBook Pro 14-inch (M4 Pro, 2024)
            "Mac16,5": "2024",   // MacBook Pro 16-inch (M4 Pro, 2024)
            "Mac16,6": "2024",   // MacBook Pro 16-inch (M4 Max, 2024)
            "Mac15,3": "2023",   // MacBook Pro 14-inch (M3, 2023)
            "Mac15,6": "2023",   // MacBook Pro 14-inch (M3 Pro/Max, 2023)
            "Mac15,8": "2023",   // MacBook Pro 16-inch (M3 Pro/Max, 2023)
            "Mac14,5": "2023",   // MacBook Pro 14-inch (M2 Pro/Max, 2023)
            "Mac14,6": "2023",   // MacBook Pro 16-inch (M2 Pro/Max, 2023)
            "Mac14,7": "2022",   // MacBook Pro 13-inch (M2, 2022)
            
            // MacBook Air
            "Mac15,12": "2024",  // MacBook Air 13-inch (M3, 2024)
            "Mac15,13": "2024",  // MacBook Air 15-inch (M3, 2024)
            "Mac14,15": "2023",  // MacBook Air 15-inch (M2, 2023)
            "Mac14,2": "2022",   // MacBook Air 13-inch (M2, 2022)
            "MacBookAir10,1": "2020", // MacBook Air 13-inch (M1, 2020)
            
            // iMac
            "Mac16,3": "2024",   // iMac 24-inch (M4, 2024)
            "Mac15,4": "2023",   // iMac 24-inch (M3, 2023)
            "iMac21,1": "2021",  // iMac 24-inch (M1, 2021)
            "iMac21,2": "2021",  // iMac 24-inch (M1, 2021)
            
            // Mac Studio
            "Mac15,5": "2024",   // Mac Studio (M2 Ultra, 2024)
            "Mac14,13": "2023",  // Mac Studio (M2 Max, 2023)
            "Mac14,14": "2023",  // Mac Studio (M2 Ultra, 2023)
            "Mac13,1": "2022",   // Mac Studio (M1 Max, 2022)
            "Mac13,2": "2022",   // Mac Studio (M1 Ultra, 2022)
            
            // Mac Pro
            "Mac14,8": "2023",   // Mac Pro (M2 Ultra, 2023)
        ]
        
        return modelYearMap[modelIdentifier] ?? ""
    }
    
    // MARK: - Processor Info (osquery: system_info + bash sysctl)
    
    private func collectProcessorInfo() async throws -> [String: Any] {
        // osquery system_info provides: cpu_brand, cpu_logical_cores, cpu_physical_cores, cpu_type
        let osqueryScript = """
            SELECT 
                cpu_brand, cpu_logical_cores, cpu_physical_cores,
                cpu_type, cpu_subtype, cpu_microcode
            FROM system_info;
        """
        
        // bash fallback using sysctl - works on both Intel and Apple Silicon
        let bashScript = """
            brand=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "Apple Silicon")
            physical=$(sysctl -n hw.physicalcpu 2>/dev/null || echo "0")
            logical=$(sysctl -n hw.logicalcpu 2>/dev/null || echo "0")
            packages=$(sysctl -n hw.packages 2>/dev/null || echo "1")
            freq_max=$(sysctl -n hw.cpufrequency_max 2>/dev/null || echo "0")
            l1d=$(sysctl -n hw.l1dcachesize 2>/dev/null || echo "0")
            l1i=$(sysctl -n hw.l1icachesize 2>/dev/null || echo "0")
            l2=$(sysctl -n hw.l2cachesize 2>/dev/null || echo "0")
            l3=$(sysctl -n hw.l3cachesize 2>/dev/null || echo "0")
            perflevel0=$(sysctl -n hw.perflevel0.physicalcpu 2>/dev/null || echo "")
            perflevel1=$(sysctl -n hw.perflevel1.physicalcpu 2>/dev/null || echo "")
            
            echo "{"
            echo "  \\"cpu_brand\\": \\"$brand\\","
            echo "  \\"cpu_physical_cores\\": $physical,"
            echo "  \\"cpu_logical_cores\\": $logical,"
            echo "  \\"packages\\": $packages,"
            echo "  \\"frequency_max\\": $freq_max,"
            echo "  \\"cache_size_l1d\\": $l1d,"
            echo "  \\"cache_size_l1i\\": $l1i,"
            echo "  \\"cache_size_l2\\": $l2,"
            echo "  \\"cache_size_l3\\": $l3,"
            echo "  \\"performance_cores\\": \\"${perflevel0:-}\\","
            echo "  \\"efficiency_cores\\": \\"${perflevel1:-}\\"" 
            echo "}"
        """
        
        var result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript,
            python: nil
        )
        
        // Enhance with system_profiler data for number_processors (proc total:perf:eff format)
        // This gives us the performance/efficiency core breakdown on Apple Silicon
        let spHardwareScript = """
            system_profiler SPHardwareDataType -json 2>/dev/null | python3 -c "import sys, json; data = json.load(sys.stdin).get('SPHardwareDataType', [{}])[0]; print(json.dumps({'number_processors': data.get('number_processors', ''), 'chip_type': data.get('chip_type', '')}))"
        """
        
        if let spJson = try? await BashService.execute(spHardwareScript),
           let spData = spJson.data(using: .utf8),
           let spDict = try? JSONSerialization.jsonObject(with: spData) as? [String: Any] {
            if var resultDict = result as? [String: Any] {
                // Add number_processors (e.g., "proc 14:10:4")
                if let numProcs = spDict["number_processors"] as? String, !numProcs.isEmpty {
                    resultDict["number_processors"] = numProcs
                }
                // Add chip_type if cpu_brand is generic
                if let chipType = spDict["chip_type"] as? String, !chipType.isEmpty {
                    let currentBrand = resultDict["cpu_brand"] as? String ?? ""
                    if currentBrand.isEmpty || currentBrand == "Apple Silicon" {
                        resultDict["cpu_brand"] = chipType
                    }
                }
                result = resultDict
            }
        }
        
        return result
    }
    
    // MARK: - Memory Info (osquery: memory_devices, virtual_memory_info)
    
    private func collectMemoryInfo() async throws -> [String: Any] {
        // osquery memory_devices provides: memory type, size per slot
        // osquery virtual_memory_info provides: active, compressed, wired, free, swap stats
        // osquery system_info provides physical_memory
        
        let systemMemoryScript = """
            SELECT physical_memory FROM system_info;
        """
        
        // bash fallback with comprehensive memory data
        let bashScript = """
            memsize=$(sysctl -n hw.memsize 2>/dev/null || echo "0")
            pagesize=$(sysctl -n hw.pagesize 2>/dev/null || echo "4096")
            
            # Get vm_stat output and parse
            vmstat=$(vm_stat 2>/dev/null)
            pages_active=$(echo "$vmstat" | grep "Pages active" | awk '{print $NF}' | tr -d '.')
            pages_inactive=$(echo "$vmstat" | grep "Pages inactive" | awk '{print $NF}' | tr -d '.')
            pages_speculative=$(echo "$vmstat" | grep "Pages speculative" | awk '{print $NF}' | tr -d '.')
            pages_wired=$(echo "$vmstat" | grep "Pages wired" | awk '{print $NF}' | tr -d '.')
            pages_compressed=$(echo "$vmstat" | grep "Pages occupied by compressor" | awk '{print $NF}' | tr -d '.')
            pages_free=$(echo "$vmstat" | grep "Pages free" | awk '{print $NF}' | tr -d '.')
            pageins=$(echo "$vmstat" | grep "Pageins" | awk '{print $NF}' | tr -d '.')
            pageouts=$(echo "$vmstat" | grep "Pageouts" | awk '{print $NF}' | tr -d '.')
            swapins=$(echo "$vmstat" | grep "Swapins" | awk '{print $NF}' | tr -d '.')
            swapouts=$(echo "$vmstat" | grep "Swapouts" | awk '{print $NF}' | tr -d '.')
            
            # Try memory_pressure for overall system pressure
            mem_pressure=$(memory_pressure 2>/dev/null | grep "System-wide memory free percentage" | grep -o '[0-9]*' | head -1 || echo "0")
            
            # Get memory type from system_profiler
            sp_mem=$(system_profiler SPMemoryDataType 2>/dev/null)
            mem_type=$(echo "$sp_mem" | grep "Type:" | head -1 | awk -F': ' '{print $2}' | tr -d ' ')
            
            echo "{"
            echo "  \\"physical_memory\\": $memsize,"
            echo "  \\"page_size\\": $pagesize,"
            echo "  \\"memory_type\\": \\"${mem_type:-Unknown}\\","
            echo "  \\"pages_active\\": ${pages_active:-0},"
            echo "  \\"pages_inactive\\": ${pages_inactive:-0},"
            echo "  \\"pages_speculative\\": ${pages_speculative:-0},"
            echo "  \\"pages_wired\\": ${pages_wired:-0},"
            echo "  \\"pages_compressed\\": ${pages_compressed:-0},"
            echo "  \\"pages_free\\": ${pages_free:-0},"
            echo "  \\"pageins\\": ${pageins:-0},"
            echo "  \\"pageouts\\": ${pageouts:-0},"
            echo "  \\"swapins\\": ${swapins:-0},"
            echo "  \\"swapouts\\": ${swapouts:-0},"
            echo "  \\"memory_pressure_percent\\": ${mem_pressure:-0}"
            echo "}"
        """
        
        var result = try await executeWithFallback(
            osquery: systemMemoryScript,
            bash: bashScript,
            python: nil
        )
        
        // Enhance with system_profiler SPMemoryDataType for type and manufacturer
        let spMemoryScript = """
            system_profiler SPMemoryDataType -json 2>/dev/null | python3 -c "import sys, json; data = json.load(sys.stdin).get('SPMemoryDataType', [{}])[0]; dimms = data.get('_items', []); d = dimms[0] if dimms else data; print(json.dumps({'dimm_type': d.get('dimm_type', ''), 'dimm_manufacturer': d.get('dimm_manufacturer', '')}))"
        """
        
        if let spJson = try? await BashService.execute(spMemoryScript),
           let spData = spJson.data(using: .utf8),
           let spDict = try? JSONSerialization.jsonObject(with: spData) as? [String: Any] {
            if var resultDict = result as? [String: Any] {
                // Add memory type (e.g., "LPDDR5")
                if let memType = spDict["dimm_type"] as? String, !memType.isEmpty {
                    resultDict["dimm_type"] = memType
                }
                // Add manufacturer (e.g., "Hynix", "Samsung")
                if let manufacturer = spDict["dimm_manufacturer"] as? String, !manufacturer.isEmpty {
                    resultDict["dimm_manufacturer"] = manufacturer
                }
                result = resultDict
            }
        }
        
        return result
    }
    
    // MARK: - Storage Info (osquery: mounts + bash diskutil)
    
    private func collectStorageInfo() async throws -> [String: Any] {
        // osquery mounts provides: device, path, type, blocks, blocks_free, blocks_size
        let osqueryScript = """
            SELECT device, path, type, blocks, blocks_free, blocks_size, flags, 
                   blocks_available, inodes, inodes_free
            FROM mounts WHERE type NOT LIKE 'autofs%' AND type != 'devfs';
        """
        
        // bash fallback using df and diskutil for comprehensive storage info
        let bashScript = """
            # Get mounted volumes via df
            volumes_json="["
            first=true
            while IFS= read -r line; do
                if [ "$first" = true ]; then
                    first=false
                else
                    fs=$(echo "$line" | awk '{print $1}')
                    size=$(echo "$line" | awk '{print $2}')
                    used=$(echo "$line" | awk '{print $3}')
                    avail=$(echo "$line" | awk '{print $4}')
                    cap=$(echo "$line" | awk '{print $5}')
                    mount=$(echo "$line" | awk '{for(i=9;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/ $//')
                    
                    [ -n "$volumes_json" ] && [ "$volumes_json" != "[" ] && volumes_json="${volumes_json},"
                    volumes_json="${volumes_json}{\\\"filesystem\\\":\\\"$fs\\\",\\\"size\\\":\\\"$size\\\",\\\"used\\\":\\\"$used\\\",\\\"available\\\":\\\"$avail\\\",\\\"capacity\\\":\\\"$cap\\\",\\\"mount\\\":\\\"$mount\\\"}"
                fi
            done < <(df -h 2>/dev/null)
            volumes_json="${volumes_json}]"
            
            # Get physical disk info
            boot_disk=$(diskutil info / 2>/dev/null | grep "Part of Whole:" | awk '{print $4}')
            disk_info=$(diskutil info "$boot_disk" 2>/dev/null)
            disk_size=$(echo "$disk_info" | grep "Disk Size:" | awk -F'(' '{print $1}' | awk '{for(i=3;i<=NF;i++) printf "%s ", $i}' | sed 's/ $//')
            disk_type=$(echo "$disk_info" | grep "Solid State:" | awk '{print $3}')
            
            # APFS container info
            apfs_info=$(diskutil apfs list 2>/dev/null | head -20)
            
            echo "{"
            echo "  \\"mounted_volumes\\": $volumes_json,"
            echo "  \\"boot_disk\\": \\"${boot_disk:-unknown}\\","
            echo "  \\"disk_size\\": \\"${disk_size:-unknown}\\","
            echo "  \\"is_ssd\\": \\"${disk_type:-Yes}\\"" 
            echo "}"
        """
        
        return try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript,
            python: nil
        )
    }
    
    // MARK: - Graphics Info (bash: system_profiler - no osquery equivalent)
    
    private func collectGraphicsInfo() async throws -> [String: Any] {
        // osquery doesn't have good macOS graphics support
        // Use system_profiler SPDisplaysDataType directly
        let bashScript = """
            sp_json=$(system_profiler SPDisplaysDataType -json 2>/dev/null)
            
            if [ -n "$sp_json" ]; then
                echo "$sp_json"
            else
                # Minimal fallback
                echo '{"SPDisplaysDataType":[],"source":"fallback"}'
            fi
        """
        
        return try await executeWithFallback(
            osquery: nil,
            bash: bashScript,
            python: nil
        )
    }
    
    // MARK: - Battery Info (osquery: battery + bash pmset)
    
    // MARK: - Wireless Info (system_profiler + airport)
    
    private func collectWirelessInfo() async throws -> [String: Any]? {
        // Use system_profiler for Wi-Fi adapter info and airport for connection status
        let bashScript = """
            # Get Wi-Fi adapter info from system_profiler
            sp_wifi=$(system_profiler SPAirPortDataType -json 2>/dev/null)
            
            if [ -z "$sp_wifi" ] || ! echo "$sp_wifi" | grep -q "SPAirPortDataType"; then
                echo '{"isAvailable":false}'
                exit 0
            fi
            
            # Extract adapter name and supported protocols
            adapter_name=$(echo "$sp_wifi" | grep -o '"_name"[^,]*' | head -1 | cut -d'"' -f4)
            
            # Get current Wi-Fi status using airport utility
            airport_path="/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
            
            if [ -x "$airport_path" ]; then
                wifi_info=$("$airport_path" -I 2>/dev/null)
                ssid=$(echo "$wifi_info" | awk -F': ' '/ SSID/{print $2}' | head -1)
                bssid=$(echo "$wifi_info" | awk -F': ' '/BSSID/{print $2}')
                channel=$(echo "$wifi_info" | awk -F': ' '/channel/{print $2}')
                rssi=$(echo "$wifi_info" | awk -F': ' '/agrCtlRSSI/{print $2}')
                noise=$(echo "$wifi_info" | awk -F': ' '/agrCtlNoise/{print $2}')
                tx_rate=$(echo "$wifi_info" | awk -F': ' '/lastTxRate/{print $2}')
                phy_mode=$(echo "$wifi_info" | awk -F': ' '/link auth/{print $2}')
                mcs_index=$(echo "$wifi_info" | awk -F': ' '/MCS/{print $2}')
            fi
            
            # Get MAC address
            mac_addr=$(networksetup -getmacaddress Wi-Fi 2>/dev/null | awk '{print $3}')
            
            # Determine Wi-Fi status
            if [ -n "$ssid" ]; then
                status="Connected"
            else
                # Check if Wi-Fi is on but not connected
                power_status=$(networksetup -getairportpower en0 2>/dev/null | grep -o "On\\|Off")
                if [ "$power_status" = "On" ]; then
                    status="Disconnected"
                else
                    status="Off"
                fi
            fi
            
            # Get supported protocols from system_profiler
            protocols=""
            if echo "$sp_wifi" | grep -qi "802.11ax\\|Wi-Fi 6"; then
                protocols="Wi-Fi 6 (802.11ax)"
            elif echo "$sp_wifi" | grep -qi "802.11ac\\|Wi-Fi 5"; then
                protocols="Wi-Fi 5 (802.11ac)"
            elif echo "$sp_wifi" | grep -qi "802.11n"; then
                protocols="Wi-Fi 4 (802.11n)"
            fi
            
            # Get locale/country code
            locale=$(echo "$sp_wifi" | grep -o '"spairport_locale"[^,]*' | cut -d'"' -f4)
            
            echo "{"
            echo "  \\"isAvailable\\": true,"
            echo "  \\"name\\": \\"${adapter_name:-Wi-Fi}\\","
            echo "  \\"manufacturer\\": \\"Apple\\","
            echo "  \\"macAddress\\": \\"${mac_addr:-}\\","
            echo "  \\"status\\": \\"$status\\","
            echo "  \\"protocol\\": \\"${protocols:-802.11}\\","
            echo "  \\"currentNetwork\\": {"
            echo "    \\"ssid\\": \\"${ssid:-}\\","
            echo "    \\"bssid\\": \\"${bssid:-}\\","
            echo "    \\"channel\\": \\"${channel:-}\\","
            echo "    \\"rssi\\": ${rssi:--100},"
            echo "    \\"noise\\": ${noise:--100},"
            echo "    \\"txRate\\": \\"${tx_rate:-0}\\" "
            echo "  },"
            echo "  \\"locale\\": \\"${locale:-}\\""
            echo "}"
        """
        
        let result = try await executeWithFallback(
            osquery: nil,
            bash: bashScript,
            python: nil
        )
        
        // Check if wireless is available
        if let available = result["isAvailable"] as? Bool, !available {
            return nil
        }
        
        return result
    }
    
    // MARK: - Bluetooth Info (system_profiler SPBluetoothDataType)
    
    private func collectBluetoothInfo() async throws -> [String: Any]? {
        // Use system_profiler for Bluetooth adapter info
        let bashScript = """
            # Get Bluetooth info from system_profiler
            sp_bt=$(system_profiler SPBluetoothDataType -json 2>/dev/null)
            
            if [ -z "$sp_bt" ] || ! echo "$sp_bt" | grep -q "SPBluetoothDataType"; then
                echo '{"isAvailable":false}'
                exit 0
            fi
            
            # Parse controller info
            controller_info=$(echo "$sp_bt" | grep -A 50 "controller_properties" 2>/dev/null)
            
            # Extract Bluetooth version (e.g., "5.3")
            bt_version=$(echo "$controller_info" | grep -o '"controller_supportedServices"[^]]*' | grep -o 'Bluetooth [0-9.]*' | head -1 | awk '{print $2}')
            if [ -z "$bt_version" ]; then
                # Try alternate method
                bt_version=$(echo "$sp_bt" | grep -o '"controller_chipset"[^,]*' | grep -o '[0-9]\\.[0-9]' | head -1)
            fi
            
            # Get controller address (MAC)
            bt_address=$(echo "$sp_bt" | grep -o '"controller_address"[^,]*' | cut -d'"' -f4)
            
            # Get controller state
            bt_state=$(echo "$sp_bt" | grep -o '"controller_state"[^,]*' | cut -d'"' -f4)
            if [ "$bt_state" = "attrib_on" ]; then
                status="On"
            else
                status="Off"
            fi
            
            # Get chipset info
            chipset=$(echo "$sp_bt" | grep -o '"controller_chipset"[^,]*' | cut -d'"' -f4)
            
            # Get firmware version
            firmware=$(echo "$sp_bt" | grep -o '"controller_firmwareVersion"[^,]*' | cut -d'"' -f4)
            
            # Get vendor ID
            vendor_id=$(echo "$sp_bt" | grep -o '"controller_vendorID"[^,]*' | cut -d'"' -f4)
            
            # Get transport type
            transport=$(echo "$sp_bt" | grep -o '"controller_transport"[^,]*' | cut -d'"' -f4)
            
            # Determine if discoverable
            discoverable=$(echo "$sp_bt" | grep -o '"controller_discoverable"[^,]*' | cut -d'"' -f4)
            if [ "$discoverable" = "attrib_on" ]; then
                is_discoverable="true"
            else
                is_discoverable="false"
            fi
            
            # Count connected devices
            connected_count=$(echo "$sp_bt" | grep -c '"device_connected" *: *"attrib_Yes"' || echo "0")
            
            echo "{"
            echo "  \\"isAvailable\\": true,"
            echo "  \\"name\\": \\"${chipset:-Bluetooth}\\","
            echo "  \\"manufacturer\\": \\"Apple\\","
            echo "  \\"macAddress\\": \\"${bt_address:-}\\","
            echo "  \\"status\\": \\"$status\\","
            echo "  \\"bluetoothVersion\\": \\"${bt_version:-5.0}\\","
            echo "  \\"firmwareVersion\\": \\"${firmware:-}\\","
            echo "  \\"transport\\": \\"${transport:-}\\","
            echo "  \\"discoverable\\": $is_discoverable,"
            echo "  \\"connectedDevices\\": $connected_count"
            echo "}"
        """
        
        let result = try await executeWithFallback(
            osquery: nil,
            bash: bashScript,
            python: nil
        )
        
        // Check if Bluetooth is available
        if let available = result["isAvailable"] as? Bool, !available {
            return nil
        }
        
        return result
    }
    
    // MARK: - Battery Info (osquery + bash fallback)
    
    private func collectBatteryInfo() async throws -> [String: Any] {
        // osquery battery table provides: cycle_count, designed_capacity, health, etc.
        let osqueryScript = """
            SELECT charged, charging, current_capacity, designed_capacity, 
                   health, percent_remaining, condition, 
                   manufacturer, manufacture_date, model, serial_number,
                   max_capacity, cycle_count, amperage, voltage, minutes_until_empty
            FROM battery;
        """
        
        // bash fallback using pmset and system_profiler
        let bashScript = """
            # Check if we have a battery
            has_battery=$(pmset -g batt 2>/dev/null | grep -c "InternalBattery" || echo "0")
            
            if [ "$has_battery" = "0" ]; then
                # Desktop - no battery
                echo '{"has_battery":false,"power_source":"AC Power"}'
            else
                # Parse pmset output
                pmset_out=$(pmset -g batt 2>/dev/null)
                percentage=$(echo "$pmset_out" | grep -o '[0-9]*%' | tr -d '%')
                
                # Determine charging status
                if echo "$pmset_out" | grep -q "charging"; then
                    status="charging"
                elif echo "$pmset_out" | grep -q "discharging"; then
                    status="discharging"
                elif echo "$pmset_out" | grep -q "charged"; then
                    status="charged"
                else
                    status="unknown"
                fi
                
                # Get power source
                if echo "$pmset_out" | grep -q "AC Power"; then
                    source="AC Power"
                else
                    source="Battery"
                fi
                
                # Time remaining
                time_remaining=$(echo "$pmset_out" | grep -o '[0-9]*:[0-9]*' | head -1 || echo "")
                
                # Get detailed battery info from system_profiler
                sp_power=$(system_profiler SPPowerDataType -json 2>/dev/null)
                cycle_count=$(echo "$sp_power" | grep -o '"sppower_battery_cycle_count"[^,}]*' | cut -d':' -f2 | tr -d ' "')
                condition=$(echo "$sp_power" | grep -o '"sppower_battery_health"[^,}]*' | cut -d':' -f2 | tr -d ' "')
                max_cap=$(echo "$sp_power" | grep -o '"sppower_battery_max_capacity"[^,}]*' | cut -d':' -f2 | tr -d ' "')
                
                echo "{"
                echo "  \\"has_battery\\": true,"
                echo "  \\"percent_remaining\\": ${percentage:-0},"
                echo "  \\"status\\": \\"$status\\","
                echo "  \\"power_source\\": \\"$source\\","
                echo "  \\"time_remaining\\": \\"${time_remaining:-}\\","
                echo "  \\"cycle_count\\": ${cycle_count:-0},"
                echo "  \\"condition\\": \\"${condition:-Normal}\\","
                echo "  \\"max_capacity\\": ${max_cap:-100}"
                echo "}"
            fi
        """
        
        return try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript,
            python: nil
        )
    }
    
    // MARK: - Thermal Info (bash: pmset)
    
    private func collectThermalInfo() async throws -> [String: Any] {
        // osquery doesn't have thermal monitoring for macOS
        // Use pmset for thermal state
        let bashScript = """
            therm_out=$(pmset -g therm 2>/dev/null)
            
            if echo "$therm_out" | grep -q "No thermal"; then
                speed_limit=100
                thermal_state="nominal"
            else
                # Parse thermal warnings
                speed_limit=$(echo "$therm_out" | grep "CPU_Speed_Limit" | awk '{print $3}' || echo "100")
                thermal_state="throttled"
            fi
            
            # Fan info (if available via smc - may require third-party tools)
            fans_available="false"
            
            echo "{"
            echo "  \\"thermal_state\\": \\"$thermal_state\\","
            echo "  \\"cpu_speed_limit\\": ${speed_limit:-100},"
            echo "  \\"fans_available\\": $fans_available"
            echo "}"
        """
        
        return try await executeWithFallback(
            osquery: nil,
            bash: bashScript,
            python: nil
        )
    }
    
    // MARK: - Warranty Info
    
    private func collectWarrantyInfo() async throws -> [String: Any] {
        // Try to get warranty info from system_profiler or Apple's API
        // For now, return empty structure that can be populated
        let bashScript = """
            # Check if computer has hardware UUID for warranty lookup
            hw_uuid=$(ioreg -d2 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}')
            serial=$(system_profiler SPHardwareDataType | awk '/Serial/ {print $4}')
            
            # Warranty API would go here - requires authentication
            # For now, return structure with empty values
            echo "{"
            echo "  \\"items\\": [],"
            echo "  \\"serial\\": \\"$serial\\","
            echo "  \\"uuid\\": \\"$hw_uuid\\""
            echo "}"
        """
        
        do {
            let result = try await executeWithFallback(
                osquery: nil,
                bash: bashScript,
                python: nil
            )
            return result
        } catch {
            // If collection fails, return empty structure
            return [
                "items": [],
                "error": "Unable to collect warranty information"
            ]
        }
    }
    
    // MARK: - NPU Info (bash: sysctl for Apple Silicon detection)
    
    private func collectNPUInfo() async throws -> [String: Any]? {
        // No osquery support for Apple Neural Engine
        // Use sysctl to detect chip and infer NPU specs
        let bashScript = """
            arch=$(uname -m 2>/dev/null)
            
            if [ "$arch" != "arm64" ]; then
                # Intel Mac - no NPU
                echo '{"has_npu":false,"architecture":"x86_64"}'
            else
                # Apple Silicon - has Neural Engine
                chip=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "Apple Silicon")
                
                # Determine NPU specs based on chip
                if echo "$chip" | grep -q "M1"; then
                    npu_name="Apple Neural Engine (M1)"
                    cores=16
                    tops="11"
                elif echo "$chip" | grep -q "M2"; then
                    npu_name="Apple Neural Engine (M2)"
                    cores=16
                    tops="15.8"
                elif echo "$chip" | grep -q "M3"; then
                    npu_name="Apple Neural Engine (M3)"
                    cores=16
                    tops="18"
                elif echo "$chip" | grep -q "M4"; then
                    npu_name="Apple Neural Engine (M4)"
                    cores=16
                    tops="38"
                else
                    npu_name="Apple Neural Engine"
                    cores=16
                    tops="unknown"
                fi
                
                echo "{"
                echo "  \\"has_npu\\": true,"
                echo "  \\"name\\": \\"$npu_name\\","
                echo "  \\"cores\\": $cores,"
                echo "  \\"performance_tops\\": \\"$tops\\","
                echo "  \\"family\\": \\"Apple Neural Engine\\","
                echo "  \\"chip\\": \\"$chip\\""
                echo "}"
            fi
        """
        
        return try await executeWithFallback(
            osquery: nil,
            bash: bashScript,
            python: nil
        )
    }
    
    // MARK: - Storage Directory Analysis (for directory breakdown like Windows)
    
    private func collectStorageDirectoryAnalysis(forDrivePath: String = "/") async throws -> [[String: Any]] {
        // Analyze root-level directories on macOS
        // This mirrors Windows' directory breakdown functionality
        // Categories: Applications, Users, Library, System, Other
        let bashScript = """
            # Format bytes to human readable
            format_size() {
                local size=$1
                if [ $size -ge 1099511627776 ]; then
                    printf "%.1f TB" $(echo "scale=1; $size / 1099511627776" | bc)
                elif [ $size -ge 1073741824 ]; then
                    printf "%.1f GB" $(echo "scale=1; $size / 1073741824" | bc)
                elif [ $size -ge 1048576 ]; then
                    printf "%.1f MB" $(echo "scale=1; $size / 1048576" | bc)
                elif [ $size -ge 1024 ]; then
                    printf "%.1f KB" $(echo "scale=1; $size / 1024" | bc)
                else
                    printf "%d B" $size
                fi
            }
            
            # Get total disk capacity
            total_capacity=$(df -P / | awk 'NR==2 {print $2 * 512}')
            
            # Analyze a directory and output JSON
            analyze_directory() {
                local path="$1"
                local name="$2"
                local category="$3"
                local depth="$4"
                
                if [ ! -d "$path" ]; then
                    return
                fi
                
                # Get size using du with better flags
                # -x: don't cross filesystems (stay on same volume)
                # -d 0: depth 0 (just the directory itself)
                local size_output=$(du -x -d 0 -k "$path" 2>/dev/null | cut -f1)
                local size_bytes=$((${size_output:-0} * 1024))
                
                # Count files and subdirectories
                local file_count=$(find "$path" -maxdepth 1 -type f 2>/dev/null | wc -l | tr -d ' ')
                local subdir_count=$(find "$path" -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
                subdir_count=$((subdir_count - 1))  # Exclude the directory itself
                
                # Get last modified time
                local last_modified=$(stat -f "%Sm" -t "%Y-%m-%dT%H:%M:%SZ" "$path" 2>/dev/null || echo "")
                
                # Calculate percentage of drive
                local percentage=0
                if [ $total_capacity -gt 0 ]; then
                    percentage=$(echo "scale=2; $size_bytes * 100 / $total_capacity" | bc)
                fi
                
                # Format size
                local formatted_size=$(format_size $size_bytes)
                
                echo "{"
                echo "  \\"name\\": \\"$name\\","
                echo "  \\"path\\": \\"$path\\","
                echo "  \\"size\\": $size_bytes,"
                echo "  \\"depth\\": $depth,"
                echo "  \\"category\\": \\"$category\\","
                echo "  \\"driveRoot\\": \\"/\\","
                echo "  \\"fileCount\\": $file_count,"
                echo "  \\"largeFiles\\": [],"
                echo "  \\"lastModified\\": \\"$last_modified\\","
                echo "  \\"formattedSize\\": \\"$formatted_size\\","
                echo "  \\"subdirectories\\": [],"
                echo "  \\"percentageOfDrive\\": $percentage,"
                echo "  \\"subdirectoryCount\\": $subdir_count"
                echo "}"
            }
            
            echo "["
            
            # Applications
            analyze_directory "/Applications" "Applications" "Applications" 1
            echo ","
            
            # Users
            analyze_directory "/Users" "Users" "Users" 1
            echo ","
            
            # Library (system-wide)
            analyze_directory "/Library" "Library" "System" 1
            echo ","
            
            # System
            analyze_directory "/System" "System" "System" 1
            echo ","
            
            # private (contains var, tmp, etc)
            analyze_directory "/private" "Private" "System" 1
            echo ","
            
            # opt (Homebrew, etc)
            if [ -d "/opt" ]; then
                analyze_directory "/opt" "opt" "Applications" 1
                echo ","
            fi
            
            # usr/local (Homebrew, etc)
            analyze_directory "/usr/local" "usr/local" "Applications" 2
            
            echo "]"
        """
        
        let result = try await executeWithFallback(
            osquery: nil,
            bash: bashScript,
            python: nil
        )
        
        // Result should be an array; if dictionary, extract items
        if let items = result["items"] as? [[String: Any]] {
            return items
        } else if let array = result as? [[String: Any]] {
            return array
        }
        
        return []
    }
    
    /// Adds rootDirectories to a storage device for directory breakdown visualization
    private func addStorageAnalysisToDevice(_ device: inout [String: Any], directoryAnalysis: [[String: Any]]) {
        // Add storage analysis enabled flag
        device["storageAnalysisEnabled"] = true
        device["lastAnalyzed"] = ISO8601DateFormatter().string(from: Date())
        device["rootDirectories"] = directoryAnalysis
    }
}
    
