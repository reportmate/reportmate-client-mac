import Foundation

/// Peripherals module processor - Comprehensive peripheral device collection
/// Based on MunkiReport patterns for peripheral device collection
/// Reference: https://github.com/munkireport/usb, bluetooth, displays
/// No Python - uses osquery for: usb_devices, audio_devices, system_controls
/// Bash fallback for: Bluetooth, printers, Thunderbolt, input devices, tablets
///
/// Categories collected:
/// - USB Devices (hubs, storage, peripherals)
/// - Input Devices (keyboards, mice, trackpads, graphics tablets)
/// - Audio Devices (speakers, microphones, interfaces)
/// - Bluetooth Devices (paired and connected)
/// - Cameras (built-in and external)
/// - Thunderbolt Devices
/// - Printers (CUPS, network, direct-connect) - HIGH EMPHASIS
/// - Scanners
/// - External Storage (USB drives, SD cards, external SSDs)
///
/// NOTE: Displays are NOT collected here - they are part of Hardware module
public class PeripheralsModuleProcessor: BaseModuleProcessor, @unchecked Sendable {
    
    public init(configuration: ReportMateConfiguration) {
        super.init(moduleId: "peripherals", configuration: configuration)
    }
    
    // Helper function to get timestamp for logging
    private func timestamp() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        return formatter.string(from: Date())
    }
    
    public override func collectData() async throws -> ModuleData {
        print("[\(timestamp())] === PERIPHERALS MODULE COLLECTION ===")
        print("[\(timestamp())] Collecting comprehensive peripheral device data...")
        print("[\(timestamp())] Using osquery + bash (no Python)")
        print("[\(timestamp())] Categories: USB, Input, Audio, Bluetooth, Cameras, Thunderbolt, Printers, Scanners, Storage")
        print("[\(timestamp())] NOTE: Displays are collected in Hardware module, not here")
        print("[\(timestamp())] ─────────────────────────────────────")
        
        let startTime = Date()
        
        // Collect peripheral data
        print("[\(timestamp())]   [1/10] Collecting USB devices...")
        let usbDevices = try await collectUSBDevices()
        
        print("[\(timestamp())]   [2/10] Collecting input devices (keyboards, mice, trackpads, tablets)...")
        let inputDevices = try await collectInputDevices()
        
        print("[\(timestamp())]   [3/10] Collecting audio devices...")
        let audioDevices = try await collectAudioDevices()
        
        print("[\(timestamp())]   [4/10] Collecting Bluetooth devices...")
        let bluetoothDevices = try await collectBluetoothDevices()
        
        print("[\(timestamp())]   [5/10] Collecting camera devices...")
        let cameraDevices = try await collectCameraDevices()
        
        print("[\(timestamp())]   [6/10] Collecting Thunderbolt devices...")
        let thunderboltDevices = try await collectThunderboltDevices()
        
        print("[\(timestamp())]   [7/10] Collecting printer information (PRIORITY)...")
        let printerInfo = try await collectPrinters()
        
        print("[\(timestamp())]   [8/10] Collecting scanner devices...")
        let scannerDevices = try await collectScanners()
        
        print("[\(timestamp())]   [9/10] Collecting external storage...")
        let externalStorage = try await collectExternalStorage()
        
        print("[\(timestamp())]   [10/10] Collecting serial/COM ports...")
        let serialPorts = try await collectSerialPorts()
        
        let duration = Date().timeIntervalSince(startTime)
        
        // Build structured output matching Windows parity
        let peripheralsData: [String: Any] = [
            "collectedAt": ISO8601DateFormatter().string(from: Date()),
            "usbDevices": usbDevices,
            "inputDevices": inputDevices,
            "audioDevices": audioDevices,
            "bluetoothDevices": bluetoothDevices,
            "cameras": cameraDevices,
            "thunderboltDevices": thunderboltDevices,
            "printers": printerInfo,
            "scanners": scannerDevices,
            "externalStorage": externalStorage,
            "serialPorts": serialPorts
        ]
        
        // Log summary
        print("[\(timestamp())] ─────────────────────────────────────")
        print("[\(timestamp())] Peripherals collection completed in \(String(format: "%.2f", duration)) seconds")
        print("[\(timestamp())]   USB Devices: \(usbDevices.count)")
        print("[\(timestamp())]   Input Devices: \(countInputDevices(inputDevices))")
        print("[\(timestamp())]   Audio Devices: \(audioDevices.count)")
        print("[\(timestamp())]   Bluetooth Devices: \(bluetoothDevices.count)")
        print("[\(timestamp())]   Cameras: \(cameraDevices.count)")
        print("[\(timestamp())]   Thunderbolt Devices: \(thunderboltDevices.count)")
        print("[\(timestamp())]   Printers: \(printerInfo.count)")
        print("[\(timestamp())]   Scanners: \(scannerDevices.count)")
        print("[\(timestamp())]   External Storage: \(externalStorage.count)")
        
        return BaseModuleData(moduleId: moduleId, data: peripheralsData)
    }
    
    // MARK: - Helper Methods for Counting
    
    private func countInputDevices(_ inputDevices: [String: Any]) -> String {
        let keyboards = (inputDevices["keyboards"] as? [[String: Any]])?.count ?? 0
        let mice = (inputDevices["mice"] as? [[String: Any]])?.count ?? 0
        let trackpads = (inputDevices["trackpads"] as? [[String: Any]])?.count ?? 0
        let tablets = (inputDevices["tablets"] as? [[String: Any]])?.count ?? 0
        return "\(keyboards) keyboards, \(mice) mice, \(trackpads) trackpads, \(tablets) tablets"
    }
    
    // MARK: - USB Devices (osquery: usb_devices)
    
    private func collectUSBDevices() async throws -> [[String: Any]] {
        let osqueryScript = """
            SELECT 
                usb_address,
                usb_port,
                vendor,
                vendor_id,
                model,
                model_id,
                serial,
                removable,
                version,
                class
            FROM usb_devices;
            """
        
        // Bash fallback using system_profiler
        let bashScript = """
            echo "["
            first=true
            
            system_profiler SPUSBDataType 2>/dev/null | awk '
            BEGIN { name=""; vendor=""; vendor_id=""; product_id=""; serial=""; speed=""; first=1 }
            /^[[:space:]]+[A-Za-z].*:$/ {
                if (name != "" && name !~ /USB/ && name !~ /Bus/ && name !~ /Host/) {
                    if (!first) printf ","
                    printf "{\\"name\\": \\"%s\\", \\"vendor\\": \\"%s\\", \\"vendorId\\": \\"%s\\", \\"productId\\": \\"%s\\", \\"serial\\": \\"%s\\", \\"speed\\": \\"%s\\"}", name, vendor, vendor_id, product_id, serial, speed
                    first = 0
                }
                gsub(/^[[:space:]]+/, "")
                gsub(/:$/, "")
                name = $0
                vendor = ""; vendor_id = ""; product_id = ""; serial = ""; speed = ""
            }
            /Manufacturer:/ { gsub(/.*Manufacturer:[[:space:]]*/, ""); vendor = $0 }
            /Vendor ID:/ { gsub(/.*Vendor ID:[[:space:]]*/, ""); vendor_id = $0 }
            /Product ID:/ { gsub(/.*Product ID:[[:space:]]*/, ""); product_id = $0 }
            /Serial Number:/ { gsub(/.*Serial Number:[[:space:]]*/, ""); serial = $0 }
            /Speed:/ { gsub(/.*Speed:[[:space:]]*/, ""); speed = $0 }
            END {
                if (name != "" && name !~ /USB/ && name !~ /Bus/ && name !~ /Host/) {
                    if (!first) printf ","
                    printf "{\\"name\\": \\"%s\\", \\"vendor\\": \\"%s\\", \\"vendorId\\": \\"%s\\", \\"productId\\": \\"%s\\", \\"serial\\": \\"%s\\", \\"speed\\": \\"%s\\"}", name, vendor, vendor_id, product_id, serial, speed
                }
            }
            '
            
            echo "]"
            """
        
        let result = try await executeWithFallback(osquery: osqueryScript, bash: bashScript)
        
        var devices: [[String: Any]] = []
        if let items = result["items"] as? [[String: Any]] {
            devices = items
        }
        
        return devices.map { device in
            let name = device["name"] as? String ?? device["model"] as? String ?? "Unknown USB Device"
            let deviceType = determineUSBDeviceType(name: name, deviceClass: device["class"] as? String ?? "")
            
            return [
                "name": name,
                "vendor": device["vendor"] as? String ?? "",
                "vendorId": device["vendor_id"] as? String ?? device["vendorId"] as? String ?? "",
                "productId": device["model_id"] as? String ?? device["productId"] as? String ?? "",
                "serialNumber": device["serial"] as? String ?? "",
                "speed": device["speed"] as? String ?? device["version"] as? String ?? "",
                "isRemovable": device["removable"] as? String == "1",
                "deviceType": deviceType,
                "connectionType": "USB"
            ]
        }
    }
    
    /// Determine USB device type from name and class
    private func determineUSBDeviceType(name: String, deviceClass: String) -> String {
        let lowercased = name.lowercased()
        
        if lowercased.contains("hub") { return "USB Hub" }
        if lowercased.contains("keyboard") { return "Keyboard" }
        if lowercased.contains("mouse") { return "Mouse" }
        if lowercased.contains("trackpad") || lowercased.contains("touchpad") { return "Trackpad" }
        if lowercased.contains("camera") || lowercased.contains("webcam") || lowercased.contains("facetime") { return "Camera" }
        if lowercased.contains("audio") || lowercased.contains("speaker") || lowercased.contains("headphone") || lowercased.contains("microphone") { return "Audio Device" }
        if lowercased.contains("storage") || lowercased.contains("disk") || lowercased.contains("drive") || lowercased.contains("flash") { return "Storage" }
        if lowercased.contains("printer") { return "Printer" }
        if lowercased.contains("scanner") { return "Scanner" }
        if lowercased.contains("bluetooth") { return "Bluetooth Adapter" }
        if lowercased.contains("ethernet") || lowercased.contains("network") { return "Network Adapter" }
        if lowercased.contains("wacom") || lowercased.contains("tablet") || lowercased.contains("huion") || lowercased.contains("xp-pen") { return "Graphics Tablet" }
        if lowercased.contains("controller") || lowercased.contains("gamepad") || lowercased.contains("joystick") { return "Game Controller" }
        if lowercased.contains("card reader") || lowercased.contains("sd card") { return "Card Reader" }
        
        // Check class codes
        switch deviceClass {
        case "8", "08": return "Storage"
        case "3", "03": return "HID Device"
        case "1", "01": return "Audio Device"
        case "14", "0e": return "Camera"
        case "7", "07": return "Printer"
        case "9", "09": return "USB Hub"
        default: return "USB Device"
        }
    }
    
    // MARK: - Input Devices
    
    private func collectInputDevices() async throws -> [String: Any] {
        let keyboards = try await collectKeyboards()
        let mice = try await collectMice()
        let trackpads = try await collectTrackpads()
        let tablets = try await collectGraphicsTablets()
        
        return [
            "keyboards": keyboards,
            "mice": mice,
            "trackpads": trackpads,
            "tablets": tablets
        ]
    }
    
    private func collectKeyboards() async throws -> [[String: Any]] {
        let bashScript = """
            echo "["
            first=true
            
            # Check for keyboards using IOKit
            ioreg -r -c IOHIDKeyboard 2>/dev/null | awk '
            BEGIN { name=""; vendor=""; product=""; first=1 }
            /"Product"/ { gsub(/.*"Product" = "/, ""); gsub(/".*/, ""); name = $0 }
            /"Manufacturer"/ { gsub(/.*"Manufacturer" = "/, ""); gsub(/".*/, ""); vendor = $0 }
            /"VendorID"/ { gsub(/.*"VendorID" = /, ""); gsub(/[^0-9].*/, ""); product = $0 }
            /"IOClass" = "IOHIDKeyboard"/ {
                if (name != "") {
                    if (!first) printf ","
                    printf "{\\"name\\": \\"%s\\", \\"vendor\\": \\"%s\\", \\"vendorId\\": \\"%s\\"}", name, vendor, product
                    first = 0
                }
                name = ""; vendor = ""; product = ""
            }
            '
            
            echo "]"
            """
        
        let result = try await executeWithFallback(osquery: nil, bash: bashScript)
        
        var keyboards: [[String: Any]] = []
        if let items = result["items"] as? [[String: Any]] {
            keyboards = items
        }
        
        return keyboards.map { kb in
            let name = kb["name"] as? String ?? "Keyboard"
            let isBuiltIn = name.lowercased().contains("internal") || name.lowercased().contains("built-in")
            let connectionType = isBuiltIn ? "Built-in" : (name.lowercased().contains("bluetooth") ? "Bluetooth" : "USB")
            
            return [
                "name": name,
                "vendor": kb["vendor"] as? String ?? "",
                "vendorId": kb["vendorId"] as? String ?? "",
                "isBuiltIn": isBuiltIn,
                "connectionType": connectionType,
                "deviceType": "Keyboard"
            ]
        }
    }
    
    private func collectMice() async throws -> [[String: Any]] {
        let bashScript = """
            echo "["
            first=true
            
            # Check for mice using IOKit
            ioreg -r -c IOHIDPointing 2>/dev/null | awk '
            BEGIN { name=""; vendor=""; first=1 }
            /"Product"/ { gsub(/.*"Product" = "/, ""); gsub(/".*/, ""); name = $0 }
            /"Manufacturer"/ { gsub(/.*"Manufacturer" = "/, ""); gsub(/".*/, ""); vendor = $0 }
            /"IOClass" = "IOHIDPointing"/ {
                if (name != "" && tolower(name) !~ /trackpad/) {
                    if (!first) printf ","
                    printf "{\\"name\\": \\"%s\\", \\"vendor\\": \\"%s\\"}", name, vendor
                    first = 0
                }
                name = ""; vendor = ""
            }
            '
            
            echo "]"
            """
        
        let result = try await executeWithFallback(osquery: nil, bash: bashScript)
        
        var mice: [[String: Any]] = []
        if let items = result["items"] as? [[String: Any]] {
            mice = items
        }
        
        return mice.map { mouse in
            let name = mouse["name"] as? String ?? "Mouse"
            let connectionType = name.lowercased().contains("bluetooth") || name.lowercased().contains("magic") ? "Bluetooth" : "USB"
            
            return [
                "name": name,
                "vendor": mouse["vendor"] as? String ?? "",
                "connectionType": connectionType,
                "deviceType": "Mouse"
            ]
        }
    }
    
    private func collectTrackpads() async throws -> [[String: Any]] {
        // Use simpler awk without problematic quote escaping
        let bashScript = """
            system_profiler SPBluetoothDataType SPUSBDataType 2>/dev/null | grep -i trackpad | awk '
            BEGIN { first=1; print "[" }
            {
                name = $0
                gsub(/:.*/, "", name)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", name)
                if (name == "") next
                
                if (!first) printf ","
                printf "{\\"name\\": \\"%s\\"}", name
                first = 0
            }
            END { print "]" }
            '
            """
        
        let result = try await executeWithFallback(osquery: nil, bash: bashScript)
        
        var trackpads: [[String: Any]] = []
        if let items = result["items"] as? [[String: Any]] {
            trackpads = items
        }
        
        // Deduplicate and process
        var seen = Set<String>()
        var uniqueTrackpads: [[String: Any]] = []
        
        for trackpad in trackpads {
            let name = trackpad["name"] as? String ?? "Trackpad"
            if !seen.contains(name) {
                seen.insert(name)
                let isBuiltIn = name.lowercased().contains("internal") || name.lowercased().contains("built-in") || name.lowercased().contains("force touch")
                let connectionType = isBuiltIn ? "Built-in" : (name.lowercased().contains("magic") ? "Bluetooth" : "USB")
                
                uniqueTrackpads.append([
                    "name": name,
                    "isBuiltIn": isBuiltIn,
                    "supportsForcTouch": name.lowercased().contains("force touch") || name.lowercased().contains("magic trackpad 2"),
                    "connectionType": connectionType,
                    "deviceType": "Trackpad"
                ])
            }
        }
        
        return uniqueTrackpads
    }
    
    private func collectGraphicsTablets() async throws -> [[String: Any]] {
        let bashScript = """
            echo "["
            first=true
            
            # Look for graphics tablets in USB devices
            system_profiler SPUSBDataType 2>/dev/null | awk '
            BEGIN { in_device=0; name=""; vendor=""; first=1 }
            /^[[:space:]]+[A-Za-z].*:$/ {
                if (in_device && name != "" && (tolower(name) ~ /wacom|huion|xp-pen|tablet|intuos|cintiq|bamboo/)) {
                    if (!first) printf ","
                    printf "{\\"name\\": \\"%s\\", \\"vendor\\": \\"%s\\"}", name, vendor
                    first = 0
                }
                gsub(/^[[:space:]]+/, "")
                gsub(/:$/, "")
                name = $0
                vendor = ""
                in_device = 1
            }
            /Manufacturer:/ {
                gsub(/.*Manufacturer:[[:space:]]*/, "")
                vendor = $0
            }
            END {
                if (in_device && name != "" && (tolower(name) ~ /wacom|huion|xp-pen|tablet|intuos|cintiq|bamboo/)) {
                    if (!first) printf ","
                    printf "{\\"name\\": \\"%s\\", \\"vendor\\": \\"%s\\"}", name, vendor
                }
            }
            '
            
            echo "]"
            """
        
        let result = try await executeWithFallback(osquery: nil, bash: bashScript)
        
        var tablets: [[String: Any]] = []
        if let items = result["items"] as? [[String: Any]] {
            tablets = items
        }
        
        return tablets.map { tablet in
            let name = tablet["name"] as? String ?? "Graphics Tablet"
            let vendor = tablet["vendor"] as? String ?? ""
            
            var tabletType = "Graphics Tablet"
            if name.lowercased().contains("cintiq") || name.lowercased().contains("display") {
                tabletType = "Pen Display"
            } else if name.lowercased().contains("intuos") || name.lowercased().contains("bamboo") {
                tabletType = "Pen Tablet"
            }
            
            return [
                "name": name,
                "vendor": vendor,
                "connectionType": "USB",
                "tabletType": tabletType,
                "deviceType": "Graphics Tablet"
            ]
        }
    }
    
    // MARK: - Audio Devices
    
    private func collectAudioDevices() async throws -> [[String: Any]] {
        let bashScript = """
            echo "["
            first=true
            
            system_profiler SPAudioDataType 2>/dev/null | awk '
            BEGIN { in_device=0; name=""; manufacturer=""; type=""; first=1 }
            /^[[:space:]]+[A-Za-z].*:$/ && !/Audio:/ && !/Devices:/ {
                if (in_device && name != "") {
                    if (!first) printf ","
                    printf "{\\"name\\": \\"%s\\", \\"manufacturer\\": \\"%s\\", \\"type\\": \\"%s\\"}", name, manufacturer, type
                    first = 0
                }
                gsub(/^[[:space:]]+/, "")
                gsub(/:$/, "")
                name = $0
                type = "Output"
                manufacturer = ""
                in_device = 1
            }
            /Default Output Device:.*Yes/ { type = "Default Output" }
            /Default Input Device:.*Yes/ { type = "Default Input" }
            /Manufacturer:/ { gsub(/.*Manufacturer:[[:space:]]*/, ""); manufacturer = $0 }
            END {
                if (in_device && name != "") {
                    if (!first) printf ","
                    printf "{\\"name\\": \\"%s\\", \\"manufacturer\\": \\"%s\\", \\"type\\": \\"%s\\"}", name, manufacturer, type
                }
            }
            '
            
            echo "]"
            """
        
        let result = try await executeWithFallback(osquery: nil, bash: bashScript)
        
        var devices: [[String: Any]] = []
        if let items = result["items"] as? [[String: Any]] {
            devices = items
        }
        
        return devices.map { device in
            let name = device["name"] as? String ?? "Audio Device"
            let deviceType = device["type"] as? String ?? "Unknown"
            let isDefault = deviceType.contains("Default")
            let isInput = deviceType.contains("Input")
            let isBuiltIn = name.lowercased().contains("built-in") || name.lowercased().contains("macbook") || name.lowercased().contains("mac mini")
            
            return [
                "name": name,
                "manufacturer": device["manufacturer"] as? String ?? "",
                "type": isInput ? "Input" : "Output",
                "isDefault": isDefault,
                "isInput": isInput,
                "isOutput": !isInput,
                "isBuiltIn": isBuiltIn,
                "connectionType": isBuiltIn ? "Built-in" : "External",
                "deviceType": "Audio Device"
            ]
        }
    }
    
    // MARK: - Bluetooth Devices
    
    private func collectBluetoothDevices() async throws -> [[String: Any]] {
        let bashScript = """
            echo "["
            
            bt_info=$(system_profiler SPBluetoothDataType 2>/dev/null || echo "")
            
            if [ -n "$bt_info" ]; then
                echo "$bt_info" | awk '
                BEGIN { first=1; in_device=0; name=""; addr=""; connected="false"; type="" }
                /Devices \\(Paired\\):/ || /Connected:/ { in_device=1 }
                /^[[:space:]]+[A-Za-z].*:$/ && in_device {
                    if (name != "" && addr != "") {
                        if (!first) printf ","
                        printf "{\\"name\\": \\"%s\\", \\"address\\": \\"%s\\", \\"connected\\": %s, \\"type\\": \\"%s\\"}", name, addr, connected, type
                        first = 0
                    }
                    gsub(/^[[:space:]]+/, "")
                    gsub(/:$/, "")
                    name = $0
                    addr = ""
                    connected = "false"
                    type = ""
                }
                /Address:/ && in_device { gsub(/.*Address:[[:space:]]*/, ""); addr = $0 }
                /Connected:/ && in_device && !/Devices/ {
                    gsub(/.*Connected:[[:space:]]*/, "")
                    if ($0 == "Yes") connected = "true"
                }
                /Minor Type:/ && in_device { gsub(/.*Minor Type:[[:space:]]*/, ""); type = $0 }
                END {
                    if (name != "" && addr != "") {
                        if (!first) printf ","
                        printf "{\\"name\\": \\"%s\\", \\"address\\": \\"%s\\", \\"connected\\": %s, \\"type\\": \\"%s\\"}", name, addr, connected, type
                    }
                }
                '
            fi
            
            echo "]"
            """
        
        let result = try await executeWithFallback(osquery: nil, bash: bashScript)
        
        var devices: [[String: Any]] = []
        if let items = result["items"] as? [[String: Any]] {
            devices = items
        }
        
        return devices.map { device in
            let name = device["name"] as? String ?? "Bluetooth Device"
            let minorType = device["type"] as? String ?? ""
            let deviceCategory = determineBluetoothCategory(name: name, minorType: minorType)
            
            return [
                "name": name,
                "address": device["address"] as? String ?? "",
                "isConnected": device["connected"] as? Bool ?? false,
                "isPaired": true,
                "deviceType": minorType,
                "deviceCategory": deviceCategory,
                "isAppleDevice": name.lowercased().contains("apple") || name.lowercased().contains("airpods") || name.lowercased().contains("magic")
            ]
        }
    }
    
    private func determineBluetoothCategory(name: String, minorType: String) -> String {
        let lowercased = name.lowercased()
        
        if lowercased.contains("airpods") || lowercased.contains("headphone") || lowercased.contains("earbuds") || lowercased.contains("beats") { return "Headphones" }
        if lowercased.contains("keyboard") || minorType.lowercased().contains("keyboard") { return "Keyboard" }
        if lowercased.contains("mouse") || lowercased.contains("magic mouse") { return "Mouse" }
        if lowercased.contains("trackpad") || lowercased.contains("magic trackpad") { return "Trackpad" }
        if lowercased.contains("speaker") || lowercased.contains("homepod") { return "Speaker" }
        if lowercased.contains("watch") { return "Watch" }
        if lowercased.contains("pencil") { return "Stylus" }
        if lowercased.contains("controller") || lowercased.contains("gamepad") { return "Game Controller" }
        if lowercased.contains("phone") || lowercased.contains("iphone") { return "Phone" }
        if lowercased.contains("ipad") { return "Tablet" }
        
        return "Other"
    }
    
    // MARK: - Camera Devices
    
    private func collectCameraDevices() async throws -> [[String: Any]] {
        let bashScript = """
            echo "["
            
            system_profiler SPCameraDataType 2>/dev/null | awk '
            BEGIN { first=1; name=""; model_id="" }
            /^[[:space:]]+[A-Za-z].*:$/ {
                if (name != "") {
                    if (!first) printf ","
                    printf "{\\"name\\": \\"%s\\", \\"modelId\\": \\"%s\\"}", name, model_id
                    first = 0
                }
                gsub(/^[[:space:]]+/, "")
                gsub(/:$/, "")
                name = $0
                model_id = ""
            }
            /Model ID:/ { gsub(/.*Model ID:[[:space:]]*/, ""); model_id = $0 }
            END {
                if (name != "") {
                    if (!first) printf ","
                    printf "{\\"name\\": \\"%s\\", \\"modelId\\": \\"%s\\"}", name, model_id
                }
            }
            '
            
            echo "]"
            """
        
        let result = try await executeWithFallback(osquery: nil, bash: bashScript)
        
        var cameras: [[String: Any]] = []
        if let items = result["items"] as? [[String: Any]] {
            cameras = items
        }
        
        return cameras.map { camera in
            let name = camera["name"] as? String ?? "Camera"
            let isBuiltIn = name.lowercased().contains("facetime") || name.lowercased().contains("isight") || name.lowercased().contains("built-in")
            
            return [
                "name": name,
                "modelId": camera["modelId"] as? String ?? "",
                "isBuiltIn": isBuiltIn,
                "connectionType": isBuiltIn ? "Built-in" : "USB",
                "deviceType": "Camera"
            ]
        }
    }
    
    // MARK: - Thunderbolt Devices
    
    private func collectThunderboltDevices() async throws -> [[String: Any]] {
        let bashScript = """
            echo "["
            
            system_profiler SPThunderboltDataType 2>/dev/null | awk '
            BEGIN { first=1; name=""; vendor=""; device_id=""; uid="" }
            /^[[:space:]]+[A-Za-z].*:$/ && !/Thunderbolt Bus/ {
                if (name != "") {
                    if (!first) printf ","
                    printf "{\\"name\\": \\"%s\\", \\"vendor\\": \\"%s\\", \\"deviceId\\": \\"%s\\", \\"uid\\": \\"%s\\"}", name, vendor, device_id, uid
                    first = 0
                }
                gsub(/^[[:space:]]+/, "")
                gsub(/:$/, "")
                name = $0
                vendor = ""; device_id = ""; uid = ""
            }
            /Vendor Name:/ { gsub(/.*Vendor Name:[[:space:]]*/, ""); vendor = $0 }
            /Device ID:/ { gsub(/.*Device ID:[[:space:]]*/, ""); device_id = $0 }
            /UID:/ { gsub(/.*UID:[[:space:]]*/, ""); uid = $0 }
            END {
                if (name != "") {
                    if (!first) printf ","
                    printf "{\\"name\\": \\"%s\\", \\"vendor\\": \\"%s\\", \\"deviceId\\": \\"%s\\", \\"uid\\": \\"%s\\"}", name, vendor, device_id, uid
                }
            }
            '
            
            echo "]"
            """
        
        let result = try await executeWithFallback(osquery: nil, bash: bashScript)
        
        var devices: [[String: Any]] = []
        if let items = result["items"] as? [[String: Any]] {
            devices = items
        }
        
        return devices.map { device in
            let name = device["name"] as? String ?? "Thunderbolt Device"
            
            var deviceType = "Thunderbolt Device"
            let lowercased = name.lowercased()
            if lowercased.contains("dock") || lowercased.contains("docking") { deviceType = "Thunderbolt Dock" }
            else if lowercased.contains("display") || lowercased.contains("monitor") { deviceType = "Thunderbolt Display" }
            else if lowercased.contains("storage") || lowercased.contains("disk") || lowercased.contains("drive") || lowercased.contains("ssd") { deviceType = "Thunderbolt Storage" }
            else if lowercased.contains("hub") { deviceType = "Thunderbolt Hub" }
            else if lowercased.contains("egpu") || lowercased.contains("graphics") { deviceType = "eGPU" }
            
            return [
                "name": name,
                "vendor": device["vendor"] as? String ?? "",
                "deviceId": device["deviceId"] as? String ?? "",
                "uid": device["uid"] as? String ?? "",
                "deviceType": deviceType,
                "connectionType": "Thunderbolt"
            ]
        }
    }
    
    // MARK: - External Storage
    
    private func collectExternalStorage() async throws -> [[String: Any]] {
        let osqueryScript = """
            SELECT 
                m.device,
                m.path,
                m.type,
                m.blocks,
                m.blocks_available,
                m.blocks_free
            FROM mounts m
            WHERE m.device LIKE '/dev/disk%'
              AND m.path NOT LIKE '/System/%'
              AND m.path NOT LIKE '/private/%';
            """
        
        // awk-based solution to avoid subshell issues
        let bashScript = """
            disks=$(diskutil list external 2>/dev/null | grep -E "^/dev/disk" | awk '{print $1}')
            
            if [ -n "$disks" ]; then
                echo "$disks" | while read disk; do
                    diskutil info "$disk" 2>/dev/null
                    echo "---DISK_SEPARATOR---"
                done | awk '
                BEGIN { first=1; print "["; name=""; device=""; mount=""; fs=""; size=""; protocol="" }
                /---DISK_SEPARATOR---/ {
                    if (name != "") {
                        gsub(/"/, "\\\\\"", name)
                        gsub(/"/, "\\\\\"", mount)
                        if (!first) printf ","
                        printf "{\\"name\\": \\"%s\\", \\"device\\": \\"%s\\", \\"mountPoint\\": \\"%s\\", \\"fileSystem\\": \\"%s\\", \\"size\\": \\"%s\\", \\"protocol\\": \\"%s\\"}", name, device, mount, fs, size, protocol
                        first = 0
                    }
                    name = ""; device = ""; mount = ""; fs = ""; size = ""; protocol = ""
                    next
                }
                /Device Identifier:/ { device = $NF }
                /Volume Name:/ { gsub(/.*Volume Name:[[:space:]]*/, ""); name = $0 }
                /Media Name:/ { if (name == "") { gsub(/.*Media Name:[[:space:]]*/, ""); name = $0 } }
                /Mount Point:/ { gsub(/.*Mount Point:[[:space:]]*/, ""); mount = $0 }
                /Type \\(Bundle\\):/ { gsub(/.*Type \\(Bundle\\):[[:space:]]*/, ""); fs = $0 }
                /Total Size:/ { gsub(/.*Total Size:[[:space:]]*/, ""); gsub(/\\(.*/, ""); gsub(/[[:space:]]*$/, ""); size = $0 }
                /Protocol:/ { gsub(/.*Protocol:[[:space:]]*/, ""); protocol = $0 }
                END { print "]" }
                '
            else
                echo "[]"
            fi
            """
        
        let result = try await executeWithFallback(osquery: osqueryScript, bash: bashScript)
        
        var devices: [[String: Any]] = []
        if let items = result["items"] as? [[String: Any]] {
            devices = items
        }
        
        return devices.map { device in
            let deviceProtocol = device["protocol"] as? String ?? ""
            
            var storageType = "External Storage"
            if deviceProtocol.lowercased().contains("usb") { storageType = "USB Drive" }
            else if deviceProtocol.lowercased().contains("thunderbolt") { storageType = "Thunderbolt Storage" }
            else if (device["name"] as? String ?? "").lowercased().contains("sd") { storageType = "SD Card" }
            
            return [
                "name": device["name"] as? String ?? "External Storage",
                "devicePath": device["device"] as? String ?? "",
                "mountPoint": device["path"] as? String ?? device["mountPoint"] as? String ?? "",
                "fileSystem": device["type"] as? String ?? device["fileSystem"] as? String ?? "",
                "totalSize": device["size"] as? String ?? "",
                "protocol": deviceProtocol,
                "storageType": storageType,
                "deviceType": "External Storage"
            ]
        }
    }
    
    // MARK: - Printers (HIGHEST PRIORITY)
    
    private func collectPrinters() async throws -> [[String: Any]] {
        // Enhanced printer collection with lpoptions and system_profiler
        let bashScript = """
            default_printer=$(lpstat -d 2>/dev/null | sed 's/.*: //' || echo "")
            
            # Get comprehensive printer info from system_profiler
            profiler_data=$(system_profiler SPPrintersDataType 2>/dev/null)
            
            # Get basic printer list from lpstat
            lpstat -v 2>/dev/null | awk -v default_printer="$default_printer" '
            BEGIN { first=1; print "[" }
            {
                line = $0
                gsub(/^device for /, "", line)
                idx = index(line, ": ")
                if (idx > 0) {
                    printer = substr(line, 1, idx-1)
                    uri = substr(line, idx+2)
                    gsub(/^[[:space:]]+|[[:space:]]+$/, "", printer)
                    gsub(/^[[:space:]]+|[[:space:]]+$/, "", uri)
                    
                    if (printer == "") next
                    
                    # Connection type from URI
                    conn_type = "Unknown"
                    if (uri ~ /^usb:/) conn_type = "USB"
                    else if (uri ~ /^ipp:/ || uri ~ /^ipps:/) conn_type = "Network (IPP)"
                    else if (uri ~ /^socket:/) conn_type = "Network (Socket)"
                    else if (uri ~ /^lpd:/) conn_type = "Network (LPD)"
                    else if (uri ~ /^smb:/) conn_type = "Network (SMB)"
                    else if (uri ~ /^dnssd:/) conn_type = "Network (Bonjour)"
                    
                    is_default = "false"
                    if (printer == default_printer) is_default = "true"
                    
                    # Get lpoptions for this printer
                    cmd = "lpoptions -p " printer " 2>/dev/null || echo \\"\\""
                    cmd | getline lpopts
                    close(cmd)
                    
                    # Parse lpoptions key=value pairs
                    auth_info = ""
                    device_uri = uri
                    make_model = ""
                    printer_state = ""
                    printer_state_reasons = ""
                    printer_type = ""
                    printer_uri = ""
                    printer_commands = ""
                    
                    split(lpopts, pairs, " ")
                    for (i in pairs) {
                        split(pairs[i], kv, "=")
                        key = kv[1]
                        val = kv[2]
                        
                        if (key == "auth-info-required") auth_info = val
                        else if (key == "device-uri") device_uri = val
                        else if (key == "printer-make-and-model") make_model = val
                        else if (key == "printer-state") printer_state = val
                        else if (key == "printer-state-reasons") printer_state_reasons = val
                        else if (key == "printer-type") printer_type = val
                        else if (key == "printer-uri-supported") printer_uri = val
                        else if (key == "printer-commands") printer_commands = val
                    }
                    
                    # Output JSON for this printer
                    if (!first) printf ","
                    printf "{\\"name\\": \\"%s\\", \\"uri\\": \\"%s\\", \\"connectionType\\": \\"%s\\", \\"isDefault\\": %s, \\"authInfoRequired\\": \\"%s\\", \\"makeAndModel\\": \\"%s\\", \\"printerState\\": \\"%s\\", \\"printerStateReasons\\": \\"%s\\", \\"printerType\\": \\"%s\\", \\"printerUriSupported\\": \\"%s\\", \\"printerCommands\\": \\"%s\\"}", printer, device_uri, conn_type, is_default, auth_info, make_model, printer_state, printer_state_reasons, printer_type, printer_uri, printer_commands
                    first = 0
                }
            }
            END { print "]" }
            '
            
            # Now parse system_profiler data for additional details
            echo "$profiler_data" | awk '
            BEGIN { in_printer=0; printer_name=""; status=""; driver=""; ppd=""; ppd_version=""; cups_version=""; scanning=""; commands=""; date_added=""; cups_filters=""; fax=""; pdes="" }
            /^[[:space:]]+[A-Za-z0-9].*:$/ && !/Printers:/ {
                # Save previous printer data if we have it
                if (printer_name != "") {
                    # Print separator for merging later
                    printf "PRINTER_DETAILS:%s|status=%s|driver=%s|ppd=%s|ppd_version=%s|cups_version=%s|scanning=%s|commands=%s|date_added=%s|cups_filters=%s|fax=%s|pdes=%s\\n", printer_name, status, driver, ppd, ppd_version, cups_version, scanning, commands, date_added, cups_filters, fax, pdes
                }
                
                # New printer
                gsub(/^[[:space:]]+/, "")
                gsub(/:$/, "")
                printer_name = $0
                status = ""
                driver = ""
                ppd = ""
                ppd_version = ""
                cups_version = ""
                scanning = ""
                commands = ""
                date_added = ""
                cups_filters = ""
                fax = ""
                pdes = ""
                in_printer = 1
            }
            in_printer && /Status:/ { gsub(/.*Status:[[:space:]]*/, ""); status = $0 }
            in_printer && /Driver Version:/ { gsub(/.*Driver Version:[[:space:]]*/, ""); driver = $0 }
            in_printer && /PPD:/ && !/PPD File Version:/ { gsub(/.*PPD:[[:space:]]*/, ""); ppd = $0 }
            in_printer && /PPD File Version:/ { gsub(/.*PPD File Version:[[:space:]]*/, ""); ppd_version = $0 }
            in_printer && /CUPS Version:/ { gsub(/.*CUPS Version:[[:space:]]*/, ""); cups_version = $0 }
            in_printer && /Scanning support:/ { gsub(/.*Scanning support:[[:space:]]*/, ""); scanning = $0 }
            in_printer && /Printer Commands:/ { gsub(/.*Printer Commands:[[:space:]]*/, ""); commands = $0 }
            in_printer && /Added:/ { gsub(/.*Added:[[:space:]]*/, ""); date_added = $0 }
            in_printer && /CUPS filters:/ { gsub(/.*CUPS filters:[[:space:]]*/, ""); cups_filters = $0 }
            in_printer && /Fax support:/ { gsub(/.*Fax support:[[:space:]]*/, ""); fax = $0 }
            in_printer && /PDEs:/ { gsub(/.*PDEs:[[:space:]]*/, ""); pdes = $0 }
            END {
                if (printer_name != "") {
                    printf "PRINTER_DETAILS:%s|status=%s|driver=%s|ppd=%s|ppd_version=%s|cups_version=%s|scanning=%s|commands=%s|date_added=%s|cups_filters=%s|fax=%s|pdes=%s\\n", printer_name, status, driver, ppd, ppd_version, cups_version, scanning, commands, date_added, cups_filters, fax, pdes
                }
            }
            '
            """
        
        let result = try await executeWithFallback(osquery: nil, bash: bashScript)
        
        // Parse the output which now includes both JSON array and PRINTER_DETAILS lines
        var printers: [[String: Any]] = []
        if let items = result["items"] as? [[String: Any]] {
            printers = items
        }
        
        // Also check for raw output containing PRINTER_DETAILS
        var detailsMap: [String: [String: String]] = [:]
        if let rawOutput = result["raw_output"] as? String {
            let lines = rawOutput.components(separatedBy: "\n")
            for line in lines where line.hasPrefix("PRINTER_DETAILS:") {
                let parts = line.replacingOccurrences(of: "PRINTER_DETAILS:", with: "").components(separatedBy: "|")
                if parts.count > 0 {
                    let printerName = parts[0]
                    var details: [String: String] = [:]
                    for i in 1..<parts.count {
                        let kv = parts[i].components(separatedBy: "=")
                        if kv.count == 2 {
                            details[kv[0]] = kv[1]
                        }
                    }
                    detailsMap[printerName] = details
                }
            }
        }
        
        return printers.map { printer in
            let name = printer["name"] as? String ?? "Unknown Printer"
            let uri = printer["uri"] as? String ?? ""
            let makeAndModel = printer["makeAndModel"] as? String ?? ""
            
            // Get additional details from system_profiler
            let details = detailsMap[name] ?? [:]
            
            // Determine printer type
            var printerType = "Standard Printer"
            let nameLower = name.lowercased()
            let makeModelLower = makeAndModel.lowercased()
            if nameLower.contains("fax") || details["fax"] == "Yes" { printerType = "Fax" }
            else if nameLower.contains("pdf") { printerType = "Virtual (PDF)" }
            else if uri.contains("dnssd") { printerType = "AirPrint" }
            else if nameLower.contains("label") || makeModelLower.contains("dymo") || makeModelLower.contains("zebra") { printerType = "Label Printer" }
            
            // Parse make and model
            var make = ""
            var model = ""
            if !makeAndModel.isEmpty {
                let parts = makeAndModel.components(separatedBy: " ")
                if parts.count > 0 {
                    make = parts[0]
                    if parts.count > 1 {
                        model = parts[1...].joined(separator: " ")
                    }
                }
            }
            
            // Parse state
            let stateStr = printer["printerState"] as? String ?? ""
            var state = "idle"
            var isAcceptingJobs = true
            if stateStr == "3" { state = "idle" }
            else if stateStr == "4" { state = "processing" }
            else if stateStr == "5" { state = "stopped"; isAcceptingJobs = false }
            
            // Parse capabilities from printer type
            let typeValue = Int(printer["printerType"] as? String ?? "0") ?? 0
            let colorCapable = (typeValue & 0x4) != 0
            let duplexCapable = (typeValue & 0x8) != 0
            
            return [
                "name": name,
                "displayName": name,
                "uri": uri,
                "connectionType": printer["connectionType"] as? String ?? "Unknown",
                "status": details["status"] ?? "Available",
                "state": state,
                "stateMessage": details["status"] ?? "",
                "stateReasons": (printer["printerStateReasons"] as? String ?? "none").components(separatedBy: ","),
                "isDefault": printer["isDefault"] as? Bool ?? false,
                "isShared": false,
                "isAcceptingJobs": isAcceptingJobs,
                "pendingJobs": 0,
                "printerType": printerType,
                "deviceType": "Printer",
                "make": make,
                "model": model,
                "makeAndModel": makeAndModel,
                "driverName": details["driver"] ?? "",
                "ppd": details["ppd"] ?? "",
                "ppdVersion": details["ppd_version"] ?? "",
                "cupsVersion": details["cups_version"] ?? "",
                "authInfoRequired": printer["authInfoRequired"] as? String ?? "none",
                "printerCommands": (printer["printerCommands"] as? String ?? "").components(separatedBy: ","),
                "printerUriSupported": printer["printerUriSupported"] as? String ?? uri,
                "scanningSupport": details["scanning"] ?? "No",
                "dateAdded": details["date_added"] ?? "",
                "cupsFilters": details["cups_filters"] ?? "",
                "faxSupport": details["fax"] ?? "No",
                "pdes": details["pdes"] ?? "",
                "colorCapable": colorCapable,
                "duplexCapable": duplexCapable
            ]
        }
    }
    
    // MARK: - Scanners
    
    private func collectScanners() async throws -> [[String: Any]] {
        let bashScript = """
            echo "["
            first=true
            
            # Look for scanners in USB devices
            system_profiler SPUSBDataType 2>/dev/null | awk '
            BEGIN { in_device=0; name=""; manufacturer="" }
            /^[[:space:]]+[A-Za-z].*:$/ {
                if (in_device && name != "" && (tolower(name) ~ /scan|mfp|multifunction/)) {
                    if (first != 1) printf ","
                    printf "{\\"name\\": \\"%s\\", \\"manufacturer\\": \\"%s\\", \\"connectionType\\": \\"USB\\"}", name, manufacturer
                    first = 0
                }
                gsub(/^[[:space:]]+/, "")
                gsub(/:$/, "")
                name = $0
                manufacturer = ""
                in_device = 1
            }
            /Manufacturer:/ {
                gsub(/.*Manufacturer:[[:space:]]*/, "")
                manufacturer = $0
            }
            END {
                if (in_device && name != "" && (tolower(name) ~ /scan|mfp|multifunction/)) {
                    if (first != 1) printf ","
                    printf "{\\"name\\": \\"%s\\", \\"manufacturer\\": \\"%s\\", \\"connectionType\\": \\"USB\\"}", name, manufacturer
                }
            }
            '
            
            echo "]"
            """
        
        let result = try await executeWithFallback(osquery: nil, bash: bashScript)
        
        var scanners: [[String: Any]] = []
        if let items = result["items"] as? [[String: Any]] {
            scanners = items
        }
        
        return scanners.map { scanner in
            return [
                "name": scanner["name"] as? String ?? "Scanner",
                "manufacturer": scanner["manufacturer"] as? String ?? "",
                "connectionType": scanner["connectionType"] as? String ?? "Unknown",
                "status": "Available",
                "scannerType": "Scanner",
                "deviceType": "Scanner"
            ]
        }
    }
    
    // MARK: - Serial Ports
    
    private func collectSerialPorts() async throws -> [[String: Any]] {
        // Simple approach without quote escaping
        let bashScript = """
            ls /dev/cu.* 2>/dev/null | grep -v -E '(cu\\.MALS|cu\\.SOC)' | awk '
            BEGIN { first=1; print "[" }
            {
                port = $0
                
                port_type = "Serial Port"
                if (port ~ /cu\\.Bluetooth/) port_type = "Bluetooth"
                else if (port ~ /cu\\.usbserial/) port_type = "USB Serial"
                else if (port ~ /cu\\.usbmodem/) port_type = "USB Modem"
                else if (port ~ /cu\\.debug/) port_type = "Debug"
                
                name = port
                gsub(/.*\\/cu\\./, "", name)
                
                if (!first) printf ","
                printf "{\\"name\\": \\"%s\\", \\"device\\": \\"%s\\", \\"portType\\": \\"%s\\"}", name, port, port_type
                first = 0
            }
            END { print "]" }
            '
            """
        
        let result = try await executeWithFallback(osquery: nil, bash: bashScript)
        
        var ports: [[String: Any]] = []
        if let items = result["items"] as? [[String: Any]] {
            ports = items
        }
        
        return ports.map { port in
            let portType = port["portType"] as? String ?? "Serial Port"
            let connectionType = portType.contains("USB") ? "USB" : (portType.contains("Bluetooth") ? "Bluetooth" : "Serial")
            
            return [
                "name": port["name"] as? String ?? "Serial Port",
                "device": port["device"] as? String ?? "",
                "portType": portType,
                "connectionType": connectionType,
                "deviceType": "Serial Port"
            ]
        }
    }
}
