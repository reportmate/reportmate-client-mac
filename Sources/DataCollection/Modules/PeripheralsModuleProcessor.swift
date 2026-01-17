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
        
        // Enhanced bash fallback using system_profiler with more fields
        let bashScript = """
            echo "["
            first=true
            
            system_profiler SPUSBDataType 2>/dev/null | awk '
            BEGIN { name=""; vendor=""; vendor_id=""; product_id=""; serial=""; speed=""; location=""; conn_type=""; power=""; version=""; first=1 }
            /^[[:space:]]+[A-Za-z].*:$/ {
                if (name != "" && name !~ /USB/ && name !~ /Bus/ && name !~ /Host/) {
                    if (!first) printf ","
                    gsub(/"/, "\\\\\\"", name)
                    gsub(/"/, "\\\\\\"", vendor)
                    gsub(/"/, "\\\\\\"", serial)
                    gsub(/"/, "\\\\\\"", speed)
                    gsub(/"/, "\\\\\\"", power)
                    printf "{\\"name\\": \\"%s\\", \\"vendor\\": \\"%s\\", \\"vendorId\\": \\"%s\\", \\"productId\\": \\"%s\\", \\"serial\\": \\"%s\\", \\"speed\\": \\"%s\\", \\"locationId\\": \\"%s\\", \\"connectionType\\": \\"%s\\", \\"powerAllocated\\": \\"%s\\", \\"version\\": \\"%s\\"}", name, vendor, vendor_id, product_id, serial, speed, location, conn_type, power, version
                    first = 0
                }
                gsub(/^[[:space:]]+/, "")
                gsub(/:$/, "")
                name = $0
                vendor = ""; vendor_id = ""; product_id = ""; serial = ""; speed = ""; location = ""; conn_type = ""; power = ""; version = ""
            }
            /Manufacturer:/ { gsub(/.*Manufacturer:[[:space:]]*/, ""); vendor = $0 }
            /Vendor ID:/ { gsub(/.*Vendor ID:[[:space:]]*/, ""); vendor_id = $0 }
            /Product ID:/ { gsub(/.*Product ID:[[:space:]]*/, ""); product_id = $0 }
            /Serial Number:/ { gsub(/.*Serial Number:[[:space:]]*/, ""); serial = $0 }
            /Speed:/ { gsub(/.*Speed:[[:space:]]*/, ""); speed = $0 }
            /Link Speed:/ { gsub(/.*Link Speed:[[:space:]]*/, ""); speed = $0 }
            /Location ID:/ { gsub(/.*Location ID:[[:space:]]*/, ""); location = $0 }
            /Connection Type:/ { gsub(/.*Connection Type:[[:space:]]*/, ""); conn_type = $0 }
            /Power Allocated:/ { gsub(/.*Power Allocated:[[:space:]]*/, ""); power = $0 }
            /USB Product Version:/ { gsub(/.*USB Product Version:[[:space:]]*/, ""); version = $0 }
            END {
                if (name != "" && name !~ /USB/ && name !~ /Bus/ && name !~ /Host/) {
                    if (!first) printf ","
                    gsub(/"/, "\\\\\\"", name)
                    gsub(/"/, "\\\\\\"", vendor)
                    gsub(/"/, "\\\\\\"", serial)
                    gsub(/"/, "\\\\\\"", speed)
                    gsub(/"/, "\\\\\\"", power)
                    printf "{\\"name\\": \\"%s\\", \\"vendor\\": \\"%s\\", \\"vendorId\\": \\"%s\\", \\"productId\\": \\"%s\\", \\"serial\\": \\"%s\\", \\"speed\\": \\"%s\\", \\"locationId\\": \\"%s\\", \\"connectionType\\": \\"%s\\", \\"powerAllocated\\": \\"%s\\", \\"version\\": \\"%s\\"}", name, vendor, vendor_id, product_id, serial, speed, location, conn_type, power, version
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
            
            // Determine connection type (removable vs built-in)
            let connectionType = device["connectionType"] as? String ?? 
                                (device["removable"] as? String == "1" ? "Removable" : "Built-in")
            
            return [
                "name": name,
                "vendor": device["vendor"] as? String ?? "",
                "vendorId": device["vendor_id"] as? String ?? device["vendorId"] as? String ?? "",
                "productId": device["model_id"] as? String ?? device["productId"] as? String ?? "",
                "serialNumber": device["serial"] as? String ?? "",
                "speed": device["speed"] as? String ?? device["version"] as? String ?? "",
                "linkSpeed": device["speed"] as? String ?? "",  // Enhanced: "10 Gb/s" format
                "locationId": device["locationId"] as? String ?? "",  // Enhanced: "0x21310000"
                "powerAllocated": device["powerAllocated"] as? String ?? "",  // Enhanced: "4.48 W (896 mA)"
                "usbVersion": device["version"] as? String ?? "",  // Enhanced: "0x5603"
                "isRemovable": device["removable"] as? String == "1",
                "deviceType": deviceType,
                "connectionType": connectionType  // Enhanced: "Removable" or "Built-in"
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
        // Use simple df + diskutil approach - execute from Swift directly
        let dfOutput = try await BashService.execute("df -H | grep '^/dev/disk' | awk '{print $1}' | sort -u")
        let devices = dfOutput.split(separator: "\n").map(String.init)
        
        var storageDevices: [[String: Any]] = []
        
        for device in devices {
            let trimmedDevice = device.trimmingCharacters(in: .whitespaces)
            guard !trimmedDevice.isEmpty else { continue }
            
            // Get detailed info for each device
            let infoCmd = "diskutil info '\(trimmedDevice)'"
            if let infoOutput = try? await BashService.execute(infoCmd) {
                var volumeName = ""
                var mountPoint = ""
                var fileSystem = ""
                var diskSize = ""
                var deviceProtocol = ""
                
                // Parse the output line by line
                for line in infoOutput.split(separator: "\n") {
                    let lineStr = String(line).trimmingCharacters(in: .whitespaces)
                    
                    if lineStr.hasPrefix("Volume Name:") {
                        volumeName = lineStr.replacingOccurrences(of: "Volume Name:", with: "").trimmingCharacters(in: .whitespaces)
                    } else if lineStr.hasPrefix("Mount Point:") {
                        mountPoint = lineStr.replacingOccurrences(of: "Mount Point:", with: "").trimmingCharacters(in: .whitespaces)
                    } else if lineStr.hasPrefix("Type (Bundle):") {
                        fileSystem = lineStr.replacingOccurrences(of: "Type (Bundle):", with: "").trimmingCharacters(in: .whitespaces)
                    } else if lineStr.hasPrefix("Disk Size:") {
                        let sizeStr = lineStr.replacingOccurrences(of: "Disk Size:", with: "").trimmingCharacters(in: .whitespaces)
                        // Extract just "2.0 TB" part
                        if let match = sizeStr.range(of: "^[0-9.]+ [KMGT]B", options: .regularExpression) {
                            diskSize = String(sizeStr[match])
                        }
                    } else if lineStr.hasPrefix("Protocol:") {
                        deviceProtocol = lineStr.replacingOccurrences(of: "Protocol:", with: "").trimmingCharacters(in: .whitespaces)
                    }
                }
                
                // Use volume name or fallback
                if volumeName.isEmpty || volumeName == "Not applicable" {
                    volumeName = "External Storage"
                }
                
                // ONLY include actual external devices - skip internal Apple Fabric drives
                let isExternal = !deviceProtocol.isEmpty && 
                                 !deviceProtocol.lowercased().contains("apple fabric") &&
                                 !deviceProtocol.lowercased().contains("internal")
                
                if isExternal {
                    storageDevices.append([
                        "name": volumeName,
                        "device": trimmedDevice,
                        "mountPoint": mountPoint,
                        "fileSystem": fileSystem,
                        "size": diskSize,
                        "protocol": deviceProtocol
                    ])
                }
            }
        }
        
        return storageDevices.map { device in
            let deviceProtocol = device["protocol"] as? String ?? ""
            
            var storageType = "External Storage"
            if deviceProtocol.lowercased().contains("usb") { storageType = "USB Drive" }
            else if deviceProtocol.lowercased().contains("thunderbolt") { storageType = "Thunderbolt Storage" }
            else if (device["name"] as? String ?? "").lowercased().contains("sd") { storageType = "SD Card" }
            
            return [
                "name": device["name"] as? String ?? "External Storage",
                "devicePath": device["device"] as? String ?? "",
                "mountPoint": device["mountPoint"] as? String ?? "",
                "fileSystem": device["fileSystem"] as? String ?? "",
                "totalSize": device["size"] as? String ?? "",
                "protocol": deviceProtocol,
                "storageType": storageType,
                "deviceType": "External Storage"
            ]
        }
    }
    
    // MARK: - Printers (HIGHEST PRIORITY)
    
    private func collectPrinters() async throws -> [[String: Any]] {
        // Use system_profiler with jq for comprehensive printer data (NO PYTHON - see CLAUDE.md)
        let bashScript = """
            system_profiler SPPrintersDataType -json 2>/dev/null | jq '[.SPPrintersDataType[]? | {
                name: (._name // "Unknown"),
                status: (.status // "Unknown"),
                uri: (.uri // ""),
                ppd: (.ppd // ""),
                ppdFileVersion: (.ppdfileversion // ""),
                driverVersion: (.driverversion // ""),
                postScriptVersion: (.psversion // ""),
                cupsVersion: (.cupsversion // ""),
                isDefault: ((.default // "no") | ascii_downcase == "yes"),
                isShared: ((.shared // "no") | ascii_downcase == "yes"),
                printerCommands: (.printercommands // ""),
                scanningSupport: (."Scanning support" // "No"),
                faxSupport: (."Fax Support" // "No"),
                dateAdded: (.addeddate // ""),
                cupsFilters: [."cups filters"[]? | {
                    name: (._name // ""),
                    path: (."filter path" // ""),
                    permissions: (."filter permissions" // ""),
                    version: (."filter version" // "")
                }]
            }]'
            """
        
        let result = try await executeWithFallback(osquery: nil, bash: bashScript)
        
        var printers: [[String: Any]] = []
        if let items = result["items"] as? [[String: Any]] {
            printers = items
        } else if let output = result["output"] as? String,
                  let data = output.data(using: .utf8),
                  let jsonArray = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] {
            printers = jsonArray
        }
        
        // Fallback to lpstat if system_profiler fails
        if printers.isEmpty {
            printers = try await collectPrintersWithLpstat()
        }
        
        return printers.map { printer in
            let name = printer["name"] as? String ?? "Unknown Printer"
            let uri = printer["uri"] as? String ?? ""
            let ppd = printer["ppd"] as? String ?? ""
            
            // Determine connection type from URI
            var connectionType = "Unknown"
            if uri.contains("usb:") { connectionType = "USB" }
            else if uri.contains("ipp:") || uri.contains("ipps:") { connectionType = "Network (IPP)" }
            else if uri.contains("socket:") { connectionType = "Network (Socket)" }
            else if uri.contains("lpd:") { connectionType = "Network (LPD)" }
            else if uri.contains("smb:") { connectionType = "Network (SMB)" }
            else if uri.contains("dnssd:") { connectionType = "Network (Bonjour)" }
            
            // Parse make and model from PPD
            var make = ""
            let model = ppd
            if !ppd.isEmpty {
                let parts = ppd.components(separatedBy: " ")
                if parts.count > 0 {
                    make = parts[0]
                }
            }
            
            // Parse status
            let statusStr = printer["status"] as? String ?? "Idle"
            
            return [
                "name": name,
                "displayName": name,
                "uri": uri,
                "connectionType": connectionType,
                "status": statusStr.capitalized,
                "make": make,
                "model": model,
                "makeAndModel": ppd,
                "ppd": ppd,
                "ppdFileVersion": printer["ppdFileVersion"] as? String ?? "",
                "driverVersion": printer["driverVersion"] as? String ?? "",
                "postScriptVersion": printer["postScriptVersion"] as? String ?? "",
                "cupsVersion": printer["cupsVersion"] as? String ?? "",
                "printerCommands": printer["printerCommands"] as? String ?? "",
                "scanningSupport": printer["scanningSupport"] as? String ?? "",
                "faxSupport": printer["faxSupport"] as? String ?? "",
                "dateAdded": printer["dateAdded"] as? String ?? "",
                "cupsFilters": printer["cupsFilters"] as? [[String: Any]] ?? []
            ]
        }
    }
    
    // Fallback method using lpstat for basic printer info
    private func collectPrintersWithLpstat() async throws -> [[String: Any]] {
        let bashScript = """
            echo "["
            first=true
            
            # Get default printer
            default_printer=$(lpstat -d 2>/dev/null | awk '{print $NF}' || echo "")
            
            # Process each printer
            lpstat -v 2>/dev/null | while IFS=: read -r device_part uri_part; do
                # Extract printer name (remove "device for " prefix)
                printer_name=$(echo "$device_part" | sed 's/^device for //')
                # Extract URI (trim whitespace)
                printer_uri=$(echo "$uri_part" | sed 's/^[[:space:]]*//')
                
                [ -z "$printer_name" ] && continue
                
                # Check if default
                is_default="false"
                [ "$printer_name" = "$default_printer" ] && is_default="true"
                
                # Get lpoptions details
                lp_info=$(lpoptions -p "$printer_name" 2>/dev/null || echo "")
                
                # Extract make and model
                make_model=$(echo "$lp_info" | grep -o "printer-make-and-model='[^']*'" | sed "s/printer-make-and-model='//;s/'$//")
                [ -z "$make_model" ] && make_model="Unknown"
                
                # Output JSON
                [ "$first" = false ] && echo ","
                cat <<-EOF
            {
              "name": "$printer_name",
              "uri": "$printer_uri",
              "isDefault": $is_default,
              "ppd": "$make_model"
            }
            EOF
                first=false
            done
            
            echo "]"
            """
        
        let result = try await executeWithFallback(osquery: nil, bash: bashScript)
        
        var printers: [[String: Any]] = []
        if let items = result["items"] as? [[String: Any]] {
            printers = items
        }
        
        return printers
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
