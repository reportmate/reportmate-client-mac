import Foundation

/// Peripherals module processor - uses osquery first with bash fallback
/// Based on MunkiReport patterns for peripheral device collection
/// Reference: https://github.com/munkireport/usb, bluetooth, displays
/// No Python - uses osquery for: usb_devices, audio_devices, system_controls
/// Bash fallback for: Bluetooth, displays, printers, Thunderbolt
public class PeripheralsModuleProcessor: BaseModuleProcessor, @unchecked Sendable {
    
    public init(configuration: ReportMateConfiguration) {
        super.init(moduleId: "peripherals", configuration: configuration)
    }
    
    public override func collectData() async throws -> ModuleData {
        // Collect peripheral data in parallel
        async let usbDevices = collectUSBDevices()
        async let audioDevices = collectAudioDevices()
        async let bluetoothDevices = collectBluetoothDevices()
        async let cameraDevices = collectCameraDevices()
        async let externalStorage = collectExternalStorage()
        async let thunderboltDevices = collectThunderboltDevices()
        async let displayInfo = collectDisplayInfo()
        async let printerInfo = collectPrinters()
        
        // Await all results
        let usb = try await usbDevices
        let audio = try await audioDevices
        let bluetooth = try await bluetoothDevices
        let cameras = try await cameraDevices
        let storage = try await externalStorage
        let thunderbolt = try await thunderboltDevices
        let displays = try await displayInfo
        let printers = try await printerInfo
        
        let peripheralsData: [String: Any] = [
            "usbDevices": usb,
            "audioDevices": audio,
            "bluetoothDevices": bluetooth,
            "cameras": cameras,
            "externalStorage": storage,
            "thunderboltDevices": thunderbolt,
            "displays": displays,
            "printers": printers
        ]
        
        return BaseModuleData(moduleId: moduleId, data: peripheralsData)
    }
    
    // MARK: - USB Devices (osquery: usb_devices)
    
    private func collectUSBDevices() async throws -> [[String: Any]] {
        // osquery usb_devices table provides USB device info
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
        
        // Pure bash + awk solution for USB device extraction (NO Python)
        let bashScript = """
            # Get USB device info using system_profiler (NO Python - pure awk parsing)
            echo "["
            first=true
            
            system_profiler SPUSBDataType 2>/dev/null | awk '
            BEGIN { name=""; vendor=""; vendor_id=""; product_id=""; serial=""; version=""; first=1 }
            /^[[:space:]]+[A-Za-z0-9].*:$/ && !/USB/ && !/Bus/ && !/Host Controller/ {
                if (name != "") {
                    if (!first) printf ","
                    printf "{\\"model\\": \\"%s\\", \\"vendor\\": \\"%s\\", \\"vendor_id\\": \\"%s\\", \\"model_id\\": \\"%s\\", \\"serial\\": \\"%s\\", \\"version\\": \\"%s\\"}", name, vendor, vendor_id, product_id, serial, version
                    first = 0
                }
                gsub(/^[[:space:]]+/, "")
                gsub(/:$/, "")
                name = $0
                vendor = ""
                vendor_id = ""
                product_id = ""
                serial = ""
                version = ""
            }
            /Manufacturer:/ { gsub(/.*Manufacturer:[[:space:]]*/, ""); vendor = $0 }
            /Vendor ID:/ { gsub(/.*Vendor ID:[[:space:]]*/, ""); vendor_id = $0 }
            /Product ID:/ { gsub(/.*Product ID:[[:space:]]*/, ""); product_id = $0 }
            /Serial Number:/ { gsub(/.*Serial Number:[[:space:]]*/, ""); serial = $0 }
            /Version:/ { gsub(/.*Version:[[:space:]]*/, ""); version = $0 }
            END {
                if (name != "") {
                    if (!first) printf ","
                    printf "{\\"model\\": \\"%s\\", \\"vendor\\": \\"%s\\", \\"vendor_id\\": \\"%s\\", \\"model_id\\": \\"%s\\", \\"serial\\": \\"%s\\", \\"version\\": \\"%s\\"}", name, vendor, vendor_id, product_id, serial, version
                }
            }
            '
            
            echo "]"
            """
        
        // Prefer osquery, fallback to system_profiler via bash
        let result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript,
            python: nil
        )
        
        var devices: [[String: Any]] = []
        
        if let items = result["items"] as? [[String: Any]] {
            devices = items
        } else if !result.isEmpty && result["model"] != nil {
            devices = [result]
        }
        
        // Transform to standardized format
        return devices.map { device in
            [
                "name": device["model"] as? String ?? "Unknown USB Device",
                "vendor": device["vendor"] as? String ?? "",
                "vendorId": device["vendor_id"] as? String ?? "",
                "productId": device["model_id"] as? String ?? "",
                "serialNumber": device["serial"] as? String ?? "",
                "usbVersion": device["version"] as? String ?? "",
                "deviceClass": device["class"] as? String ?? "",
                "isRemovable": (device["removable"] as? String == "1") ||
                              (device["removable"] as? Bool == true),
                "busAddress": device["usb_address"] as? String ?? "",
                "portNumber": device["usb_port"] as? String ?? ""
            ]
        }
    }
    
    // MARK: - Audio Devices (osquery: audio_devices via IOKit)
    
    private func collectAudioDevices() async throws -> [[String: Any]] {
        let bashScript = """
            # Get audio devices using system_profiler
            echo "["
            first=true
            
            # Get output devices
            system_profiler SPAudioDataType 2>/dev/null | grep -E "^[[:space:]]+(.*):$|Default Output Device:|Default Input Device:|Manufacturer:" | \
            awk '
            BEGIN { in_device = 0; name = ""; type = ""; manufacturer = "" }
            /:$/ && !/Default/ && !/Manufacturer/ { 
                if (in_device && name != "") {
                    printf "%s{\\"name\\": \\"%s\\", \\"type\\": \\"%s\\", \\"manufacturer\\": \\"%s\\"}", (NR>1 ? "," : ""), name, type, manufacturer
                }
                gsub(/^[[:space:]]+/, "")
                gsub(/:$/, "")
                name = $0
                type = "Output"
                manufacturer = ""
                in_device = 1
            }
            /Default Output Device:/ { 
                gsub(/.*Default Output Device:[[:space:]]*/, "")
                if ($0 == "Yes") type = "Default Output"
            }
            /Default Input Device:/ {
                gsub(/.*Default Input Device:[[:space:]]*/, "")
                if ($0 == "Yes") type = "Default Input"
            }
            /Manufacturer:/ {
                gsub(/.*Manufacturer:[[:space:]]*/, "")
                manufacturer = $0
            }
            END {
                if (in_device && name != "") {
                    printf "%s{\\"name\\": \\"%s\\", \\"type\\": \\"%s\\", \\"manufacturer\\": \\"%s\\"}", (NR>1 ? "," : ""), name, type, manufacturer
                }
            }
            '
            
            echo "]"
        """
        
        let result = try await executeWithFallback(
            osquery: nil,
            bash: bashScript,
            python: nil
        )
        
        var devices: [[String: Any]] = []
        
        if let items = result["items"] as? [[String: Any]] {
            devices = items
        }
        
        // Transform to standardized format
        return devices.map { device in
            let deviceType = device["type"] as? String ?? "Unknown"
            let isDefault = deviceType.contains("Default")
            let direction = deviceType.contains("Input") ? "Input" : "Output"
            
            return [
                "name": device["name"] as? String ?? "Unknown Audio Device",
                "manufacturer": device["manufacturer"] as? String ?? "",
                "type": direction,
                "isDefault": isDefault,
                "isInput": direction == "Input",
                "isOutput": direction == "Output"
            ]
        }
    }
    
    // MARK: - Bluetooth Devices (bash: system_profiler SPBluetoothDataType)
    
    private func collectBluetoothDevices() async throws -> [[String: Any]] {
        let bashScript = """
            # Get Bluetooth info
            echo "["
            
            # Host controller info
            bt_info=$(system_profiler SPBluetoothDataType 2>/dev/null || echo "")
            
            if [ -n "$bt_info" ]; then
                # Get paired devices
                echo "$bt_info" | awk '
                BEGIN { first = 1; in_device = 0; name = ""; addr = ""; connected = "false"; type = "" }
                /Devices \\(Paired\\):/ || /Connected:/ { in_device = 1 }
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
        
        let result = try await executeWithFallback(
            osquery: nil,
            bash: bashScript,
            python: nil
        )
        
        var devices: [[String: Any]] = []
        
        if let items = result["items"] as? [[String: Any]] {
            devices = items
        }
        
        // Transform to standardized format
        return devices.map { device in
            [
                "name": device["name"] as? String ?? "Unknown Bluetooth Device",
                "address": device["address"] as? String ?? "",
                "isConnected": (device["connected"] as? Bool == true) ||
                              (device["connected"] as? String == "true"),
                "deviceType": device["type"] as? String ?? "Unknown",
                "isPaired": true  // These are from paired devices list
            ]
        }
    }
    
    // MARK: - Camera Devices (bash: system_profiler SPCameraDataType)
    
    private func collectCameraDevices() async throws -> [[String: Any]] {
        let bashScript = """
            # Get camera info
            echo "["
            
            system_profiler SPCameraDataType 2>/dev/null | awk '
            BEGIN { first = 1; name = ""; model_id = ""; unique_id = "" }
            /^[[:space:]]+[A-Za-z].*:$/ {
                if (name != "") {
                    if (!first) printf ","
                    printf "{\\"name\\": \\"%s\\", \\"modelId\\": \\"%s\\", \\"uniqueId\\": \\"%s\\"}", name, model_id, unique_id
                    first = 0
                }
                gsub(/^[[:space:]]+/, "")
                gsub(/:$/, "")
                name = $0
                model_id = ""
                unique_id = ""
            }
            /Model ID:/ { gsub(/.*Model ID:[[:space:]]*/, ""); model_id = $0 }
            /Unique ID:/ { gsub(/.*Unique ID:[[:space:]]*/, ""); unique_id = $0 }
            END {
                if (name != "") {
                    if (!first) printf ","
                    printf "{\\"name\\": \\"%s\\", \\"modelId\\": \\"%s\\", \\"uniqueId\\": \\"%s\\"}", name, model_id, unique_id
                }
            }
            '
            
            echo "]"
        """
        
        let result = try await executeWithFallback(
            osquery: nil,
            bash: bashScript,
            python: nil
        )
        
        var devices: [[String: Any]] = []
        
        if let items = result["items"] as? [[String: Any]] {
            devices = items
        }
        
        // Transform to standardized format
        return devices.map { device in
            let name = device["name"] as? String ?? "Unknown Camera"
            let isBuiltIn = name.lowercased().contains("facetime") || name.lowercased().contains("isight")
            
            return [
                "name": name,
                "modelId": device["modelId"] as? String ?? "",
                "uniqueId": device["uniqueId"] as? String ?? "",
                "isBuiltIn": isBuiltIn
            ]
        }
    }
    
    // MARK: - External Storage (osquery: mounts + disk_info)
    
    private func collectExternalStorage() async throws -> [[String: Any]] {
        // osquery mounts and disk_info for external drives
        let osqueryScript = """
            SELECT 
                m.device,
                m.path,
                m.type,
                m.blocks,
                m.blocks_available,
                m.blocks_free,
                m.flags,
                d.id,
                d.name,
                d.disk_size,
                d.block_size
            FROM mounts m
            LEFT JOIN disk_info d ON m.device = d.id
            WHERE m.device LIKE '/dev/disk%'
              AND m.path NOT LIKE '/System/%';
        """
        
        let bashScript = """
            # Get external storage info
            echo "["
            first=true
            
            # Get mounted external volumes
            diskutil list external 2>/dev/null | grep -E "^/dev/disk" | while read -r disk rest; do
                info=$(diskutil info "$disk" 2>/dev/null || echo "")
                [ -z "$info" ] && continue
                
                name=$(echo "$info" | grep "Volume Name:" | sed 's/.*Volume Name:[[:space:]]*//')
                [ -z "$name" ] && name=$(echo "$info" | grep "Media Name:" | sed 's/.*Media Name:[[:space:]]*//')
                
                size=$(echo "$info" | grep "Total Size:" | sed 's/.*Total Size:[[:space:]]*//' | cut -d'(' -f1)
                fs_type=$(echo "$info" | grep "Type (Bundle):" | sed 's/.*Type (Bundle):[[:space:]]*//')
                mount_point=$(echo "$info" | grep "Mount Point:" | sed 's/.*Mount Point:[[:space:]]*//')
                removable=$(echo "$info" | grep "Removable Media:" | sed 's/.*Removable Media:[[:space:]]*//')
                protocol=$(echo "$info" | grep "Protocol:" | sed 's/.*Protocol:[[:space:]]*//')
                
                is_removable="false"
                [ "$removable" = "Removable" ] && is_removable="true"
                
                # Escape for JSON
                name_esc=$(echo "$name" | sed 's/"/\\\\"/g')
                mount_esc=$(echo "$mount_point" | sed 's/"/\\\\"/g')
                
                if [ "$first" = "true" ]; then
                    first=false
                else
                    echo ","
                fi
                
                echo "{\\"name\\": \\"$name_esc\\", \\"device\\": \\"$disk\\", \\"mountPoint\\": \\"$mount_esc\\", \\"fileSystem\\": \\"$fs_type\\", \\"size\\": \\"$size\\", \\"protocol\\": \\"$protocol\\", \\"isRemovable\\": $is_removable}"
            done
            
            echo "]"
        """
        
        let result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript,
            python: nil
        )
        
        var devices: [[String: Any]] = []
        
        if let items = result["items"] as? [[String: Any]] {
            devices = items
        } else if !result.isEmpty && (result["device"] != nil || result["name"] != nil) {
            devices = [result]
        }
        
        // Transform to standardized format
        return devices.map { device in
            [
                "name": device["name"] as? String ?? "External Storage",
                "devicePath": device["device"] as? String ?? "",
                "mountPoint": device["path"] as? String ?? device["mountPoint"] as? String ?? "",
                "fileSystem": device["type"] as? String ?? device["fileSystem"] as? String ?? "",
                "totalSize": device["disk_size"] as? String ?? device["size"] as? String ?? "",
                "protocol": device["protocol"] as? String ?? "",
                "isRemovable": (device["isRemovable"] as? Bool == true) ||
                              (device["isRemovable"] as? String == "true")
            ]
        }
    }
    
    // MARK: - Thunderbolt Devices (bash: system_profiler SPThunderboltDataType)
    
    private func collectThunderboltDevices() async throws -> [[String: Any]] {
        let bashScript = """
            # Get Thunderbolt device info
            echo "["
            
            system_profiler SPThunderboltDataType 2>/dev/null | awk '
            BEGIN { first = 1; name = ""; vendor = ""; device_id = ""; uid = "" }
            /^[[:space:]]+[A-Za-z].*:$/ && !/Thunderbolt Bus/ {
                if (name != "") {
                    if (!first) printf ","
                    printf "{\\"name\\": \\"%s\\", \\"vendor\\": \\"%s\\", \\"deviceId\\": \\"%s\\", \\"uid\\": \\"%s\\"}", name, vendor, device_id, uid
                    first = 0
                }
                gsub(/^[[:space:]]+/, "")
                gsub(/:$/, "")
                name = $0
                vendor = ""
                device_id = ""
                uid = ""
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
        
        let result = try await executeWithFallback(
            osquery: nil,
            bash: bashScript,
            python: nil
        )
        
        var devices: [[String: Any]] = []
        
        if let items = result["items"] as? [[String: Any]] {
            devices = items
        }
        
        return devices.map { device in
            [
                "name": device["name"] as? String ?? "Thunderbolt Device",
                "vendor": device["vendor"] as? String ?? "",
                "deviceId": device["deviceId"] as? String ?? "",
                "uid": device["uid"] as? String ?? ""
            ]
        }
    }
    
    // MARK: - Display Info (bash: system_profiler SPDisplaysDataType)
    
    private func collectDisplayInfo() async throws -> [[String: Any]] {
        let bashScript = """
            # Get display info
            echo "["
            
            system_profiler SPDisplaysDataType 2>/dev/null | awk '
            BEGIN { first = 1; name = ""; resolution = ""; vendor = ""; serial = ""; builtin = "false" }
            /^[[:space:]]+[A-Za-z].*:$/ && !/Graphics/ && !/Chipset/ {
                if (name != "") {
                    if (!first) printf ","
                    printf "{\\"name\\": \\"%s\\", \\"resolution\\": \\"%s\\", \\"vendor\\": \\"%s\\", \\"serial\\": \\"%s\\", \\"isBuiltIn\\": %s}", name, resolution, vendor, serial, builtin
                    first = 0
                }
                gsub(/^[[:space:]]+/, "")
                gsub(/:$/, "")
                name = $0
                resolution = ""
                vendor = ""
                serial = ""
                builtin = "false"
            }
            /Resolution:/ { 
                gsub(/.*Resolution:[[:space:]]*/, "")
                gsub(/[[:space:]]*\\(.*/, "")
                resolution = $0 
            }
            /Vendor:/ { gsub(/.*Vendor:[[:space:]]*/, ""); vendor = $0 }
            /Display Serial Number:/ { gsub(/.*Display Serial Number:[[:space:]]*/, ""); serial = $0 }
            /Display Type:/ { 
                if ($0 ~ /Built-In/) builtin = "true" 
            }
            /Connection Type:/ {
                if ($0 ~ /Internal/) builtin = "true"
            }
            END {
                if (name != "") {
                    if (!first) printf ","
                    printf "{\\"name\\": \\"%s\\", \\"resolution\\": \\"%s\\", \\"vendor\\": \\"%s\\", \\"serial\\": \\"%s\\", \\"isBuiltIn\\": %s}", name, resolution, vendor, serial, builtin
                }
            }
            '
            
            echo "]"
        """
        
        let result = try await executeWithFallback(
            osquery: nil,
            bash: bashScript,
            python: nil
        )
        
        var displays: [[String: Any]] = []
        
        if let items = result["items"] as? [[String: Any]] {
            displays = items
        }
        
        return displays.map { display in
            [
                "name": display["name"] as? String ?? "Unknown Display",
                "resolution": display["resolution"] as? String ?? "",
                "vendor": display["vendor"] as? String ?? "",
                "serialNumber": display["serial"] as? String ?? "",
                "isBuiltIn": (display["isBuiltIn"] as? Bool == true) ||
                            (display["isBuiltIn"] as? String == "true")
            ]
        }
    }
    
    // MARK: - Printers (bash: lpstat + CUPS)
    
    private func collectPrinters() async throws -> [[String: Any]] {
        let bashScript = """
            # Get printer info
            echo "["
            first=true
            
            # Get all printers from lpstat
            lpstat -p 2>/dev/null | while read -r line; do
                printer=$(echo "$line" | awk '{print $2}')
                [ -z "$printer" ] && continue
                
                # Get printer details
                info=$(lpoptions -p "$printer" -l 2>/dev/null || echo "")
                device_uri=$(lpstat -v "$printer" 2>/dev/null | awk '{print $NF}')
                
                # Check status
                status="Unknown"
                if echo "$line" | grep -qi "idle"; then
                    status="Idle"
                elif echo "$line" | grep -qi "printing"; then
                    status="Printing"
                elif echo "$line" | grep -qi "disabled"; then
                    status="Disabled"
                fi
                
                # Check if default
                default_printer=$(lpstat -d 2>/dev/null | awk -F': ' '{print $2}')
                is_default="false"
                [ "$printer" = "$default_printer" ] && is_default="true"
                
                # Escape for JSON
                printer_esc=$(echo "$printer" | sed 's/"/\\\\"/g')
                uri_esc=$(echo "$device_uri" | sed 's/"/\\\\"/g')
                
                if [ "$first" = "true" ]; then
                    first=false
                else
                    echo ","
                fi
                
                echo "{\\"name\\": \\"$printer_esc\\", \\"status\\": \\"$status\\", \\"deviceUri\\": \\"$uri_esc\\", \\"isDefault\\": $is_default}"
            done
            
            echo "]"
        """
        
        let result = try await executeWithFallback(
            osquery: nil,
            bash: bashScript,
            python: nil
        )
        
        var printers: [[String: Any]] = []
        
        if let items = result["items"] as? [[String: Any]] {
            printers = items
        }
        
        // Get active print jobs
        let printJobs = try await collectPrintJobs()
        
        // Transform and add job counts
        return printers.map { printer in
            let printerName = printer["name"] as? String ?? ""
            let jobCount = printJobs.filter { ($0["printer"] as? String) == printerName }.count
            
            return [
                "name": printerName,
                "status": printer["status"] as? String ?? "Unknown",
                "deviceUri": printer["deviceUri"] as? String ?? "",
                "isDefault": (printer["isDefault"] as? Bool == true) ||
                            (printer["isDefault"] as? String == "true"),
                "activeJobCount": jobCount
            ]
        }
    }
    
    private func collectPrintJobs() async throws -> [[String: Any]] {
        let bashScript = """
            # Get active print jobs
            echo "["
            first=true
            
            lpstat -o 2>/dev/null | while read -r job rest; do
                [ -z "$job" ] && continue
                
                # Parse job ID and printer
                printer=$(echo "$job" | cut -d'-' -f1)
                job_id=$(echo "$job" | sed 's/.*-//')
                
                # Get job details
                user=$(lpstat -o "$job" 2>/dev/null | awk '{print $3}')
                
                job_esc=$(echo "$job" | sed 's/"/\\\\"/g')
                printer_esc=$(echo "$printer" | sed 's/"/\\\\"/g')
                user_esc=$(echo "$user" | sed 's/"/\\\\"/g')
                
                if [ "$first" = "true" ]; then
                    first=false
                else
                    echo ","
                fi
                
                echo "{\\"jobId\\": \\"$job_esc\\", \\"printer\\": \\"$printer_esc\\", \\"user\\": \\"$user_esc\\"}"
            done
            
            echo "]"
        """
        
        let result = try await executeWithFallback(
            osquery: nil,
            bash: bashScript,
            python: nil
        )
        
        if let items = result["items"] as? [[String: Any]] {
            return items
        }
        return []
    }
}
