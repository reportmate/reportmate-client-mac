import Foundation

/// Hardware module processor for collecting hardware information
public class HardwareModuleProcessor: BaseModuleProcessor, @unchecked Sendable {
    
    public init(configuration: ReportMateConfiguration) {
        super.init(moduleId: "hardware", configuration: configuration)
    }
    
    public override func collectData() async throws -> ModuleData {
        let hardwareData = try await collectHardwareInfo()
        return BaseModuleData(moduleId: moduleId, data: hardwareData)
    }
    
    private func collectHardwareInfo() async throws -> [String: Any] {
        return try await executeWithFallback(
            osquery: """
            SELECT 
                cpu_brand, cpu_logical_cores, cpu_physical_cores,
                physical_memory, hardware_vendor, hardware_model
            FROM system_info;
            """,
            bash: "system_profiler SPHardwareDataType -json",
            python: """
import json
import subprocess
import platform

def get_hardware_info():
    info = {
        "cpu_brand": platform.processor(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "system": platform.system(),
        "release": platform.release()
    }
    
    # Try to get more detailed info via system_profiler
    try:
        result = subprocess.run(['system_profiler', 'SPHardwareDataType', '-json'], 
                               capture_output=True, text=True)
        if result.returncode == 0:
            data = json.loads(result.stdout)
            info["system_profiler"] = data
    except:
        pass
    
    return info

print(json.dumps(get_hardware_info()))
"""
        )
    }
}

/// System module processor for collecting system information
public class SystemModuleProcessor: BaseModuleProcessor, @unchecked Sendable {
    
    public init(configuration: ReportMateConfiguration) {
        super.init(moduleId: "system", configuration: configuration)
    }
    
    public override func collectData() async throws -> ModuleData {
        let systemData = try await collectSystemInfo()
        return BaseModuleData(moduleId: moduleId, data: systemData)
    }
    
    private func collectSystemInfo() async throws -> [String: Any] {
        return try await executeWithFallback(
            osquery: """
            SELECT 
                hostname, uptime, total_seconds, 
                local_hostname, computer_name
            FROM uptime 
            JOIN system_info;
            """,
            bash: """
            echo "{"
            echo "  \"hostname\": \"$(hostname)\","
            echo "  \"uptime\": \"$(uptime)\","
            echo "  \"date\": \"$(date)\","
            echo "  \"kernel\": \"$(uname -a)\""
            echo "}"
            """,
            python: """
import json
import platform
import subprocess
from datetime import datetime

def get_system_info():
    info = {
        "hostname": platform.node(),
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "timestamp": datetime.now().isoformat()
    }
    
    # Get uptime
    try:
        result = subprocess.run(['uptime'], capture_output=True, text=True)
        if result.returncode == 0:
            info["uptime"] = result.stdout.strip()
    except:
        pass
    
    return info

print(json.dumps(get_system_info()))
"""
        )
    }
}

/// Network module processor for collecting network information  
public class NetworkModuleProcessor: BaseModuleProcessor, @unchecked Sendable {
    
    public init(configuration: ReportMateConfiguration) {
        super.init(moduleId: "network", configuration: configuration)
    }
    
    public override func collectData() async throws -> ModuleData {
        let networkData = try await collectNetworkInfo()
        return BaseModuleData(moduleId: moduleId, data: networkData)
    }
    
    private func collectNetworkInfo() async throws -> [String: Any] {
        return try await executeWithFallback(
            osquery: """
            SELECT interface, address, mask, type, mac 
            FROM interface_addresses 
            JOIN interface_details USING (interface);
            """,
            bash: """
            echo "{"
            echo "  \"interfaces\": ["
            ifconfig -a | grep -E "^[a-z]" | cut -d: -f1 | while read iface; do
                echo "    \"$iface\","
            done | sed '$ s/,$//'
            echo "  ]"
            echo "}"
            """,
            python: """
import json
import subprocess
import socket

def get_network_info():
    info = {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn()
    }
    
    # Get network interfaces
    try:
        result = subprocess.run(['ifconfig', '-a'], capture_output=True, text=True)
        if result.returncode == 0:
            info["ifconfig"] = result.stdout
    except:
        pass
    
    return info

print(json.dumps(get_network_info()))
"""
        )
    }
}

/// Security module processor for collecting security information
public class SecurityModuleProcessor: BaseModuleProcessor, @unchecked Sendable {
    
    public init(configuration: ReportMateConfiguration) {
        super.init(moduleId: "security", configuration: configuration)
    }
    
    public override func collectData() async throws -> ModuleData {
        let securityData = try await collectSecurityInfo()
        return BaseModuleData(moduleId: moduleId, data: securityData)
    }
    
    private func collectSecurityInfo() async throws -> [String: Any] {
        return try await executeWithFallback(
            osquery: """
            SELECT * FROM gatekeeper;
            """,
            bash: """
            echo "{"
            echo "  \"gatekeeper\": \"$(spctl --status 2>&1)\","
            echo "  \"sip\": \"$(csrutil status 2>&1)\","
            echo "  \"filevault\": \"$(fdesetup status 2>&1)\""
            echo "}"
            """,
            python: """
import json
import subprocess

def get_security_info():
    info = {}
    
    # Check Gatekeeper status
    try:
        result = subprocess.run(['spctl', '--status'], capture_output=True, text=True)
        info["gatekeeper"] = result.stdout.strip() if result.returncode == 0 else result.stderr.strip()
    except:
        info["gatekeeper"] = "unknown"
    
    # Check SIP status
    try:
        result = subprocess.run(['csrutil', 'status'], capture_output=True, text=True)
        info["sip"] = result.stdout.strip() if result.returncode == 0 else result.stderr.strip()
    except:
        info["sip"] = "unknown"
    
    # Check FileVault status
    try:
        result = subprocess.run(['fdesetup', 'status'], capture_output=True, text=True)
        info["filevault"] = result.stdout.strip() if result.returncode == 0 else result.stderr.strip()
    except:
        info["filevault"] = "unknown"
    
    return info

print(json.dumps(get_security_info()))
"""
        )
    }
}

/// Applications module processor for collecting application information
public class ApplicationsModuleProcessor: BaseModuleProcessor, @unchecked Sendable {
    
    public init(configuration: ReportMateConfiguration) {
        super.init(moduleId: "applications", configuration: configuration)
    }
    
    public override func collectData() async throws -> ModuleData {
        let appsData = try await collectApplicationsInfo()
        return BaseModuleData(moduleId: moduleId, data: appsData)
    }
    
    private func collectApplicationsInfo() async throws -> [String: Any] {
        return try await executeWithFallback(
            osquery: """
            SELECT name, version, bundle_identifier, path 
            FROM apps;
            """,
            bash: """
            echo "{"
            echo "  \"applications\": ["
            find /Applications -name "*.app" -maxdepth 1 | while read app; do
                echo "    \"$(basename "$app")\","
            done | sed '$ s/,$//'
            echo "  ]"
            echo "}"
            """,
            python: """
import json
import os
import plistlib

def get_applications():
    apps = []
    app_dirs = ["/Applications", "/System/Applications"]
    
    for app_dir in app_dirs:
        if os.path.exists(app_dir):
            for item in os.listdir(app_dir):
                if item.endswith('.app'):
                    app_path = os.path.join(app_dir, item)
                    info_plist_path = os.path.join(app_path, 'Contents', 'Info.plist')
                    
                    app_info = {"name": item, "path": app_path}
                    
                    # Try to read Info.plist
                    try:
                        with open(info_plist_path, 'rb') as f:
                            plist_data = plistlib.load(f)
                            app_info.update({
                                "bundle_id": plist_data.get("CFBundleIdentifier", "unknown"),
                                "version": plist_data.get("CFBundleShortVersionString", "unknown")
                            })
                    except:
                        pass
                    
                    apps.append(app_info)
    
    return {"applications": apps}

print(json.dumps(get_applications()))
"""
        )
    }
}

/// Management module processor for collecting MDM and management information
public class ManagementModuleProcessor: BaseModuleProcessor, @unchecked Sendable {
    
    public init(configuration: ReportMateConfiguration) {
        super.init(moduleId: "management", configuration: configuration)
    }
    
    public override func collectData() async throws -> ModuleData {
        let managementData = try await collectManagementInfo()
        return BaseModuleData(moduleId: moduleId, data: managementData)
    }
    
    private func collectManagementInfo() async throws -> [String: Any] {
        return try await executeWithFallback(
            bash: """
            echo "{"
            echo "  \"profiles\": \"$(profiles -P 2>/dev/null || echo 'No profiles')\","
            echo "  \"mdm\": \"$(profiles status 2>/dev/null || echo 'Unknown')\""
            echo "}"
            """,
            python: """
import json
import subprocess

def get_management_info():
    info = {}
    
    # Check profiles
    try:
        result = subprocess.run(['profiles', '-P'], capture_output=True, text=True)
        info["profiles"] = result.stdout.strip() if result.returncode == 0 else "No profiles"
    except:
        info["profiles"] = "Command not available"
    
    # Check MDM status
    try:
        result = subprocess.run(['profiles', 'status'], capture_output=True, text=True)
        info["mdm_status"] = result.stdout.strip() if result.returncode == 0 else "Unknown"
    except:
        info["mdm_status"] = "Command not available"
    
    return info

print(json.dumps(get_management_info()))
"""
        )
    }
}

/// Inventory module processor for collecting inventory information
public class InventoryModuleProcessor: BaseModuleProcessor, @unchecked Sendable {
    
    public init(configuration: ReportMateConfiguration) {
        super.init(moduleId: "inventory", configuration: configuration)
    }
    
    public override func collectData() async throws -> ModuleData {
        let inventoryData = try await collectInventoryInfo()
        return BaseModuleData(moduleId: moduleId, data: inventoryData)
    }
    
    private func collectInventoryInfo() async throws -> [String: Any] {
        return try await executeWithFallback(
            osquery: """
            SELECT uuid, hardware_serial, computer_name 
            FROM system_info;
            """,
            bash: """
            echo "{"
            echo "  \"serial\": \"$(system_profiler SPHardwareDataType | grep 'Serial Number' | awk '{print $4}')\","
            echo "  \"uuid\": \"$(system_profiler SPHardwareDataType | grep 'Hardware UUID' | awk '{print $3}')\","
            echo "  \"hostname\": \"$(hostname)\""
            echo "}"
            """,
            python: """
import json
import subprocess
import uuid

def get_inventory_info():
    info = {
        "mac_address": hex(uuid.getnode())[2:],
        "python_uuid": str(uuid.uuid4())
    }
    
    # Get hardware info
    try:
        result = subprocess.run(['system_profiler', 'SPHardwareDataType'], 
                               capture_output=True, text=True)
        if result.returncode == 0:
            output = result.stdout
            for line in output.split('\\n'):
                if 'Serial Number' in line:
                    info["serial_number"] = line.split(': ')[-1].strip()
                elif 'Hardware UUID' in line:
                    info["hardware_uuid"] = line.split(': ')[-1].strip()
    except:
        pass
    
    return info

print(json.dumps(get_inventory_info()))
"""
        )
    }
}

// MARK: - Display Module Processor

/// Display module processor for collecting display and graphics information on macOS
public class DisplayModuleProcessor: BaseModuleProcessor, @unchecked Sendable {
    
    public init(configuration: ReportMateConfiguration) {
        super.init(moduleId: "displays", configuration: configuration)
    }
    
    public override func collectData() async throws -> ModuleData {
        let displayData = try await collectDisplayInfo()
        return BaseModuleData(moduleId: moduleId, data: displayData)
    }
    
    private func collectDisplayInfo() async throws -> [String: Any] {
        return try await executeWithFallback(
            osquery: """
            SELECT 
                name, vendor, model, width, height,
                pixels_per_inch, color_space, connection_type,
                display_id, active
            FROM video_info;
            """,
            bash: "system_profiler SPDisplaysDataType -json",
            python: """
import json
import subprocess

def get_display_info():
    info = {
        "displays": [],
        "adapters": []
    }
    
    # Get display information
    try:
        result = subprocess.run(['system_profiler', 'SPDisplaysDataType', '-json'], 
                               capture_output=True, text=True)
        if result.returncode == 0:
            data = json.loads(result.stdout)
            info["system_profiler"] = data
            
            # Parse display data
            if "SPDisplaysDataType" in data:
                for adapter in data["SPDisplaysDataType"]:
                    adapter_info = {
                        "name": adapter.get("spdisplays_device-id", "Unknown"),
                        "vendor": adapter.get("spdisplays_vendor", ""),
                        "model": adapter.get("spdisplays_model", ""),
                        "chipset": adapter.get("spdisplays_chipset_model", ""),
                        "vram": adapter.get("spdisplays_vram_shared", adapter.get("spdisplays_vram", "0 MB")),
                        "bus": adapter.get("spdisplays_bus", "")
                    }
                    info["adapters"].append(adapter_info)
                    
                    # Process connected displays
                    if "spdisplays_displays" in adapter:
                        for display in adapter["spdisplays_displays"]:
                            display_info = {
                                "name": display.get("_spdisplays_display-name", "Unknown Display"),
                                "vendor": display.get("spdisplays_display_vendor", ""),
                                "model": display.get("spdisplays_display-model", ""),
                                "serial": display.get("spdisplays_display_serial_number"),
                                "resolution": display.get("spdisplays_resolution", ""),
                                "connection": display.get("spdisplays_connection_type", ""),
                                "is_main": display.get("spdisplays_main") == "spdisplays_yes",
                                "is_mirrored": display.get("spdisplays_mirror") == "spdisplays_on",
                                "is_retina": display.get("spdisplays_retina") == "Yes",
                                "color_space": display.get("spdisplays_color_space", ""),
                                "color_profile": display.get("spdisplays_color_profile"),
                                "pixels_per_inch": display.get("spdisplays_pixels_per_inch"),
                                "display_size": display.get("spdisplays_display_size")
                            }
                            info["displays"].append(display_info)
                            
    except Exception as e:
        info["error"] = str(e)
    
    return info

print(json.dumps(get_display_info()))
"""
        )
    }
}

// MARK: - Peripherals Module Processor

/// Peripherals module processor for collecting peripheral device information on macOS
public class PeripheralsModuleProcessor: BaseModuleProcessor, @unchecked Sendable {
    
    public init(configuration: ReportMateConfiguration) {
        super.init(moduleId: "peripherals", configuration: configuration)
    }
    
    public override func collectData() async throws -> ModuleData {
        let peripheralsData = try await collectPeripheralsInfo()
        return BaseModuleData(moduleId: moduleId, data: peripheralsData)
    }
    
    private func collectPeripheralsInfo() async throws -> [String: Any] {
        return try await executeWithFallback(
            osquery: """
            SELECT p.name, p.vendor, p.model, p.serial, p.class as device_class,
                   p.usb_address, p.usb_port, p.version, p.removable
            FROM usb_devices p;
            """,
            bash: "system_profiler SPUSBDataType SPAudioDataType SPBluetoothDataType -json",
            python: """
import json
import subprocess
import os

def get_peripherals_info():
    info = {
        "usb_devices": [],
        "input_devices": [],
        "audio_devices": [],
        "bluetooth_devices": [],
        "camera_devices": [],
        "storage_devices": [],
        "thunderbolt_devices": []
    }
    
    # Get USB device information
    try:
        result = subprocess.run(['system_profiler', 'SPUSBDataType', '-json'], 
                               capture_output=True, text=True)
        if result.returncode == 0:
            data = json.loads(result.stdout)
            if "SPUSBDataType" in data:
                for usb_bus in data["SPUSBDataType"]:
                    def parse_usb_devices(devices, parent_name=""):
                        for device in devices:
                            device_info = {
                                "name": device.get("_name", "Unknown Device"),
                                "device_id": device.get("product_id"),
                                "vendor": device.get("manufacturer", ""),
                                "vendor_id": device.get("vendor_id"),
                                "product": device.get("_name", ""),
                                "product_id": device.get("product_id"),
                                "serial_number": device.get("serial_num"),
                                "speed": device.get("speed", ""),
                                "location": device.get("location_id"),
                                "power": device.get("bus_power") or device.get("built_in") or "Unknown",
                                "device_class": device.get("bDeviceClass"),
                                "device_subclass": device.get("bDeviceSubClass"),
                                "device_protocol": device.get("bDeviceProtocol"),
                                "is_apple_device": "Apple" in device.get("manufacturer", ""),
                                "is_external": device.get("removable") == "Yes"
                            }
                            info["usb_devices"].append(device_info)
                            
                            # Recursively parse sub-devices
                            if "_items" in device:
                                parse_usb_devices(device["_items"], device.get("_name", ""))
                    
                    if "_items" in usb_bus:
                        parse_usb_devices(usb_bus["_items"])
                        
    except Exception as e:
        info["usb_error"] = str(e)
    
    # Get Audio device information
    try:
        result = subprocess.run(['system_profiler', 'SPAudioDataType', '-json'], 
                               capture_output=True, text=True)
        if result.returncode == 0:
            data = json.loads(result.stdout)
            if "SPAudioDataType" in data:
                for audio_device in data["SPAudioDataType"]:
                    device_info = {
                        "name": audio_device.get("_name", "Unknown Audio Device"),
                        "device_id": audio_device.get("coreaudio_device_id"),
                        "manufacturer": audio_device.get("coreaudio_device_manufacturer", ""),
                        "model": audio_device.get("_name", ""),
                        "serial_number": audio_device.get("coreaudio_device_srate"),
                        "device_type": audio_device.get("coreaudio_device_transport", ""),
                        "connection_type": audio_device.get("coreaudio_device_transport", ""),
                        "sample_rate": audio_device.get("coreaudio_device_srate"),
                        "bit_depth": audio_device.get("coreaudio_device_format"),
                        "channels": audio_device.get("coreaudio_input_channels") or audio_device.get("coreaudio_output_channels"),
                        "is_default": audio_device.get("coreaudio_default_audio_input_device") == "spaudio_yes" or 
                                     audio_device.get("coreaudio_default_audio_output_device") == "spaudio_yes",
                        "is_built_in": "Built-in" in audio_device.get("_name", "") or "Internal" in audio_device.get("_name", "")
                    }
                    info["audio_devices"].append(device_info)
                    
    except Exception as e:
        info["audio_error"] = str(e)
    
    # Get Bluetooth device information
    try:
        result = subprocess.run(['system_profiler', 'SPBluetoothDataType', '-json'], 
                               capture_output=True, text=True)
        if result.returncode == 0:
            data = json.loads(result.stdout)
            if "SPBluetoothDataType" in data:
                for bt_controller in data["SPBluetoothDataType"]:
                    if "device_title" in bt_controller:
                        # Parse paired devices
                        for device_key, device_info in bt_controller.items():
                            if isinstance(device_info, dict) and "device_minorClassOfDevice" in device_info:
                                bt_device = {
                                    "name": device_info.get("device_title", device_key),
                                    "address": device_info.get("device_address", ""),
                                    "device_class": device_info.get("device_classOfDevice", ""),
                                    "major_device_class": device_info.get("device_majorClassOfDevice", ""),
                                    "minor_device_class": device_info.get("device_minorClassOfDevice", ""),
                                    "manufacturer": device_info.get("device_manufacturer", ""),
                                    "is_connected": device_info.get("device_isconnected") == "attrib_Yes",
                                    "is_paired": True,  # If it's in the list, it's paired
                                    "rssi": device_info.get("device_rssi"),
                                    "battery_level": None,  # May need separate query
                                    "last_connected": None  # May need separate query
                                }
                                info["bluetooth_devices"].append(bt_device)
                                
    except Exception as e:
        info["bluetooth_error"] = str(e)
    
    # Get Camera device information using system_profiler
    try:
        result = subprocess.run(['system_profiler', 'SPCameraDataType', '-json'], 
                               capture_output=True, text=True)
        if result.returncode == 0:
            data = json.loads(result.stdout)
            if "SPCameraDataType" in data:
                for camera in data["SPCameraDataType"]:
                    camera_info = {
                        "name": camera.get("_name", "Unknown Camera"),
                        "device_id": camera.get("spcamera_unique-id"),
                        "manufacturer": camera.get("spcamera_vendor", ""),
                        "model": camera.get("spcamera_model", camera.get("_name", "")),
                        "serial_number": None,
                        "connection_type": camera.get("spcamera_device-id", "Built-in"),
                        "max_resolution": camera.get("spcamera_resolution"),
                        "supported_formats": [],  # Would need additional parsing
                        "is_built_in": "Built-in" in camera.get("_name", ""),
                        "is_default": True,  # Assume first camera is default
                        "is_in_use": False   # Would need lsof or similar to detect
                    }
                    info["camera_devices"].append(camera_info)
                    
    except Exception as e:
        info["camera_error"] = str(e)
    
    # Get external storage information
    try:
        result = subprocess.run(['diskutil', 'list', '-plist', 'external'], 
                               capture_output=True, text=True)
        if result.returncode == 0:
            import plistlib
            plist_data = plistlib.loads(result.stdout.encode())
            if "AllDisks" in plist_data:
                for disk in plist_data["AllDisks"]:
                    disk_info_result = subprocess.run(['diskutil', 'info', '-plist', disk], 
                                                     capture_output=True, text=True)
                    if disk_info_result.returncode == 0:
                        disk_data = plistlib.loads(disk_info_result.stdout.encode())
                        if disk_data.get("External", False):
                            storage_info = {
                                "name": disk_data.get("MediaName", disk),
                                "device_id": disk_data.get("DeviceIdentifier"),
                                "manufacturer": disk_data.get("MediaName", "").split()[0] if disk_data.get("MediaName") else "",
                                "model": disk_data.get("MediaName", ""),
                                "serial_number": None,
                                "capacity": disk_data.get("SizeString", ""),
                                "connection_type": disk_data.get("BusProtocol", "USB"),
                                "file_system": disk_data.get("FilesystemType"),
                                "mount_point": disk_data.get("MountPoint"),
                                "is_removable": disk_data.get("Removable", True),
                                "is_encrypted": disk_data.get("Encrypted", False),
                                "is_mounted": disk_data.get("Mounted", False),
                                "disk_type": "SSD" if "SSD" in disk_data.get("MediaName", "") else 
                                           "USB Flash" if "USB" in disk_data.get("MediaName", "") else "HDD"
                            }
                            info["storage_devices"].append(storage_info)
                            
    except Exception as e:
        info["storage_error"] = str(e)
    
    # Get Thunderbolt device information
    try:
        result = subprocess.run(['system_profiler', 'SPThunderboltDataType', '-json'], 
                               capture_output=True, text=True)
        if result.returncode == 0:
            data = json.loads(result.stdout)
            if "SPThunderboltDataType" in data:
                for tb_controller in data["SPThunderboltDataType"]:
                    if "_items" in tb_controller:
                        for device in tb_controller["_items"]:
                            tb_device = {
                                "name": device.get("_name", "Unknown Thunderbolt Device"),
                                "device_id": device.get("device_name"),
                                "vendor": device.get("vendor_name", ""),
                                "device_type": device.get("domain_uuid", ""),
                                "port": device.get("port", ""),
                                "link_speed": device.get("link_speed"),
                                "link_width": device.get("link_width"),
                                "is_active": device.get("status") == "active",
                                "firmware_version": device.get("firmware_version")
                            }
                            info["thunderbolt_devices"].append(tb_device)
                            
    except Exception as e:
        info["thunderbolt_error"] = str(e)
    
    # Get input devices using ioreg
    try:
        result = subprocess.run(['ioreg', '-p', 'IOUSB', '-w', '0'], 
                               capture_output=True, text=True)
        if result.returncode == 0:
            lines = result.stdout.split('\\n')
            current_device = {}
            
            for line in lines:
                if '"Product Name"' in line and '=' in line:
                    name = line.split('=')[1].strip().strip('"')
                    current_device['name'] = name
                elif '"Vendor Name"' in line and '=' in line:
                    vendor = line.split('=')[1].strip().strip('"')
                    current_device['vendor'] = vendor
                elif '"Serial Number"' in line and '=' in line:
                    serial = line.split('=')[1].strip().strip('"')
                    current_device['serial_number'] = serial
                
                # Check if this is an input device
                if any(keyword in line.lower() for keyword in ['mouse', 'keyboard', 'trackpad', 'tablet']) and current_device:
                    input_device = {
                        "name": current_device.get('name', 'Unknown Input Device'),
                        "device_id": None,
                        "vendor": current_device.get('vendor', ''),
                        "product": current_device.get('name', ''),
                        "serial_number": current_device.get('serial_number'),
                        "device_type": "Mouse" if "mouse" in line.lower() else
                                      "Keyboard" if "keyboard" in line.lower() else
                                      "Trackpad" if "trackpad" in line.lower() else
                                      "Tablet" if "tablet" in line.lower() else "Unknown",
                        "connection_type": "USB",
                        "is_apple_device": "Apple" in current_device.get('vendor', ''),
                        "is_built_in": "Built-in" in current_device.get('name', ''),
                        "is_wireless": False,
                        "battery_level": None
                    }
                    info["input_devices"].append(input_device)
                    current_device = {}
                    
    except Exception as e:
        info["input_error"] = str(e)
    
    return info

print(json.dumps(get_peripherals_info()))
"""
        )
    }
}

// MARK: - Printer Module Processor

/// Printer module processor for collecting printer and print system information on macOS
public class PrinterModuleProcessor: BaseModuleProcessor, @unchecked Sendable {
    
    public init(configuration: ReportMateConfiguration) {
        super.init(moduleId: "printers", configuration: configuration)
    }
    
    public override func collectData() async throws -> ModuleData {
        let printerData = try await collectPrinterInfo()
        return BaseModuleData(moduleId: moduleId, data: printerData)
    }
    
    private func collectPrinterInfo() async throws -> [String: Any] {
        return try await executeWithFallback(
            osquery: """
            SELECT name, description, default_flag, shared_flag,
                   network_flag, status, state, accepting_jobs,
                   job_count, device_uri, location
            FROM cups_destinations;
            """,
            bash: "lpstat -a && lpstat -v && lpstat -p",
            python: """
import json
import subprocess
import os
import datetime
import glob

def get_printer_info():
    info = {
        "printers": [],
        "print_queues": [],
        "print_jobs": [],
        "print_drivers": [],
        "cups_info": {},
        "airprint_services": []
    }
    
    # Get printer information using lpstat and lpoptions
    try:
        # Get all printers and their basic info
        lpstat_result = subprocess.run(['lpstat', '-a'], capture_output=True, text=True)
        if lpstat_result.returncode == 0:
            for line in lpstat_result.stdout.strip().split('\\n'):
                if line and 'accepting requests' in line:
                    parts = line.split()
                    if parts:
                        printer_name = parts[0]
                        is_accepting = 'accepting requests' in line
                        
                        # Get detailed printer information
                        lpoptions_result = subprocess.run(['lpoptions', '-p', printer_name], 
                                                         capture_output=True, text=True)
                        printer_options = {}
                        if lpoptions_result.returncode == 0:
                            # Parse printer options
                            for option_line in lpoptions_result.stdout.strip().split('\\n'):
                                if '=' in option_line:
                                    key, value = option_line.split('=', 1)
                                    printer_options[key.strip()] = value.strip()
                        
                        # Get printer device URI
                        lpstat_v_result = subprocess.run(['lpstat', '-v', printer_name], 
                                                        capture_output=True, text=True)
                        device_uri = ""
                        if lpstat_v_result.returncode == 0:
                            uri_line = lpstat_v_result.stdout.strip()
                            if 'device for' in uri_line:
                                device_uri = uri_line.split(': ')[-1] if ': ' in uri_line else ""
                        
                        # Get printer status and state
                        lpstat_p_result = subprocess.run(['lpstat', '-p', printer_name], 
                                                        capture_output=True, text=True)
                        status = ""
                        state = ""
                        if lpstat_p_result.returncode == 0:
                            status_line = lpstat_p_result.stdout.strip()
                            if 'is idle' in status_line:
                                state = 'idle'
                                status = 'Ready'
                            elif 'is printing' in status_line:
                                state = 'processing'
                                status = 'Printing'
                            elif 'disabled' in status_line:
                                state = 'stopped'
                                status = 'Disabled'
                        
                        # Check if this is the default printer
                        default_result = subprocess.run(['lpstat', '-d'], capture_output=True, text=True)
                        is_default = False
                        if default_result.returncode == 0:
                            is_default = printer_name in default_result.stdout
                        
                        # Determine connection type from device URI
                        connection_type = "Unknown"
                        if device_uri:
                            if device_uri.startswith("usb://"):
                                connection_type = "USB"
                            elif device_uri.startswith("ipp://") or device_uri.startswith("ipps://"):
                                connection_type = "IPP/Network"
                            elif device_uri.startswith("lpd://"):
                                connection_type = "LPD/Network"
                            elif device_uri.startswith("socket://"):
                                connection_type = "Socket/Network"
                            elif "airprint" in device_uri.lower():
                                connection_type = "AirPrint"
                        
                        printer_info = {
                            "name": printer_name,
                            "display_name": printer_options.get("printer-info", printer_name),
                            "location": printer_options.get("printer-location", ""),
                            "description": printer_options.get("printer-info", ""),
                            "make": printer_options.get("printer-make-and-model", "").split()[0] if printer_options.get("printer-make-and-model") else "",
                            "model": printer_options.get("printer-make-and-model", ""),
                            "device_uri": device_uri,
                            "driver_name": printer_options.get("printer-make-and-model", ""),
                            "ppd": None,  # Would need to check /etc/cups/ppd/ folder
                            "status": status,
                            "state": state,
                            "state_message": "",
                            "state_reasons": [],
                            "is_default": is_default,
                            "is_shared": printer_options.get("printer-is-shared", "false") == "true",
                            "is_accepting_jobs": is_accepting,
                            "job_count": 0,  # Will be populated later
                            "connection_type": connection_type,
                            "ip_address": None,
                            "mac_address": None,
                            "serial": None,
                            "firmware": None,
                            "supported_media_types": [],
                            "supported_resolutions": [],
                            "color_capable": "ColorModel" in printer_options,
                            "duplex_capable": "Duplex" in printer_options,
                            "cups_version": None
                        }
                        info["printers"].append(printer_info)
                        
    except Exception as e:
        info["printer_error"] = str(e)
    
    # Get print jobs
    try:
        lpq_result = subprocess.run(['lpstat', '-o'], capture_output=True, text=True)
        if lpq_result.returncode == 0:
            for line in lpq_result.stdout.strip().split('\\n'):
                if line and '-' in line:
                    # Parse job line: "printer-jobid user size date time"
                    parts = line.split()
                    if len(parts) >= 5:
                        job_printer = parts[0].split('-')[0]
                        job_id = parts[0].split('-')[1] if '-' in parts[0] else "0"
                        job_user = parts[1]
                        job_size = parts[2] if parts[2].isdigit() else 0
                        
                        job_info = {
                            "id": int(job_id) if job_id.isdigit() else 0,
                            "name": "Print Job",
                            "user": job_user,
                            "printer": job_printer,
                            "status": "pending",
                            "priority": 50,
                            "size": int(job_size) if str(job_size).isdigit() else 0,
                            "pages": 1,
                            "completed_pages": 0,
                            "submission_time": datetime.datetime.now().isoformat(),
                            "process_time": None,
                            "completion_time": None,
                            "format": "unknown"
                        }
                        info["print_jobs"].append(job_info)
                        
                        # Update job count for printer
                        for printer in info["printers"]:
                            if printer["name"] == job_printer:
                                printer["job_count"] += 1
                                break
                        
    except Exception as e:
        info["job_error"] = str(e)
    
    # Get CUPS system information
    try:
        # Get CUPS version
        cups_config_result = subprocess.run(['cups-config', '--version'], 
                                          capture_output=True, text=True)
        cups_version = ""
        if cups_config_result.returncode == 0:
            cups_version = cups_config_result.stdout.strip()
        
        # Check if CUPS daemon is running
        ps_result = subprocess.run(['pgrep', 'cupsd'], capture_output=True, text=True)
        is_running = ps_result.returncode == 0
        
        cups_info = {
            "version": cups_version,
            "server_name": "localhost",
            "server_version": cups_version,
            "is_running": is_running,
            "config_file": "/etc/cups/cupsd.conf",
            "log_file": "/var/log/cups/error_log",
            "error_log_file": "/var/log/cups/error_log",
            "access_log_file": "/var/log/cups/access_log",
            "page_log_file": "/var/log/cups/page_log",
            "server_root": "/etc/cups",
            "data_dir": "/usr/share/cups",
            "document_root": "/usr/share/doc/cups",
            "request_root": "/var/spool/cups",
            "temp_dir": "/var/spool/cups/tmp",
            "max_jobs": 500,
            "max_jobs_per_user": 0,
            "max_jobs_per_printer": 0,
            "job_retry_limit": 5,
            "job_retry_interval": 300
        }
        info["cups_info"] = cups_info
        
    except Exception as e:
        info["cups_error"] = str(e)
    
    # Look for print drivers
    try:
        ppd_files = glob.glob("/usr/share/cups/model/*.ppd")
        ppd_files.extend(glob.glob("/etc/cups/ppd/*.ppd"))
        ppd_files.extend(glob.glob("/usr/share/ppd/**/*.ppd", recursive=True))
        
        for ppd_file in ppd_files[:20]:  # Limit to first 20 to avoid too much data
            try:
                with open(ppd_file, 'r', encoding='utf-8', errors='ignore') as f:
                    ppd_content = f.read(2000)  # Read first 2000 chars
                    
                driver_info = {
                    "name": os.path.basename(ppd_file),
                    "version": "",
                    "vendor": "",
                    "model_supported": "",
                    "language": "PostScript" if "postscript" in ppd_content.lower() else "PCL",
                    "ppd_file": ppd_file,
                    "filter_path": None,
                    "install_date": None,
                    "is_system_driver": "/usr/share" in ppd_file,
                    "supported_features": []
                }
                
                # Extract some basic info from PPD
                for line in ppd_content.split('\\n')[:50]:  # First 50 lines
                    if line.startswith('*Manufacturer:'):
                        driver_info["vendor"] = line.split(':', 1)[1].strip().strip('"')
                    elif line.startswith('*ModelName:'):
                        driver_info["model_supported"] = line.split(':', 1)[1].strip().strip('"')
                    elif line.startswith('*LanguageLevel:'):
                        driver_info["language"] = f"PostScript Level {line.split(':', 1)[1].strip()}"
                
                info["print_drivers"].append(driver_info)
                
            except Exception:
                continue  # Skip files that can't be read
                
    except Exception as e:
        info["driver_error"] = str(e)
    
    # Try to discover AirPrint services using dns-sd (if available)
    try:
        dns_sd_result = subprocess.run(['dns-sd', '-B', '_ipp._tcp'], 
                                      capture_output=True, text=True, timeout=5)
        # This would require parsing DNS-SD output which is complex
        # For now, just note that we attempted discovery
        info["airprint_discovery_attempted"] = True
        
    except Exception as e:
        info["airprint_error"] = str(e)
    
    return info

print(json.dumps(get_printer_info()))
"""
        )
    }
}

// MARK: - Installs Module Processor

/// Installs module processor for collecting software installation and package management information on macOS
public class InstallsModuleProcessor: BaseModuleProcessor, @unchecked Sendable {
    
    public init(configuration: ReportMateConfiguration) {
        super.init(moduleId: "installs", configuration: configuration)
    }
    
    public override func collectData() async throws -> ModuleData {
        let installsData = try await collectInstallsInfo()
        return BaseModuleData(moduleId: moduleId, data: installsData)
    }
    
    private func collectInstallsInfo() async throws -> [String: Any] {
        return try await executeWithFallback(
            osquery: """
            SELECT name, version, bundle_identifier, path, 
                   bundle_version, minimum_system_version, 
                   category, copyright, development_region,
                   bundle_executable, info_string, last_opened_time
            FROM apps;
            """,
            bash: "system_profiler SPApplicationsDataType -json && brew list --versions 2>/dev/null",
            python: """
import json
import subprocess
import os
import datetime
import glob
import plistlib

def get_installs_info():
    info = {
        "homebrew_info": {},
        "macports_info": {},
        "applications": [],
        "system_packages": [],
        "recent_installs": [],
        "package_managers": []
    }
    
    # Get Homebrew information
    try:
        # Check if brew is installed
        brew_check = subprocess.run(['which', 'brew'], capture_output=True, text=True)
        if brew_check.returncode == 0:
            # Get brew version and info
            brew_version = subprocess.run(['brew', '--version'], capture_output=True, text=True)
            version_info = ""
            if brew_version.returncode == 0:
                version_info = brew_version.stdout.strip().split('\\n')[0].replace('Homebrew ', '')
            
            # Get brew prefix
            brew_prefix = subprocess.run(['brew', '--prefix'], capture_output=True, text=True)
            prefix = brew_prefix.stdout.strip() if brew_prefix.returncode == 0 else "/usr/local"
            
            # Get installed formulae
            formulae_list = []
            brew_list = subprocess.run(['brew', 'list', '--versions'], capture_output=True, text=True)
            if brew_list.returncode == 0:
                for line in brew_list.stdout.strip().split('\\n'):
                    if line:
                        parts = line.split(' ', 1)
                        if len(parts) >= 2:
                            formulae_info = {
                                "name": parts[0],
                                "version": parts[1],
                                "installed_version": parts[1],
                                "description": "",
                                "homepage": "",
                                "available_version": parts[1],
                                "is_outdated": False,
                                "install_date": None,
                                "dependencies": [],
                                "size": ""
                            }
                            formulae_list.append(formulae_info)
            
            # Get installed casks
            casks_list = []
            brew_cask_list = subprocess.run(['brew', 'list', '--cask', '--versions'], 
                                          capture_output=True, text=True)
            if brew_cask_list.returncode == 0:
                for line in brew_cask_list.stdout.strip().split('\\n'):
                    if line:
                        parts = line.split(' ', 1)
                        if len(parts) >= 2:
                            cask_info = {
                                "name": parts[0],
                                "version": parts[1],
                                "description": "",
                                "homepage": "",
                                "app_name": parts[0],
                                "artifact_path": "",
                                "install_date": None,
                                "size": ""
                            }
                            casks_list.append(cask_info)
            
            # Get tap repositories
            brew_taps = subprocess.run(['brew', 'tap'], capture_output=True, text=True)
            taps = brew_taps.stdout.strip().split('\\n') if brew_taps.returncode == 0 else []
            
            homebrew_info = {
                "is_installed": True,
                "version": version_info,
                "prefix": prefix,
                "repository": "",
                "last_updated": None,
                "total_packages": len(formulae_list),
                "outdated_packages": 0,
                "cask_packages": len(casks_list),
                "tap_repositories": [tap for tap in taps if tap],
                "installed_formulae": formulae_list,
                "installed_casks": casks_list
            }
            info["homebrew_info"] = homebrew_info
            
            # Add to package managers list
            info["package_managers"].append({
                "name": "Homebrew",
                "version": version_info,
                "path": prefix + "/bin/brew",
                "is_active": True,
                "last_used": None,
                "total_packages": len(formulae_list) + len(casks_list),
                "config_file": os.path.expanduser("~/.brewfile")
            })
            
    except Exception as e:
        info["homebrew_error"] = str(e)
    
    # Get MacPorts information
    try:
        # Check if port is installed
        port_check = subprocess.run(['which', 'port'], capture_output=True, text=True)
        if port_check.returncode == 0:
            # Get port version
            port_version = subprocess.run(['port', 'version'], capture_output=True, text=True)
            version_info = ""
            if port_version.returncode == 0:
                version_line = port_version.stdout.strip().split('\\n')[0]
                if 'Version' in version_line:
                    version_info = version_line.split('Version')[1].strip()
            
            # Get installed ports
            ports_list = []
            port_installed = subprocess.run(['port', 'installed'], capture_output=True, text=True)
            if port_installed.returncode == 0:
                lines = port_installed.stdout.strip().split('\\n')[1:]  # Skip header
                for line in lines:
                    if line and '@' in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            name = parts[0]
                            version_part = parts[1] if parts[1].startswith('@') else '@unknown'
                            version = version_part[1:]  # Remove @
                            
                            port_info = {
                                "name": name,
                                "version": version,
                                "revision": "",
                                "variants": [],
                                "description": "",
                                "homepage": "",
                                "is_active": "(active)" in line,
                                "is_outdated": False,
                                "install_date": None,
                                "dependencies": []
                            }
                            ports_list.append(port_info)
            
            macports_info = {
                "is_installed": True,
                "version": version_info,
                "prefix": "/opt/local",
                "last_synced": None,
                "total_ports": len(ports_list),
                "outdated_ports": 0,
                "active_ports": sum(1 for p in ports_list if p["is_active"]),
                "installed_ports": ports_list
            }
            info["macports_info"] = macports_info
            
            # Add to package managers list
            info["package_managers"].append({
                "name": "MacPorts",
                "version": version_info,
                "path": "/opt/local/bin/port",
                "is_active": True,
                "last_used": None,
                "total_packages": len(ports_list),
                "config_file": "/opt/local/etc/macports/macports.conf"
            })
            
    except Exception as e:
        info["macports_error"] = str(e)
    
    # Get installed applications using system_profiler
    try:
        apps_result = subprocess.run(['system_profiler', 'SPApplicationsDataType', '-json'], 
                                   capture_output=True, text=True)
        if apps_result.returncode == 0:
            data = json.loads(apps_result.stdout)
            if "SPApplicationsDataType" in data:
                for app in data["SPApplicationsDataType"]:
                    app_info = {
                        "name": app.get("_name", "Unknown"),
                        "display_name": app.get("_name", "Unknown"),
                        "bundle_identifier": app.get("info", ""),
                        "version": app.get("version", ""),
                        "build_version": app.get("version", ""),
                        "path": app.get("path", ""),
                        "size": 0,  # Would need separate calculation
                        "install_date": None,
                        "last_modified": app.get("lastModified"),
                        "developer": app.get("info", ""),
                        "category": app.get("kind", ""),
                        "is_system_app": "/System/" in app.get("path", "") or "/Library/" in app.get("path", ""),
                        "is_mac_app_store": False,  # Would need separate check
                        "copyright": "",
                        "minimum_system_version": "",
                        "architectures": [],
                        "code_signature": None
                    }
                    
                    # Try to get more detailed info from bundle plist
                    if app.get("path"):
                        plist_path = os.path.join(app["path"], "Contents", "Info.plist")
                        try:
                            if os.path.exists(plist_path):
                                with open(plist_path, 'rb') as f:
                                    plist_data = plistlib.load(f)
                                    app_info["bundle_identifier"] = plist_data.get("CFBundleIdentifier", "")
                                    app_info["version"] = plist_data.get("CFBundleShortVersionString", app_info["version"])
                                    app_info["build_version"] = plist_data.get("CFBundleVersion", "")
                                    app_info["minimum_system_version"] = plist_data.get("LSMinimumSystemVersion", "")
                                    app_info["copyright"] = plist_data.get("NSHumanReadableCopyright", "")
                        except Exception:
                            pass  # Skip if we can't read plist
                    
                    info["applications"].append(app_info)
                    
    except Exception as e:
        info["applications_error"] = str(e)
    
    # Get system packages from receipts
    try:
        receipts_path = "/var/db/receipts"
        if os.path.exists(receipts_path):
            receipt_files = glob.glob(os.path.join(receipts_path, "*.plist"))
            for receipt_file in receipt_files[:50]:  # Limit to first 50
                try:
                    with open(receipt_file, 'rb') as f:
                        receipt_data = plistlib.load(f)
                        
                    package_info = {
                        "name": receipt_data.get("PackageFileName", os.path.basename(receipt_file)),
                        "version": receipt_data.get("PackageVersion", ""),
                        "identifier": receipt_data.get("PackageIdentifier", ""),
                        "path": receipt_data.get("InstallPrefixPath", ""),
                        "package_type": "PKG",
                        "install_date": receipt_data.get("InstallDate"),
                        "size": receipt_data.get("PackageSize", 0),
                        "receipt": receipt_file,
                        "is_apple": "com.apple." in receipt_data.get("PackageIdentifier", "")
                    }
                    info["system_packages"].append(package_info)
                    
                except Exception:
                    continue  # Skip receipts we can't read
                    
    except Exception as e:
        info["receipts_error"] = str(e)
    
    # Try to find recent install activity from logs (simplified)
    try:
        # Check installer log for recent activity
        installer_log = "/var/log/install.log"
        if os.path.exists(installer_log):
            # Get last 100 lines from installer log
            tail_result = subprocess.run(['tail', '-n', '100', installer_log], 
                                       capture_output=True, text=True)
            if tail_result.returncode == 0:
                recent_count = 0
                for line in tail_result.stdout.split('\\n'):
                    if 'INSTALL' in line or 'PKG' in line or 'installer' in line.lower():
                        recent_count += 1
                        if recent_count <= 10:  # Limit to 10 recent items
                            recent_install = {
                                "name": "Recent Installation",
                                "version": "",
                                "install_date": datetime.datetime.now().isoformat(),
                                "source": "System Installer",
                                "installer": "installer",
                                "status": "Success",
                                "size": 0
                            }
                            info["recent_installs"].append(recent_install)
                            
    except Exception as e:
        info["recent_installs_error"] = str(e)
    
    return info

print(json.dumps(get_installs_info()))
"""
        )
    }
}

// MARK: - Profiles Module Processor

/// Profiles module processor for collecting configuration profiles and system policy information on macOS
public class ProfilesModuleProcessor: BaseModuleProcessor, @unchecked Sendable {
    
    public init(configuration: ReportMateConfiguration) {
        super.init(moduleId: "profiles", configuration: configuration)
    }
    
    public override func collectData() async throws -> ModuleData {
        let profilesData = try await collectProfilesInfo()
        return BaseModuleData(moduleId: moduleId, data: profilesData)
    }
    
    private func collectProfilesInfo() async throws -> [String: Any] {
        return try await executeWithFallback(
            osquery: """
            SELECT identifier, display_name, organization, description,
                   install_date, payload_count, removal_allowed,
                   verification_state, profile_path
            FROM configuration_profiles;
            """,
            bash: "profiles -P && profiles -C",
            python: """
import json
import subprocess
import os
import datetime
import plistlib

def get_profiles_info():
    info = {
        "configuration_profiles": [],
        "system_preferences": [],
        "mdm_policies": [],
        "security_policies": [],
        "restriction_policies": [],
        "payload_types": []
    }
    
    # Get configuration profiles using profiles command
    try:
        # Get system profiles (requires admin)
        system_profiles_result = subprocess.run(['profiles', '-P'], 
                                               capture_output=True, text=True)
        if system_profiles_result.returncode == 0:
            lines = system_profiles_result.stdout.strip().split('\\n')
            current_profile = None
            
            for line in lines:
                line = line.strip()
                if line.startswith('_computerlevel['):
                    # Parse computer level profiles
                    if ']' in line:
                        profile_num = line.split('[')[1].split(']')[0]
                        current_profile = {
                            "identifier": "",
                            "uuid": "",
                            "display_name": "",
                            "description": "",
                            "organization": "",
                            "version": 1,
                            "payload_type": "Configuration",
                            "payload_version": 1,
                            "install_date": None,
                            "last_modified": None,
                            "is_system": True,
                            "is_user": False,
                            "is_removal_allowed": True,
                            "is_managed": True,
                            "source": "MDM",
                            "scope": "System",
                            "payloads": [],
                            "verification_state": "unsigned",
                            "has_removal_passcode": False
                        }
                elif line and current_profile and ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    if key == "attribute: name":
                        current_profile["display_name"] = value
                    elif key == "attribute: profileIdentifier":
                        current_profile["identifier"] = value
                    elif key == "attribute: organization":
                        current_profile["organization"] = value
                    elif key == "attribute: profileDescription":
                        current_profile["description"] = value
                    elif key == "attribute: profileUUID":
                        current_profile["uuid"] = value
                    elif key == "attribute: installDate":
                        current_profile["install_date"] = value
                    elif key == "attribute: profileRemovalDisallowed":
                        current_profile["is_removal_allowed"] = value.lower() != "true"
                    elif key == "attribute: profileVerificationState":
                        current_profile["verification_state"] = value
                    
                if current_profile and (line == "" or "computerlevel[" in line):
                    if current_profile["identifier"]:  # Only add if we have an identifier
                        info["configuration_profiles"].append(current_profile)
                    current_profile = None
        
        # Get user profiles
        user_profiles_result = subprocess.run(['profiles', '-P', '-U'], 
                                            capture_output=True, text=True)
        if user_profiles_result.returncode == 0:
            # Similar parsing for user profiles
            lines = user_profiles_result.stdout.strip().split('\\n')
            current_profile = None
            
            for line in lines:
                line = line.strip()
                if line.startswith('_userlevel['):
                    if ']' in line:
                        profile_num = line.split('[')[1].split(']')[0]
                        current_profile = {
                            "identifier": "",
                            "uuid": "",
                            "display_name": "",
                            "description": "",
                            "organization": "",
                            "version": 1,
                            "payload_type": "Configuration",
                            "payload_version": 1,
                            "install_date": None,
                            "last_modified": None,
                            "is_system": False,
                            "is_user": True,
                            "is_removal_allowed": True,
                            "is_managed": False,
                            "source": "Manual",
                            "scope": "User",
                            "payloads": [],
                            "verification_state": "unsigned",
                            "has_removal_passcode": False
                        }
                elif line and current_profile and ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    if key == "attribute: name":
                        current_profile["display_name"] = value
                    elif key == "attribute: profileIdentifier":
                        current_profile["identifier"] = value
                    elif key == "attribute: organization":
                        current_profile["organization"] = value
                    elif key == "attribute: profileDescription":
                        current_profile["description"] = value
                    elif key == "attribute: profileUUID":
                        current_profile["uuid"] = value
                
                if current_profile and (line == "" or "_userlevel[" in line):
                    if current_profile["identifier"]:  # Only add if we have an identifier
                        info["configuration_profiles"].append(current_profile)
                    current_profile = None
                    
    except Exception as e:
        info["profiles_error"] = str(e)
    
    # Get system preferences using defaults command
    try:
        # Get some common system preferences
        common_domains = [
            "NSGlobalDomain", 
            "com.apple.dock",
            "com.apple.finder", 
            "com.apple.screensaver",
            "com.apple.TimeMachine",
            "com.apple.loginwindow",
            "com.apple.security"
        ]
        
        for domain in common_domains:
            try:
                defaults_result = subprocess.run(['defaults', 'read', domain], 
                                               capture_output=True, text=True)
                if defaults_result.returncode == 0:
                    # Parse defaults output (simplified)
                    for line in defaults_result.stdout.split('\\n')[:20]:  # Limit output
                        if '=' in line:
                            key_value = line.split('=', 1)
                            if len(key_value) == 2:
                                key = key_value[0].strip()
                                value = key_value[1].strip().rstrip(';').strip('"')
                                
                                pref_info = {
                                    "domain": domain,
                                    "key": key,
                                    "value": value,
                                    "type": "string",
                                    "scope": "System",
                                    "is_managed": False,
                                    "source": "defaults",
                                    "category": "System Preference",
                                    "last_modified": None
                                }
                                info["system_preferences"].append(pref_info)
            except Exception:
                continue  # Skip domains we can't read
                
    except Exception as e:
        info["preferences_error"] = str(e)
    
    # Get security policies
    try:
        security_info = []
        
        # Check FileVault status
        try:
            fv_result = subprocess.run(['fdesetup', 'status'], capture_output=True, text=True)
            if fv_result.returncode == 0:
                fv_status = "enabled" if "On" in fv_result.stdout else "disabled"
                security_info.append({
                    "policy_name": "FileVault",
                    "policy_area": "Disk Encryption",
                    "setting": "FileVaultStatus",
                    "value": fv_status,
                    "source": "system",
                    "last_applied": None,
                    "compliance_status": "compliant" if fv_status == "enabled" else "non-compliant",
                    "severity": "high",
                    "details": {"status": fv_status}
                })
        except Exception:
            pass
        
        # Check System Integrity Protection (SIP)
        try:
            sip_result = subprocess.run(['csrutil', 'status'], capture_output=True, text=True)
            if sip_result.returncode == 0:
                sip_status = "enabled" if "enabled" in sip_result.stdout else "disabled"
                security_info.append({
                    "policy_name": "System Integrity Protection",
                    "policy_area": "System Security",
                    "setting": "SIPStatus",
                    "value": sip_status,
                    "source": "system",
                    "last_applied": None,
                    "compliance_status": "compliant" if sip_status == "enabled" else "non-compliant",
                    "severity": "critical",
                    "details": {"status": sip_status}
                })
        except Exception:
            pass
        
        # Check Gatekeeper status
        try:
            gk_result = subprocess.run(['spctl', '--status'], capture_output=True, text=True)
            if gk_result.returncode == 0:
                gk_status = "enabled" if "enabled" in gk_result.stdout else "disabled"
                security_info.append({
                    "policy_name": "Gatekeeper",
                    "policy_area": "Application Security",
                    "setting": "GatekeeperStatus",
                    "value": gk_status,
                    "source": "system",
                    "last_applied": None,
                    "compliance_status": "compliant" if gk_status == "enabled" else "non-compliant",
                    "severity": "high",
                    "details": {"status": gk_status}
                })
        except Exception:
            pass
        
        # Check firewall status
        try:
            fw_result = subprocess.run(['defaults', 'read', '/Library/Preferences/com.apple.alf', 'globalstate'], 
                                     capture_output=True, text=True)
            if fw_result.returncode == 0:
                fw_status = "enabled" if fw_result.stdout.strip() != "0" else "disabled"
                security_info.append({
                    "policy_name": "Application Firewall",
                    "policy_area": "Network Security",
                    "setting": "FirewallStatus",
                    "value": fw_status,
                    "source": "system",
                    "last_applied": None,
                    "compliance_status": "compliant" if fw_status == "enabled" else "non-compliant",
                    "severity": "medium",
                    "details": {"status": fw_status}
                })
        except Exception:
            pass
        
        info["security_policies"] = security_info
        
    except Exception as e:
        info["security_error"] = str(e)
    
    # Get MDM enrollment status
    try:
        mdm_policies = []
        
        # Check if device is enrolled in MDM
        mdm_result = subprocess.run(['profiles', 'status'], capture_output=True, text=True)
        if mdm_result.returncode == 0:
            if "enrolled" in mdm_result.stdout.lower():
                mdm_policy = {
                    "policy_id": "mdm-enrollment",
                    "policy_name": "MDM Enrollment",
                    "policy_type": "Device Management",
                    "platform": "macOS",
                    "assigned_date": None,
                    "last_sync": None,
                    "status": "enrolled",
                    "enforcement_state": "active",
                    "settings": [],
                    "configuration": {"enrollment_status": "enrolled"}
                }
                mdm_policies.append(mdm_policy)
        
        info["mdm_policies"] = mdm_policies
        
    except Exception as e:
        info["mdm_error"] = str(e)
    
    # Add common payload types for reference
    payload_types = [
        {
            "type": "com.apple.wifi.managed",
            "display_name": "Wi-Fi",
            "description": "Configures Wi-Fi settings",
            "is_supported": True,
            "version": "1.0",
            "category": "Network",
            "required_keys": ["SSID"],
            "optional_keys": ["Password", "Security"]
        },
        {
            "type": "com.apple.security.pkcs12",
            "display_name": "PKCS#12 Certificate",
            "description": "Installs a PKCS#12 certificate",
            "is_supported": True,
            "version": "1.0",
            "category": "Security",
            "required_keys": ["PayloadContent"],
            "optional_keys": ["Password"]
        },
        {
            "type": "com.apple.applicationaccess",
            "display_name": "Application Restrictions",
            "description": "Restricts access to applications",
            "is_supported": True,
            "version": "1.0",
            "category": "Restrictions",
            "required_keys": [],
            "optional_keys": ["allowCamera", "allowScreenShot"]
        }
    ]
    info["payload_types"] = payload_types
    
    return info

print(json.dumps(get_profiles_info()))
"""
        )
    }
}