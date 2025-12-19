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
        
        var hardwareData: [String: Any] = [:]
        
        // Collect system information (osquery: system_info + bash fallback)
        print("  [1/7] Collecting system information...")
        hardwareData["system"] = try await collectSystemInfo()
        
        // Collect processor information (osquery: system_info + bash sysctl)
        print("  [2/7] Collecting processor information...")
        hardwareData["processor"] = try await collectProcessorInfo()
        
        // Collect memory information (osquery: memory_devices, virtual_memory_info + bash)
        print("  [3/7] Collecting memory information...")
        hardwareData["memory"] = try await collectMemoryInfo()
        
        // Collect storage information (osquery: mounts + bash diskutil)
        print("  [4/7] Collecting storage information...")
        hardwareData["storage"] = try await collectStorageInfo()
        
        // Collect graphics information (bash: system_profiler)
        print("  [5/7] Collecting graphics information...")
        hardwareData["graphics"] = try await collectGraphicsInfo()
        
        // Collect battery information (osquery: battery + bash pmset)
        print("  [6/7] Collecting battery information...")
        hardwareData["battery"] = try await collectBatteryInfo()
        
        // Collect thermal information (bash: pmset)
        print("  [7/7] Collecting thermal information...")
        hardwareData["thermal"] = try await collectThermalInfo()
        
        // Collect NPU information (bash: sysctl for Apple Silicon detection)
        if let npuInfo = try await collectNPUInfo() {
            hardwareData["npu"] = npuInfo
        }
        
        print("Hardware collection completed successfully")
        return hardwareData
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
        
        // bash fallback using system_profiler
        let bashScript = """
            sp_json=$(system_profiler SPHardwareDataType -json 2>/dev/null)
            if [ -n "$sp_json" ]; then
                model_name=$(echo "$sp_json" | grep -o '"machine_name"[^,]*' | cut -d'"' -f4)
                model_id=$(echo "$sp_json" | grep -o '"machine_model"[^,]*' | cut -d'"' -f4)
                serial=$(echo "$sp_json" | grep -o '"serial_number"[^,]*' | cut -d'"' -f4)
                hw_uuid=$(echo "$sp_json" | grep -o '"platform_UUID"[^,]*' | cut -d'"' -f4)
                chip=$(echo "$sp_json" | grep -o '"chip_type"[^,]*' | cut -d'"' -f4)
            fi
            
            echo "{"
            echo "  \\"hostname\\": \\"$(hostname -s)\\","
            echo "  \\"hardware_serial\\": \\"${serial:-$(ioreg -l | grep IOPlatformSerialNumber | awk -F'"' '{print $4}')}\\","
            echo "  \\"hardware_vendor\\": \\"Apple Inc.\\","
            echo "  \\"hardware_model\\": \\"${model_id:-$(sysctl -n hw.model)}\\","
            echo "  \\"computer_name\\": \\"$(scutil --get ComputerName 2>/dev/null || hostname -s)\\","
            echo "  \\"hardware_version\\": \\"${chip:-}\\","
            echo "  \\"uuid\\": \\"${hw_uuid:-$(ioreg -d2 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}')}\\","
            echo "  \\"model_name\\": \\"${model_name:-Mac}\\"" 
            echo "}"
        """
        
        return try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript,
            python: nil
        )
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
        
        return try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript,
            python: nil
        )
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
        
        return try await executeWithFallback(
            osquery: systemMemoryScript,
            bash: bashScript,
            python: nil
        )
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
}
    
