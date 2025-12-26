import Foundation

/// System module processor - uses osquery first with bash fallback
/// Based on MunkiReport patterns for system info collection
/// Reference: https://github.com/munkireport/machine
/// No Python - uses osquery for: system_info, os_version, uptime, launchd
/// Bash fallback for: hostnames, locale, keyboard, rosetta, software updates, system preferences
public class SystemModuleProcessor: BaseModuleProcessor, @unchecked Sendable {
    
    public init(configuration: ReportMateConfiguration) {
        super.init(moduleId: "system", configuration: configuration)
    }
    
    public override func collectData() async throws -> ModuleData {
        // Collect all system data in parallel for efficiency
        async let osInfoData = collectOSInfo()
        async let systemDetailsData = collectSystemDetails()
        async let uptimeData = collectUptimeInfo()
        async let kernelData = collectKernelInfo()
        async let launchItemsData = collectLaunchItems()
        async let launchdServicesData = collectLaunchdServices()
        async let softwareUpdatesData = collectSoftwareUpdates()
        async let pendingAppleUpdatesData = collectPendingAppleUpdates()
        async let systemConfigData = collectSystemConfiguration()
        async let environmentData = collectEnvironment()
        
        // Await all results
        let osInfo = try await osInfoData
        let systemDetails = try await systemDetailsData
        let uptimeInfo = try await uptimeData
        let kernelInfo = try await kernelData
        let launchItems = try await launchItemsData
        let launchdServices = try await launchdServicesData
        let softwareUpdates = try await softwareUpdatesData
        let pendingUpdates = try await pendingAppleUpdatesData
        let systemConfig = try await systemConfigData
        let environment = try await environmentData
        
        // Build the combined system data dictionary
        let systemData: [String: Any] = [
            "operatingSystem": osInfo,
            "systemDetails": systemDetails,
            "uptime": uptimeInfo["uptimeSeconds"] as? Int ?? 0,
            "uptimeString": uptimeInfo["uptimeString"] as? String ?? "Unknown",
            "kernelInfo": kernelInfo,
            "scheduledTasks": launchItems,
            "services": launchdServices,
            "pendingAppleUpdates": pendingUpdates,
            "environment": environment,
            "systemConfiguration": systemConfig
        ]
        
        return BaseModuleData(moduleId: moduleId, data: systemData)
    }
    
    // MARK: - OS Version Info (osquery: os_version)
    
    private func collectOSInfo() async throws -> [String: Any] {
        // osquery: os_version provides name, version, major, minor, patch, build, arch
        let osqueryScript = """
            SELECT name, version, major, minor, patch, build, arch FROM os_version;
        """
        
        // bash fallback: sw_vers and uname
        let bashScript = """
            version=$(sw_vers -productVersion 2>/dev/null || echo "")
            build=$(sw_vers -buildVersion 2>/dev/null || echo "")
            arch=$(uname -m 2>/dev/null || echo "")
            kernel=$(uname -r 2>/dev/null || echo "")
            
            # Parse version parts
            major=$(echo "$version" | cut -d. -f1)
            minor=$(echo "$version" | cut -d. -f2)
            patch=$(echo "$version" | cut -d. -f3)
            [ -z "$minor" ] && minor=0
            [ -z "$patch" ] && patch=0
            
            echo "{"
            echo "  \\"name\\": \\"macOS\\","
            echo "  \\"version\\": \\"$version\\","
            echo "  \\"major\\": $major,"
            echo "  \\"minor\\": $minor,"
            echo "  \\"patch\\": $patch,"
            echo "  \\"build\\": \\"$build\\","
            echo "  \\"arch\\": \\"$arch\\","
            echo "  \\"kernelVersion\\": \\"$kernel\\""
            echo "}"
        """
        
        let result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript,
            python: nil
        )
        
        // Transform osquery result to match expected format
        return [
            "name": result["name"] as? String ?? "macOS",
            "version": result["version"] as? String ?? "",
            "majorVersion": (result["major"] as? Int) ?? Int(result["major"] as? String ?? "0") ?? 0,
            "minorVersion": (result["minor"] as? Int) ?? Int(result["minor"] as? String ?? "0") ?? 0,
            "patchVersion": (result["patch"] as? Int) ?? Int(result["patch"] as? String ?? "0") ?? 0,
            "buildNumber": result["build"] as? String ?? "",
            "platform": "Darwin",
            "architecture": result["arch"] as? String ?? "",
            "kernelVersion": result["kernelVersion"] as? String ?? ""
        ]
    }
    
    // MARK: - System Details (osquery: system_info + bash for hostnames)
    
    private func collectSystemDetails() async throws -> [String: Any] {
        // osquery: system_info for UUID, hostname basics
        let osqueryScript = """
            SELECT hostname, uuid, hardware_serial, computer_name, local_hostname FROM system_info;
        """
        
        let osqueryResult = try? await executeWithFallback(
            osquery: osqueryScript,
            bash: nil,
            python: nil
        )
        
        // bash for additional details that osquery doesn't provide
        let bashScript = """
            computer_name=$(scutil --get ComputerName 2>/dev/null || hostname -s)
            local_hostname=$(scutil --get LocalHostName 2>/dev/null || hostname -s)
            hostname=$(hostname 2>/dev/null || echo "")
            uuid=$(ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}' 2>/dev/null || echo "")
            current_user=$(stat -f%Su /dev/console 2>/dev/null || whoami)
            
            # Boot time
            boot_time_sec=$(sysctl -n kern.boottime 2>/dev/null | awk -F'[= ,]' '{print $4}')
            boot_time_iso=$(date -r "$boot_time_sec" -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "")
            
            # Timezone
            timezone=$(systemsetup -gettimezone 2>/dev/null | sed 's/Time Zone: //' || cat /etc/localtime 2>/dev/null | strings | tail -1)
            
            # Locale
            locale=$(defaults read .GlobalPreferences AppleLocale 2>/dev/null || echo "en_US")
            
            # Keyboard layouts
            keyboards=$(defaults read com.apple.HIToolbox AppleEnabledInputSources 2>/dev/null | grep -E '"KeyboardLayout Name"' | sed 's/.*= "\\(.*\\)";/\\1/' | tr '\\n' ',' | sed 's/,$//' || echo "US")
            
            # Rosetta 2 status (Apple Silicon)
            arch=$(uname -m)
            rosetta_installed="false"
            rosetta_status="not_applicable"
            if [ "$arch" = "arm64" ]; then
                if [ -d "/Library/Apple/usr/share/rosetta" ]; then
                    rosetta_installed="true"
                    rosetta_status="installed"
                else
                    rosetta_status="not_installed"
                fi
            fi
            
            # SIP status
            sip_enabled="false"
            sip_output=$(csrutil status 2>/dev/null)
            if echo "$sip_output" | grep -q "enabled"; then
                sip_enabled="true"
            fi
            
            echo "{"
            echo "  \\"hostname\\": \\"$hostname\\","
            echo "  \\"computerName\\": \\"$computer_name\\","
            echo "  \\"localHostname\\": \\"${local_hostname}.local\\","
            echo "  \\"systemUUID\\": \\"$uuid\\","
            echo "  \\"currentUser\\": \\"$current_user\\","
            echo "  \\"bootTime\\": \\"$boot_time_iso\\","
            echo "  \\"timeZone\\": \\"$timezone\\","
            echo "  \\"locale\\": \\"$locale\\","
            echo "  \\"systemIntegrityProtection\\": $sip_enabled,"
            echo "  \\"secureBootLevel\\": \\"Unknown\\","
            echo "  \\"keyboardLayouts\\": [\\"$keyboards\\"],"
            echo "  \\"rosetta2Installed\\": $rosetta_installed,"
            echo "  \\"rosetta2Status\\": \\"$rosetta_status\\""
            echo "}"
        """
        
        let bashResult = try await executeWithFallback(
            osquery: nil,
            bash: bashScript,
            python: nil
        )
        
        // Merge osquery and bash results, preferring osquery for UUID
        var details = bashResult
        if let osqResult = osqueryResult {
            if let uuid = osqResult["uuid"] as? String, !uuid.isEmpty {
                details["systemUUID"] = uuid
            }
        }
        
        return details
    }
    
    // MARK: - Uptime Info (osquery: uptime)
    
    private func collectUptimeInfo() async throws -> [String: Any] {
        let osqueryScript = """
            SELECT days, hours, minutes, seconds, total_seconds FROM uptime;
        """
        
        let bashScript = """
            boot_time_sec=$(sysctl -n kern.boottime 2>/dev/null | awk -F'[= ,]' '{print $4}')
            current_time=$(date +%s)
            total_seconds=$((current_time - boot_time_sec))
            
            days=$((total_seconds / 86400))
            hours=$(((total_seconds % 86400) / 3600))
            minutes=$(((total_seconds % 3600) / 60))
            
            echo "{"
            echo "  \\"days\\": $days,"
            echo "  \\"hours\\": $hours,"
            echo "  \\"minutes\\": $minutes,"
            echo "  \\"total_seconds\\": $total_seconds"
            echo "}"
        """
        
        let result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript,
            python: nil
        )
        
        let totalSeconds = (result["total_seconds"] as? Int) ?? Int(result["total_seconds"] as? String ?? "0") ?? 0
        let days = (result["days"] as? Int) ?? Int(result["days"] as? String ?? "0") ?? 0
        let hours = (result["hours"] as? Int) ?? Int(result["hours"] as? String ?? "0") ?? 0
        let minutes = (result["minutes"] as? Int) ?? Int(result["minutes"] as? String ?? "0") ?? 0
        
        return [
            "uptimeSeconds": totalSeconds,
            "uptimeString": "\(days)d \(hours)h \(minutes)m"
        ]
    }
    
    // MARK: - Kernel Info (osquery: kernel_info)
    
    private func collectKernelInfo() async throws -> [String: Any] {
        let osqueryScript = """
            SELECT version, arguments FROM kernel_info;
        """
        
        let bashScript = """
            version=$(uname -v 2>/dev/null || echo "")
            release=$(uname -r 2>/dev/null || echo "")
            machine=$(uname -m 2>/dev/null || echo "")
            
            echo "{"
            echo "  \\"version\\": \\"$version\\","
            echo "  \\"release\\": \\"$release\\","
            echo "  \\"machine\\": \\"$machine\\","
            echo "  \\"arguments\\": []"
            echo "}"
        """
        
        let result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript,
            python: nil
        )
        
        // Parse kernel arguments if present
        var arguments: [String] = []
        if let args = result["arguments"] as? String, !args.isEmpty {
            arguments = args.components(separatedBy: " ").filter { !$0.isEmpty }
        } else if let argsArray = result["arguments"] as? [String] {
            arguments = argsArray
        }
        
        return [
            "version": result["version"] as? String ?? "",
            "release": result["release"] as? String ?? "",
            "machine": result["machine"] as? String ?? "",
            "arguments": arguments
        ]
    }
    
    // MARK: - Launch Items (osquery: launchd)
    
    private func collectLaunchItems() async throws -> [[String: Any]] {
        // osquery launchd table provides all launch daemon/agent info
        let osqueryScript = """
            SELECT 
                label, path, program, program_arguments, 
                run_at_load, keep_alive, disabled, 
                username, groupname
            FROM launchd
            WHERE path LIKE '/Library/%' 
               OR path LIKE '/System/Library/%'
               OR path LIKE '%/Library/LaunchAgents/%';
        """
        
        let result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: nil,
            python: nil
        )
        
        // Handle both single result and array of results
        var items: [[String: Any]] = []
        
        if let resultItems = result["items"] as? [[String: Any]] {
            items = resultItems
        } else if !result.isEmpty && result["label"] != nil {
            // Single item result
            items = [result]
        }
        
        // Transform to match StartupItem struct
        return items.map { item in
            let path = item["path"] as? String ?? ""
            let label = item["label"] as? String ?? ""
            let program = item["program"] as? String ?? ""
            let programArgs = item["program_arguments"] as? String ?? ""
            let runAtLoad = item["run_at_load"] as? String ?? ""
            let disabled = item["disabled"] as? String ?? ""
            let username = item["username"] as? String
            
            // Determine type and source from path
            var itemType = "LaunchDaemon"
            var source = "System"
            if path.contains("LaunchAgents") {
                itemType = "LaunchAgent"
            }
            if path.hasPrefix("/System/") {
                source = "Apple"
            } else if path.contains(NSHomeDirectory()) {
                source = "User"
            }
            
            // Parse arguments
            var arguments: [String] = []
            if !programArgs.isEmpty {
                // osquery returns space-separated args, skip first (program path)
                let allArgs = programArgs.components(separatedBy: " ").filter { !$0.isEmpty }
                if allArgs.count > 1 {
                    arguments = Array(allArgs.dropFirst())
                }
            }
            
            // Determine status
            var status = "Enabled"
            if disabled == "1" || disabled.lowercased() == "true" {
                status = "Disabled"
            } else if runAtLoad == "1" || runAtLoad.lowercased() == "true" {
                status = "Loaded"
            }
            
            // Get program path
            let execPath = !program.isEmpty ? program : (programArgs.components(separatedBy: " ").first ?? "")
            
            return [
                "name": label.isEmpty ? (path as NSString).lastPathComponent.replacingOccurrences(of: ".plist", with: "") : label,
                "path": execPath,
                "arguments": arguments,
                "type": itemType,
                "source": source,
                "status": status,
                "runAtLoad": runAtLoad == "1" || runAtLoad.lowercased() == "true",
                "username": username as Any
            ]
        }
    }
    
    // MARK: - Launchd Services (bash: launchctl list + osquery: launchd for details)
    
    private func collectLaunchdServices() async throws -> [[String: Any]] {
        // Use bash to get running services from launchctl, then enrich with osquery launchd data
        let bashScript = """
            # Get all loaded services with PID and status
            launchctl list 2>/dev/null | tail -n +2 | while IFS=$'\\t' read -r pid status label; do
                # Skip empty labels
                [ -z "$label" ] && continue
                
                # Determine running status
                if [ "$pid" != "-" ] && [ -n "$pid" ]; then
                    running="true"
                    pid_val="$pid"
                else
                    running="false"
                    pid_val="null"
                fi
                
                echo "{\\"label\\": \\"$label\\", \\"pid\\": $pid_val, \\"running\\": $running},"
            done | sed '$ s/,$//'
        """
        
        // Get the raw launchctl list
        let launchctlResult = try await executeWithFallback(
            osquery: nil,
            bash: """
                echo '['
                \(bashScript)
                echo ']'
                """,
            python: nil
        )
        
        // Get detailed info from osquery launchd table
        let osqueryScript = """
            SELECT 
                label, path, program, program_arguments,
                run_at_load, keep_alive, on_demand, disabled,
                username, groupname, working_directory, root_directory,
                stdout_path, stderr_path, start_interval,
                watch_paths, queue_directories
            FROM launchd;
        """
        
        let launchdDetails = try await executeWithFallback(
            osquery: osqueryScript,
            bash: nil,
            python: nil
        )
        
        // Build a lookup map from osquery results
        var detailsMap: [String: [String: Any]] = [:]
        if let items = launchdDetails["items"] as? [[String: Any]] {
            for item in items {
                if let label = item["label"] as? String {
                    detailsMap[label] = item
                }
            }
        }
        
        // Parse launchctl results and enrich with osquery data
        var services: [[String: Any]] = []
        
        if let items = launchctlResult["items"] as? [[String: Any]] {
            for item in items {
                guard let label = item["label"] as? String else { continue }
                let pid = item["pid"] as? Int
                let isRunning = item["running"] as? Bool ?? false
                
                // Get details from osquery
                let details = detailsMap[label] ?? [:]
                
                let status = isRunning ? "Running" : "Stopped"
                let path = details["path"] as? String ?? ""
                let program = details["program"] as? String
                let programArgs = details["program_arguments"] as? String ?? ""
                let runAtLoad = details["run_at_load"] as? String ?? ""
                let keepAlive = details["keep_alive"] as? String ?? ""
                let onDemand = details["on_demand"] as? String ?? ""
                let disabled = details["disabled"] as? String ?? ""
                
                // Parse program arguments into array
                var programArguments: [String] = []
                if !programArgs.isEmpty {
                    programArguments = programArgs.components(separatedBy: " ").filter { !$0.isEmpty }
                }
                
                // Parse watch paths and queue directories
                let watchPaths = (details["watch_paths"] as? String)?.components(separatedBy: ",").filter { !$0.isEmpty } ?? []
                let queueDirs = (details["queue_directories"] as? String)?.components(separatedBy: ",").filter { !$0.isEmpty } ?? []
                
                services.append([
                    "label": label,
                    "path": path,
                    "status": status,
                    "pid": pid as Any,
                    "program": program as Any,
                    "programArguments": programArguments,
                    "runAtLoad": runAtLoad == "1" || runAtLoad.lowercased() == "true",
                    "keepAlive": keepAlive == "1" || keepAlive.lowercased() == "true",
                    "onDemand": onDemand == "1" || onDemand.lowercased() == "true",
                    "disabled": disabled == "1" || disabled.lowercased() == "true",
                    "username": details["username"] as Any,
                    "groupname": details["groupname"] as Any,
                    "workingDirectory": details["working_directory"] as Any,
                    "rootDirectory": details["root_directory"] as Any,
                    "standardOutPath": details["stdout_path"] as Any,
                    "standardErrorPath": details["stderr_path"] as Any,
                    "exitTimeout": nil as Int?,
                    "startInterval": Int(details["start_interval"] as? String ?? "") as Any,
                    "watchPaths": watchPaths,
                    "queueDirectories": queueDirs
                ])
            }
        }
        
        return services
    }
    
    // MARK: - Software Updates (bash: softwareupdate)
    
    private func collectSoftwareUpdates() async throws -> [[String: Any]] {
        let bashScript = """
            # Get pending software updates (no-scan uses cached results)
            updates_output=$(softwareupdate --list --no-scan 2>/dev/null)
            
            if echo "$updates_output" | grep -q "No new software available"; then
                echo "[]"
                exit 0
            fi
            
            echo "["
            first=true
            current_name=""
            current_version=""
            current_size=""
            current_recommended="false"
            current_restart="false"
            
            echo "$updates_output" | while IFS= read -r line; do
                # New update starts with *
                if echo "$line" | grep -q "^\\s*\\*"; then
                    # Output previous if exists
                    if [ -n "$current_name" ]; then
                        if [ "$first" = "false" ]; then echo ","; fi
                        first=false
                        echo "{\\"name\\": \\"$current_name\\", \\"version\\": \\"$current_version\\", \\"size\\": \\"$current_size\\", \\"recommended\\": $current_recommended, \\"restart_required\\": $current_restart}"
                    fi
                    current_name=$(echo "$line" | sed 's/^[[:space:]]*\\*[[:space:]]*//' | cut -d',' -f1)
                    current_version=""
                    current_size=""
                    current_recommended="false"
                    current_restart="false"
                elif echo "$line" | grep -qi "Version:"; then
                    current_version=$(echo "$line" | sed 's/.*Version:[[:space:]]*//')
                elif echo "$line" | grep -qi "Size:"; then
                    current_size=$(echo "$line" | sed 's/.*Size:[[:space:]]*//')
                elif echo "$line" | grep -qi "Recommended:.*YES"; then
                    current_recommended="true"
                elif echo "$line" | grep -qi "Restart:.*YES"; then
                    current_restart="true"
                fi
            done
            
            # Output last item
            if [ -n "$current_name" ]; then
                if [ "$first" = "false" ]; then echo ","; fi
                echo "{\\"name\\": \\"$current_name\\", \\"version\\": \\"$current_version\\", \\"size\\": \\"$current_size\\", \\"recommended\\": $current_recommended, \\"restart_required\\": $current_restart}"
            fi
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
    
    // MARK: - Pending Apple Updates (macadmins extension: pending_apple_updates)
    
    private func collectPendingAppleUpdates() async throws -> [[String: Any]] {
        // macadmins extension: pending_apple_updates table provides structured update info
        let osqueryScript = """
            SELECT 
                display_name,
                product_key,
                version,
                install_date,
                is_recommended,
                is_security,
                reboot_required
            FROM pending_apple_updates;
        """
        
        // Fallback to bash softwareupdate command
        let bashScript = """
            # Get pending software updates (no-scan uses cached results)
            updates_output=$(softwareupdate --list --no-scan 2>/dev/null)
            
            if echo "$updates_output" | grep -q "No new software available"; then
                echo "[]"
                exit 0
            fi
            
            echo "["
            first=true
            current_name=""
            current_version=""
            current_size=""
            current_recommended="false"
            current_restart="false"
            
            echo "$updates_output" | while IFS= read -r line; do
                # New update starts with *
                if echo "$line" | grep -q "^\\s*\\*"; then
                    # Output previous if exists
                    if [ -n "$current_name" ]; then
                        if [ "$first" = "false" ]; then echo ","; fi
                        first=false
                        echo "{\\"name\\": \\"$current_name\\", \\"version\\": \\"$current_version\\", \\"size\\": \\"$current_size\\", \\"recommended\\": $current_recommended, \\"restart_required\\": $current_restart}"
                    fi
                    current_name=$(echo "$line" | sed 's/^[[:space:]]*\\*[[:space:]]*//' | cut -d',' -f1)
                    current_version=""
                    current_size=""
                    current_recommended="false"
                    current_restart="false"
                elif echo "$line" | grep -qi "Version:"; then
                    current_version=$(echo "$line" | sed 's/.*Version:[[:space:]]*//')
                elif echo "$line" | grep -qi "Size:"; then
                    current_size=$(echo "$line" | sed 's/.*Size:[[:space:]]*//')
                elif echo "$line" | grep -qi "Recommended:.*YES"; then
                    current_recommended="true"
                elif echo "$line" | grep -qi "Restart:.*YES"; then
                    current_restart="true"
                fi
            done
            
            # Output last item
            if [ -n "$current_name" ]; then
                if [ "$first" = "false" ]; then echo ","; fi
                echo "{\\"name\\": \\"$current_name\\", \\"version\\": \\"$current_version\\", \\"size\\": \\"$current_size\\", \\"recommended\\": $current_recommended, \\"restart_required\\": $current_restart}"
            fi
            echo "]"
        """
        
        let result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript,
            python: nil
        )
        
        var updates: [[String: Any]] = []
        
        if let items = result["items"] as? [[String: Any]] {
            // Normalize macadmins extension format
            updates = items.map { item in
                var normalized: [String: Any] = [:]
                
                normalized["name"] = item["display_name"] as? String ?? item["product_key"] as? String ?? ""
                normalized["productKey"] = item["product_key"] as? String ?? ""
                normalized["version"] = item["version"] as? String ?? ""
                normalized["installDate"] = item["install_date"] as? String ?? ""
                
                // Parse boolean flags
                let isRecommended = item["is_recommended"] as? String ?? "0"
                normalized["recommended"] = (isRecommended == "1" || isRecommended == "true")
                
                let isSecurity = item["is_security"] as? String ?? "0"
                normalized["isSecurity"] = (isSecurity == "1" || isSecurity == "true")
                
                let rebootRequired = item["reboot_required"] as? String ?? "0"
                normalized["restartRequired"] = (rebootRequired == "1" || rebootRequired == "true")
                
                return normalized
            }
        } else if let items = result as? [[String: Any]] {
            // Bash fallback format
            updates = items
        }
        
        return updates
    }
    
    // MARK: - System Configuration (bash: defaults read for preferences)
    
    private func collectSystemConfiguration() async throws -> [String: Any] {
        let bashScript = """
            # Software Update preferences
            su_auto_check=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null || echo "1")
            su_auto_download=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload 2>/dev/null || echo "0")
            su_auto_os=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null || echo "0")
            su_auto_app=$(defaults read /Library/Preferences/com.apple.commerce AutoUpdate 2>/dev/null || echo "0")
            su_critical=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null || echo "0")
            su_config=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall 2>/dev/null || echo "0")
            
            # Timezone
            timezone=$(systemsetup -gettimezone 2>/dev/null | sed 's/Time Zone: //' || echo "")
            
            # Locale
            locale=$(defaults read .GlobalPreferences AppleLocale 2>/dev/null || echo "en_US")
            country=$(echo "$locale" | cut -d'_' -f2)
            language=$(echo "$locale" | cut -d'_' -f1)
            
            # Convert 1/0 to true/false
            bool_val() {
                [ "$1" = "1" ] && echo "true" || echo "false"
            }
            
            echo "{"
            echo "  \\"softwareUpdateSettings\\": {"
            echo "    \\"automaticCheckEnabled\\": $(bool_val $su_auto_check),"
            echo "    \\"automaticDownloadEnabled\\": $(bool_val $su_auto_download),"
            echo "    \\"automaticInstallOSUpdates\\": $(bool_val $su_auto_os),"
            echo "    \\"automaticInstallAppUpdates\\": $(bool_val $su_auto_app),"
            echo "    \\"automaticInstallSecurityUpdates\\": $(bool_val $su_critical),"
            echo "    \\"automaticInstallConfigDataUpdates\\": $(bool_val $su_config),"
            echo "    \\"pendingUpdates\\": [],"
            echo "    \\"lastCheckTime\\": \\"\\"," 
            echo "    \\"lastFullCheckTime\\": \\"\\"" 
            echo "  },"
            echo "  \\"energySettings\\": {"
            echo "    \\"computerSleepTime\\": 0,"
            echo "    \\"displaySleepTime\\": 0,"
            echo "    \\"disableSleep\\": false,"
            echo "    \\"wakeOnNetworkAccess\\": false,"
            echo "    \\"restartAfterPowerFailure\\": false"
            echo "  },"
            echo "  \\"dateTimeSettings\\": {"
            echo "    \\"timeZone\\": \\"$timezone\\","
            echo "    \\"ntpEnabled\\": true,"
            echo "    \\"is24HourFormat\\": true,"
            echo "    \\"dateFormat\\": \\"MM/dd/yyyy\\","
            echo "    \\"automaticTimeZone\\": true"
            echo "  },"
            echo "  \\"regionSettings\\": {"
            echo "    \\"country\\": \\"$country\\","
            echo "    \\"locale\\": \\"$locale\\","
            echo "    \\"language\\": \\"$language\\","
            echo "    \\"currency\\": \\"USD\\","
            echo "    \\"measurementUnits\\": \\"Metric\\","
            echo "    \\"calendarType\\": \\"Gregorian\\""
            echo "  },"
            echo "  \\"screenSaverSettings\\": {"
            echo "    \\"enabled\\": true,"
            echo "    \\"timeout\\": 20,"
            echo "    \\"askForPasswordDelay\\": 0,"
            echo "    \\"showClock\\": false"
            echo "  }"
            echo "}"
        """
        
        return try await executeWithFallback(
            osquery: nil,
            bash: bashScript,
            python: nil
        )
    }
    
    // MARK: - Environment Variables (bash)
    
    private func collectEnvironment() async throws -> [String: String] {
        let bashScript = """
            # Output environment as JSON
            echo "{"
            first=true
            env | while IFS='=' read -r key value; do
                # Skip if key is empty or contains problematic characters
                [ -z "$key" ] && continue
                # Escape quotes in value
                escaped_value=$(echo "$value" | sed 's/\\\\/\\\\\\\\/g' | sed 's/"/\\\\"/g')
                if [ "$first" = "true" ]; then
                    first=false
                else
                    echo ","
                fi
                echo "  \\"$key\\": \\"$escaped_value\\""
            done
            echo "}"
        """
        
        let result = try await executeWithFallback(
            osquery: nil,
            bash: bashScript,
            python: nil
        )
        
        // Convert to [String: String]
        var env: [String: String] = [:]
        for (key, value) in result {
            if let strValue = value as? String {
                env[key] = strValue
            }
        }
        return env
    }
}
