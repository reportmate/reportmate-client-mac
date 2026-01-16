import Foundation

/// System module processor - uses osquery first with bash fallback
/// Based on MunkiReport patterns for system info collection
/// Reference: https://github.com/munkireport/machine
/// No Python - uses osquery for: system_info, os_version, uptime, launchd, system_extensions, kernel_extensions, startup_items, package_receipts
/// Bash fallback for: hostnames, locale, keyboard, rosetta, software updates, system preferences, privileged helpers
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
        async let installHistoryData = collectInstallHistory()
        async let systemConfigData = collectSystemConfiguration()
        async let environmentData = collectEnvironment()
        // Mac-specific components (moved from Profiles module)
        async let loginItemsData = collectLoginItems()
        async let systemExtensionsData = collectSystemExtensions()
        async let kernelExtensionsData = collectKernelExtensions()
        async let privilegedHelpersData = collectPrivilegedHelperTools()
        
        // Await all results
        let osInfo = try await osInfoData
        let systemDetails = try await systemDetailsData
        let uptimeInfo = try await uptimeData
        let kernelInfo = try await kernelData
        let launchItems = try await launchItemsData
        let launchdServices = try await launchdServicesData
        _ = try await softwareUpdatesData  // Collected but not used; pendingAppleUpdates provides this data
        let pendingUpdates = try await pendingAppleUpdatesData
        let installHistory = try await installHistoryData
        let systemConfig = try await systemConfigData
        let environment = try await environmentData
        // Mac-specific
        let loginItems = try await loginItemsData
        let systemExtensions = try await systemExtensionsData
        let kernelExtensions = try await kernelExtensionsData
        let privilegedHelpers = try await privilegedHelpersData
        
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
            "installHistory": installHistory,
            "environment": environment,
            "systemConfiguration": systemConfig,
            // Mac-specific system components
            "loginItems": loginItems,
            "systemExtensions": systemExtensions,
            "kernelExtensions": kernelExtensions,
            "privilegedHelperTools": privilegedHelpers
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
            bash: bashScript
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
            bash: nil
        )
        
        // bash for additional details that osquery doesn't provide
        let bashScript = """
            computer_name=$(scutil --get ComputerName 2>/dev/null || hostname -s)
            local_hostname=$(scutil --get LocalHostName 2>/dev/null || hostname -s)
            hostname=$(hostname 2>/dev/null || echo "")
            uuid=$(ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}' 2>/dev/null || echo "")
            current_user=$(stat -f%Su /dev/console 2>/dev/null || whoami)
            
            # Boot time - extract seconds from kern.boottime
            boot_time_sec=$(sysctl -n kern.boottime 2>/dev/null | awk '{gsub(/[{}=,]/, " "); print $2}')
            if [ -n "$boot_time_sec" ] && [ "$boot_time_sec" != "0" ]; then
                boot_time_iso=$(date -r "$boot_time_sec" -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "")
            else
                boot_time_iso=""
            fi
            
            # Timezone
            timezone=$(systemsetup -gettimezone 2>/dev/null | sed 's/Time Zone: //' || cat /etc/localtime 2>/dev/null | strings | tail -1)
            
            # Locale
            locale=$(defaults read .GlobalPreferences AppleLocale 2>/dev/null || echo "en_US")
            
            # Keyboard layouts - need to read from console user's domain (not root's)
            console_user=$(stat -f%Su /dev/console 2>/dev/null || whoami)
            keyboard_name=""
            
            # Try reading from console user's preferences
            if [ "$console_user" != "root" ] && [ -n "$console_user" ]; then
                user_home=$(eval echo ~$console_user)
                keyboard_plist_file="$user_home/Library/Preferences/com.apple.HIToolbox.plist"
                if [ -f "$keyboard_plist_file" ]; then
                    # Read the selected input sources - need to escape space in key name with backslash
                    keyboard_name=$(/usr/libexec/PlistBuddy -c 'Print :AppleSelectedInputSources:0:KeyboardLayout\\ Name' "$keyboard_plist_file" 2>/dev/null || echo "")
                fi
            fi
            
            # Fallback: try defaults command (works if not running as root)
            if [ -z "$keyboard_name" ]; then
                keyboard_name=$(defaults read com.apple.HIToolbox AppleSelectedInputSources 2>/dev/null | grep -E "KeyboardLayout Name" | head -1 | sed 's/.*= "\\(.*\\)".*/\\1/' | tr -d ';' 2>/dev/null || echo "")
            fi
            
            # Final fallback
            if [ -z "$keyboard_name" ]; then
                keyboard_name="Unknown"
            fi
            keyboards="$keyboard_name"
            
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
            bash: bashScript
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
            bash: bashScript
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
            bash: bashScript
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
            bash: nil
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
            // Note: When running as root, NSHomeDirectory() returns /var/root, not user's home
            // Check for /Users/ in path for user-level items
            var itemType = "LaunchDaemon"
            var source = "System"
            if path.contains("LaunchAgents") {
                itemType = "LaunchAgent"
            }
            if path.hasPrefix("/System/") || label.hasPrefix("com.apple.") {
                source = "Apple"
            } else if path.contains("/Users/") {
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
    
    // MARK: - Launchd Services (bash: launchctl list + osquery: launchd for details + plist content)
    
    private func collectLaunchdServices() async throws -> [[String: Any]] {
        // Use bash to get running services from launchctl, then enrich with osquery launchd data
        // Note: We need to collect BOTH system-level (launchctl list) AND user-level (as console user) items
        let bashScript = """
            # Collect system-level services (running as root)
            launchctl list 2>/dev/null | tail -n +2 | while IFS=$'\\t' read -r pid status label; do
                [ -z "$label" ] && continue
                
                if [ "$pid" != "-" ] && [ -n "$pid" ]; then
                    running="true"
                    pid_val="$pid"
                else
                    running="false"
                    pid_val="null"
                fi
                
                echo "{\\"label\\": \\"$label\\", \\"pid\\": $pid_val, \\"running\\": $running, \\"domain\\": \\"system\\"},"
            done
            
            # Also collect user-level services (run launchctl as console user)
            console_user=$(stat -f%Su /dev/console 2>/dev/null)
            if [ -n "$console_user" ] && [ "$console_user" != "root" ]; then
                console_uid=$(id -u "$console_user" 2>/dev/null)
                if [ -n "$console_uid" ]; then
                    # Use launchctl print to get user domain items, or run launchctl as user
                    sudo -u "$console_user" launchctl list 2>/dev/null | tail -n +2 | while IFS=$'\\t' read -r pid status label; do
                        [ -z "$label" ] && continue
                        
                        if [ "$pid" != "-" ] && [ -n "$pid" ]; then
                            running="true"
                            pid_val="$pid"
                        else
                            running="false"
                            pid_val="null"
                        fi
                        
                        echo "{\\"label\\": \\"$label\\", \\"pid\\": $pid_val, \\"running\\": $running, \\"domain\\": \\"user\\"},"
                    done
                fi
            fi
        """
        
        // Get the raw launchctl list (both system and user)
        let launchctlResult = try await executeWithFallback(
            osquery: nil,
            bash: """
                echo '['
                \(bashScript) | sed '$ s/,$//'
                echo ']'
                """
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
            bash: nil
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
        
        // Parse launchctl results and enrich with osquery data and plist content
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
                
                // Get the domain (system vs user) from launchctl output
                let domain = item["domain"] as? String ?? "system"
                
                // Parse program arguments into array
                var programArguments: [String] = []
                if !programArgs.isEmpty {
                    programArguments = programArgs.components(separatedBy: " ").filter { !$0.isEmpty }
                }
                
                // Parse watch paths and queue directories
                let watchPaths = (details["watch_paths"] as? String)?.components(separatedBy: ",").filter { !$0.isEmpty } ?? []
                let queueDirs = (details["queue_directories"] as? String)?.components(separatedBy: ",").filter { !$0.isEmpty } ?? []
                
                // Determine source (Apple, System, User)
                // Use domain from launchctl + path patterns
                var source = "System"
                if label.hasPrefix("com.apple.") || path.hasPrefix("/System/") {
                    source = "Apple"
                } else if domain == "user" || path.contains("/Users/") {
                    source = "User"
                }
                
                // Determine type from path
                var itemType = "LaunchDaemon"
                if path.contains("LaunchAgents") || domain == "user" {
                    itemType = "LaunchAgent"
                }
                
                // Get plist content if path exists
                var plistContent: String? = nil
                if !path.isEmpty && FileManager.default.fileExists(atPath: path) {
                    // Read and convert plist to JSON for display
                    if let plistData = FileManager.default.contents(atPath: path),
                       let plist = try? PropertyListSerialization.propertyList(from: plistData, options: [], format: nil),
                       let jsonData = try? JSONSerialization.data(withJSONObject: plist, options: [.prettyPrinted, .sortedKeys]),
                       let jsonString = String(data: jsonData, encoding: .utf8) {
                        plistContent = jsonString
                    }
                }
                
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
                    "exitTimeout": Optional<Int>.none as Any,
                    "startInterval": Int(details["start_interval"] as? String ?? "") as Any,
                    "watchPaths": watchPaths,
                    "queueDirectories": queueDirs,
                    "source": source,
                    "type": itemType,
                    "plistContent": plistContent as Any
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
            bash: bashScript
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
            bash: bashScript
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
            bash: bashScript
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
            bash: bashScript
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
    
    // MARK: - Install History (osquery: package_receipts)
    
    private func collectInstallHistory() async throws -> [[String: Any]] {
        // Get packages installed in the last 90 days (3 months)
        // Calculate timestamp for 90 days ago
        let ninetyDaysAgo = Int(Date().timeIntervalSince1970) - (90 * 24 * 60 * 60)
        
        // osquery package_receipts provides macOS install history
        let osqueryScript = """
            SELECT 
                package_id,
                package_filename,
                version,
                location,
                install_time,
                installer_name,
                path
            FROM package_receipts
            WHERE install_time >= '\(ninetyDaysAgo)'
            ORDER BY install_time DESC;
        """
        
        let bashScript = """
            # Fallback: parse receipts from filesystem (last 90 days)
            ninety_days_ago=$(date -v-90d +%s 2>/dev/null || date -d "90 days ago" +%s 2>/dev/null || echo "0")
            
            echo "["
            first=true
            for receipt in /var/db/receipts/*.plist; do
                [ -f "$receipt" ] || continue
                
                # Get modification time of receipt file
                mod_time=$(stat -f%m "$receipt" 2>/dev/null || echo "0")
                [ "$mod_time" -lt "$ninety_days_ago" ] && continue
                
                pkg_id=$(/usr/libexec/PlistBuddy -c "Print :PackageIdentifier" "$receipt" 2>/dev/null || echo "")
                version=$(/usr/libexec/PlistBuddy -c "Print :PackageVersion" "$receipt" 2>/dev/null || echo "")
                install_time=$(/usr/libexec/PlistBuddy -c "Print :InstallDate" "$receipt" 2>/dev/null || echo "")
                
                [ -z "$pkg_id" ] && continue
                
                if [ "$first" = "true" ]; then
                    first=false
                else
                    echo ","
                fi
                
                echo "{\\"package_id\\": \\"$pkg_id\\", \\"version\\": \\"$version\\", \\"install_time\\": \\"$install_time\\"}"
            done
            echo "]"
        """
        
        let result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript
        )
        
        var history: [[String: Any]] = []
        
        if let items = result["items"] as? [[String: Any]] {
            history = items.map { item in
                var normalized: [String: Any] = [:]
                
                normalized["packageId"] = item["package_id"] as? String ?? ""
                normalized["packageFilename"] = item["package_filename"] as? String ?? ""
                normalized["version"] = item["version"] as? String ?? ""
                normalized["location"] = item["location"] as? String ?? ""
                normalized["installTime"] = item["install_time"] as? String ?? ""
                normalized["installerName"] = item["installer_name"] as? String ?? ""
                normalized["path"] = item["path"] as? String ?? ""
                
                return normalized
            }
        }
        
        return history
    }
    
    // MARK: - Login Items (Open at Login apps - uses sfltool for BTM database)
    
    private func collectLoginItems() async throws -> [[String: Any]] {
        // The "Open at Login" items in macOS System Settings come from the BTM (Background Task Management) database
        // These are Type: app (0x2) entries with Disposition: [enabled, ...]
        // sfltool dumpbtm shows all items - we filter for enabled apps that are NOT helper apps
        
        let bashScript = """
            # Get login items using sfltool (lists BTM-registered apps)
            # Filter for Type: app with enabled disposition - these are the "Open at Login" items
            
            sudo sfltool dumpbtm 2>/dev/null | awk '
            BEGIN { RS = ""; FS = "\\n"; first = 1 }
            {
                name = ""
                url = ""
                type = ""
                disposition = ""
                bundle_id = ""
                
                for (i = 1; i <= NF; i++) {
                    if ($i ~ /^[[:space:]]*Name:/) {
                        gsub(/^[[:space:]]*Name:[[:space:]]*/, "", $i)
                        name = $i
                    }
                    if ($i ~ /^[[:space:]]*Type:/) {
                        gsub(/^[[:space:]]*Type:[[:space:]]*/, "", $i)
                        type = $i
                    }
                    if ($i ~ /^[[:space:]]*Disposition:/) {
                        gsub(/^[[:space:]]*Disposition:[[:space:]]*/, "", $i)
                        disposition = $i
                    }
                    if ($i ~ /^[[:space:]]*URL:.*file:/) {
                        gsub(/^[[:space:]]*URL:[[:space:]]*file:\\/\\//, "", $i)
                        gsub(/\\/$/, "", $i)
                        # URL decode
                        gsub(/%20/, " ", $i)
                        url = $i
                    }
                    if ($i ~ /^[[:space:]]*Bundle Identifier:/) {
                        gsub(/^[[:space:]]*Bundle Identifier:[[:space:]]*/, "", $i)
                        bundle_id = $i
                    }
                }
                
                # Filter for app type (0x2) that is enabled
                if (type ~ /app \\(0x2\\)/ && disposition ~ /enabled/) {
                    if (name != "" && name != "(null)") {
                        if (!first) printf ","
                        first = 0
                        # Escape quotes in name
                        gsub(/"/, "\\\\\\"", name)
                        gsub(/"/, "\\\\\\"", url)
                        printf "{\\"name\\":\\"%s\\",\\"path\\":\\"%s\\",\\"type\\":\\"Application\\",\\"bundleId\\":\\"%s\\"}", name, url, bundle_id
                    }
                }
            }
            END { }
            ' | (echo "["; cat; echo "]") | jq '.'
        """
        
        let result = try await executeWithFallback(
            osquery: nil,
            bash: bashScript
        )
        
        var items: [[String: Any]] = []
        
        if let resultItems = result["items"] as? [[String: Any]] {
            items = resultItems
        }
        
        return items.map { item in
            [
                "name": item["name"] as? String ?? "",
                "path": item["path"] as? String ?? "",
                "type": item["type"] as? String ?? "Application",
                "bundleId": item["bundleId"] as? String ?? "",
                "enabled": true,
                "source": "BTM"
            ]
        }
    }
    
    // MARK: - System Extensions (osquery: system_extensions + app extensions)
    
    private func collectSystemExtensions() async throws -> [[String: Any]] {
        var allExtensions: [[String: Any]] = []
        
        // 1. System Extensions (osquery system_extensions table for macOS 10.15+)
        let osqueryScript = """
            SELECT 
                identifier,
                version,
                state,
                team,
                bundle_path,
                category
            FROM system_extensions;
        """
        
        let sysExtResult = try? await executeWithFallback(
            osquery: osqueryScript,
            bash: nil
        )
        
        if let items = sysExtResult?["items"] as? [[String: Any]] {
            for ext in items {
                let category = ext["category"] as? String ?? ""
                var extType = "System"
                if category.contains("Network") || category.contains("network") {
                    extType = "Network"
                } else if category.contains("Endpoint") || category.contains("endpoint") || category.contains("Security") {
                    extType = "EndpointSecurity"
                } else if category.contains("DriverKit") || category.contains("driver") {
                    extType = "DriverKit"
                }
                
                allExtensions.append([
                    "identifier": ext["identifier"] as? String ?? "",
                    "version": ext["version"] as? String ?? "",
                    "state": ext["state"] as? String ?? "unknown",
                    "teamId": ext["team"] as? String ?? "",
                    "bundlePath": ext["bundle_path"] as? String ?? "",
                    "category": category,
                    "type": extType,
                    "extensionCategory": category.isEmpty ? "Driver Extensions" : category,
                    "appName": ""
                ])
            }
        }
        
        // 2. App Extensions (pluginkit - Quick Look, Sharing, Finder, etc.)
        let appExtScript = """
            # Get all app extensions using pluginkit
            pluginkit -mDAv 2>/dev/null | awk '
            BEGIN { first = 1 }
            {
                # Parse lines like: com.app.extension(1.0) identifier
                # or: Path: /path/to/extension
                if ($0 ~ /^[[:space:]]*[A-Za-z0-9._-]+\\(/) {
                    # New extension entry
                    if (identifier != "" && !first) print ","
                    first = 0
                    
                    # Extract identifier
                    match($0, /[A-Za-z0-9._-]+/)
                    identifier = substr($0, RSTART, RLENGTH)
                    
                    # Extract version
                    if (match($0, /\\([0-9.]+\\)/)) {
                        version = substr($0, RSTART+1, RLENGTH-2)
                    } else {
                        version = ""
                    }
                    
                    path = ""
                    category = ""
                    appName = ""
                }
                else if ($0 ~ /^[[:space:]]*Path:/) {
                    gsub(/^[[:space:]]*Path:[[:space:]]*/, "")
                    path = $0
                    
                    # Extract app name from path
                    if (match(path, /\\/([^\\/]+)\\.app/)) {
                        appName = substr(path, RSTART+1, RLENGTH-5)
                    }
                    
                    # Determine category from path or identifier
                    if (path ~ /QuickLook/) category = "Quick Look"
                    else if (path ~ /ShareExtension/ || identifier ~ /share/) category = "Sharing"
                    else if (path ~ /FinderSync/ || identifier ~ /finder/) category = "Finder"
                    else if (path ~ /PhotosExtension/ || identifier ~ /photo/) category = "Photos Editing"
                    else if (path ~ /SpotlightExtension/ || identifier ~ /spotlight/) category = "Spotlight"
                    else if (path ~ /ActionExtension/ || identifier ~ /action/) category = "Actions"
                    else if (path ~ /FileProvider/ || identifier ~ /fileprovider/) category = "File Providers"
                    else if (path ~ /SourceEditorExtension/ || identifier ~ /sourceeditor/) category = "Xcode Source Editor"
                    else if (identifier ~ /camera/) category = "Camera Extensions"
                    else if (identifier ~ /media/) category = "Media Extensions"
                    else if (identifier ~ /dock/) category = "Dock Tiles"
                    else category = "Other"
                    
                    printf "{\\"identifier\\": \\"%s\\", \\"version\\": \\"%s\\", \\"bundlePath\\": \\"%s\\", \\"category\\": \\"%s\\", \\"appName\\": \\"%s\\", \\"state\\": \\"enabled\\", \\"type\\": \\"AppExtension\\"}", identifier, version, path, category, appName
                }
            }
            END {
                if (identifier != "") print ""
            }
            ' | sed 's/\\\\"/"/g'
        """
        
        // Run app extensions collection
        let appExtResult = try await executeWithFallback(
            osquery: nil,
            bash: """
                echo "["
                \(appExtScript)
                echo "]"
                """
        )
        
        if let items = appExtResult["items"] as? [[String: Any]] {
            for ext in items {
                allExtensions.append([
                    "identifier": ext["identifier"] as? String ?? "",
                    "version": ext["version"] as? String ?? "",
                    "state": ext["state"] as? String ?? "enabled",
                    "teamId": ext["teamId"] as? String ?? "",
                    "bundlePath": ext["bundlePath"] as? String ?? "",
                    "category": ext["category"] as? String ?? "Other",
                    "type": ext["type"] as? String ?? "AppExtension",
                    "extensionCategory": ext["category"] as? String ?? "Other",
                    "appName": ext["appName"] as? String ?? ""
                ])
            }
        }
        
        // 3. Also get extensions from PlugIns directories
        let pluginsScript = """
            echo "["
            first=true
            
            # Search for app extensions in standard locations
            for appdir in /Applications/*.app ~/Applications/*.app /System/Applications/*.app; do
                [ -d "$appdir" ] || continue
                
                plugins_dir="$appdir/Contents/PlugIns"
                [ -d "$plugins_dir" ] || continue
                
                app_name=$(basename "$appdir" .app)
                
                for ext in "$plugins_dir"/*.appex; do
                    [ -d "$ext" ] || continue
                    
                    ext_name=$(basename "$ext" .appex)
                    info_plist="$ext/Contents/Info.plist"
                    
                    if [ -f "$info_plist" ]; then
                        identifier=$(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$info_plist" 2>/dev/null || echo "$ext_name")
                        version=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$info_plist" 2>/dev/null || echo "")
                        ext_type=$(/usr/libexec/PlistBuddy -c "Print :NSExtension:NSExtensionPointIdentifier" "$info_plist" 2>/dev/null || echo "")
                        
                        # Map extension point to category
                        case "$ext_type" in
                            *quicklook*) category="Quick Look" ;;
                            *share*) category="Sharing" ;;
                            *finder*) category="Finder" ;;
                            *photos*) category="Photos Editing" ;;
                            *spotlight*) category="Spotlight" ;;
                            *action*) category="Actions" ;;
                            *fileprovider*) category="File Providers" ;;
                            *sourceeditor*) category="Xcode Source Editor" ;;
                            *) category="Other" ;;
                        esac
                        
                        if [ "$first" = "true" ]; then
                            first=false
                        else
                            echo ","
                        fi
                        
                        echo "{\\"identifier\\": \\"$identifier\\", \\"version\\": \\"$version\\", \\"bundlePath\\": \\"$ext\\", \\"category\\": \\"$category\\", \\"appName\\": \\"$app_name\\", \\"state\\": \\"enabled\\", \\"type\\": \\"AppExtension\\"}"
                    fi
                done
            done
            
            echo "]"
        """
        
        let pluginsResult = try await executeWithFallback(
            osquery: nil,
            bash: pluginsScript
        )
        
        // Deduplicate by identifier (pluginkit may have found them already)
        var seenIds = Set(allExtensions.compactMap { $0["identifier"] as? String })
        
        if let items = pluginsResult["items"] as? [[String: Any]] {
            for ext in items {
                let identifier = ext["identifier"] as? String ?? ""
                if !identifier.isEmpty && !seenIds.contains(identifier) {
                    seenIds.insert(identifier)
                    allExtensions.append([
                        "identifier": identifier,
                        "version": ext["version"] as? String ?? "",
                        "state": ext["state"] as? String ?? "enabled",
                        "teamId": "",
                        "bundlePath": ext["bundlePath"] as? String ?? "",
                        "category": ext["category"] as? String ?? "Other",
                        "type": ext["type"] as? String ?? "AppExtension",
                        "extensionCategory": ext["category"] as? String ?? "Other",
                        "appName": ext["appName"] as? String ?? ""
                    ])
                }
            }
        }
        
        return allExtensions
    }
    
    // MARK: - Kernel Extensions (osquery: kernel_extensions)
    
    private func collectKernelExtensions() async throws -> [[String: Any]] {
        // osquery kernel_extensions table
        let osqueryScript = """
            SELECT 
                idx,
                refs,
                size,
                name,
                version,
                linked_against,
                path
            FROM kernel_extensions
            WHERE name NOT LIKE 'com.apple.%';
        """
        
        let bashScript = """
            # Get kernel extensions using kextstat
            kextstat 2>/dev/null | awk '
            BEGIN { print "["; first = 1 }
            NR > 1 && $6 !~ /^com\\.apple\\./ {
                idx = $1
                refs = $2
                size = $4
                name = $6
                version = ""
                
                # Extract version from name if present
                if (match(name, /\\([0-9.]+\\)/)) {
                    version = substr(name, RSTART+1, RLENGTH-2)
                    name = substr(name, 1, RSTART-1)
                }
                
                if (!first) print ","
                printf "{\\"idx\\": \\"%s\\", \\"refs\\": \\"%s\\", \\"size\\": \\"%s\\", \\"name\\": \\"%s\\", \\"version\\": \\"%s\\"}", idx, refs, size, name, version
                first = 0
            }
            END { print "]" }
            '
        """
        
        let result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript
        )
        
        var kexts: [[String: Any]] = []
        
        if let items = result["items"] as? [[String: Any]] {
            kexts = items
        }
        
        return kexts.map { kext in
            let sizeStr = kext["size"] as? String ?? "0"
            let sizeInt = Int(sizeStr) ?? 0
            
            return [
                "name": kext["name"] as? String ?? "",
                "version": kext["version"] as? String ?? "",
                "path": kext["path"] as? String ?? "",
                "size": sizeInt,
                "references": Int(kext["refs"] as? String ?? "0") ?? 0,
                "index": Int(kext["idx"] as? String ?? "0") ?? 0,
                "loaded": true
            ]
        }
    }
    
    // MARK: - Privileged Helper Tools
    
    private func collectPrivilegedHelperTools() async throws -> [[String: Any]] {
        // List privileged helper tools installed by third-party apps
        // Uses jq for reliable JSON construction
        let bashScript = """
            collect_helper() {
                local helper="$1"
                local name=$(basename "$helper")
                
                # Get file info
                size=$(stat -f%z "$helper" 2>/dev/null || echo "0")
                modified=$(stat -f%m "$helper" 2>/dev/null || echo "0")
                mod_date=$(date -r "$modified" -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "")
                
                # Get code signature info
                team_id=""
                signed="false"
                codesign_output=$(codesign -dvv "$helper" 2>&1 || echo "")
                if echo "$codesign_output" | grep -q "Authority="; then
                    signed="true"
                    team_id=$(echo "$codesign_output" | grep "TeamIdentifier=" | cut -d= -f2)
                fi
                
                # Get bundle identifier from codesign output (more reliable than parsing binary)
                bundle_id=$(echo "$codesign_output" | grep "Identifier=" | cut -d= -f2)
                [ -z "$bundle_id" ] && bundle_id="$name"
                
                jq -n --arg n "$name" --arg p "$helper" --arg b "$bundle_id" --arg t "$team_id" \\
                    --argjson s "$size" --arg m "$mod_date" --argjson sg "$([ \"$signed\" = \"true\" ] && echo true || echo false)" \\
                    '{name: $n, path: $p, bundleIdentifier: $b, teamId: $t, size: $s, modifiedDate: $m, signed: $sg}'
            }
            
            # Collect all helpers
            items="[]"
            
            for helper in /Library/PrivilegedHelperTools/*; do
                [ -f "$helper" ] || continue
                item=$(collect_helper "$helper" 2>/dev/null)
                [ -n "$item" ] && items=$(echo "$items" | jq --argjson item "$item" '. + [$item]')
            done
            
            echo "$items"
        """
        
        let result = try await executeWithFallback(
            osquery: nil,
            bash: bashScript
        )
        
        var helpers: [[String: Any]] = []
        
        if let items = result["items"] as? [[String: Any]] {
            helpers = items
        }
        
        return helpers.map { helper in
            [
                "name": helper["name"] as? String ?? "",
                "path": helper["path"] as? String ?? "",
                "bundleIdentifier": helper["bundleIdentifier"] as? String ?? "",
                "teamId": helper["teamId"] as? String ?? "",
                "size": helper["size"] as? Int ?? 0,
                "modifiedDate": helper["modifiedDate"] as? String ?? "",
                "signed": helper["signed"] as? Bool ?? false
            ]
        }
    }
}
