import Foundation

/// Applications module processor - uses osquery first with bash fallback
/// Based on MunkiReport patterns for application and process collection
/// Reference: https://github.com/munkireport/applications
/// No Python - uses osquery for: apps, processes, startup_items, launchd
/// Bash fallback for: plist reading, startup program details
public class ApplicationsModuleProcessor: BaseModuleProcessor, @unchecked Sendable {
    
    /// Reference to application usage service for usage data
    private let applicationUsageService: ApplicationUsageService?
    
    public init(configuration: ReportMateConfiguration, applicationUsageService: ApplicationUsageService? = nil) {
        self.applicationUsageService = applicationUsageService
        super.init(moduleId: "applications", configuration: configuration)
    }
    
    public override func collectData() async throws -> ModuleData {
        // Collect application data in parallel
        async let installedApps = collectInstalledApplications()
        async let runningProcesses = collectRunningProcesses()
        async let startupPrograms = collectStartupPrograms()
        
        // Await all results
        let apps = try await installedApps
        let processes = try await runningProcesses
        let startup = try await startupPrograms
        
        // Get application usage data if available
        var usageData: [String: Any] = [:]
        if let usageService = applicationUsageService {
            let usageSnapshot = await usageService.collectUsageData(installedApps: apps)
            usageData = [
                "status": usageSnapshot.status,
                "generatedAt": ISO8601DateFormatter().string(from: usageSnapshot.generatedAt),
                "windowStart": ISO8601DateFormatter().string(from: usageSnapshot.windowStart),
                "windowEnd": ISO8601DateFormatter().string(from: usageSnapshot.windowEnd),
                "captureMethod": usageSnapshot.captureMethod,
                "totalLaunches": usageSnapshot.totalLaunches,
                "totalUsageSeconds": usageSnapshot.totalUsageSeconds,
                "activeSessions": usageSnapshot.activeSessions.map { $0.toDictionary() }
            ]
        }
        
        let applicationsData: [String: Any] = [
            "installedApplications": apps,
            "runningProcesses": processes,
            "startupPrograms": startup,
            "applicationUsage": usageData
        ]
        
        return BaseModuleData(moduleId: moduleId, data: applicationsData)
    }
    
    // MARK: - Installed Applications (osquery: apps)
    
    private func collectInstalledApplications() async throws -> [[String: Any]] {
        // osquery apps table provides comprehensive app info
        let osqueryScript = """
            SELECT 
                name,
                path,
                bundle_identifier,
                bundle_name,
                bundle_short_version,
                bundle_version,
                category,
                compiler,
                development_region,
                display_name,
                info_string,
                minimum_system_version,
                element
            FROM apps
            WHERE path LIKE '/Applications/%'
               OR path LIKE '/System/Applications/%'
               OR path LIKE '%/Applications/%';
        """
        
        let result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: nil,
            python: nil
        )
        
        var applications: [[String: Any]] = []
        
        if let items = result["items"] as? [[String: Any]] {
            applications = items
        } else if !result.isEmpty && result["name"] != nil {
            // Single result
            applications = [result]
        }
        
        // If osquery didn't return results, fall back to bash
        if applications.isEmpty {
            applications = try await collectInstalledApplicationsBash()
        }
        
        // Transform to standardized format
        return applications.map { app in
            let path = app["path"] as? String ?? ""
            let name = app["name"] as? String ?? app["bundle_name"] as? String ?? app["display_name"] as? String ?? (path as NSString).lastPathComponent
            let version = app["bundle_short_version"] as? String ?? app["bundle_version"] as? String ?? ""
            let bundleId = app["bundle_identifier"] as? String ?? ""
            
            // Determine source based on path
            var source = "User"
            if path.hasPrefix("/System/") {
                source = "Apple"
            } else if path.hasPrefix("/Applications/") && !path.contains(NSHomeDirectory()) {
                source = "Local"
            } else if path.contains("App Store") || (app["element"] as? String)?.contains("mas") == true {
                source = "App Store"
            }
            
            return [
                "name": name,
                "path": path,
                "bundleIdentifier": bundleId,
                "version": version,
                "buildVersion": app["bundle_version"] as? String ?? "",
                "category": app["category"] as? String ?? "Unknown",
                "source": source,
                "minimumSystemVersion": app["minimum_system_version"] as? String ?? "",
                "developmentRegion": app["development_region"] as? String ?? "",
                "compiler": app["compiler"] as? String ?? ""
            ]
        }
    }
    
    private func collectInstalledApplicationsBash() async throws -> [[String: Any]] {
        let bashScript = """
            # List all .app bundles in standard locations
            find /Applications /System/Applications ~/Applications -maxdepth 3 -name "*.app" -type d 2>/dev/null | while read -r app_path; do
                plist="$app_path/Contents/Info.plist"
                [ ! -f "$plist" ] && continue
                
                name=$(/usr/libexec/PlistBuddy -c "Print :CFBundleName" "$plist" 2>/dev/null || basename "$app_path" .app)
                bundle_id=$(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$plist" 2>/dev/null || echo "")
                version=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$plist" 2>/dev/null || echo "")
                build=$(/usr/libexec/PlistBuddy -c "Print :CFBundleVersion" "$plist" 2>/dev/null || echo "")
                category=$(/usr/libexec/PlistBuddy -c "Print :LSApplicationCategoryType" "$plist" 2>/dev/null || echo "")
                
                # Escape for JSON
                name_escaped=$(echo "$name" | sed 's/\\\\/\\\\\\\\/g' | sed 's/"/\\\\"/g')
                path_escaped=$(echo "$app_path" | sed 's/\\\\/\\\\\\\\/g' | sed 's/"/\\\\"/g')
                
                echo "{\\"name\\": \\"$name_escaped\\", \\"path\\": \\"$path_escaped\\", \\"bundle_identifier\\": \\"$bundle_id\\", \\"bundle_short_version\\": \\"$version\\", \\"bundle_version\\": \\"$build\\", \\"category\\": \\"$category\\"},"
            done | sed '$ s/,$//'
        """
        
        let result = try await executeWithFallback(
            osquery: nil,
            bash: "echo '['; " + bashScript + " echo ']'",
            python: nil
        )
        
        if let items = result["items"] as? [[String: Any]] {
            return items
        }
        return []
    }
    
    // MARK: - Running Processes (osquery: processes)
    
    private func collectRunningProcesses() async throws -> [[String: Any]] {
        // osquery processes table for running process info
        let osqueryScript = """
            SELECT 
                p.pid,
                p.name,
                p.path,
                p.cmdline,
                p.state,
                p.cwd,
                p.root,
                p.uid,
                p.gid,
                p.euid,
                p.egid,
                p.on_disk,
                p.wired_size,
                p.resident_size,
                p.total_size,
                p.user_time,
                p.system_time,
                p.start_time,
                p.parent,
                u.username
            FROM processes p
            LEFT JOIN users u ON p.uid = u.uid
            WHERE p.pid > 0
            ORDER BY p.resident_size DESC
            LIMIT 100;
        """
        
        let bashScript = """
            # Get top processes by memory usage
            ps aux -m | head -101 | tail -100 | while read -r user pid cpu mem vsz rss tty stat start time command; do
                # Skip header line
                [ "$pid" = "PID" ] && continue
                
                # Escape command for JSON
                cmd_escaped=$(echo "$command" | sed 's/\\\\/\\\\\\\\/g' | sed 's/"/\\\\"/g')
                
                echo "{\\"pid\\": $pid, \\"name\\": \\"$cmd_escaped\\", \\"username\\": \\"$user\\", \\"cpu_percent\\": $cpu, \\"memory_percent\\": $mem, \\"resident_size\\": $((rss * 1024)), \\"state\\": \\"$stat\\"},"
            done | sed '$ s/,$//'
        """
        
        let result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: "echo '['; " + bashScript + " echo ']'",
            python: nil
        )
        
        var processes: [[String: Any]] = []
        
        if let items = result["items"] as? [[String: Any]] {
            processes = items
        } else if !result.isEmpty && result["pid"] != nil {
            processes = [result]
        }
        
        // Transform to standardized format
        return processes.map { proc in
            let pid = (proc["pid"] as? Int) ?? Int(proc["pid"] as? String ?? "0") ?? 0
            let name = proc["name"] as? String ?? ""
            let path = proc["path"] as? String ?? ""
            let state = proc["state"] as? String ?? ""
            let username = proc["username"] as? String ?? ""
            
            // Parse memory sizes
            let residentSize = (proc["resident_size"] as? Int64) ??
                              Int64(proc["resident_size"] as? String ?? "0") ?? 0
            let totalSize = (proc["total_size"] as? Int64) ??
                           Int64(proc["total_size"] as? String ?? "0") ?? 0
            
            // Parse times
            let userTime = (proc["user_time"] as? String) ?? "0"
            let systemTime = (proc["system_time"] as? String) ?? "0"
            let startTime = (proc["start_time"] as? String) ?? ""
            
            // Determine process state description
            var stateDesc = "Unknown"
            switch state.prefix(1) {
            case "R": stateDesc = "Running"
            case "S": stateDesc = "Sleeping"
            case "D": stateDesc = "Disk Sleep"
            case "T": stateDesc = "Stopped"
            case "Z": stateDesc = "Zombie"
            case "I": stateDesc = "Idle"
            default: stateDesc = state.isEmpty ? "Unknown" : state
            }
            
            return [
                "pid": pid,
                "name": name,
                "path": path,
                "commandLine": proc["cmdline"] as? String ?? "",
                "state": stateDesc,
                "username": username,
                "uid": (proc["uid"] as? Int) ?? Int(proc["uid"] as? String ?? "0") ?? 0,
                "parentPid": (proc["parent"] as? Int) ?? Int(proc["parent"] as? String ?? "0") ?? 0,
                "memoryResidentBytes": residentSize,
                "memoryTotalBytes": totalSize,
                "cpuUserTime": userTime,
                "cpuSystemTime": systemTime,
                "startTime": startTime,
                "workingDirectory": proc["cwd"] as? String ?? "",
                "isOnDisk": (proc["on_disk"] as? String == "1") ||
                           (proc["on_disk"] as? Bool == true)
            ]
        }
    }
    
    // MARK: - Startup Programs (osquery: startup_items + launchd)
    
    private func collectStartupPrograms() async throws -> [[String: Any]] {
        // osquery startup_items table + launchd for comprehensive startup info
        let osqueryScript = """
            SELECT 
                name,
                path,
                args,
                type,
                source,
                status,
                username
            FROM startup_items
            UNION ALL
            SELECT 
                label as name,
                program as path,
                program_arguments as args,
                'LaunchAgent/Daemon' as type,
                CASE 
                    WHEN path LIKE '/System/%' THEN 'System'
                    WHEN path LIKE '/Library/%' THEN 'Local'
                    ELSE 'User'
                END as source,
                CASE WHEN disabled = '0' THEN 'Enabled' ELSE 'Disabled' END as status,
                username
            FROM launchd
            WHERE run_at_load = '1';
        """
        
        let bashScript = """
            # Get login items for current user
            echo "["
            
            # Get LaunchAgents (user)
            for plist in ~/Library/LaunchAgents/*.plist; do
                [ ! -f "$plist" ] && continue
                label=$(/usr/libexec/PlistBuddy -c "Print :Label" "$plist" 2>/dev/null || basename "$plist" .plist)
                program=$(/usr/libexec/PlistBuddy -c "Print :Program" "$plist" 2>/dev/null || echo "")
                if [ -z "$program" ]; then
                    program=$(/usr/libexec/PlistBuddy -c "Print :ProgramArguments:0" "$plist" 2>/dev/null || echo "")
                fi
                disabled=$(/usr/libexec/PlistBuddy -c "Print :Disabled" "$plist" 2>/dev/null || echo "false")
                status="Enabled"
                [ "$disabled" = "true" ] && status="Disabled"
                
                label_escaped=$(echo "$label" | sed 's/"/\\\\"/g')
                program_escaped=$(echo "$program" | sed 's/"/\\\\"/g')
                
                echo "{\\"name\\": \\"$label_escaped\\", \\"path\\": \\"$program_escaped\\", \\"type\\": \\"LaunchAgent\\", \\"source\\": \\"User\\", \\"status\\": \\"$status\\"},"
            done
            
            # Get LaunchAgents (system)
            for plist in /Library/LaunchAgents/*.plist; do
                [ ! -f "$plist" ] && continue
                label=$(/usr/libexec/PlistBuddy -c "Print :Label" "$plist" 2>/dev/null || basename "$plist" .plist)
                program=$(/usr/libexec/PlistBuddy -c "Print :Program" "$plist" 2>/dev/null || echo "")
                if [ -z "$program" ]; then
                    program=$(/usr/libexec/PlistBuddy -c "Print :ProgramArguments:0" "$plist" 2>/dev/null || echo "")
                fi
                disabled=$(/usr/libexec/PlistBuddy -c "Print :Disabled" "$plist" 2>/dev/null || echo "false")
                status="Enabled"
                [ "$disabled" = "true" ] && status="Disabled"
                
                label_escaped=$(echo "$label" | sed 's/"/\\\\"/g')
                program_escaped=$(echo "$program" | sed 's/"/\\\\"/g')
                
                echo "{\\"name\\": \\"$label_escaped\\", \\"path\\": \\"$program_escaped\\", \\"type\\": \\"LaunchAgent\\", \\"source\\": \\"Local\\", \\"status\\": \\"$status\\"},"
            done
            
            # Get Login Items via osascript (if available)
            osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null | tr ',' '\\n' | while read -r item; do
                item=$(echo "$item" | xargs)
                [ -z "$item" ] && continue
                item_escaped=$(echo "$item" | sed 's/"/\\\\"/g')
                echo "{\\"name\\": \\"$item_escaped\\", \\"path\\": \\"\\", \\"type\\": \\"LoginItem\\", \\"source\\": \\"User\\", \\"status\\": \\"Enabled\\"},"
            done
            
            echo "{}]" | sed 's/,{}]/]/'
        """
        
        let result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript,
            python: nil
        )
        
        var startupItems: [[String: Any]] = []
        
        if let items = result["items"] as? [[String: Any]] {
            startupItems = items
        } else if !result.isEmpty && result["name"] != nil {
            startupItems = [result]
        }
        
        // Transform to standardized format
        return startupItems.compactMap { item -> [String: Any]? in
            let name = item["name"] as? String ?? ""
            guard !name.isEmpty else { return nil }
            
            let path = item["path"] as? String ?? ""
            let itemType = item["type"] as? String ?? "Unknown"
            let source = item["source"] as? String ?? "Unknown"
            let status = item["status"] as? String ?? "Unknown"
            
            // Parse arguments
            var arguments: [String] = []
            if let args = item["args"] as? String, !args.isEmpty {
                arguments = args.components(separatedBy: " ").filter { !$0.isEmpty }
            } else if let argsArray = item["args"] as? [String] {
                arguments = argsArray
            }
            
            return [
                "name": name,
                "path": path,
                "arguments": arguments,
                "type": itemType,
                "source": source,
                "status": status,
                "enabled": status == "Enabled",
                "username": item["username"] as? String ?? ""
            ]
        }
    }
}
