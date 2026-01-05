import Foundation

/// Installs module processor - uses osquery first with bash fallback
/// Supports both Munki (macOS) and Cimian (cross-platform) managed installs
/// Reference: https://github.com/macadmins/osquery-extension for Munki tables
/// Tables: munki_info, munki_installs (macadmins extension)
/// NO PYTHON - uses osquery for: package_install_history, homebrew_packages, munki_info, munki_installs
/// Bash/plutil/awk fallback for: Munki manifests, install history plist
public class InstallsModuleProcessor: BaseModuleProcessor, @unchecked Sendable {
    
    public init(configuration: ReportMateConfiguration) {
        super.init(moduleId: "installs", configuration: configuration)
    }
    
    public override func collectData() async throws -> ModuleData {
        // Collect install data in parallel
        async let installHistory = collectInstallHistory()
        async let homebrewPackages = collectHomebrewPackages()
        async let munkiInfo = collectMunkiInfo()
        async let munkiInstalls = collectMunkiManagedInstalls()
        async let pendingUpdates = collectPendingUpdates()
        
        // Await all results
        let history = try await installHistory
        let homebrew = try await homebrewPackages
        let info = try await munkiInfo
        let installs = try await munkiInstalls
        let pending = try await pendingUpdates
        
        // Build MunkiInfo object if Munki is detected
        var munkiInfoObject: MunkiInfo? = nil
        if info["isInstalled"] as? Bool == true || !installs.isEmpty {
            var munki = MunkiInfo()
            munki.isInstalled = info["isInstalled"] as? Bool ?? !installs.isEmpty
            munki.version = info["version"] as? String ?? ""
            munki.clientIdentifier = info["clientIdentifier"] as? String
            munki.manifestName = info["manifestName"] as? String
            munki.softwareRepoURL = info["softwareRepoURL"] as? String
            munki.consoleUser = info["consoleUser"] as? String
            munki.startTime = info["startTime"] as? String
            munki.endTime = info["endTime"] as? String
            munki.lastRunSuccess = (info["success"] as? String) == "true"
            munki.errors = info["errors"] as? String
            munki.warnings = info["warnings"] as? String
            munki.problemInstalls = info["problemInstalls"] as? String
            
            // Parse endTime to lastRun date
            if let endTimeStr = info["endTime"] as? String, !endTimeStr.isEmpty {
                let formatter = ISO8601DateFormatter()
                formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
                munki.lastRun = formatter.date(from: endTimeStr)
            }
            
            // Determine overall status
            if let errors = munki.errors, !errors.isEmpty {
                munki.status = "Error"
            } else if let warnings = munki.warnings, !warnings.isEmpty {
                munki.status = "Warning"
            } else if munki.lastRunSuccess {
                munki.status = "Active"
            } else if munki.isInstalled {
                munki.status = "Inactive"
            }
            
            // Add collected items
            munki.items = installs
            
            munkiInfoObject = munki
        }
        
        let installsData: [String: Any] = [
            "installHistory": history,
            "homebrewPackages": homebrew,
            "managedInstalls": installs.map { item -> [String: Any] in
                [
                    "name": item.name,
                    "displayName": item.displayName,
                    "version": item.version,
                    "installedVersion": item.installedVersion,
                    "status": item.status,
                    "type": item.type,
                    "installedSize": item.installedSize
                ]
            },
            "pendingUpdates": pending,
            "munki": munkiInfoObject.map { munki -> [String: Any] in
                var dict: [String: Any] = [
                    "isInstalled": munki.isInstalled,
                    "version": munki.version,
                    "status": munki.status,
                    "lastRunSuccess": munki.lastRunSuccess,
                    "items": munki.items.map { item -> [String: Any] in
                        [
                            "id": item.id,
                            "name": item.name,
                            "displayName": item.displayName,
                            "version": item.version,
                            "installedVersion": item.installedVersion,
                            "status": item.status,
                            "type": item.type,
                            "installedSize": item.installedSize,
                            "endTime": item.endTime
                        ]
                    }
                ]
                if let clientId = munki.clientIdentifier { dict["clientIdentifier"] = clientId }
                if let manifest = munki.manifestName { dict["manifestName"] = manifest }
                if let repoURL = munki.softwareRepoURL { dict["softwareRepoURL"] = repoURL }
                if let console = munki.consoleUser { dict["consoleUser"] = console }
                if let start = munki.startTime { dict["startTime"] = start }
                if let end = munki.endTime { dict["endTime"] = end }
                if let errors = munki.errors { dict["errors"] = errors }
                if let warnings = munki.warnings { dict["warnings"] = warnings }
                if let problems = munki.problemInstalls { dict["problemInstalls"] = problems }
                if let lastRun = munki.lastRun { dict["lastRun"] = ISO8601DateFormatter().string(from: lastRun) }
                return dict
            } ?? [:]
        ]
        
        return BaseModuleData(moduleId: moduleId, data: installsData)
    }
    
    // MARK: - Munki Info (osquery: munki_info table via macadmins extension)
    
    private func collectMunkiInfo() async throws -> [String: Any] {
        // osquery munki_info table from macadmins extension
        // Reference: https://fleetdm.com/tables/munki_info
        let osqueryScript = """
            SELECT 
                version,
                manifest_name,
                console_user,
                start_time,
                end_time,
                success,
                errors,
                warnings,
                problem_installs
            FROM munki_info;
            """
        
        // Bash fallback: Read from Munki preferences and ManagedInstallReport
        let bashScript = """
            # Check if Munki is installed
            if [ ! -d "/Library/Managed Installs" ]; then
                echo '{"isInstalled": false}'
                exit 0
            fi
            
            echo '{"isInstalled": true,'
            
            # Get version from managedsoftwareupdate
            if [ -f "/usr/local/munki/managedsoftwareupdate" ]; then
                version=$(/usr/local/munki/managedsoftwareupdate --version 2>/dev/null | head -1 || echo "")
                echo '"version": "'$version'",'
            fi
            
            # Get config from ManagedInstalls plist
            plist="/Library/Preferences/ManagedInstalls.plist"
            if [ -f "$plist" ]; then
                softwareRepoURL=$(defaults read "$plist" SoftwareRepoURL 2>/dev/null || echo "")
                clientIdentifier=$(defaults read "$plist" ClientIdentifier 2>/dev/null || echo "")
                echo '"softwareRepoURL": "'$softwareRepoURL'",'
                echo '"clientIdentifier": "'$clientIdentifier'",'
            fi
            
            # Get last run info from ManagedInstallReport
            report="/Library/Managed Installs/ManagedInstallReport.plist"
            if [ -f "$report" ]; then
                startTime=$(defaults read "$report" StartTime 2>/dev/null || echo "")
                endTime=$(defaults read "$report" EndTime 2>/dev/null || echo "")
                consoleUser=$(defaults read "$report" ConsoleUser 2>/dev/null || echo "")
                errors=$(defaults read "$report" Errors 2>/dev/null | tr '\\n' ' ' || echo "")
                warnings=$(defaults read "$report" Warnings 2>/dev/null | tr '\\n' ' ' || echo "")
                problemInstalls=$(defaults read "$report" ProblemInstalls 2>/dev/null | tr '\\n' ' ' || echo "")
                
                echo '"startTime": "'$startTime'",'
                echo '"endTime": "'$endTime'",'
                echo '"consoleUser": "'$consoleUser'",'
                
                # Determine success based on errors
                if [ -z "$errors" ]; then
                    echo '"success": "true",'
                else
                    echo '"success": "false",'
                fi
                
                echo '"errors": "'$errors'",'
                echo '"warnings": "'$warnings'",'
                echo '"problemInstalls": "'$problemInstalls'"'
            else
                echo '"success": "false"'
            fi
            
            echo '}'
            """
        
        let result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript,
            python: nil
        )
        
        var info: [String: Any] = [:]
        
        // Check if Munki is installed (either via osquery result or bash fallback)
        let hasData = result["version"] != nil || result["isInstalled"] as? Bool == true
        info["isInstalled"] = hasData
        
        if let version = result["version"] as? String, !version.isEmpty {
            info["version"] = version
        }
        
        // Map osquery column names to our model names
        info["manifestName"] = result["manifest_name"] as? String ?? result["manifestName"] as? String
        info["consoleUser"] = result["console_user"] as? String ?? result["consoleUser"] as? String
        info["startTime"] = result["start_time"] as? String ?? result["startTime"] as? String
        info["endTime"] = result["end_time"] as? String ?? result["endTime"] as? String
        info["success"] = result["success"] as? String
        info["errors"] = result["errors"] as? String
        info["warnings"] = result["warnings"] as? String
        info["problemInstalls"] = result["problem_installs"] as? String ?? result["problemInstalls"] as? String
        info["softwareRepoURL"] = result["softwareRepoURL"] as? String
        info["clientIdentifier"] = result["clientIdentifier"] as? String
        
        return info
    }
    
    // MARK: - Install History (osquery: package_install_history)
    
    private func collectInstallHistory() async throws -> [[String: Any]] {
        // osquery package_install_history table for macOS installer history
        let osqueryScript = """
            SELECT 
                package_id,
                name,
                version,
                source,
                time
            FROM package_install_history
            ORDER BY time DESC
            LIMIT 100;
            """
        
        // Pure bash + plutil + awk approach - NO Python
        let bashScript = """
            history_file="/Library/Receipts/InstallHistory.plist"
            
            if [ -f "$history_file" ]; then
                # Convert plist to JSON
                json_output=$(plutil -convert json -o - "$history_file" 2>/dev/null)
                
                if [ -n "$json_output" ]; then
                    # Parse JSON using awk (no Python/JavaScript needed for basic extraction)
                    # Output last 100 entries as JSON array
                    echo "$json_output" | awk '
                    BEGIN { RS="},"; FS="\\n"; count=0; print "[" }
                    {
                        if (count >= 100) exit
                        name=""; version=""; pkgId=""; date=""; process=""
                        for (i=1; i<=NF; i++) {
                            if ($i ~ /"displayName"/) {
                                gsub(/.*"displayName"[[:space:]]*:[[:space:]]*"/, "", $i)
                                gsub(/".*/, "", $i)
                                name = $i
                            }
                            if ($i ~ /"displayVersion"/) {
                                gsub(/.*"displayVersion"[[:space:]]*:[[:space:]]*"/, "", $i)
                                gsub(/".*/, "", $i)
                                version = $i
                            }
                            if ($i ~ /"processName"/) {
                                gsub(/.*"processName"[[:space:]]*:[[:space:]]*"/, "", $i)
                                gsub(/".*/, "", $i)
                                process = $i
                            }
                            if ($i ~ /"date"/) {
                                gsub(/.*"date"[[:space:]]*:[[:space:]]*"/, "", $i)
                                gsub(/".*/, "", $i)
                                date = $i
                            }
                        }
                        if (name != "") {
                            if (count > 0) printf ","
                            printf "{\\"name\\": \\"%s\\", \\"version\\": \\"%s\\", \\"time\\": \\"%s\\", \\"source\\": \\"%s\\"}", name, version, date, process
                            count++
                        }
                    }
                    END { print "]" }
                    ' 2>/dev/null || echo '[]'
                else
                    echo '[]'
                fi
            else
                echo '[]'
            fi
            """
        
        let result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript,
            python: nil
        )
        
        var history: [[String: Any]] = []
        
        if let items = result["items"] as? [[String: Any]] {
            history = items
        }
        
        return history.map { item in
            [
                "name": item["name"] as? String ?? "",
                "version": item["version"] as? String ?? "",
                "packageId": item["package_id"] as? String ?? "",
                "installedDate": item["time"] as? String ?? "",
                "source": item["source"] as? String ?? ""
            ]
        }
    }
    
    // MARK: - Homebrew Packages (osquery: homebrew_packages)
    
    private func collectHomebrewPackages() async throws -> [[String: Any]] {
        // osquery homebrew_packages table
        let osqueryScript = """
            SELECT 
                name,
                version,
                path,
                prefix
            FROM homebrew_packages;
            """
        
        let bashScript = """
            # Get Homebrew packages if installed - pure bash with awk
            if command -v brew >/dev/null 2>&1; then
                brew list --versions 2>/dev/null | awk '
                BEGIN { print "["; first = 1 }
                {
                    name = $1
                    $1 = ""
                    version = $0
                    gsub(/^[[:space:]]+/, "", version)
                    if (!first) print ","
                    printf "{\\"name\\": \\"%s\\", \\"version\\": \\"%s\\"}", name, version
                    first = 0
                }
                END { print "]" }
                '
            else
                echo '[]'
            fi
            """
        
        let result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript,
            python: nil
        )
        
        var packages: [[String: Any]] = []
        
        if let items = result["items"] as? [[String: Any]] {
            packages = items
        }
        
        return packages.map { pkg in
            [
                "name": pkg["name"] as? String ?? "",
                "version": pkg["version"] as? String ?? "",
                "installPath": pkg["path"] as? String ?? pkg["prefix"] as? String ?? ""
            ]
        }
    }
    
    // MARK: - Munki Managed Installs (osquery: munki_installs table via macadmins extension)
    
    private func collectMunkiManagedInstalls() async throws -> [MunkiItem] {
        // osquery munki_installs table from macadmins extension
        // Reference: https://fleetdm.com/tables/munki_installs
        let osqueryScript = """
            SELECT 
                name,
                installed,
                installed_version,
                end_time
            FROM munki_installs;
            """
        
        // Bash fallback: Parse Munki InstallInfo.plist
        let bashScript = """
            managed_install_dir="/Library/Managed Installs"
            install_info="$managed_install_dir/InstallInfo.plist"
            
            if [ -f "$install_info" ]; then
                plutil -convert json -o - "$install_info" 2>/dev/null | awk '
                BEGIN { 
                    RS="},"; 
                    in_managed=0; 
                    in_removals=0; 
                    print "["; 
                    first=1 
                }
                /"managed_installs"/ { in_managed=1 }
                /"removals"/ { in_managed=0; in_removals=1 }
                {
                    if (in_managed || in_removals) {
                        name=""; version=""; size=0; installed="false"
                        if (match($0, /"name"[[:space:]]*:[[:space:]]*"[^"]+"/)) {
                            n = substr($0, RSTART, RLENGTH)
                            gsub(/.*"name"[[:space:]]*:[[:space:]]*"/, "", n)
                            gsub(/".*/, "", n)
                            name = n
                        }
                        if (match($0, /"version_to_install"[[:space:]]*:[[:space:]]*"[^"]+"/)) {
                            v = substr($0, RSTART, RLENGTH)
                            gsub(/.*"version_to_install"[[:space:]]*:[[:space:]]*"/, "", v)
                            gsub(/".*/, "", v)
                            version = v
                        }
                        if (match($0, /"installed_size"[[:space:]]*:[[:space:]]*[0-9]+/)) {
                            s = substr($0, RSTART, RLENGTH)
                            gsub(/.*"installed_size"[[:space:]]*:[[:space:]]*/, "", s)
                            size = s
                        }
                        if (match($0, /"installed"[[:space:]]*:[[:space:]]*(true|false)/)) {
                            i = substr($0, RSTART, RLENGTH)
                            if (i ~ /true/) installed = "true"
                        }
                        if (name != "") {
                            status = in_removals ? "pending_removal" : (installed == "true" ? "installed" : "pending")
                            if (!first) printf ","
                            printf "{\\"name\\": \\"%s\\", \\"version\\": \\"%s\\", \\"status\\": \\"%s\\", \\"installed\\": \\"%s\\", \\"installedSize\\": %d}", name, version, status, installed, size
                            first=0
                        }
                    }
                }
                END { print "]" }
                ' 2>/dev/null || echo '[]'
            else
                echo '[]'
            fi
            """
        
        let result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript,
            python: nil
        )
        
        var items: [MunkiItem] = []
        
        if let resultItems = result["items"] as? [[String: Any]] {
            for itemData in resultItems {
                var item = MunkiItem()
                
                let name = itemData["name"] as? String ?? ""
                item.name = name
                item.displayName = name  // Munki doesn't have separate display name in osquery
                item.id = name.lowercased().replacingOccurrences(of: " ", with: "-")
                item.version = itemData["version"] as? String ?? ""
                item.installedVersion = itemData["installed_version"] as? String ?? itemData["installedVersion"] as? String ?? ""
                item.installedSize = itemData["installedSize"] as? Int ?? 0
                item.endTime = itemData["end_time"] as? String ?? ""
                item.type = "munki"
                
                // Map 'installed' column to status
                let installedStr = itemData["installed"] as? String ?? ""
                let statusStr = itemData["status"] as? String ?? ""
                
                if statusStr == "pending_removal" {
                    item.status = "Removed"
                } else if installedStr == "true" || installedStr == "1" {
                    item.status = "Installed"
                } else {
                    item.status = "Pending"
                }
                
                items.append(item)
            }
        }
        
        return items
    }
    
    // MARK: - Pending Updates - NO Python
    
    private func collectPendingUpdates() async throws -> [[String: Any]] {
        // Check for pending software updates using pure bash + awk
        let bashScript = """
            (
            echo "["
            first=true
            
            # Check Software Update and output as JSON
            softwareupdate -l 2>&1 | grep -E "^[[:space:]]+\\*" | while read -r line; do
                name=$(echo "$line" | sed 's/^[[:space:]]*\\*[[:space:]]*//' | sed 's/,.*//')
                version=$(echo "$line" | grep -oE 'Version: [0-9.]+' | sed 's/Version: //')
                size=$(echo "$line" | grep -oE 'Size: [0-9]+' | sed 's/Size: //')
                
                # Escape for JSON
                name_esc=$(echo "$name" | sed 's/"/\\\\"/g')
                
                if [ "$first" = "true" ]; then
                    first=false
                else
                    echo ","
                fi
                
                echo "{\\"name\\": \\"$name_esc\\", \\"version\\": \\"$version\\", \\"size\\": \\"$size\\", \\"source\\": \\"softwareupdate\\"}"
            done
            
            # Check Munki pending installs using awk (NO Python)
            munki_report="/Library/Managed Installs/ManagedInstallReport.plist"
            if [ -f "$munki_report" ]; then
                plutil -convert json -o - "$munki_report" 2>/dev/null | awk '
                BEGIN { RS="},"; in_items=0 }
                /"ItemsToInstall"/ { in_items=1 }
                {
                    if (in_items) {
                        name=""; version=""
                        if (match($0, /"display_name"[[:space:]]*:[[:space:]]*"[^"]+"/)) {
                            n = substr($0, RSTART, RLENGTH)
                            gsub(/.*"display_name"[[:space:]]*:[[:space:]]*"/, "", n)
                            gsub(/".*/, "", n)
                            name = n
                        }
                        if (name == "" && match($0, /"name"[[:space:]]*:[[:space:]]*"[^"]+"/)) {
                            n = substr($0, RSTART, RLENGTH)
                            gsub(/.*"name"[[:space:]]*:[[:space:]]*"/, "", n)
                            gsub(/".*/, "", n)
                            name = n
                        }
                        if (match($0, /"version_to_install"[[:space:]]*:[[:space:]]*"[^"]+"/)) {
                            v = substr($0, RSTART, RLENGTH)
                            gsub(/.*"version_to_install"[[:space:]]*:[[:space:]]*"/, "", v)
                            gsub(/".*/, "", v)
                            version = v
                        }
                        if (name != "") {
                            printf ",{\\"name\\": \\"%s\\", \\"version\\": \\"%s\\", \\"source\\": \\"munki\\"}", name, version
                        }
                    }
                }
                ' 2>/dev/null
            fi
            
            echo "]"
            ) 2>/dev/null | tr -d '\\n' | sed 's/\\[,/[/' | sed 's/,,/,/g'
            """
        
        let result = try await executeWithFallback(
            osquery: nil,
            bash: bashScript,
            python: nil
        )
        
        var updates: [[String: Any]] = []
        
        if let items = result["items"] as? [[String: Any]] {
            updates = items
        }
        
        return updates.map { update in
            [
                "name": update["name"] as? String ?? "",
                "version": update["version"] as? String ?? "",
                "size": update["size"] as? String ?? "",
                "source": update["source"] as? String ?? "unknown"
            ]
        }
    }
}
