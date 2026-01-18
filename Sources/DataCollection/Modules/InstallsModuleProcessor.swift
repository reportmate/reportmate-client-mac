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
        async let munkiRunLog = collectMunkiRunLog()
        
        // Await all results
        let history = try await installHistory
        let homebrew = try await homebrewPackages
        let info = try await munkiInfo
        let installs = try await munkiInstalls
        let pending = try await pendingUpdates
        let runLog = try await munkiRunLog
        
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
        
        // Build installs data - runLog at top level like Cimian does
        var installsData: [String: Any] = [
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
                            "endTime": item.endTime,
                            "lastError": item.lastError,
                            "lastWarning": item.lastWarning,
                            "pendingReason": item.pendingReason
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
        
        // Add runLog at top level (same key as Cimian for API compatibility)
        if !runLog.isEmpty {
            installsData["runLog"] = runLog
        }
        
        return BaseModuleData(moduleId: moduleId, data: installsData)
    }
    
    // MARK: - Munki Run Log (extract last complete run from ManagedSoftwareUpdate.log)
    
    /// Collects the last complete run from Munki's ManagedSoftwareUpdate.log
    /// Munki logs are cumulative with runs delimited by:
    /// - "### Starting managedsoftwareupdate run: <type> ###"
    /// - "### Ending managedsoftwareupdate run ###"
    /// We extract only the last complete run (not all historical runs)
    private func collectMunkiRunLog() async throws -> String {
        let logPath = "/Library/Managed Installs/Logs/ManagedSoftwareUpdate.log"
        
        // Check if log exists
        guard FileManager.default.fileExists(atPath: logPath) else {
            return ""
        }
        
        // Use tac to read file in reverse, find markers, then restore order
        // This is efficient as it doesn't need to load the entire log file
        let bashScript = """
            logfile="/Library/Managed Installs/Logs/ManagedSoftwareUpdate.log"
            
            if [ ! -f "$logfile" ]; then
                exit 0
            fi
            
            # Use awk to find the last run by reading from the end
            # Get line numbers of all "### Starting" and "### Ending" markers
            ending_lines=$(grep -n "### Ending managedsoftwareupdate run ###" "$logfile" | tail -1 | cut -d: -f1)
            starting_lines=$(grep -n "### Starting managedsoftwareupdate run:" "$logfile" | tail -1 | cut -d: -f1)
            
            # If we have both markers and ending is after starting (complete run)
            if [ -n "$starting_lines" ] && [ -n "$ending_lines" ] && [ "$ending_lines" -ge "$starting_lines" ]; then
                # Extract lines from starting to ending (inclusive)
                sed -n "${starting_lines},${ending_lines}p" "$logfile"
            elif [ -n "$starting_lines" ]; then
                # Incomplete run - extract from starting to end of file
                sed -n "${starting_lines},\\$p" "$logfile"
            fi
            """
        
        // Execute bash script
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/bash")
        process.arguments = ["-c", bashScript]
        
        let outputPipe = Pipe()
        let errorPipe = Pipe()
        process.standardOutput = outputPipe
        process.standardError = errorPipe
        
        do {
            try process.run()
            process.waitUntilExit()
            
            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
               !output.isEmpty {
                // Limit to reasonable size (100KB max to avoid bloating the payload)
                let maxSize = 100_000
                if output.count > maxSize {
                    let truncated = String(output.suffix(maxSize))
                    return "... (truncated, showing last \(maxSize) characters) ...\n\n" + truncated
                }
                return output
            }
        } catch {
            // Log error but don't fail - run log is optional
            print("Warning: Failed to collect Munki run log: \(error)")
        }
        
        return ""
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
        
        // Robust bash fallback using PlistBuddy to read ManagedInstallReport.plist
        // This is the same plist the macadmins osquery extension reads
        let bashScript = """
            plistbuddy="/usr/libexec/PlistBuddy"
            report="/Library/Managed Installs/ManagedInstallReport.plist"
            prefs="/Library/Preferences/ManagedInstalls.plist"
            
            # Check if Munki is installed
            if [ ! -d "/Library/Managed Installs" ]; then
                echo '{"isInstalled": false}'
                exit 0
            fi
            
            # Start JSON output
            printf '{'
            printf '"isInstalled": true'
            
            # Get version from managedsoftwareupdate
            if [ -f "/usr/local/munki/managedsoftwareupdate" ]; then
                version=$(/usr/local/munki/managedsoftwareupdate --version 2>/dev/null | head -1 || echo "")
                printf ', "version": "%s"' "$version"
            fi
            
            # Get config from ManagedInstalls.plist preference file
            if [ -f "$prefs" ]; then
                softwareRepoURL=$($plistbuddy -c "Print :SoftwareRepoURL" "$prefs" 2>/dev/null || echo "")
                clientIdentifier=$($plistbuddy -c "Print :ClientIdentifier" "$prefs" 2>/dev/null || echo "")
                printf ', "softwareRepoURL": "%s"' "$softwareRepoURL"
                printf ', "clientIdentifier": "%s"' "$clientIdentifier"
            fi
            
            # Get last run info from ManagedInstallReport.plist
            if [ -f "$report" ]; then
                # ManifestName - the resolved manifest path
                manifestName=$($plistbuddy -c "Print :ManifestName" "$report" 2>/dev/null || echo "")
                printf ', "manifestName": "%s"' "$manifestName"
                
                # ManagedInstallVersion - version stored in report
                munkiVersion=$($plistbuddy -c "Print :ManagedInstallVersion" "$report" 2>/dev/null || echo "")
                if [ -n "$munkiVersion" ]; then
                    printf ', "version": "%s"' "$munkiVersion"
                fi
                
                # ConsoleUser at time of run
                consoleUser=$($plistbuddy -c "Print :ConsoleUser" "$report" 2>/dev/null || echo "")
                printf ', "consoleUser": "%s"' "$consoleUser"
                
                # StartTime and EndTime
                startTime=$($plistbuddy -c "Print :StartTime" "$report" 2>/dev/null || echo "")
                endTime=$($plistbuddy -c "Print :EndTime" "$report" 2>/dev/null || echo "")
                printf ', "startTime": "%s"' "$startTime"
                printf ', "endTime": "%s"' "$endTime"
                
                # Errors (array - check if empty)
                errorCount=$($plistbuddy -c "Print :Errors" "$report" 2>/dev/null | grep -c "^    " || echo "0")
                if [ "$errorCount" -gt 0 ]; then
                    errors=$($plistbuddy -c "Print :Errors" "$report" 2>/dev/null | grep "^    " | tr '\\n' ';' | sed 's/^[[:space:]]*//' || echo "")
                    # Escape quotes
                    errors=$(echo "$errors" | sed 's/"/\\\\"/g')
                    printf ', "errors": "%s"' "$errors"
                    printf ', "success": "false"'
                else
                    printf ', "success": "true"'
                fi
                
                # Warnings (array)
                warningCount=$($plistbuddy -c "Print :Warnings" "$report" 2>/dev/null | grep -c "^    " || echo "0")
                if [ "$warningCount" -gt 0 ]; then
                    warnings=$($plistbuddy -c "Print :Warnings" "$report" 2>/dev/null | grep "^    " | tr '\\n' ';' | sed 's/^[[:space:]]*//' || echo "")
                    warnings=$(echo "$warnings" | sed 's/"/\\\\"/g')
                    printf ', "warnings": "%s"' "$warnings"
                fi
                
                # ProblemInstalls (array)
                problemCount=$($plistbuddy -c "Print :ProblemInstalls" "$report" 2>/dev/null | grep -c "^    " || echo "0")
                if [ "$problemCount" -gt 0 ]; then
                    problems=$($plistbuddy -c "Print :ProblemInstalls" "$report" 2>/dev/null | grep "^    " | tr '\\n' ';' | sed 's/^[[:space:]]*//' || echo "")
                    problems=$(echo "$problems" | sed 's/"/\\\\"/g')
                    printf ', "problemInstalls": "%s"' "$problems"
                fi
            fi
            
            printf '}'
            """
        
        let result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript
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
            bash: bashScript
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
            bash: bashScript
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
        // Columns: name, display_name, installed, installed_version, end_time
        let osqueryScript = """
            SELECT 
                name,
                display_name,
                installed,
                installed_version,
                end_time
            FROM munki_installs;
            """
        
        // Robust bash fallback using PlistBuddy to read ManagedInstallReport.plist
        // This is the same plist the macadmins osquery extension reads
        let bashScript = """
            report="/Library/Managed Installs/ManagedInstallReport.plist"
            plistbuddy="/usr/libexec/PlistBuddy"
            
            if [ ! -f "$report" ]; then
                echo '[]'
                exit 0
            fi
            
            # Get the count of ManagedInstalls
            count=$($plistbuddy -c "Print :ManagedInstalls" "$report" 2>/dev/null | grep -c "^    Dict" || echo "0")
            
            if [ "$count" -eq 0 ]; then
                echo '[]'
                exit 0
            fi
            
            # Get end_time from the report (same for all items in this run)
            end_time=$($plistbuddy -c "Print :EndTime" "$report" 2>/dev/null || echo "")
            
            echo "["
            first=true
            
            i=0
            while [ $i -lt $count ]; do
                name=$($plistbuddy -c "Print :ManagedInstalls:$i:name" "$report" 2>/dev/null || echo "")
                display_name=$($plistbuddy -c "Print :ManagedInstalls:$i:display_name" "$report" 2>/dev/null || echo "$name")
                installed=$($plistbuddy -c "Print :ManagedInstalls:$i:installed" "$report" 2>/dev/null || echo "false")
                installed_version=$($plistbuddy -c "Print :ManagedInstalls:$i:installed_version" "$report" 2>/dev/null || echo "")
                installed_size=$($plistbuddy -c "Print :ManagedInstalls:$i:installed_size" "$report" 2>/dev/null || echo "0")
                
                # Escape any quotes in strings for JSON
                name=$(echo "$name" | sed 's/"/\\\\"/g')
                display_name=$(echo "$display_name" | sed 's/"/\\\\"/g')
                
                if [ -n "$name" ]; then
                    if [ "$first" = "true" ]; then
                        first=false
                    else
                        echo ","
                    fi
                    
                    # Output JSON object
                    printf '{"name": "%s", "display_name": "%s", "installed": "%s", "installed_version": "%s", "installed_size": %s, "end_time": "%s"}' \\
                        "$name" "$display_name" "$installed" "$installed_version" "${installed_size:-0}" "$end_time"
                fi
                
                i=$((i + 1))
            done
            
            echo "]"
            """
        
        let result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript
        )
        
        var items: [MunkiItem] = []
        
        if let resultItems = result["items"] as? [[String: Any]] {
            for itemData in resultItems {
                var item = MunkiItem()
                
                let name = itemData["name"] as? String ?? ""
                item.name = name
                // Use display_name from osquery/bash if available, otherwise fall back to name
                item.displayName = itemData["display_name"] as? String ?? itemData["displayName"] as? String ?? name
                item.id = name.lowercased().replacingOccurrences(of: " ", with: "-")
                item.version = itemData["version"] as? String ?? ""
                item.installedVersion = itemData["installed_version"] as? String ?? itemData["installedVersion"] as? String ?? ""
                
                // Handle installed_size - could be Int or String
                if let sizeInt = itemData["installed_size"] as? Int {
                    item.installedSize = sizeInt
                } else if let sizeStr = itemData["installed_size"] as? String, let sizeInt = Int(sizeStr) {
                    item.installedSize = sizeInt
                } else if let sizeInt = itemData["installedSize"] as? Int {
                    item.installedSize = sizeInt
                }
                
                item.endTime = itemData["end_time"] as? String ?? itemData["endTime"] as? String ?? ""
                item.type = "munki"
                
                // Map 'installed' column to status
                let installedStr = itemData["installed"] as? String ?? ""
                let statusStr = itemData["status"] as? String ?? ""
                
                if statusStr == "pending_removal" {
                    item.status = "Removed"
                } else if installedStr.lowercased() == "true" || installedStr == "1" {
                    item.status = "Installed"
                } else {
                    item.status = "Pending"
                }
                
                // Derive pendingReason for pending items
                if item.status == "Pending" {
                    item.pendingReason = derivePendingReason(item: item)
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
            bash: bashScript
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
    
    // MARK: - Derive Pending Reason
    
    /// Derives a human-readable pending reason for a MunkiItem based on its state
    /// Mirrors the Windows CimianItem.DerivePendingReason() logic
    private func derivePendingReason(item: MunkiItem) -> String {
        let version = item.version.isEmpty ? "Unknown" : item.version
        let installedVersion = item.installedVersion.isEmpty ? "Unknown" : item.installedVersion
        
        // Not yet installed (no installed version)
        if installedVersion == "Unknown" || installedVersion.isEmpty {
            return "Not yet installed"
        }
        
        // Version mismatch = update available
        if version != installedVersion && version != "Unknown" {
            return "Update available: \(installedVersion) → \(version)"
        }
        
        // Versions match but still pending (possible re-install or metadata sync)
        if version == installedVersion {
            return "Reinstallation pending"
        }
        
        // Generic pending
        return "Installation pending"
    }
}
