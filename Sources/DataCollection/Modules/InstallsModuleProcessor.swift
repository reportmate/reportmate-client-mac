import Foundation

/// Installs module processor - uses osquery first with bash fallback
/// Based on MunkiReport patterns for managed install collection
/// Reference: https://github.com/munkireport/munkireport (installhistory)
/// NO PYTHON - uses osquery for: package_install_history, homebrew_packages
/// Bash/plutil/awk fallback for: Munki manifests, install history plist
public class InstallsModuleProcessor: BaseModuleProcessor, @unchecked Sendable {
    
    public init(configuration: ReportMateConfiguration) {
        super.init(moduleId: "installs", configuration: configuration)
    }
    
    public override func collectData() async throws -> ModuleData {
        // Collect install data in parallel
        async let installHistory = collectInstallHistory()
        async let homebrewPackages = collectHomebrewPackages()
        async let munkiInstalls = collectMunkiManagedInstalls()
        async let pendingUpdates = collectPendingUpdates()
        
        // Await all results
        let history = try await installHistory
        let homebrew = try await homebrewPackages
        let munki = try await munkiInstalls
        let pending = try await pendingUpdates
        
        let installsData: [String: Any] = [
            "installHistory": history,
            "homebrewPackages": homebrew,
            "managedInstalls": munki,
            "pendingUpdates": pending
        ]
        
        return BaseModuleData(moduleId: moduleId, data: installsData)
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
    
    // MARK: - Munki Managed Installs (bash: ManagedInstallDir) - NO Python
    
    private func collectMunkiManagedInstalls() async throws -> [[String: Any]] {
        // Parse Munki InstallInfo.plist using pure bash + plutil + awk
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
                        name=""; version=""; size=0
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
                        if (name != "") {
                            status = in_removals ? "pending_removal" : "managed"
                            if (!first) printf ","
                            printf "{\\"name\\": \\"%s\\", \\"version\\": \\"%s\\", \\"status\\": \\"%s\\", \\"installedSize\\": %d}", name, version, status, size
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
        
        // Also check for Cimian managed installs (ReportMate specific) - NO Python
        let cimianBashScript = """
            cimian_dir="/Library/Cimian"
            manifest="$cimian_dir/manifest.plist"
            
            if [ -f "$manifest" ]; then
                plutil -convert json -o - "$manifest" 2>/dev/null | awk '
                BEGIN { 
                    RS="},"; 
                    in_managed=0; 
                    print "["; 
                    first=1 
                }
                /"managed_installs"/ { in_managed=1 }
                {
                    if (in_managed) {
                        name=""; version=""
                        if (match($0, /"name"[[:space:]]*:[[:space:]]*"[^"]+"/)) {
                            n = substr($0, RSTART, RLENGTH)
                            gsub(/.*"name"[[:space:]]*:[[:space:]]*"/, "", n)
                            gsub(/".*/, "", n)
                            name = n
                        }
                        if (match($0, /"version"[[:space:]]*:[[:space:]]*"[^"]+"/)) {
                            v = substr($0, RSTART, RLENGTH)
                            gsub(/.*"version"[[:space:]]*:[[:space:]]*"/, "", v)
                            gsub(/".*/, "", v)
                            version = v
                        }
                        if (name != "") {
                            if (!first) printf ","
                            printf "{\\"name\\": \\"%s\\", \\"version\\": \\"%s\\", \\"status\\": \\"cimian_managed\\"}", name, version
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
        
        // Execute both in sequence
        let munkiResult = try await executeWithFallback(
            osquery: nil,
            bash: bashScript,
            python: nil
        )
        
        let cimianResult = try await executeWithFallback(
            osquery: nil,
            bash: cimianBashScript,
            python: nil
        )
        
        var allInstalls: [[String: Any]] = []
        
        if let munkiItems = munkiResult["items"] as? [[String: Any]] {
            allInstalls.append(contentsOf: munkiItems)
        }
        
        if let cimianItems = cimianResult["items"] as? [[String: Any]] {
            allInstalls.append(contentsOf: cimianItems)
        }
        
        return allInstalls.map { item in
            [
                "name": item["name"] as? String ?? "",
                "version": item["version"] as? String ?? "",
                "status": item["status"] as? String ?? "unknown",
                "installedSize": item["installedSize"] as? Int ?? 0
            ]
        }
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
