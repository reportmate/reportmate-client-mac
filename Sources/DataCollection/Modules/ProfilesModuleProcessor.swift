import Foundation

/// Profiles module processor - uses osquery first with bash fallback
/// Based on MunkiReport patterns for profile collection
/// Reference: https://github.com/munkireport/profile
/// No Python - uses osquery for: system_extensions, managed_policies
/// Bash fallback for: profiles command, kernel/system extensions
public class ProfilesModuleProcessor: BaseModuleProcessor, @unchecked Sendable {
    
    public init(configuration: ReportMateConfiguration) {
        super.init(moduleId: "profiles", configuration: configuration)
    }
    
    public override func collectData() async throws -> ModuleData {
        // Collect profile data in parallel
        async let configProfiles = collectConfigurationProfiles()
        async let systemExtensions = collectSystemExtensions()
        async let kernelExtensions = collectKernelExtensions()
        async let loginItems = collectLoginItems()
        async let serviceManagement = collectServiceManagement()
        
        // Await all results
        let profiles = try await configProfiles
        let sysExt = try await systemExtensions
        let kext = try await kernelExtensions
        let login = try await loginItems
        let services = try await serviceManagement
        
        let profilesData: [String: Any] = [
            "configurationProfiles": profiles,
            "systemExtensions": sysExt,
            "kernelExtensions": kext,
            "loginItems": login,
            "serviceManagement": services
        ]
        
        return BaseModuleData(moduleId: moduleId, data: profilesData)
    }
    
    // MARK: - Configuration Profiles (bash: profiles command)
    
    private func collectConfigurationProfiles() async throws -> [[String: Any]] {
        // osquery managed_policies for MDM-deployed profiles
        let osqueryScript = """
            SELECT 
                domain,
                name,
                value,
                manual
            FROM managed_policies
            WHERE domain != '';
        """
        
        // Pure bash + awk solution for profile parsing (NO Python)
        let bashScript = """
            # Get configuration profiles using profiles command - parsed with awk
            profiles_output=$(profiles list 2>/dev/null || echo "")
            
            if [ -n "$profiles_output" ]; then
                echo "["
                echo "$profiles_output" | awk '
                BEGIN { 
                    first = 1 
                    identifier = ""
                    name = ""
                    org = ""
                    uuid = ""
                    scope = "system"
                }
                /_computerlevel/ { scope = "system" }
                /_userlevel/ { scope = "user" }
                /profileIdentifier:/ { 
                    gsub(/.*profileIdentifier:[[:space:]]*/, "")
                    identifier = $0
                }
                /profileDisplayName:/ { 
                    gsub(/.*profileDisplayName:[[:space:]]*/, "")
                    name = $0
                }
                /profileOrganization:/ { 
                    gsub(/.*profileOrganization:[[:space:]]*/, "")
                    org = $0
                }
                /profileUUID:/ { 
                    gsub(/.*profileUUID:[[:space:]]*/, "")
                    uuid = $0
                }
                /\\{$/ || /^[[:space:]]*\\}$/ {
                    if (identifier != "") {
                        if (!first) printf ","
                        printf "{\\"identifier\\": \\"%s\\", \\"displayName\\": \\"%s\\", \\"organization\\": \\"%s\\", \\"uuid\\": \\"%s\\", \\"scope\\": \\"%s\\", \\"verified\\": true}", identifier, name, org, uuid, scope
                        first = 0
                        identifier = ""
                        name = ""
                        org = ""
                        uuid = ""
                    }
                }
                END {
                    if (identifier != "") {
                        if (!first) printf ","
                        printf "{\\"identifier\\": \\"%s\\", \\"displayName\\": \\"%s\\", \\"organization\\": \\"%s\\", \\"uuid\\": \\"%s\\", \\"scope\\": \\"%s\\", \\"verified\\": true}", identifier, name, org, uuid, scope
                    }
                }
                '
                echo "]"
            else
                echo '[]'
            fi
            """
        
        let result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript,
            python: nil
        )
        
        var profiles: [[String: Any]] = []
        
        if let items = result["items"] as? [[String: Any]] {
            profiles = items
        }
        
        // Transform osquery managed_policies to profile format if needed
        return profiles.map { profile in
            if let domain = profile["domain"] as? String, !domain.isEmpty {
                // osquery format - managed policy
                return [
                    "identifier": domain,
                    "displayName": profile["name"] as? String ?? domain,
                    "organization": "",
                    "installDate": "",
                    "uuid": "",
                    "scope": (profile["manual"] as? String == "1") ? "manual" : "managed",
                    "verified": true
                ]
            } else {
                // profiles command format
                return [
                    "identifier": profile["identifier"] as? String ?? "",
                    "displayName": profile["displayName"] as? String ?? "",
                    "organization": profile["organization"] as? String ?? "",
                    "installDate": profile["installDate"] as? String ?? "",
                    "uuid": profile["uuid"] as? String ?? "",
                    "scope": profile["scope"] as? String ?? "system",
                    "verified": (profile["verified"] as? Bool == true)
                ]
            }
        }
    }
    
    // MARK: - System Extensions (osquery: system_extensions)
    
    private func collectSystemExtensions() async throws -> [[String: Any]] {
        // osquery system_extensions table (macOS 10.15+)
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
        
        let bashScript = """
            # Get system extensions using systemextensionsctl
            systemextensionsctl list 2>/dev/null | awk '
            BEGIN { print "["; first = 1 }
            /enabled|disabled|activated/ {
                # Parse extension info
                gsub(/^[[:space:]]+/, "")
                split($0, parts, /[[:space:]]+/)
                
                if (length(parts) >= 3) {
                    identifier = parts[1]
                    team = parts[2]
                    state = "unknown"
                    for (i = 1; i <= NF; i++) {
                        if (parts[i] ~ /enabled|disabled|activated/) {
                            state = parts[i]
                            break
                        }
                    }
                    
                    if (!first) print ","
                    printf "{\\"identifier\\": \\"%s\\", \\"team\\": \\"%s\\", \\"state\\": \\"%s\\"}", identifier, team, state
                    first = 0
                }
            }
            END { print "]" }
            '
        """
        
        let result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript,
            python: nil
        )
        
        var extensions: [[String: Any]] = []
        
        if let items = result["items"] as? [[String: Any]] {
            extensions = items
        }
        
        return extensions.map { ext in
            [
                "identifier": ext["identifier"] as? String ?? "",
                "version": ext["version"] as? String ?? "",
                "state": ext["state"] as? String ?? "unknown",
                "teamId": ext["team"] as? String ?? "",
                "bundlePath": ext["bundle_path"] as? String ?? "",
                "category": ext["category"] as? String ?? ""
            ]
        }
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
            bash: bashScript,
            python: nil
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
                "index": Int(kext["idx"] as? String ?? "0") ?? 0
            ]
        }
    }
    
    // MARK: - Login Items (osquery: startup_items + launchd)
    
    private func collectLoginItems() async throws -> [[String: Any]] {
        // osquery startup_items for login items
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
            WHERE type = 'Login Item' OR source LIKE '%LoginItems%';
        """
        
        let bashScript = """
            # Get login items using various methods
            echo "["
            first=true
            
            # System login items via defaults
            sfltool dumpbtm 2>/dev/null | awk '
            BEGIN { name = ""; path = ""; enabled = "true" }
            /Name:/ { name = $2 }
            /URL:/ { 
                path = $0
                gsub(/.*URL:[[:space:]]*/, "", path)
            }
            /Hidden:/ {
                if ($2 == "true") enabled = "false"
            }
            name != "" && path != "" {
                printf "%s{\\"name\\": \\"%s\\", \\"path\\": \\"%s\\", \\"enabled\\": %s, \\"type\\": \\"ServiceManagement\\"}", (NR>1 ? "," : ""), name, path, enabled
                name = ""
                path = ""
                enabled = "true"
            }
            '
            
            # User login items from preferences
            osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null | \
            tr ',' '\\n' | while read -r item; do
                item=$(echo "$item" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
                [ -z "$item" ] && continue
                
                if [ "$first" = "true" ]; then
                    first=false
                else
                    echo ","
                fi
                
                item_esc=$(echo "$item" | sed 's/"/\\\\"/g')
                echo "{\\"name\\": \\"$item_esc\\", \\"type\\": \\"LoginItem\\", \\"enabled\\": true}"
            done
            
            echo "]"
        """
        
        let result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript,
            python: nil
        )
        
        var items: [[String: Any]] = []
        
        if let resultItems = result["items"] as? [[String: Any]] {
            items = resultItems
        }
        
        return items.map { item in
            [
                "name": item["name"] as? String ?? "",
                "path": item["path"] as? String ?? "",
                "type": item["type"] as? String ?? "LoginItem",
                "enabled": (item["enabled"] as? Bool == true) ||
                          (item["status"] as? String != "disabled"),
                "username": item["username"] as? String ?? ""
            ]
        }
    }
    
    // MARK: - Service Management (SMAppService items)
    
    private func collectServiceManagement() async throws -> [[String: Any]] {
        // Pure bash + awk solution for sfltool parsing (NO Python)
        let bashScript = """
            # Get Service Management items using sfltool (macOS 13+) - parsed with awk
            if command -v sfltool >/dev/null 2>&1; then
                echo "["
                sfltool dumpbtm 2>/dev/null | awk '
                BEGIN { 
                    first = 1
                    name = ""
                    developer = ""
                    url = ""
                    executable = ""
                    type = ""
                    enabled = "true"
                    hidden = "false"
                }
                /^Name:/ { 
                    if (name != "") {
                        if (!first) printf ","
                        printf "{\\"name\\": \\"%s\\", \\"developer\\": \\"%s\\", \\"url\\": \\"%s\\", \\"executable\\": \\"%s\\", \\"type\\": \\"%s\\", \\"enabled\\": %s, \\"hidden\\": %s}", name, developer, url, executable, type, enabled, hidden
                        first = 0
                    }
                    gsub(/^Name:[[:space:]]*/, "")
                    name = $0
                    developer = ""
                    url = ""
                    executable = ""
                    type = ""
                    enabled = "true"
                    hidden = "false"
                }
                /^Developer Name:/ { 
                    gsub(/^Developer Name:[[:space:]]*/, "")
                    developer = $0
                }
                /^URL:/ { 
                    gsub(/^URL:[[:space:]]*/, "")
                    url = $0
                }
                /^Executable:/ { 
                    gsub(/^Executable:[[:space:]]*/, "")
                    executable = $0
                }
                /^Type:/ { 
                    gsub(/^Type:[[:space:]]*/, "")
                    type = $0
                }
                /^Disposition:/ {
                    if ($0 ~ /[Dd]isabled/) enabled = "false"
                }
                /^Hidden:/ {
                    if ($0 ~ /true/) hidden = "true"
                }
                END {
                    if (name != "") {
                        if (!first) printf ","
                        printf "{\\"name\\": \\"%s\\", \\"developer\\": \\"%s\\", \\"url\\": \\"%s\\", \\"executable\\": \\"%s\\", \\"type\\": \\"%s\\", \\"enabled\\": %s, \\"hidden\\": %s}", name, developer, url, executable, type, enabled, hidden
                    }
                }
                '
                echo "]"
            else
                # Fallback for older macOS
                echo '[]'
            fi
            """
        
        let result = try await executeWithFallback(
            osquery: nil,
            bash: bashScript,
            python: nil
        )
        
        var services: [[String: Any]] = []
        
        if let items = result["items"] as? [[String: Any]] {
            services = items
        }
        
        return services.map { service in
            [
                "name": service["name"] as? String ?? "",
                "developer": service["developer"] as? String ?? "",
                "url": service["url"] as? String ?? "",
                "executable": service["executable"] as? String ?? "",
                "type": service["type"] as? String ?? "",
                "enabled": (service["enabled"] as? Bool == true),
                "hidden": (service["hidden"] as? Bool == true)
            ]
        }
    }
}
