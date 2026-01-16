import Foundation

/// Profiles module processor - uses osquery first with bash fallback
/// Based on MunkiReport patterns for profile collection
/// Reference: https://github.com/munkireport/profile
/// No Python - uses osquery for: managed_policies
/// Bash fallback for: profiles command
/// NOTE: Login Items, System Extensions, and Kernel Extensions have been moved to SystemModuleProcessor
public class ProfilesModuleProcessor: BaseModuleProcessor, @unchecked Sendable {
    
    public init(configuration: ReportMateConfiguration) {
        super.init(moduleId: "profiles", configuration: configuration)
    }
    
    public override func collectData() async throws -> ModuleData {
        // Collect profile data in parallel
        async let configProfiles = collectConfigurationProfiles()
        async let serviceManagement = collectServiceManagement()
        
        // Await all results
        let profiles = try await configProfiles
        let services = try await serviceManagement
        
        let profilesData: [String: Any] = [
            "configurationProfiles": profiles,
            "serviceManagement": services
            // NOTE: loginItems, systemExtensions, and kernelExtensions are now in the System module
        ]
        
        return BaseModuleData(moduleId: moduleId, data: profilesData)
    }
    
    // MARK: - Configuration Profiles (macadmins extension: macos_profiles, fallback: profiles command)
    
    private func collectConfigurationProfiles() async throws -> [[String: Any]] {
        // macadmins extension: macos_profiles table provides comprehensive profile data
        let osqueryScript = """
            SELECT 
                display_name,
                identifier,
                uuid,
                install_date,
                organization,
                description,
                verified,
                payload_count,
                scope
            FROM macos_profiles
            ORDER BY install_date DESC;
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
            bash: bashScript
        )
        
        var profiles: [[String: Any]] = []
        
        if let items = result["items"] as? [[String: Any]] {
            // macadmins extension format - normalize field names
            profiles = items.map { item in
                var normalized: [String: Any] = [:]
                
                normalized["identifier"] = item["identifier"] as? String ?? ""
                normalized["displayName"] = item["display_name"] as? String ?? ""
                normalized["organization"] = item["organization"] as? String ?? ""
                normalized["description"] = item["description"] as? String ?? ""
                normalized["uuid"] = item["uuid"] as? String ?? ""
                normalized["installDate"] = item["install_date"] as? String ?? ""
                normalized["scope"] = (item["scope"] as? String)?.capitalized ?? "Unknown"
                
                // Parse verified status
                let verifiedStr = item["verified"] as? String ?? "0"
                normalized["verified"] = (verifiedStr == "1" || verifiedStr == "true")
                
                // Parse payload count
                if let payloadCount = item["payload_count"] as? String {
                    normalized["payloadCount"] = Int(payloadCount) ?? 0
                } else if let payloadCount = item["payload_count"] as? Int {
                    normalized["payloadCount"] = payloadCount
                }
                
                return normalized
            }
        }
        
        return profiles
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
            bash: bashScript
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
