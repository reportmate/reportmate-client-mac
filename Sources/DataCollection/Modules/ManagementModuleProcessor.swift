import Foundation

/// Management module processor - uses osquery first with bash fallback
/// Based on MunkiReport patterns for MDM and management collection
/// Reference: https://github.com/munkireport/munkireport-php
/// No Python - uses osquery for: mdm, managed_policies, certificates
/// Bash fallback for: ADE status, profiles, compliance checks
public class ManagementModuleProcessor: BaseModuleProcessor, @unchecked Sendable {
    
    public init(configuration: ReportMateConfiguration) {
        super.init(moduleId: "management", configuration: configuration)
    }
    
    public override func collectData() async throws -> ModuleData {
        // Collect management data in parallel
        async let mdmStatus = collectMDMEnrollmentStatus()
        async let mdmCertificateDetails = collectMDMCertificateDetails()
        async let adeConfig = collectADEConfiguration()
        async let deviceIds = collectDeviceIdentifiers()
        async let remoteManagement = collectRemoteManagement()
        async let installedProfiles = collectInstalledProfiles()

        // Await all results
        let mdm = try await mdmStatus
        let mdmCert = try await mdmCertificateDetails
        let ade = try await adeConfig
        let ids = try await deviceIds
        let remote = try await remoteManagement
        let profiles = try await installedProfiles
        
        // Collect managed policies separately (osquery managed_policies table)
        let policies = try await collectManagedPolicies()

        // Use snake_case for top-level keys to match osquery conventions
        let managementData: [String: Any] = [
            "mdm_enrollment": mdm,
            "mdm_certificate": mdmCert,
            "ade_configuration": ade,
            "device_identifiers": ids,
            "remote_management": remote,
            "installed_profiles": profiles,
            "managed_policies": policies
        ]

        return BaseModuleData(moduleId: moduleId, data: managementData)
    }
    
    // MARK: - MDM Enrollment Status (osquery: mdm table via macadmins extension + bash fallback)
    
    private func collectMDMEnrollmentStatus() async throws -> [String: Any] {
        // Try osquery with macadmins extension mdm table first
        let osqueryScript = """
            SELECT 
                enrolled,
                server_url,
                checkin_url,
                access_rights,
                installed_from_dep,
                user_approved,
                dep_capable,
                has_scep_payload
            FROM mdm;
        """
        
        let bashScript = """
            # Check MDM enrollment using profiles command
            # Output follows osquery mdm table field naming (snake_case)
            enrolled="false"
            server_url=""
            checkin_url=""
            user_approved="false"
            installed_from_dep="false"
            dep_capable="false"
            access_rights="0"
            has_scep_payload="false"

            # Check for MDM profile
            profiles_output=$(profiles status -type enrollment 2>/dev/null || echo "")

            if echo "$profiles_output" | grep -qi "MDM enrollment: Yes"; then
                enrolled="true"
            fi

            if echo "$profiles_output" | grep -qi "User Approved"; then
                user_approved="true"
            fi

            # Check for ADE/DEP enrollment (Automated Device Enrollment, formerly DEP)
            # Multiple possible output formats: "Enrolled via DEP: Yes", "DEP enrollment: Yes", "Automated Device Enrollment: Yes"
            if echo "$profiles_output" | grep -Eqi "Enrolled via DEP: Yes|DEP enrollment: Yes|Automated Device Enrollment: Yes"; then
                installed_from_dep="true"
            fi

            # DEP capable = hardware capability (all Macs 2018+ are DEP capable)
            # Check: 1) Has activation record, 2) Currently DEP enrolled, 3) Hardware year >= 2018
            if [ -f "/private/var/db/ConfigurationProfiles/Store/activationRecord.plist" ]; then
                dep_capable="true"
            elif [ "$installed_from_dep" = "true" ]; then
                dep_capable="true"
            else
                # Check model year - DEP capable if Mac is 2018 or newer
                model_id=$(system_profiler SPHardwareDataType 2>/dev/null | grep "Model Identifier" | awk '{print $3}')
                # Modern Macs (Mac14+, Mac15+, Mac16+) and recent Intel Macs are DEP capable
                if echo "$model_id" | grep -Eq "^Mac1[4-9]|^Mac[2-9][0-9]"; then
                    dep_capable="true"
                fi
            fi

            # Get MDM server URLs from system_profiler (more reliable than profiles -C)
            server_url=$(system_profiler SPConfigurationProfileDataType 2>/dev/null | grep "ServerURL" | grep "/mdm/" | head -1 | sed 's/.*= "//' | sed 's/".*//' | tr -d ';')
            checkin_url=$(system_profiler SPConfigurationProfileDataType 2>/dev/null | grep "CheckInURL" | head -1 | sed 's/.*= "//' | sed 's/".*//' | tr -d ';')

            # Check for SCEP payload
            scep_check=$(profiles -C -v 2>/dev/null | grep -i "SCEP" || echo "")
            if [ -n "$scep_check" ]; then
                has_scep_payload="true"
            fi

            echo "{"
            echo "  \\"enrolled\\": \\"$enrolled\\","
            echo "  \\"server_url\\": \\"$server_url\\","
            echo "  \\"checkin_url\\": \\"$checkin_url\\","
            echo "  \\"user_approved\\": \\"$user_approved\\","
            echo "  \\"installed_from_dep\\": \\"$installed_from_dep\\","
            echo "  \\"dep_capable\\": \\"$dep_capable\\","
            echo "  \\"access_rights\\": \\"$access_rights\\","
            echo "  \\"has_scep_payload\\": \\"$has_scep_payload\\""
            echo "}"
        """
        
        // Use executeWithFallback which tries osquery (with extension), then bash
        return try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript
        )
    }
    
    // MARK: - MDM Certificate Details (APNs Topic, SCEP, Identity Certificate)
    
    private func collectMDMCertificateDetails() async throws -> [String: Any] {
        let bashScript = """
            push_topic=""
            scep_url=""
            cert_name=""
            cert_subject=""
            cert_issuer=""
            cert_expires=""
            mdm_provider=""

            # Get Push Topic from system_profiler (not profiles command)
            push_topic=$(system_profiler SPConfigurationProfileDataType 2>/dev/null | grep "Topic" | head -1 | sed 's/.*= "//' | sed 's/".*//' | tr -d ';')

            # Get SCEP URL by deriving from MDM ServerURL (filter for /mdm/ to avoid Crypt etc)
            mdm_server=$(system_profiler SPConfigurationProfileDataType 2>/dev/null | grep "ServerURL" | grep "/mdm/" | head -1 | sed 's/.*= "//' | sed 's/".*//' | tr -d ';')
            if [ -n "$mdm_server" ]; then
                base_url=$(echo "$mdm_server" | sed 's|/mdm/.*||')
                scep_url="${base_url}/scep"
            fi

            # Get MDM certificate - use MOST RECENT certificate (sort by expiration date)
            # This handles cases where device has multiple MDM certs (re-enrollment, device+user certs)
            # Convert dates to epoch for proper numerical sorting
            cert_name=$(security find-certificate -a /Library/Keychains/System.keychain 2>/dev/null | \
                grep '"labl"' | grep -iE "MDM|Identity" | \
                while read line; do
                    name=$(echo "$line" | sed 's/.*="\\(.*\\)".*/\\1/')
                    expiry_str=$(security find-certificate -c "$name" -p /Library/Keychains/System.keychain 2>/dev/null | \
                        openssl x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//')
                    # Convert to epoch time for proper numerical sorting (latest expiry = highest number)
                    expiry_epoch=$(date -jf "%b %d %T %Y %Z" "$expiry_str" "+%s" 2>/dev/null || echo "0")
                    echo "$expiry_epoch|||$name"
                done | sort -rn | head -1 | cut -d'|' -f4-)
            
            if [ -n "$cert_name" ]; then
                cert_subject="$cert_name"
                
                # Get issuer and expiry from the certificate
                cert_info=$(security find-certificate -c "$cert_name" -p /Library/Keychains/System.keychain 2>/dev/null | openssl x509 -noout -subject -issuer -enddate 2>/dev/null)
                if [ -n "$cert_info" ]; then
                    cert_issuer=$(echo "$cert_info" | grep "^issuer=" | sed 's/issuer=//' | sed 's/.*CN=//' | sed 's/,.*//')
                    cert_expires=$(echo "$cert_info" | grep "^notAfter=" | sed 's/notAfter=//')
                fi
            fi

            # Determine MDM provider from issuer or cert name
            check_str=$(echo "$cert_issuer $cert_name" | tr '[:upper:]' '[:lower:]')
            case "$check_str" in
                *micromdm*) mdm_provider="MicroMDM" ;;
                *nanomdm*) mdm_provider="NanoMDM" ;;
                *jamf*) mdm_provider="Jamf Pro" ;;
                *mosyle*) mdm_provider="Mosyle" ;;
                *kandji*) mdm_provider="Kandji" ;;
                *intune*|*microsoft*) mdm_provider="Microsoft Intune" ;;
                *workspace*|*airwatch*) mdm_provider="VMware Workspace ONE" ;;
                *) [ -n "$cert_issuer" ] && mdm_provider="$cert_issuer" ;;
            esac

            echo "{"
            echo "  \\"push_topic\\": \\"$push_topic\\","
            echo "  \\"scep_url\\": \\"$scep_url\\","
            echo "  \\"certificate_name\\": \\"$cert_name\\","
            echo "  \\"certificate_subject\\": \\"$cert_subject\\","
            echo "  \\"certificate_issuer\\": \\"$cert_issuer\\","
            echo "  \\"certificate_expires\\": \\"$cert_expires\\","
            echo "  \\"mdm_provider\\": \\"$mdm_provider\\""
            echo "}"
        """
        
        return try await executeWithFallback(
            osquery: nil,
            bash: bashScript
        )
    }
    
    // MARK: - ADE Configuration (Automated Device Enrollment, formerly DEP)

    private func collectADEConfiguration() async throws -> [String: Any] {
        let bashScript = """
            # Get ADE status (Automated Device Enrollment, formerly DEP)
            # Output uses snake_case for consistency with osquery
            assigned="false"
            activated="false"
            organization=""
            support_phone=""
            support_email=""

            # Check ADE enrollment status (Automated Device Enrollment, formerly DEP)
            profiles_output=$(profiles status -type enrollment 2>/dev/null || echo "")

            if echo "$profiles_output" | grep -qi "DEP enrollment: Yes\\|Automated Device Enrollment: Yes"; then
                activated="true"
                assigned="true"
            fi

            # Get activation record (indicates ADE assignment)
            if [ -f "/private/var/db/ConfigurationProfiles/Store/activationRecord.plist" ]; then
                assigned="true"
                # If we have activation record, we're activated
                activated="true"
                
                # Extract organization from activation record
                organization=$(/usr/libexec/PlistBuddy -c "Print :OrganizationName" "/private/var/db/ConfigurationProfiles/Store/activationRecord.plist" 2>/dev/null || echo "")
                support_phone=$(/usr/libexec/PlistBuddy -c "Print :SupportPhoneNumber" "/private/var/db/ConfigurationProfiles/Store/activationRecord.plist" 2>/dev/null || echo "")
                support_email=$(/usr/libexec/PlistBuddy -c "Print :SupportEmailAddress" "/private/var/db/ConfigurationProfiles/Store/activationRecord.plist" 2>/dev/null || echo "")
            fi

            # Fallback: Try to get organization from MDM server URL
            if [ -z "$organization" ]; then
                server_url=$(system_profiler SPConfigurationProfileDataType 2>/dev/null | grep "ServerURL" | grep "/mdm/" | head -1 | sed 's/.*= "//' | sed 's/".*//' | tr -d ';')
                if [ -n "$server_url" ]; then
                    organization=$(echo "$server_url" | sed 's|https*://||' | sed 's|/.*||' | sed 's|:.*||')
                fi
            fi

            echo "{"
            echo "  \\"assigned\\": \\"$assigned\\","
            echo "  \\"activated\\": \\"$activated\\","
            echo "  \\"organization\\": \\"$organization\\","
            echo "  \\"support_phone\\": \\"$support_phone\\","
            echo "  \\"support_email\\": \\"$support_email\\""
            echo "}"
        """

        return try await executeWithFallback(
            osquery: nil,
            bash: bashScript
        )
    }
    
    // MARK: - Device Identifiers (osquery: system_info + bash for ioreg)
    
    private func collectDeviceIdentifiers() async throws -> [String: Any] {
        // osquery system_info provides hardware serial and UUID
        let osqueryScript = """
            SELECT 
                uuid,
                hardware_serial,
                hardware_model,
                computer_name
            FROM system_info;
        """
        
        let bashScript = """
            # Get device identifiers
            # Output uses snake_case to match osquery system_info table
            uuid=$(ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}' 2>/dev/null || echo "")
            serial=$(ioreg -l | grep IOPlatformSerialNumber | sed 's/.*"\\(.*\\)".*/\\1/' | head -1 2>/dev/null || echo "")
            model=$(sysctl -n hw.model 2>/dev/null || echo "")
            
            # Get provisioning UDID if available
            provisioning_udid=""
            if [ -f "/var/db/.AppleSetupDone" ]; then
                provisioning_udid="$uuid"
            fi
            
            # Get asset tag if set via MDM
            asset_tag=""
            asset_tag_plist="/Library/Managed Preferences/com.apple.RemoteDesktop.plist"
            if [ -f "$asset_tag_plist" ]; then
                asset_tag=$(/usr/libexec/PlistBuddy -c "Print :ARD_CustomField1" "$asset_tag_plist" 2>/dev/null || echo "")
            fi
            
            # Check alternative locations for asset tag
            if [ -z "$asset_tag" ]; then
                asset_tag_plist2="/Library/Preferences/com.apple.RemoteDesktop.plist"
                if [ -f "$asset_tag_plist2" ]; then
                    asset_tag=$(/usr/libexec/PlistBuddy -c "Print :Text1" "$asset_tag_plist2" 2>/dev/null || echo "")
                fi
            fi
            
            echo "{"
            echo "  \\"uuid\\": \\"$uuid\\","
            echo "  \\"hardware_serial\\": \\"$serial\\","
            echo "  \\"hardware_model\\": \\"$model\\","
            echo "  \\"asset_tag\\": \\"$asset_tag\\","
            echo "  \\"provisioning_udid\\": \\"$provisioning_udid\\""
            echo "}"
        """
        
        // Try osquery first
        let osqueryResult = try? await executeWithFallback(
            osquery: osqueryScript,
            bash: nil
        )
        
        // Get bash result for asset tag and additional details
        let bashResult = try await executeWithFallback(
            osquery: nil,
            bash: bashScript
        )
        
        // Merge results - osquery fields are already snake_case
        var result = bashResult
        
        if let osq = osqueryResult {
            if let uuid = osq["uuid"] as? String, !uuid.isEmpty {
                result["uuid"] = uuid
            }
            if let serial = osq["hardware_serial"] as? String, !serial.isEmpty {
                result["hardware_serial"] = serial
            }
            if let model = osq["hardware_model"] as? String, !model.isEmpty {
                result["hardware_model"] = model
            }
        }
        
        return result
    }
    
    // MARK: - Remote Management (bash)
    
    private func collectRemoteManagement() async throws -> [String: Any] {
        let bashScript = """
            # Check Remote Management (ARD) status
            # Output uses snake_case for consistency
            ard_enabled="false"
            ard_allowed_users=""
            screen_sharing_enabled="false"
            remote_login_enabled="false"
            
            # Check ARD status via launchctl
            # com.apple.RemoteDesktop.PrivilegeProxy is the system daemon for ARD
            if launchctl list 2>/dev/null | grep -q "com.apple.RemoteDesktop"; then
                ard_enabled="true"
            fi
            
            # Fallback: Check for running ARDAgent process
            if [ "$ard_enabled" = "false" ]; then
                if ps ax | grep -v grep | grep -q "ARDAgent"; then
                    ard_enabled="true"
                fi
            fi
            
            # Check Screen Sharing
            # If com.apple.screensharing is loaded in launchctl, service is enabled
            if launchctl list 2>/dev/null | grep -q "com.apple.screensharing"; then
                screen_sharing_enabled="true"
            fi
            
            # Check Remote Login (SSH)
            ssh_status=$(systemsetup -getremotelogin 2>/dev/null || echo "")
            if echo "$ssh_status" | grep -qi "On"; then
                remote_login_enabled="true"
            fi
            
            # Get allowed users for ARD
            ard_plist="/Library/Preferences/com.apple.RemoteManagement.plist"
            if [ -f "$ard_plist" ]; then
                ard_allowed_users=$(/usr/libexec/PlistBuddy -c "Print :ARD_AllLocalUsers" "$ard_plist" 2>/dev/null || echo "")
            fi
            
            echo "{"
            echo "  \\"ard_enabled\\": \\"$ard_enabled\\","
            echo "  \\"screen_sharing_enabled\\": \\"$screen_sharing_enabled\\","
            echo "  \\"remote_login_enabled\\": \\"$remote_login_enabled\\","
            echo "  \\"ard_allowed_users\\": \\"$ard_allowed_users\\""
            echo "}"
        """
        
        return try await executeWithFallback(
            osquery: nil,
            bash: bashScript
        )
    }
    
    // MARK: - Installed Profiles (Full details via /usr/bin/profiles -P)
    
    private func collectInstalledProfiles() async throws -> [[String: Any]] {
        // Use /usr/bin/profiles -P -o <file> like munkireport does - much faster than system_profiler
        let tempPath = "/tmp/reportmate_profile_temp.plist"
        
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/profiles")
        process.arguments = ["-P", "-o", tempPath]
        
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        
        try process.run()
        process.waitUntilExit()
        
        // Read the plist output file
        guard let plistData = FileManager.default.contents(atPath: tempPath),
              let plist = try? PropertyListSerialization.propertyList(from: plistData, options: [], format: nil) as? [String: Any] else {
            // Clean up temp file
            try? FileManager.default.removeItem(atPath: tempPath)
            // Fallback to basic profiles list
            return try await collectInstalledProfilesBasic()
        }
        
        // Clean up temp file
        try? FileManager.default.removeItem(atPath: tempPath)
        
        var profiles: [[String: Any]] = []
        
        // Process all the profile data - plist is keyed by user (_computerlevel for system profiles)
        for (profileUser, userProfiles) in plist {
            guard let profileList = userProfiles as? [[String: Any]] else { continue }
            
            let userScope = profileUser == "_computerlevel" ? "System Level" : profileUser
            
            for innerProfile in profileList {
                var profile: [String: Any] = [:]
                
                // Profile-level metadata
                profile["uuid"] = innerProfile["ProfileUUID"] as? String ?? ""
                profile["name"] = innerProfile["ProfileDisplayName"] as? String ?? ""
                profile["identifier"] = innerProfile["ProfileIdentifier"] as? String ?? ""
                profile["description"] = innerProfile["ProfileDescription"] as? String
                profile["organization"] = innerProfile["ProfileOrganization"] as? String
                profile["verification_state"] = innerProfile["ProfileVerificationState"] as? String ?? "not verified"
                profile["user"] = userScope
                profile["method"] = "Native"
                
                // Handle removal policy
                if let removalDisallowed = innerProfile["ProfileRemovalDisallowed"] {
                    profile["removal_disallowed"] = removalDisallowed as? Bool ?? false
                } else if let uninstallPolicy = innerProfile["ProfileUninstallPolicy"] as? String {
                    profile["removal_disallowed"] = uninstallPolicy.lowercased() == "disallowed"
                } else {
                    profile["removal_disallowed"] = false
                }
                
                // Handle install date
                if let installDate = innerProfile["ProfileInstallDate"] {
                    if let dateString = installDate as? String {
                        profile["install_date"] = dateString
                    } else if let date = installDate as? Date {
                        let formatter = ISO8601DateFormatter()
                        profile["install_date"] = formatter.string(from: date)
                    }
                }
                
                // Process profile payload items
                var payloads: [[String: Any]] = []
                if let profileItems = innerProfile["ProfileItems"] as? [[String: Any]] {
                    for payload in profileItems {
                        var payloadData: [String: Any] = [:]
                        
                        payloadData["type"] = payload["PayloadType"] as? String ?? ""
                        payloadData["display_name"] = payload["PayloadDisplayName"] as? String
                        payloadData["identifier"] = payload["PayloadIdentifier"] as? String ?? ""
                        payloadData["uuid"] = payload["PayloadUUID"] as? String ?? ""
                        payloadData["version"] = payload["PayloadVersion"] as? Int ?? 1
                        
                        // Get payload content (the actual settings)
                        if let payloadContent = payload["PayloadContent"] {
                            // Convert to JSON-safe format (handles Date objects, etc.)
                            let jsonSafeContent = makeJSONSafe(payloadContent)
                            
                            // Try to serialize as JSON for display
                            if let contentData = try? JSONSerialization.data(withJSONObject: jsonSafeContent, options: [.sortedKeys]),
                               let contentString = String(data: contentData, encoding: .utf8) {
                                payloadData["settings_json"] = contentString
                            }
                            // Also store the safe content
                            if let contentDict = jsonSafeContent as? [String: Any] {
                                payloadData["settings"] = contentDict
                            }
                        }
                        
                        payloads.append(payloadData)
                    }
                }
                profile["payloads"] = payloads
                profile["payload_count"] = payloads.count
                
                profiles.append(profile)
            }
        }
        
        return profiles
    }
    
    /// Convert any non-JSON-serializable types (Date, Data, etc.) to strings
    private func makeJSONSafe(_ value: Any) -> Any {
        if let dict = value as? [String: Any] {
            return dict.mapValues { makeJSONSafe($0) }
        } else if let array = value as? [Any] {
            return array.map { makeJSONSafe($0) }
        } else if let date = value as? Date {
            let formatter = ISO8601DateFormatter()
            return formatter.string(from: date)
        } else if let data = value as? Data {
            return data.base64EncodedString()
        } else if JSONSerialization.isValidJSONObject([value]) {
            return value
        } else {
            // Fallback: convert to string representation
            return String(describing: value)
        }
    }
    
    /// Fallback method using profiles list command (basic info only)
    private func collectInstalledProfilesBasic() async throws -> [[String: Any]] {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/profiles")
        process.arguments = ["list"]
        
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        
        try process.run()
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        guard let output = String(data: data, encoding: .utf8) else {
            return []
        }
        
        var profiles: [[String: Any]] = []
        var currentProfile: [String: Any]? = nil
        
        // Parse output format with more detail extraction
        for line in output.components(separatedBy: .newlines) {
            if line.contains("attribute: profileIdentifier:") {
                // Save previous profile if exists
                if let profile = currentProfile {
                    profiles.append(profile)
                }
                // Start new profile
                let identifier = extractValue(from: line, after: "profileIdentifier:")
                currentProfile = ["identifier": identifier]
            } else if line.contains("attribute: name:"), currentProfile != nil {
                currentProfile?["name"] = extractValue(from: line, after: "name:")
            } else if line.contains("attribute: organization:"), currentProfile != nil {
                currentProfile?["organization"] = extractValue(from: line, after: "organization:")
            } else if line.contains("attribute: installationDate:"), currentProfile != nil {
                currentProfile?["install_date"] = extractValue(from: line, after: "installationDate:")
            } else if line.contains("attribute: removalDisallowed:"), currentProfile != nil {
                let value = extractValue(from: line, after: "removalDisallowed:")
                currentProfile?["removal_disallowed"] = value.uppercased() == "TRUE"
            } else if line.contains("attribute: installedByMDM:"), currentProfile != nil {
                let value = extractValue(from: line, after: "installedByMDM:")
                currentProfile?["install_source"] = value.uppercased() == "TRUE" ? "MDM" : "Manual"
            }
        }
        
        // Add last profile
        if let profile = currentProfile {
            profiles.append(profile)
        }
        
        return profiles
    }
    
    /// Helper to extract value after a key in profiles output
    private func extractValue(from line: String, after key: String) -> String {
        if let range = line.range(of: key) {
            return String(line[range.upperBound...]).trimmingCharacters(in: .whitespaces)
        }
        return ""
    }
    
    // MARK: - Managed Policies (osquery managed_policies table)
    
    /// Collect managed policies from osquery - provides key-value pairs for each managed preference domain
    private func collectManagedPolicies() async throws -> [[String: Any]] {
        let osqueryScript = """
            SELECT domain, name, value, uuid
            FROM managed_policies
            ORDER BY domain, name;
        """
        
        // Execute osquery and get raw results
        let result = try await executeOsqueryRaw(osqueryScript)
        
        // Group policies by domain for better organization
        var policiesByDomain: [String: [[String: Any]]] = [:]
        
        for policy in result {
            guard let domain = policy["domain"] as? String else { continue }
            
            let policyEntry: [String: Any] = [
                "name": policy["name"] as? String ?? "",
                "value": policy["value"] as? String ?? "",
                "uuid": policy["uuid"] as? String ?? ""
            ]
            
            if policiesByDomain[domain] == nil {
                policiesByDomain[domain] = []
            }
            policiesByDomain[domain]?.append(policyEntry)
        }
        
        // Convert to array format with domain as a property
        var policies: [[String: Any]] = []
        for (domain, settings) in policiesByDomain.sorted(by: { $0.key < $1.key }) {
            policies.append([
                "domain": domain,
                "settings": settings,
                "setting_count": settings.count
            ])
        }
        
        return policies
    }
    
    /// Execute osquery and return raw array of dictionaries
    private func executeOsqueryRaw(_ query: String) async throws -> [[String: Any]] {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/local/bin/osqueryi")
        process.arguments = ["--json", query]
        
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        
        try process.run()
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        
        guard let result = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
            return []
        }
        
        return result
    }
    
    // MARK: - Helper to execute bash commands
    
    private func executeBashCommand(_ command: String) async throws -> String {
        let process = Process()
        let pipe = Pipe()
        
        process.standardOutput = pipe
        process.standardError = pipe
        process.executableURL = URL(fileURLWithPath: "/bin/bash")
        process.arguments = ["-c", command]
        
        try process.run()
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8) ?? ""
    }
}
