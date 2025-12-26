import Foundation

/// Management module processor - uses osquery first with bash fallback
/// Based on MunkiReport patterns for MDM and management collection
/// Reference: https://github.com/munkireport/munkireport-php
/// No Python - uses osquery for: mdm, managed_policies, certificates
/// Bash fallback for: DEP status, profiles, compliance checks
public class ManagementModuleProcessor: BaseModuleProcessor, @unchecked Sendable {
    
    public init(configuration: ReportMateConfiguration) {
        super.init(moduleId: "management", configuration: configuration)
    }
    
    public override func collectData() async throws -> ModuleData {
        // Collect management data in parallel
        async let mdmStatus = collectMDMEnrollmentStatus()
        async let depConfig = collectDEPConfiguration()
        async let deviceIds = collectDeviceIdentifiers()
        async let remoteManagement = collectRemoteManagement()
        async let complianceStatus = collectComplianceStatus()
        async let installedProfiles = collectInstalledProfiles()
        
        // Await all results
        let mdm = try await mdmStatus
        let dep = try await depConfig
        let ids = try await deviceIds
        let remote = try await remoteManagement
        let compliance = try await complianceStatus
        let profiles = try await installedProfiles
        
        let managementData: [String: Any] = [
            "mdmEnrollment": mdm,
            "depConfiguration": dep,
            "deviceIdentifiers": ids,
            "remoteManagement": remote,
            "complianceStatus": compliance,
            "installedProfiles": profiles
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
            mdm_enrolled="false"
            server_url=""
            enrollment_type=""
            user_approved="false"
            dep_enrolled="false"
            
            # Check for MDM profile
            profiles_output=$(profiles status -type enrollment 2>/dev/null || echo "")
            
            if echo "$profiles_output" | grep -qi "MDM enrollment: Yes"; then
                mdm_enrolled="true"
            fi
            
            if echo "$profiles_output" | grep -qi "User Approved"; then
                user_approved="true"
            fi
            
            if echo "$profiles_output" | grep -qi "DEP enrollment: Yes"; then
                dep_enrolled="true"
                enrollment_type="DEP"
            elif [ "$mdm_enrolled" = "true" ]; then
                enrollment_type="Manual"
            fi
            
            # Get MDM server URL from enrolled profile
            mdm_profile=$(profiles -C -v 2>/dev/null | grep -A5 "MDM Profile" | grep "ServerURL" | head -1 || echo "")
            if [ -n "$mdm_profile" ]; then
                server_url=$(echo "$mdm_profile" | sed 's/.*ServerURL[[:space:]]*=[[:space:]]*//' | tr -d ';')
            fi
            
            # Get enrollment identifier
            enrollment_id=""
            mdm_identity=$(profiles -C -v 2>/dev/null | grep -A10 "MDM Profile" | grep "PayloadIdentifier" | head -1 || echo "")
            if [ -n "$mdm_identity" ]; then
                enrollment_id=$(echo "$mdm_identity" | sed 's/.*PayloadIdentifier[[:space:]]*=[[:space:]]*//' | tr -d ';')
            fi
            
            echo "{"
            echo "  \\"enrolled\\": $mdm_enrolled,"
            echo "  \\"serverUrl\\": \\"$server_url\\","
            echo "  \\"enrollmentType\\": \\"$enrollment_type\\","
            echo "  \\"userApproved\\": $user_approved,"
            echo "  \\"depEnrolled\\": $dep_enrolled,"
            echo "  \\"enrollmentIdentifier\\": \\"$enrollment_id\\""
            echo "}"
        """
        
        // Use executeWithFallback which tries osquery (with extension), then bash
        return try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript,
            python: nil
        )
    }
    
    // MARK: - DEP Configuration (bash: profiles)
    
    private func collectDEPConfiguration() async throws -> [String: Any] {
        let bashScript = """
            # Get DEP status
            dep_assigned="false"
            dep_activated="false"
            organization=""
            support_phone=""
            support_email=""
            
            # Check DEP enrollment status
            profiles_output=$(profiles status -type enrollment 2>/dev/null || echo "")
            
            if echo "$profiles_output" | grep -qi "DEP enrollment: Yes"; then
                dep_activated="true"
                dep_assigned="true"
            fi
            
            # Try to get configuration profile info
            config_output=$(profiles -e 2>/dev/null | head -50 || echo "")
            
            if [ -n "$config_output" ]; then
                organization=$(echo "$config_output" | grep -i "ConfigurationURL" | head -1 | sed 's/.*\\/\\/\\([^\\/]*\\).*/\\1/' || echo "")
            fi
            
            # Get activation record if available
            activation_record=""
            if [ -f "/private/var/db/ConfigurationProfiles/Store/activationRecord.plist" ]; then
                dep_assigned="true"
            fi
            
            echo "{"
            echo "  \\"assigned\\": $dep_assigned,"
            echo "  \\"activated\\": $dep_activated,"
            echo "  \\"organization\\": \\"$organization\\","
            echo "  \\"supportPhone\\": \\"$support_phone\\","
            echo "  \\"supportEmail\\": \\"$support_email\\""
            echo "}"
        """
        
        return try await executeWithFallback(
            osquery: nil,
            bash: bashScript,
            python: nil
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
            echo "  \\"serialNumber\\": \\"$serial\\","
            echo "  \\"hardwareModel\\": \\"$model\\","
            echo "  \\"assetTag\\": \\"$asset_tag\\","
            echo "  \\"provisioningUDID\\": \\"$provisioning_udid\\""
            echo "}"
        """
        
        // Try osquery first
        let osqueryResult = try? await executeWithFallback(
            osquery: osqueryScript,
            bash: nil,
            python: nil
        )
        
        // Get bash result for asset tag and additional details
        let bashResult = try await executeWithFallback(
            osquery: nil,
            bash: bashScript,
            python: nil
        )
        
        // Merge results
        var result = bashResult
        
        if let osq = osqueryResult {
            if let uuid = osq["uuid"] as? String, !uuid.isEmpty {
                result["uuid"] = uuid
            }
            if let serial = osq["hardware_serial"] as? String, !serial.isEmpty {
                result["serialNumber"] = serial
            }
            if let model = osq["hardware_model"] as? String, !model.isEmpty {
                result["hardwareModel"] = model
            }
        }
        
        return result
    }
    
    // MARK: - Remote Management (bash)
    
    private func collectRemoteManagement() async throws -> [String: Any] {
        let bashScript = """
            # Check Remote Management (ARD) status
            ard_enabled="false"
            ard_users=""
            screen_sharing="false"
            remote_login="false"
            
            # Check ARD agent status
            if launchctl list 2>/dev/null | grep -q "com.apple.ARDAgent"; then
                ard_enabled="true"
            fi
            
            # Check kickstart status (requires admin)
            ard_status=$(/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -privs -getprivs 2>/dev/null || echo "")
            if [ -n "$ard_status" ]; then
                ard_enabled="true"
            fi
            
            # Check Screen Sharing
            ss_status=$(launchctl list 2>/dev/null | grep "com.apple.screensharing" || echo "")
            if [ -n "$ss_status" ]; then
                screen_sharing="true"
            fi
            # Alternative check
            ss_pref=$(defaults read /var/db/launchd.db/com.apple.launchd/overrides.plist com.apple.screensharing 2>/dev/null | grep -i "disabled.*false" || echo "")
            if [ -n "$ss_pref" ]; then
                screen_sharing="true"
            fi
            
            # Check Remote Login (SSH)
            ssh_status=$(systemsetup -getremotelogin 2>/dev/null || echo "")
            if echo "$ssh_status" | grep -qi "On"; then
                remote_login="true"
            fi
            
            # Get allowed users for ARD
            ard_plist="/Library/Preferences/com.apple.RemoteManagement.plist"
            if [ -f "$ard_plist" ]; then
                ard_users=$(/usr/libexec/PlistBuddy -c "Print :ARD_AllLocalUsers" "$ard_plist" 2>/dev/null || echo "")
            fi
            
            echo "{"
            echo "  \\"ardEnabled\\": $ard_enabled,"
            echo "  \\"screenSharingEnabled\\": $screen_sharing,"
            echo "  \\"remoteLoginEnabled\\": $remote_login,"
            echo "  \\"ardAllowedUsers\\": \\"$ard_users\\""
            echo "}"
        """
        
        return try await executeWithFallback(
            osquery: nil,
            bash: bashScript,
            python: nil
        )
    }
    
    // MARK: - Compliance Status (bash)
    
    private func collectComplianceStatus() async throws -> [String: Any] {
        let bashScript = """
            # Check various compliance indicators
            filevault_enabled="false"
            sip_enabled="false"
            gatekeeper_enabled="false"
            firewall_enabled="false"
            password_required="false"
            auto_login_disabled="true"
            
            # FileVault
            fv_status=$(fdesetup status 2>/dev/null || echo "")
            if echo "$fv_status" | grep -qi "FileVault is On"; then
                filevault_enabled="true"
            fi
            
            # SIP
            sip_status=$(csrutil status 2>/dev/null || echo "")
            if echo "$sip_status" | grep -qi "enabled"; then
                sip_enabled="true"
            fi
            
            # Gatekeeper
            gk_status=$(spctl --status 2>/dev/null || echo "")
            if echo "$gk_status" | grep -qi "enabled"; then
                gatekeeper_enabled="true"
            fi
            
            # Firewall
            fw_status=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "")
            if echo "$fw_status" | grep -qi "enabled"; then
                firewall_enabled="true"
            fi
            
            # Check auto-login (should be disabled)
            auto_login=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null || echo "")
            if [ -n "$auto_login" ]; then
                auto_login_disabled="false"
            fi
            
            # Check screen saver password requirement
            screensaver_pref="$HOME/Library/Preferences/com.apple.screensaver.plist"
            if [ -f "$screensaver_pref" ]; then
                ask_pwd=$(defaults read com.apple.screensaver askForPassword 2>/dev/null || echo "0")
                if [ "$ask_pwd" = "1" ]; then
                    password_required="true"
                fi
            fi
            
            # Calculate overall compliance score (simple example)
            compliant_count=0
            [ "$filevault_enabled" = "true" ] && compliant_count=$((compliant_count + 1))
            [ "$sip_enabled" = "true" ] && compliant_count=$((compliant_count + 1))
            [ "$gatekeeper_enabled" = "true" ] && compliant_count=$((compliant_count + 1))
            [ "$firewall_enabled" = "true" ] && compliant_count=$((compliant_count + 1))
            [ "$auto_login_disabled" = "true" ] && compliant_count=$((compliant_count + 1))
            
            compliance_score=$((compliant_count * 20))
            
            echo "{"
            echo "  \\"fileVaultEnabled\\": $filevault_enabled,"
            echo "  \\"sipEnabled\\": $sip_enabled,"
            echo "  \\"gatekeeperEnabled\\": $gatekeeper_enabled,"
            echo "  \\"firewallEnabled\\": $firewall_enabled,"
            echo "  \\"autoLoginDisabled\\": $auto_login_disabled,"
            echo "  \\"screenLockPasswordRequired\\": $password_required,"
            echo "  \\"complianceScore\\": $compliance_score,"
            echo "  \\"isCompliant\\": $([ $compliance_score -ge 80 ] && echo 'true' || echo 'false')"
            echo "}"
        """
        
        return try await executeWithFallback(
            osquery: nil,
            bash: bashScript,
            python: nil
        )
    }
    
    // MARK: - Installed Profiles (osquery: managed_policies + bash profiles)
    
    private func collectInstalledProfiles() async throws -> [[String: Any]] {
        // osquery managed_policies table
        let osqueryScript = """
            SELECT 
                domain,
                uuid,
                name,
                value,
                username
            FROM managed_policies;
        """
        
        let bashScript = """
            # Get installed configuration profiles
            echo "["
            
            profiles -C -v 2>/dev/null | grep -E "^[[:space:]]*(attribute|profileIdentifier|profileUUID|profileDisplayName|installationDate|profileOrganization):" | \
            awk '
            BEGIN { first = 1; in_profile = 0 }
            /profileDisplayName:/ { 
                if (in_profile && name != "") {
                    if (!first) printf ","
                    printf "{\\"name\\": \\"%s\\", \\"identifier\\": \\"%s\\", \\"uuid\\": \\"%s\\", \\"organization\\": \\"%s\\", \\"installDate\\": \\"%s\\"}", name, identifier, uuid, org, install_date
                    first = 0
                }
                gsub(/profileDisplayName:[[:space:]]*/, "")
                name = $0
                in_profile = 1
                identifier = ""
                uuid = ""
                org = ""
                install_date = ""
            }
            /profileIdentifier:/ { gsub(/profileIdentifier:[[:space:]]*/, ""); identifier = $0 }
            /profileUUID:/ { gsub(/profileUUID:[[:space:]]*/, ""); uuid = $0 }
            /profileOrganization:/ { gsub(/profileOrganization:[[:space:]]*/, ""); org = $0 }
            /installationDate:/ { gsub(/installationDate:[[:space:]]*/, ""); install_date = $0 }
            END {
                if (in_profile && name != "") {
                    if (!first) printf ","
                    printf "{\\"name\\": \\"%s\\", \\"identifier\\": \\"%s\\", \\"uuid\\": \\"%s\\", \\"organization\\": \\"%s\\", \\"installDate\\": \\"%s\\"}", name, identifier, uuid, org, install_date
                }
            }
            '
            
            echo "]"
        """
        
        // Try osquery first (gives policy-level details)
        let osqueryResult = try? await executeWithFallback(
            osquery: osqueryScript,
            bash: nil,
            python: nil
        )
        
        // Get profile-level details from bash
        let bashResult = try await executeWithFallback(
            osquery: nil,
            bash: bashScript,
            python: nil
        )
        
        var profiles: [[String: Any]] = []
        
        if let items = bashResult["items"] as? [[String: Any]] {
            profiles = items
        }
        
        // If osquery returned policies, add them as policy details
        if let osqItems = osqueryResult?["items"] as? [[String: Any]] {
            // Group policies by domain/profile
            var policyByDomain: [String: [[String: Any]]] = [:]
            for policy in osqItems {
                let domain = policy["domain"] as? String ?? "Unknown"
                if policyByDomain[domain] == nil {
                    policyByDomain[domain] = []
                }
                policyByDomain[domain]?.append(policy)
            }
            
            // Enrich profiles with policy details
            for i in 0..<profiles.count {
                if let identifier = profiles[i]["identifier"] as? String {
                    if let policies = policyByDomain[identifier] {
                        profiles[i]["policies"] = policies
                    }
                }
            }
        }
        
        // Transform to standardized format
        return profiles.map { profile in
            [
                "name": profile["name"] as? String ?? "Unknown",
                "identifier": profile["identifier"] as? String ?? "",
                "uuid": profile["uuid"] as? String ?? "",
                "organization": profile["organization"] as? String ?? "",
                "installDate": profile["installDate"] as? String ?? "",
                "policies": profile["policies"] as? [[String: Any]] ?? []
            ]
        }
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
