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
        async let complianceStatus = collectComplianceStatus()
        async let installedProfiles = collectInstalledProfiles()

        // Await all results
        let mdm = try await mdmStatus
        let mdmCert = try await mdmCertificateDetails
        let ade = try await adeConfig
        let ids = try await deviceIds
        let remote = try await remoteManagement
        let compliance = try await complianceStatus
        let profiles = try await installedProfiles

        // Use snake_case for top-level keys to match osquery conventions
        let managementData: [String: Any] = [
            "mdm_enrollment": mdm,
            "mdm_certificate": mdmCert,
            "ade_configuration": ade,
            "device_identifiers": ids,
            "remote_management": remote,
            "compliance_status": compliance,
            "installed_profiles": profiles
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

            # Check for ADE enrollment (Automated Device Enrollment, formerly DEP)
            if echo "$profiles_output" | grep -qi "DEP enrollment: Yes\\|Automated Device Enrollment: Yes"; then
                installed_from_dep="true"
                dep_capable="true"
            fi

            # Check if DEP capable (has activation record)
            if [ -f "/private/var/db/ConfigurationProfiles/Store/activationRecord.plist" ]; then
                dep_capable="true"
            fi

            # Get MDM server URL from enrolled profile
            mdm_profile=$(profiles -C -v 2>/dev/null | grep -A5 "MDM Profile" | grep "ServerURL" | head -1 || echo "")
            if [ -n "$mdm_profile" ]; then
                server_url=$(echo "$mdm_profile" | sed 's/.*ServerURL[[:space:]]*=[[:space:]]*//' | tr -d ';')
            fi

            # Get check-in URL
            checkin_profile=$(profiles -C -v 2>/dev/null | grep -A5 "MDM Profile" | grep "CheckInURL" | head -1 || echo "")
            if [ -n "$checkin_profile" ]; then
                checkin_url=$(echo "$checkin_profile" | sed 's/.*CheckInURL[[:space:]]*=[[:space:]]*//' | tr -d ';')
            fi

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
            bash: bashScript,
            python: nil
        )
    }
    
    // MARK: - MDM Certificate Details (APNs Topic, SCEP, Identity Certificate)
    
    private func collectMDMCertificateDetails() async throws -> [String: Any] {
        // Collect MDM push certificate and SCEP details
        // The APNs Topic is critical for push notifications
        let bashScript = """
            # Get MDM certificate details: Topic, SCEP, Identity Certificate
            # Topic format: com.apple.mgmt.External.<UUID>
            
            push_topic=""
            scep_url=""
            certificate_name=""
            certificate_issuer=""
            certificate_expires=""
            certificate_subject=""
            mdm_provider=""
            
            # Method 1: Get Topic from MDM profile via profiles command
            mdm_topic_raw=$(profiles -C -v 2>/dev/null | grep -i "Topic" | head -1 || echo "")
            if [ -n "$mdm_topic_raw" ]; then
                # Extract the topic UUID - format: com.apple.mgmt.External.<UUID>
                push_topic=$(echo "$mdm_topic_raw" | grep -oE "com\\.apple\\.mgmt\\.[^[:space:]]*" | head -1)
            fi
            
            # Method 2: Try system_profiler for push certificate
            if [ -z "$push_topic" ]; then
                sp_output=$(system_profiler SPConfigurationProfileDataType 2>/dev/null || echo "")
                push_topic=$(echo "$sp_output" | grep -oE "com\\.apple\\.mgmt\\.[^[:space:]]*" | head -1)
            fi
            
            # Get SCEP URL from profiles
            scep_raw=$(profiles -C -v 2>/dev/null | grep -A10 -i "SCEP" | grep -i "URL" | head -1 || echo "")
            if [ -n "$scep_raw" ]; then
                scep_url=$(echo "$scep_raw" | sed 's/.*URL[[:space:]]*=[[:space:]]*//' | tr -d ';" ' | head -1)
            fi
            
            # Get MDM identity certificate from keychain
            # Look for MDM-related certificates
            cert_output=$(security find-certificate -a -p /Library/Keychains/System.keychain 2>/dev/null | \
                openssl x509 -noout -subject -issuer -enddate 2>/dev/null | head -6 || echo "")
            
            # Try to find MDM identity cert specifically
            mdm_cert_cn=""
            mdm_certs=$(security find-certificate -a -c "MDM" /Library/Keychains/System.keychain 2>/dev/null || \
                        security find-certificate -a -c "Identity" /Library/Keychains/System.keychain 2>/dev/null || echo "")
            
            if [ -n "$mdm_certs" ]; then
                # Get first matching cert details
                cert_hash=$(echo "$mdm_certs" | grep -m1 "SHA-1" | awk -F'"' '{print $2}')
                if [ -n "$cert_hash" ]; then
                    cert_details=$(security find-certificate -a -Z /Library/Keychains/System.keychain 2>/dev/null | \
                        grep -A50 "$cert_hash" | head -50 || echo "")
                    certificate_name=$(echo "$cert_details" | grep '"labl"' | head -1 | awk -F'"' '{print $4}')
                fi
            fi
            
            # Alternative: Get cert info from profiles output
            if [ -z "$certificate_name" ]; then
                cert_from_profiles=$(profiles -C -v 2>/dev/null | grep -i "PayloadCertificateFileName\\|PayloadDisplayName" | head -1 || echo "")
                if [ -n "$cert_from_profiles" ]; then
                    certificate_name=$(echo "$cert_from_profiles" | sed 's/.*=[[:space:]]*//' | tr -d ';"')
                fi
            fi
            
            # Get cert expiry and issuer from keychain cert
            cert_pem=$(security find-certificate -a -p -c "MDM" /Library/Keychains/System.keychain 2>/dev/null | head -50 || \
                       security find-certificate -a -p -c "Identity" /Library/Keychains/System.keychain 2>/dev/null | head -50 || echo "")
            
            if [ -n "$cert_pem" ]; then
                cert_info=$(echo "$cert_pem" | openssl x509 -noout -subject -issuer -enddate 2>/dev/null || echo "")
                
                if [ -n "$cert_info" ]; then
                    # Extract issuer (O= or CN= from issuer line)
                    issuer_line=$(echo "$cert_info" | grep "issuer=" | head -1)
                    certificate_issuer=$(echo "$issuer_line" | grep -oE "O=[^,/]+" | sed 's/O=//' || \
                                         echo "$issuer_line" | grep -oE "CN=[^,/]+" | sed 's/CN=//')
                    
                    # Extract subject (common name)
                    subject_line=$(echo "$cert_info" | grep "subject=" | head -1)
                    certificate_subject=$(echo "$subject_line" | grep -oE "CN=[^,/]+" | sed 's/CN=//')
                    
                    # Extract expiry date
                    expiry_line=$(echo "$cert_info" | grep "notAfter=" | head -1)
                    certificate_expires=$(echo "$expiry_line" | sed 's/notAfter=//')
                fi
            fi
            
            # Detect MDM provider from certificate issuer or SCEP URL
            if echo "$certificate_issuer" | grep -qi "MicroMDM"; then
                mdm_provider="MicroMDM"
            elif echo "$certificate_issuer" | grep -qi "NanoMDM"; then
                mdm_provider="NanoMDM"
            elif echo "$scep_url" | grep -qi "micromdm"; then
                mdm_provider="MicroMDM"
            elif echo "$scep_url" | grep -qi "nanomdm"; then
                mdm_provider="NanoMDM"
            elif echo "$certificate_issuer" | grep -qi "Jamf"; then
                mdm_provider="Jamf Pro"
            elif echo "$certificate_issuer" | grep -qi "Microsoft"; then
                mdm_provider="Microsoft Intune"
            fi
            
            # If certificate_name is still empty, use subject
            if [ -z "$certificate_name" ] && [ -n "$certificate_subject" ]; then
                certificate_name="$certificate_subject"
            fi
            
            echo "{"
            echo "  \\"push_topic\\": \\"$push_topic\\","
            echo "  \\"scep_url\\": \\"$scep_url\\","
            echo "  \\"certificate_name\\": \\"$certificate_name\\","
            echo "  \\"certificate_subject\\": \\"$certificate_subject\\","
            echo "  \\"certificate_issuer\\": \\"$certificate_issuer\\","
            echo "  \\"certificate_expires\\": \\"$certificate_expires\\","
            echo "  \\"mdm_provider\\": \\"$mdm_provider\\""
            echo "}"
        """
        
        return try await executeWithFallback(
            osquery: nil,
            bash: bashScript,
            python: nil
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

            # Check ADE enrollment status
            profiles_output=$(profiles status -type enrollment 2>/dev/null || echo "")

            if echo "$profiles_output" | grep -qi "DEP enrollment: Yes\\|Automated Device Enrollment: Yes"; then
                activated="true"
                assigned="true"
            fi

            # Try to get configuration profile info
            config_output=$(profiles -e 2>/dev/null | head -50 || echo "")

            if [ -n "$config_output" ]; then
                organization=$(echo "$config_output" | grep -i "ConfigurationURL" | head -1 | sed 's/.*\\/\\/\\([^\\/]*\\).*/\\1/' || echo "")
            fi

            # Get activation record if available (indicates ADE assignment)
            if [ -f "/private/var/db/ConfigurationProfiles/Store/activationRecord.plist" ]; then
                assigned="true"
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
            bash: nil,
            python: nil
        )
        
        // Get bash result for asset tag and additional details
        let bashResult = try await executeWithFallback(
            osquery: nil,
            bash: bashScript,
            python: nil
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
                screen_sharing_enabled="true"
            fi
            # Alternative check
            ss_pref=$(defaults read /var/db/launchd.db/com.apple.launchd/overrides.plist com.apple.screensharing 2>/dev/null | grep -i "disabled.*false" || echo "")
            if [ -n "$ss_pref" ]; then
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
            bash: bashScript,
            python: nil
        )
    }
    
    // MARK: - Compliance Status (bash)
    
    private func collectComplianceStatus() async throws -> [String: Any] {
        let bashScript = """
            # Check various compliance indicators
            # Output uses snake_case for consistency
            filevault_enabled="false"
            sip_enabled="false"
            gatekeeper_enabled="false"
            firewall_enabled="false"
            screen_lock_password_required="false"
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
                    screen_lock_password_required="true"
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
            is_compliant="false"
            [ $compliance_score -ge 80 ] && is_compliant="true"
            
            echo "{"
            echo "  \\"filevault_enabled\\": \\"$filevault_enabled\\","
            echo "  \\"sip_enabled\\": \\"$sip_enabled\\","
            echo "  \\"gatekeeper_enabled\\": \\"$gatekeeper_enabled\\","
            echo "  \\"firewall_enabled\\": \\"$firewall_enabled\\","
            echo "  \\"auto_login_disabled\\": \\"$auto_login_disabled\\","
            echo "  \\"screen_lock_password_required\\": \\"$screen_lock_password_required\\","
            echo "  \\"compliance_score\\": $compliance_score,"
            echo "  \\"is_compliant\\": \\"$is_compliant\\""
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
            # Output uses snake_case for consistency
            echo "["
            
            profiles -C -v 2>/dev/null | grep -E "^[[:space:]]*(attribute|profileIdentifier|profileUUID|profileDisplayName|installationDate|profileOrganization):" | \
            awk '
            BEGIN { first = 1; in_profile = 0 }
            /profileDisplayName:/ { 
                if (in_profile && name != "") {
                    if (!first) printf ","
                    printf "{\\"name\\": \\"%s\\", \\"identifier\\": \\"%s\\", \\"uuid\\": \\"%s\\", \\"organization\\": \\"%s\\", \\"install_date\\": \\"%s\\"}", name, identifier, uuid, org, install_date
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
                    printf "{\\"name\\": \\"%s\\", \\"identifier\\": \\"%s\\", \\"uuid\\": \\"%s\\", \\"organization\\": \\"%s\\", \\"install_date\\": \\"%s\\"}", name, identifier, uuid, org, install_date
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
        
        // Transform to standardized format with snake_case
        return profiles.map { profile in
            [
                "name": profile["name"] as? String ?? "Unknown",
                "identifier": profile["identifier"] as? String ?? "",
                "uuid": profile["uuid"] as? String ?? "",
                "organization": profile["organization"] as? String ?? "",
                "install_date": profile["install_date"] as? String ?? profile["installDate"] as? String ?? "",
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
