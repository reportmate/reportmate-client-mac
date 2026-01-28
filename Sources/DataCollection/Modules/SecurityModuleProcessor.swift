import Foundation

/// Security module processor - uses osquery first with bash fallback
/// Based on MunkiReport patterns for security status collection
/// Reference: https://github.com/munkireport/security
/// No Python - uses osquery for: sip_config, gatekeeper, alf, disk_encryption, xprotect_entries
/// Bash fallback for: SecureEnclave, ActivationLock, SecureBoot, MRT status
/// EDR detection: Microsoft Defender (mdatp), CrowdStrike, SentinelOne, Carbon Black
public class SecurityModuleProcessor: BaseModuleProcessor, @unchecked Sendable {
    
    public init(configuration: ReportMateConfiguration) {
        super.init(moduleId: "security", configuration: configuration)
    }
    
    public override func collectData() async throws -> ModuleData {
        // Total collection steps for progress tracking
        let totalSteps = 23
        
        // Collect security data sequentially with progress tracking
        ConsoleFormatter.writeQueryProgress(queryName: "sip_status", current: 1, total: totalSteps)
        let sip = try await collectSIPStatus()
        
        ConsoleFormatter.writeQueryProgress(queryName: "gatekeeper", current: 2, total: totalSteps)
        let gatekeeper = try await collectGatekeeperStatus()
        
        ConsoleFormatter.writeQueryProgress(queryName: "firewall", current: 3, total: totalSteps)
        let firewall = try await collectFirewallStatus()
        
        ConsoleFormatter.writeQueryProgress(queryName: "filevault", current: 4, total: totalSteps)
        let fileVault = try await collectFileVaultStatus()
        
        ConsoleFormatter.writeQueryProgress(queryName: "xprotect", current: 5, total: totalSteps)
        let xprotect = try await collectXProtectStatus()
        
        ConsoleFormatter.writeQueryProgress(queryName: "ssh_status", current: 6, total: totalSteps)
        let ssh = try await collectSSHStatus()
        
        ConsoleFormatter.writeQueryProgress(queryName: "secure_boot", current: 7, total: totalSteps)
        let secureBoot = try await collectSecureBootStatus()
        
        ConsoleFormatter.writeQueryProgress(queryName: "firmware_password", current: 8, total: totalSteps)
        let firmwarePassword = try await collectFirmwarePasswordStatus()
        
        ConsoleFormatter.writeQueryProgress(queryName: "root_user", current: 9, total: totalSteps)
        let rootUser = try await collectRootUserStatus()
        
        ConsoleFormatter.writeQueryProgress(queryName: "mrt_status", current: 10, total: totalSteps)
        let mrt = try await collectMRTStatus()
        
        ConsoleFormatter.writeQueryProgress(queryName: "secure_enclave", current: 11, total: totalSteps)
        let secureEnclave = try await collectSecureEnclaveStatus()
        
        ConsoleFormatter.writeQueryProgress(queryName: "activation_lock", current: 12, total: totalSteps)
        let activationLock = try await collectActivationLockStatus()
        
        ConsoleFormatter.writeQueryProgress(queryName: "platform_sso", current: 13, total: totalSteps)
        let platformSSO = try await collectPlatformSSOStatus()
        
        ConsoleFormatter.writeQueryProgress(queryName: "filevault_users", current: 14, total: totalSteps)
        let fvUsers = try await collectFileVaultUsers()
        
        ConsoleFormatter.writeQueryProgress(queryName: "secure_token", current: 15, total: totalSteps)
        let secureToken = try await collectSecureTokenStatus()
        
        ConsoleFormatter.writeQueryProgress(queryName: "bootstrap_token", current: 16, total: totalSteps)
        let bootstrapToken = try await collectBootstrapTokenStatus()
        
        ConsoleFormatter.writeQueryProgress(queryName: "authdb", current: 17, total: totalSteps)
        let authdb = try await collectAuthDB()
        
        ConsoleFormatter.writeQueryProgress(queryName: "unpatched_cves", current: 18, total: totalSteps)
        let unpatchedCVEs = try await collectSofaUnpatchedCVEs()
        
        ConsoleFormatter.writeQueryProgress(queryName: "security_release", current: 19, total: totalSteps)
        let securityRelease = try await collectSofaSecurityReleaseInfo()
        
        ConsoleFormatter.writeQueryProgress(queryName: "remote_management", current: 20, total: totalSteps)
        let remoteMgmt = try await collectRemoteManagement()
        
        ConsoleFormatter.writeQueryProgress(queryName: "certificates", current: 21, total: totalSteps)
        let certificates = try await collectCertificates()
        
        ConsoleFormatter.writeQueryProgress(queryName: "endpoint_security", current: 22, total: totalSteps)
        let endpointSecurity = try await collectEndpointSecurityExtensions()
        
        ConsoleFormatter.writeQueryProgress(queryName: "edr_products", current: 23, total: totalSteps)
        let edrProducts = try await collectEDRProducts()
        
        // Build security data dictionary
        let securityData: [String: Any] = [
            "systemIntegrityProtection": sip,
            "gatekeeper": gatekeeper,
            "firewall": firewall,
            "fileVault": fileVault,
            "fileVaultUsers": fvUsers,
            "secureToken": secureToken,
            "bootstrapToken": bootstrapToken,
            "xprotect": xprotect,
            "ssh": ssh,
            "secureBoot": secureBoot,
            "firmwarePassword": firmwarePassword,
            "rootUser": rootUser,
            "mrt": mrt,
            "secureEnclave": secureEnclave,
            "activationLock": activationLock,
            "platformSSO": platformSSO,
            "authorizationDB": authdb,
            "unpatchedCVEs": unpatchedCVEs,
            "securityReleaseInfo": securityRelease,
            "remoteManagement": remoteMgmt,
            "certificates": certificates,
            "endpointSecurity": endpointSecurity,
            "edrProducts": edrProducts
        ]
        
        return BaseModuleData(moduleId: moduleId, data: securityData)
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
    
    // MARK: - System Integrity Protection (osquery: sip_config)
    
    private func collectSIPStatus() async throws -> [String: Any] {
        // osquery: sip_config table provides detailed SIP configuration
        let osqueryScript = """
            SELECT 
                config_flag,
                enabled,
                enabled_nvram
            FROM sip_config;
        """
        
        let bashScript = """
            sip_output=$(csrutil status 2>/dev/null || echo "Unknown")
            
            enabled="false"
            status="Unknown"
            
            if echo "$sip_output" | grep -qi "enabled"; then
                enabled="true"
                status="Enabled"
            elif echo "$sip_output" | grep -qi "disabled"; then
                status="Disabled"
            fi
            
            echo "{"
            echo "  \\"enabled\\": $enabled,"
            echo "  \\"status\\": \\"$status\\","
            echo "  \\"rawOutput\\": \\"$(echo "$sip_output" | head -1)\\""
            echo "}"
        """
        
        // Try osquery first for detailed config
        let osqueryResult = try? await executeWithFallback(
            osquery: osqueryScript,
            bash: nil
        )
        
        // Always get bash result for main status
        let bashResult = try await executeWithFallback(
            osquery: nil,
            bash: bashScript
        )
        
        var result = bashResult
        
        // If osquery returned config flags, add them
        if let items = osqueryResult?["items"] as? [[String: Any]] {
            var configFlags: [String: Bool] = [:]
            for item in items {
                if let flag = item["config_flag"] as? String,
                   let enabled = item["enabled"] as? String {
                    configFlags[flag] = enabled == "1"
                }
            }
            result["configFlags"] = configFlags
        }
        
        return result
    }
    
    // MARK: - Gatekeeper Status (osquery: gatekeeper)
    
    private func collectGatekeeperStatus() async throws -> [String: Any] {
        // osquery gatekeeper table provides assessments_enabled, dev_id_enabled, etc.
        let osqueryScript = """
            SELECT 
                assessments_enabled,
                dev_id_enabled,
                version
            FROM gatekeeper;
        """
        
        let bashScript = """
            gk_output=$(spctl --status 2>/dev/null || echo "Unknown")
            
            enabled="false"
            status="Unknown"
            
            if echo "$gk_output" | grep -qi "enabled"; then
                enabled="true"
                status="Enabled"
            elif echo "$gk_output" | grep -qi "disabled"; then
                status="Disabled"
            fi
            
            # Get developer ID status
            dev_id_enabled="false"
            gk_master=$(spctl --status --verbose 2>/dev/null || echo "")
            if echo "$gk_master" | grep -qi "developer id enabled"; then
                dev_id_enabled="true"
            fi
            
            echo "{"
            echo "  \\"enabled\\": $enabled,"
            echo "  \\"status\\": \\"$status\\","
            echo "  \\"developerIdEnabled\\": $dev_id_enabled"
            echo "}"
        """
        
        let result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript
        )
        
        // Normalize the result
        let enabled = (result["assessments_enabled"] as? String == "1") ||
                     (result["enabled"] as? Bool == true) ||
                     (result["enabled"] as? String == "true")
        
        let devIdEnabled = (result["dev_id_enabled"] as? String == "1") ||
                          (result["developerIdEnabled"] as? Bool == true) ||
                          (result["developerIdEnabled"] as? String == "true")
        
        return [
            "enabled": enabled,
            "status": enabled ? "Enabled" : "Disabled",
            "developerIdEnabled": devIdEnabled,
            "version": result["version"] as? String ?? ""
        ]
    }
    
    // MARK: - Application Firewall (osquery: alf)
    
    private func collectFirewallStatus() async throws -> [String: Any] {
        // osquery alf table provides Application Layer Firewall status
        let osqueryScript = """
            SELECT 
                global_state,
                stealth_enabled,
                logging_enabled,
                logging_option
            FROM alf;
        """
        
        let bashScript = """
            # Get firewall status from socketfilterfw
            fw_status=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "")
            stealth=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null || echo "")
            logging=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getloggingmode 2>/dev/null || echo "")
            block_all=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getblockall 2>/dev/null || echo "")
            signed=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getallowsigned 2>/dev/null || echo "")
            
            # Parse enabled state (0=off, 1=on, 2=block all except essential)
            enabled="false"
            global_state=0
            if echo "$fw_status" | grep -qi "enabled"; then
                enabled="true"
                global_state=1
            fi
            if echo "$block_all" | grep -qi "enabled"; then
                global_state=2
            fi
            
            stealth_enabled="false"
            if echo "$stealth" | grep -qi "enabled"; then
                stealth_enabled="true"
            fi
            
            logging_enabled="false"
            if echo "$logging" | grep -qi "throttled\\|on\\|enabled"; then
                logging_enabled="true"
            fi
            
            signed_enabled="false"
            if echo "$signed" | grep -qi "enabled"; then
                signed_enabled="true"
            fi
            
            echo "{"
            echo "  \\"enabled\\": $enabled,"
            echo "  \\"globalState\\": $global_state,"
            echo "  \\"stealthModeEnabled\\": $stealth_enabled,"
            echo "  \\"loggingEnabled\\": $logging_enabled,"
            echo "  \\"allowSignedEnabled\\": $signed_enabled"
            echo "}"
        """
        
        let result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript
        )
        
        // Normalize osquery vs bash results
        var globalState = 0
        if let gs = result["global_state"] as? String {
            globalState = Int(gs) ?? 0
        } else if let gs = result["globalState"] as? Int {
            globalState = gs
        }
        
        let enabled = globalState > 0 ||
                     (result["enabled"] as? Bool == true) ||
                     (result["enabled"] as? String == "true")
        
        let stealthEnabled = (result["stealth_enabled"] as? String == "1") ||
                            (result["stealthModeEnabled"] as? Bool == true) ||
                            (result["stealthModeEnabled"] as? String == "true")
        
        let loggingEnabled = (result["logging_enabled"] as? String == "1") ||
                            (result["loggingEnabled"] as? Bool == true) ||
                            (result["loggingEnabled"] as? String == "true")
        
        return [
            "enabled": enabled,
            "status": enabled ? "Enabled" : "Disabled",
            "globalState": globalState,
            "stealthModeEnabled": stealthEnabled,
            "loggingEnabled": loggingEnabled,
            "allowSignedEnabled": result["allowSignedEnabled"] as? Bool ?? false
        ]
    }
    
    // MARK: - FileVault Status (osquery: disk_encryption)
    
    private func collectFileVaultStatus() async throws -> [String: Any] {
        // osquery disk_encryption table for disk encryption status
        let osqueryScript = """
            SELECT 
                name,
                uuid,
                encrypted,
                type,
                encryption_status,
                filevault_status
            FROM disk_encryption;
        """
        
        let bashScript = """
            # Get FileVault status using fdesetup
            fv_status=$(fdesetup status 2>/dev/null || echo "Unknown")
            
            enabled="false"
            status="Unknown"
            
            if echo "$fv_status" | grep -qi "FileVault is On"; then
                enabled="true"
                status="Enabled"
            elif echo "$fv_status" | grep -qi "FileVault is Off"; then
                status="Disabled"
            elif echo "$fv_status" | grep -qi "Encryption in progress"; then
                status="Encrypting"
            elif echo "$fv_status" | grep -qi "Decryption in progress"; then
                status="Decrypting"
            fi
            
            # Check if deferred enablement is active
            deferred="false"
            if fdesetup showdeferralinfo 2>/dev/null | grep -qi "active"; then
                deferred="true"
            fi
            
            # Get enabled users (Volume Owners)
            enabled_users=""
            if [ "$enabled" = "true" ]; then
                enabled_users=$(fdesetup list 2>/dev/null | cut -d',' -f1 | tr '\\n' ',' | sed 's/,$//')
            fi
            
            # Get Personal Recovery Key (PRK) status - CRITICAL for MDM
            prk_exists="false"
            if fdesetup haspersonalrecoverykey 2>/dev/null | grep -qi "true"; then
                prk_exists="true"
            fi
            
            # Get Institutional Recovery Key (IRK) status
            irk_exists="false"
            if fdesetup hasinstitutionalrecoverykey 2>/dev/null | grep -qi "true"; then
                irk_exists="true"
            fi
            
            echo "{"
            echo "  \\"enabled\\": $enabled,"
            echo "  \\"status\\": \\"$status\\","
            echo "  \\"deferred\\": $deferred,"
            echo "  \\"enabledUsers\\": \\"$enabled_users\\","
            echo "  \\"personalRecoveryKey\\": $prk_exists,"
            echo "  \\"institutionalRecoveryKey\\": $irk_exists"
            echo "}"
        """
        
        let result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript
        )
        
        // Handle osquery multi-disk results vs bash single result
        var enabled = false
        var status = "Unknown"
        
        if let items = result["items"] as? [[String: Any]] {
            // Check if any disk is encrypted
            for item in items {
                if (item["encrypted"] as? String == "1") ||
                   (item["filevault_status"] as? String == "on") {
                    enabled = true
                    status = "Enabled"
                    break
                }
                if let encStatus = item["encryption_status"] as? String {
                    if encStatus.lowercased().contains("encrypting") {
                        status = "Encrypting"
                    } else if encStatus.lowercased().contains("decrypting") {
                        status = "Decrypting"
                    }
                }
            }
        } else {
            enabled = (result["enabled"] as? Bool == true) ||
                     (result["enabled"] as? String == "true")
            status = result["status"] as? String ?? "Unknown"
        }
        
        let deferred = (result["deferred"] as? Bool == true) ||
                      (result["deferred"] as? String == "true")
        
        // Parse enabled users (Volume Owners)
        var enabledUsers: [String] = []
        if let users = result["enabledUsers"] as? String, !users.isEmpty {
            enabledUsers = users.components(separatedBy: ",").filter { !$0.isEmpty }
        }
        
        // Recovery key status - critical for MDM
        // These are always from bash script output
        var personalRecoveryKey = (result["personalRecoveryKey"] as? Bool == true) ||
                                  (result["personalRecoveryKey"] as? String == "true")
        var institutionalRecoveryKey = (result["institutionalRecoveryKey"] as? Bool == true) ||
                                       (result["institutionalRecoveryKey"] as? String == "true")
        
        // If osquery was used (items array present), we need to run bash specifically for PRK/IRK
        if result["items"] != nil {
            // Run bash script specifically for recovery key status
            let prkScript = """
                prk="false"
                irk="false"
                if fdesetup haspersonalrecoverykey 2>/dev/null | grep -qi "true"; then
                    prk="true"
                fi
                if fdesetup hasinstitutionalrecoverykey 2>/dev/null | grep -qi "true"; then
                    irk="true"
                fi
                echo "{\\"personalRecoveryKey\\": $prk, \\"institutionalRecoveryKey\\": $irk}"
            """
            if let prkResult = try? await executeWithFallback(osquery: nil, bash: prkScript) {
                personalRecoveryKey = (prkResult["personalRecoveryKey"] as? Bool == true) ||
                                      (prkResult["personalRecoveryKey"] as? String == "true")
                institutionalRecoveryKey = (prkResult["institutionalRecoveryKey"] as? Bool == true) ||
                                           (prkResult["institutionalRecoveryKey"] as? String == "true")
            }
        }
        
        return [
            "enabled": enabled,
            "status": status,
            "deferred": deferred,
            "enabledUsers": enabledUsers,
            "personalRecoveryKey": personalRecoveryKey,
            "institutionalRecoveryKey": institutionalRecoveryKey
        ]
    }
    
    // MARK: - FileVault Users (macadmins extension: filevault_users)
    
    private func collectFileVaultUsers() async throws -> [[String: Any]] {
        // macadmins extension: filevault_users table
        // Columns: username, uuid
        let osqueryScript = """
            SELECT 
                username,
                uuid
            FROM filevault_users;
        """
        
        let bashScript = """
            # Get FileVault enabled users using fdesetup
            if [ "$(fdesetup status 2>/dev/null | grep -c 'FileVault is On')" -eq 0 ]; then
                echo '[]'
                exit 0
            fi
            
            users_list=$(fdesetup list 2>/dev/null || echo "")
            
            echo '['
            first=true
            while IFS=, read -r username uuid; do
                if [ -n "$username" ]; then
                    [ "$first" = false ] && echo ','
                    first=false
                    # Get UID from dscl
                    uid=$(dscl . -read /Users/"$username" UniqueID 2>/dev/null | awk '{print $2}' || echo "")
                    echo "{"
                    echo "  \\"username\\": \\"$username\\","
                    echo "  \\"uid\\": \\"$uid\\","
                    echo "  \\"user_uuid\\": \\"$uuid\\","
                    echo "  \\"passphrase_required\\": \\"true\\""
                    echo -n "}"
                fi
            done <<< "$users_list"
            echo '\n]'
        """
        
        let result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript
        )
        
        // Return users array
        if let items = result["items"] as? [[String: Any]] {
            return items
        }
        
        return []
    }
    
    // MARK: - Secure Token Status (critical for MDM management)
    
    private func collectSecureTokenStatus() async throws -> [String: Any] {
        // SecureToken is essential for MDM workflows - must be collected via bash
        // sysadminctl -secureTokenStatus <username> returns status per user
        let bashScript = """
            users_with_token=()
            users_without_token=()
            total_checked=0
            
            # Get all local users with UID >= 500 (actual users, not system accounts)
            for user in $(dscl . -list /Users UniqueID | awk '$2 >= 500 {print $1}'); do
                total_checked=$((total_checked + 1))
                status=$(sysadminctl -secureTokenStatus "$user" 2>&1 || echo "Unknown")
                
                if echo "$status" | grep -qi "enabled"; then
                    users_with_token+=("$user")
                elif echo "$status" | grep -qi "disabled"; then
                    users_without_token+=("$user")
                fi
            done
            
            # Build JSON with helper function
            array_to_json() {
                local arr=("$@")
                local first=true
                echo -n "["
                for item in "${arr[@]}"; do
                    [ "$first" = false ] && echo -n ","
                    first=false
                    echo -n "\\"$item\\""
                done
                echo -n "]"
            }
            
            has_token=false
            [ ${#users_with_token[@]} -gt 0 ] && has_token=true
            
            echo "{"
            echo "  \\"enabled\\": $has_token,"
            echo "  \\"usersWithToken\\": $(array_to_json "${users_with_token[@]}"),"
            echo "  \\"usersWithoutToken\\": $(array_to_json "${users_without_token[@]}"),"
            echo "  \\"totalUsersChecked\\": $total_checked,"
            echo "  \\"tokenGrantedCount\\": ${#users_with_token[@]},"
            echo "  \\"tokenMissingCount\\": ${#users_without_token[@]}"
            echo "}"
        """
        
        return try await executeWithFallback(
            osquery: nil,
            bash: bashScript
        )
    }
    
    // MARK: - Bootstrap Token Status (critical for MDM management)
    
    private func collectBootstrapTokenStatus() async throws -> [String: Any] {
        // Bootstrap Token is escrowed to MDM - required for Volume Ownership/DEP workflows
        // profiles status -type bootstraptoken tells us if it's escrowed
        let bashScript = """
            status="Unknown"
            escrowed=false
            supported=true
            
            # Check Bootstrap Token status via profiles command
            bt_output=$(profiles status -type bootstraptoken 2>&1 || echo "Unknown")
            
            # Parse the output
            if echo "$bt_output" | grep -qi "escrowed\\|YES"; then
                escrowed=true
                status="Escrowed"
            elif echo "$bt_output" | grep -qi "not escrowed\\|NO"; then
                status="Not Escrowed"
            elif echo "$bt_output" | grep -qi "not supported"; then
                supported=false
                status="Not Supported"
            elif echo "$bt_output" | grep -qi "requires MDM"; then
                status="Requires MDM Enrollment"
            fi
            
            # Check if device is Apple Silicon (Bootstrap Token more critical on AS)
            cpu_brand=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "")
            is_apple_silicon=false
            if echo "$cpu_brand" | grep -qi "Apple"; then
                is_apple_silicon=true
            fi
            
            echo "{"
            echo "  \\"escrowed\\": $escrowed,"
            echo "  \\"status\\": \\"$status\\","
            echo "  \\"supported\\": $supported,"
            echo "  \\"isAppleSilicon\\": $is_apple_silicon,"
            echo "  \\"rawOutput\\": \\"$(echo "$bt_output" | tr '\\n' ' ' | tr '\\"' \"'\")\\"" 
            echo "}"
        """
        
        return try await executeWithFallback(
            osquery: nil,
            bash: bashScript
        )
    }
    
    // MARK: - XProtect Status (osquery: xprotect_entries + bash for version)
    
    private func collectXProtectStatus() async throws -> [String: Any] {
        // osquery xprotect_entries for malware signatures
        let osqueryScript = """
            SELECT COUNT(*) as signature_count FROM xprotect_entries;
        """
        
        let bashScript = """
            # Get XProtect version from system
            xprotect_version=""
            xprotect_plist="/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
            alt_plist="/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
            
            if [ -f "$xprotect_plist" ]; then
                xprotect_version=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$xprotect_plist" 2>/dev/null || echo "")
            elif [ -f "$alt_plist" ]; then
                xprotect_version=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$alt_plist" 2>/dev/null || echo "")
            fi
            
            # Check if XProtect is enabled (it's always enabled on macOS, but check anyway)
            enabled="true"
            
            # Get last update time
            last_update=""
            if [ -f "$xprotect_plist" ]; then
                last_update=$(stat -f "%Sm" -t "%Y-%m-%dT%H:%M:%SZ" "$xprotect_plist" 2>/dev/null || echo "")
            fi
            
            # Get definition count (rough estimate from plist)
            sig_count=0
            xprotect_meta="/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist"
            if [ -f "$xprotect_meta" ]; then
                sig_count=$(/usr/libexec/PlistBuddy -c "Print" "$xprotect_meta" 2>/dev/null | grep -c "Dict" || echo "0")
            fi
            
            echo "{"
            echo "  \\"enabled\\": $enabled,"
            echo "  \\"version\\": \\"$xprotect_version\\","
            echo "  \\"signatureCount\\": $sig_count,"
            echo "  \\"lastUpdate\\": \\"$last_update\\""
            echo "}"
        """
        
        // Get signature count from osquery
        let osqueryResult = try? await executeWithFallback(
            osquery: osqueryScript,
            bash: nil
        )
        
        // Get version and status from bash
        let bashResult = try await executeWithFallback(
            osquery: nil,
            bash: bashScript
        )
        
        var result = bashResult
        
        // Prefer osquery signature count if available
        if let sigCount = osqueryResult?["signature_count"] as? String {
            result["signatureCount"] = Int(sigCount) ?? 0
        } else if let sigCount = osqueryResult?["signature_count"] as? Int {
            result["signatureCount"] = sigCount
        }
        
        return result
    }
    
    // MARK: - SSH Status (osquery: system_info + bash for remote login)
    
    private func collectSSHStatus() async throws -> [String: Any] {
        let bashScript = """
            # Check if SSH (Remote Login) is enabled
            ssh_status=$(systemsetup -getremotelogin 2>/dev/null || echo "")
            
            enabled="false"
            if echo "$ssh_status" | grep -qi "On"; then
                enabled="true"
            fi
            
            # Check if sshd is running
            running="false"
            if pgrep -x sshd > /dev/null 2>&1; then
                running="true"
            fi
            
            # Check SSH configuration
            permit_root="no"
            password_auth="yes"
            pubkey_auth="yes"
            
            if [ -f "/etc/ssh/sshd_config" ]; then
                permit_root=$(grep -i "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "no")
                password_auth=$(grep -i "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "yes")
                pubkey_auth=$(grep -i "^PubkeyAuthentication" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "yes")
            fi
            
            # Get authorized users
            ssh_users=""
            if [ "$enabled" = "true" ]; then
                ssh_users=$(dscl . list /Groups/com.apple.access_ssh 2>/dev/null | tr '\\n' ',' | sed 's/,$//' || echo "")
                if [ -z "$ssh_users" ]; then
                    ssh_users="all"
                fi
            fi
            
            echo "{"
            echo "  \\"enabled\\": $enabled,"
            echo "  \\"running\\": $running,"
            echo "  \\"permitRootLogin\\": \\"$permit_root\\","
            echo "  \\"passwordAuthentication\\": \\"$password_auth\\","
            echo "  \\"pubkeyAuthentication\\": \\"$pubkey_auth\\","
            echo "  \\"authorizedUsers\\": \\"$ssh_users\\""
            echo "}"
        """
        
        return try await executeWithFallback(
            osquery: nil,
            bash: bashScript
        )
    }
    
    // MARK: - Secure Boot Status (bash: bputil or nvram)
    
    private func collectSecureBootStatus() async throws -> [String: Any] {
        let bashScript = """
            arch=$(uname -m)
            secure_boot="Unknown"
            security_mode="Unknown"
            external_boot="Unknown"
            
            if [ "$arch" = "arm64" ]; then
                # Apple Silicon - use bputil
                bputil_output=$(bputil -d 2>&1 || echo "")
                
                if echo "$bputil_output" | grep -qi "full security"; then
                    secure_boot="Full"
                    security_mode="Full Security"
                elif echo "$bputil_output" | grep -qi "reduced security"; then
                    secure_boot="Reduced"
                    security_mode="Reduced Security"
                elif echo "$bputil_output" | grep -qi "permissive"; then
                    secure_boot="Permissive"
                    security_mode="Permissive Security"
                fi
                
                if echo "$bputil_output" | grep -qi "external boot.*allowed"; then
                    external_boot="Allowed"
                else
                    external_boot="Disallowed"
                fi
            else
                # Intel - check for T2 chip
                has_t2="false"
                if system_profiler SPiBridgeDataType 2>/dev/null | grep -qi "T2"; then
                    has_t2="true"
                    
                    # Try to get secure boot status from nvram
                    nvram_output=$(nvram -p 2>/dev/null | grep -i "secure" || echo "")
                    if [ -n "$nvram_output" ]; then
                        secure_boot="Enabled"
                        security_mode="Full Security"
                    fi
                fi
                
                if [ "$has_t2" = "false" ]; then
                    secure_boot="Not Applicable"
                    security_mode="No T2 Chip"
                fi
            fi
            
            echo "{"
            echo "  \\"status\\": \\"$secure_boot\\","
            echo "  \\"securityMode\\": \\"$security_mode\\","
            echo "  \\"externalBootAllowed\\": \\"$external_boot\\","
            echo "  \\"architecture\\": \\"$arch\\""
            echo "}"
        """
        
        return try await executeWithFallback(
            osquery: nil,
            bash: bashScript
        )
    }
    
    // MARK: - Firmware Password Status (bash)
    
    private func collectFirmwarePasswordStatus() async throws -> [String: Any] {
        let bashScript = """
            arch=$(uname -m)
            fw_password="Unknown"
            
            if [ "$arch" = "arm64" ]; then
                # Apple Silicon doesn't use firmware passwords in the traditional sense
                # Recovery mode uses Apple ID authentication instead
                fw_password="Not Applicable (Apple Silicon)"
            else
                # Intel Mac - check firmware password
                # Note: firmwarepasswd requires root privileges
                if [ "$(id -u)" -eq 0 ]; then
                    fw_output=$(firmwarepasswd -check 2>/dev/null || echo "")
                    if echo "$fw_output" | grep -qi "Password Enabled: Yes"; then
                        fw_password="Enabled"
                    elif echo "$fw_output" | grep -qi "Password Enabled: No"; then
                        fw_password="Disabled"
                    fi
                else
                    fw_password="Unknown (requires root)"
                fi
            fi
            
            echo "{"
            echo "  \\"status\\": \\"$fw_password\\","
            echo "  \\"architecture\\": \\"$arch\\""
            echo "}"
        """
        
        return try await executeWithFallback(
            osquery: nil,
            bash: bashScript
        )
    }
    
    // MARK: - Root User Status (bash: dscl)
    
    private func collectRootUserStatus() async throws -> [String: Any] {
        let bashScript = """
            # Check if root user is enabled
            root_enabled="false"
            root_shell="/usr/bin/false"
            
            # Check root user's shell - if it's not /usr/bin/false, root is enabled
            root_shell=$(dscl . -read /Users/root UserShell 2>/dev/null | awk '{print $2}' || echo "/usr/bin/false")
            
            if [ "$root_shell" != "/usr/bin/false" ]; then
                root_enabled="true"
            fi
            
            # Alternative check - authentication status
            auth_status=$(dscl . -read /Users/root AuthenticationAuthority 2>/dev/null || echo "")
            if echo "$auth_status" | grep -qi "DisabledUser"; then
                root_enabled="false"
            fi
            
            echo "{"
            echo "  \\"enabled\\": $root_enabled,"
            echo "  \\"shell\\": \\"$root_shell\\""
            echo "}"
        """
        
        return try await executeWithFallback(
            osquery: nil,
            bash: bashScript
        )
    }
    
    // MARK: - MRT (Malware Removal Tool) Status (bash)
    
    private func collectMRTStatus() async throws -> [String: Any] {
        let bashScript = """
            mrt_version=""
            mrt_path=""
            last_update=""
            
            # Check for MRT in various locations
            mrt_locations=(
                "/System/Library/CoreServices/MRT.app"
                "/Library/Apple/System/Library/CoreServices/MRT.app"
            )
            
            for loc in "${mrt_locations[@]}"; do
                if [ -d "$loc" ]; then
                    mrt_path="$loc"
                    mrt_version=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$loc/Contents/Info.plist" 2>/dev/null || echo "")
                    last_update=$(stat -f "%Sm" -t "%Y-%m-%dT%H:%M:%SZ" "$loc/Contents/Info.plist" 2>/dev/null || echo "")
                    break
                fi
            done
            
            enabled="false"
            if [ -n "$mrt_path" ]; then
                enabled="true"
            fi
            
            echo "{"
            echo "  \\"enabled\\": $enabled,"
            echo "  \\"version\\": \\"$mrt_version\\","
            echo "  \\"path\\": \\"$mrt_path\\","
            echo "  \\"lastUpdate\\": \\"$last_update\\""
            echo "}"
            """
        
        return try await executeWithFallback(
            osquery: nil,
            bash: bashScript
        )
    }
    
    // MARK: - Secure Enclave Status (bash: ioreg)
    
    private func collectSecureEnclaveStatus() async throws -> [String: Any] {
        let bashScript = """
            # Check for Secure Enclave (SEP) - present on T1/T2 chips and Apple Silicon
            arch=$(uname -m)
            sep_present="false"
            sep_type="None"
            
            if [ "$arch" = "arm64" ]; then
                # Apple Silicon always has Secure Enclave
                sep_present="true"
                sep_type="Apple Silicon"
            else
                # Intel - check for T1/T2 chip
                bridge_info=$(system_profiler SPiBridgeDataType 2>/dev/null || echo "")
                
                if echo "$bridge_info" | grep -qi "T2"; then
                    sep_present="true"
                    sep_type="T2"
                elif echo "$bridge_info" | grep -qi "T1"; then
                    sep_present="true"
                    sep_type="T1"
                fi
            fi
            
            # Check for Touch ID support (indicates SEP)
            touch_id="false"
            if system_profiler SPiBridgeDataType 2>/dev/null | grep -qi "Touch ID"; then
                touch_id="true"
            fi
            # Also check via bioutil on Apple Silicon
            if [ "$arch" = "arm64" ]; then
                bio_info=$(bioutil -c 2>/dev/null || echo "")
                if [ -n "$bio_info" ]; then
                    touch_id="true"
                fi
            fi
            
            echo "{"
            echo "  \\"present\\": $sep_present,"
            echo "  \\"type\\": \\"$sep_type\\","
            echo "  \\"touchIdSupported\\": $touch_id"
            echo "}"
        """
        
        return try await executeWithFallback(
            osquery: nil,
            bash: bashScript
        )
    }
    
    // MARK: - Activation Lock Status (bash)
    
    private func collectActivationLockStatus() async throws -> [String: Any] {
        let bashScript = """
            # Check Activation Lock and Find My Mac status
            # Methods:
            # 1. ioreg - Check for fmm-mobileme-token (works on Apple Silicon)
            # 2. nvram - Check for fmm-mobileme-token (Intel Macs)
            # 3. system_profiler - Activation Lock status
            # 4. MobileMeAccounts - Get iCloud account email
            # Reference: https://github.com/munkireport/findmymac
            
            activation_lock="Unknown"
            find_my_mac="Disabled"
            fmm_email=""
            fmm_owner=""
            fmm_person_id=""
            
            # METHOD 1: Check via ioreg (Apple Silicon / modern macOS)
            # On Apple Silicon, nvram data is stored differently
            # The token appears as "01:fmm-mobileme-token-FMM" with Present=Yes
            fmm_count=$(ioreg -l 2>/dev/null | grep -c "fmm-mobileme-token-FMM" || echo "0")
            if [ "$fmm_count" -gt 0 ]; then
                find_my_mac="Enabled"
            fi
            
            # METHOD 2: Check via nvram (Intel Macs / older macOS)
            if [ "$find_my_mac" = "Disabled" ]; then
                fmm_data=$(/usr/sbin/nvram -x -p 2>/dev/null | /usr/bin/awk '/fmm-mobileme-token/,/<\\/data>/' | /usr/bin/awk '/<key>/ {f=0}; f && c==1; /<key>/ {f=1; c++}' | /usr/bin/grep -v 'data\\|key' | /usr/bin/tr -d '\\t' | /usr/bin/tr -d '\\n')
                
                if [ -n "$fmm_data" ]; then
                    find_my_mac="Enabled"
                    
                    # Decode the base64 data to get additional info (Intel only)
                    fmm_plist_file="/tmp/findmymac_raw_$$.plist"
                    echo "$fmm_data" | /usr/bin/base64 --decode > "$fmm_plist_file" 2>/dev/null
                    
                    if [ -f "$fmm_plist_file" ] && [ -s "$fmm_plist_file" ]; then
                        # Extract email (iCloud account)
                        fmm_email=$(/usr/libexec/PlistBuddy -c "Print username" "$fmm_plist_file" 2>/dev/null || echo "")
                        
                        # Extract owner display name
                        fmm_owner=$(/usr/libexec/PlistBuddy -c "Print userInfo:InUseOwnerDisplayName" "$fmm_plist_file" 2>/dev/null || echo "")
                        
                        # Extract person ID (unique iCloud ID)
                        fmm_person_id=$(/usr/libexec/PlistBuddy -c "Print personID" "$fmm_plist_file" 2>/dev/null || echo "")
                        
                        # Cleanup
                        rm -f "$fmm_plist_file"
                    fi
                fi
            fi
            
            # METHOD 4: Get iCloud account from MobileMeAccounts (works on both Intel and Apple Silicon)
            # This gets the logged-in iCloud account that owns Find My
            # Note: MobileMeAccounts is per-user, so we need to read from the console user's home
            if [ -z "$fmm_email" ]; then
                # Get the console user's home directory
                console_user=$(stat -f '%Su' /dev/console 2>/dev/null || echo "")
                if [ -n "$console_user" ] && [ "$console_user" != "root" ]; then
                    user_home=$(dscl . -read "/Users/$console_user" NFSHomeDirectory 2>/dev/null | awk '{print $2}' || echo "")
                    if [ -n "$user_home" ] && [ -f "$user_home/Library/Preferences/MobileMeAccounts.plist" ]; then
                        # Read from user's preferences with full path
                        fmm_email=$(defaults read "$user_home/Library/Preferences/MobileMeAccounts" Accounts 2>/dev/null | awk -F'"' '/AccountID/ {print $2; exit}' || echo "")
                        fmm_owner=$(defaults read "$user_home/Library/Preferences/MobileMeAccounts" Accounts 2>/dev/null | awk -F'"' '/DisplayName/ {print $2; exit}' || echo "")
                    fi
                fi
            fi
            
            # METHOD 5: Check Activation Lock status from system_profiler
            # This reports the MDM-managed Activation Lock status
            hw_info=$(system_profiler SPHardwareDataType 2>/dev/null || echo "")
            
            if echo "$hw_info" | grep -qi "Activation Lock Status: Enabled"; then
                activation_lock="Enabled"
            elif echo "$hw_info" | grep -qi "Activation Lock Status: Disabled"; then
                activation_lock="Disabled"
            fi
            
            # If Activation Lock unknown but Find My is enabled, it's likely enabled
            if [ "$activation_lock" = "Unknown" ] && [ "$find_my_mac" = "Enabled" ]; then
                activation_lock="Likely Enabled"
            fi
            
            echo "{"
            echo "  \\"status\\": \\"$activation_lock\\","
            echo "  \\"findMyMac\\": \\"$find_my_mac\\","
            echo "  \\"email\\": \\"$fmm_email\\","
            echo "  \\"ownerDisplayName\\": \\"$fmm_owner\\","
            echo "  \\"personId\\": \\"$fmm_person_id\\""
            echo "}"
        """
        
        return try await executeWithFallback(
            osquery: nil,
            bash: bashScript
        )
    }
    
    // MARK: - Platform Single Sign-On Status (bash: app-sso)
    
    private func collectPlatformSSOStatus() async throws -> [String: Any] {
        // Platform SSO is macOS 13+ feature for enterprise single sign-on
        // Uses the app-sso command-line tool with -s flag to get state (JSON-like format)
        // Collects comprehensive device config + per-user SSO data
        let bashScript = """
            # Platform SSO status check (macOS 13+ Ventura and later)
            # Collects device-level config and per-user SSO registration
            
            # Check macOS version (Platform SSO requires 13+)
            os_version=$(sw_vers -productVersion | cut -d. -f1)
            if [ "$os_version" -lt 13 ]; then
                echo "{"
                echo "  \\"supported\\": false,"
                echo "  \\"registered\\": false,"
                echo "  \\"provider\\": \\"\\"," 
                echo "  \\"method\\": \\"Not supported (macOS 13+ required)\\","
                echo "  \\"extensionIdentifier\\": \\"\\"," 
                echo "  \\"loginFrequency\\": 0,"
                echo "  \\"offlineGracePeriod\\": \\"\\"," 
                echo "  \\"users\\": []"
                echo "}"
                exit 0
            fi
            
            # First get device-level SSO state (can run as root)
            sso_state=$(app-sso platform -s 2>/dev/null || echo "")
            
            # Initialize device-level variables
            registered="false"
            sso_provider=""
            method="Unknown"
            extension_id=""
            org_name=""
            login_freq="0"
            offline_grace=""
            non_psso_accounts=""
            
            if [ -n "$sso_state" ]; then
                # Check registration status
                if echo "$sso_state" | grep -q '"registrationCompleted" *: *true'; then
                    registered="true"
                fi
                
                # Extract SSO extension identifier
                extension_id=$(echo "$sso_state" | grep '"extensionIdentifier"' | head -1 | sed 's/.*: *"\\([^"]*\\)".*/\\1/' || echo "")
                
                # Extract organization/account display name (first one is org name)
                org_name=$(echo "$sso_state" | grep '"accountDisplayName"' | head -1 | sed 's/.*: *"\\([^"]*\\)".*/\\1/' || echo "")
                
                # Extract provider from accountDisplayName (find the IdP entry)
                provider_val=$(echo "$sso_state" | grep '"accountDisplayName"' | grep -i "Entra\\|Okta\\|Google\\|Jamf\\|Microsoft" | head -1 || echo "")
                if echo "$provider_val" | grep -qi "Microsoft\\|Entra"; then
                    sso_provider="Microsoft Entra ID"
                elif echo "$provider_val" | grep -qi "Okta"; then
                    sso_provider="Okta"
                elif echo "$provider_val" | grep -qi "Google"; then
                    sso_provider="Google"
                elif echo "$provider_val" | grep -qi "Jamf"; then
                    sso_provider="Jamf Connect"
                fi
                
                # Extract login type / method
                login_type=$(echo "$sso_state" | grep '"loginType"' | head -1 || echo "")
                if echo "$login_type" | grep -qi "SecureEnclaveKey"; then
                    method="Secure enclave key"
                elif echo "$login_type" | grep -qi "Password"; then
                    method="Password"
                elif echo "$login_type" | grep -qi "SmartCard"; then
                    method="Smart Card"
                fi
                
                # Extract login frequency (seconds)
                login_freq=$(echo "$sso_state" | grep '"loginFrequency"' | head -1 | sed 's/[^0-9]//g' || echo "0")
                
                # Extract offline grace period
                offline_grace=$(echo "$sso_state" | grep '"offlineGracePeriod"' | head -1 | sed 's/.*: *"\\([^"]*\\)".*/\\1/' || echo "")
                
                # Extract non-Platform SSO accounts (local accounts) - array format
                non_psso_accounts=$(echo "$sso_state" | sed -n '/"nonPlatformSSOAccounts"/,/\\]/p' | grep -v 'nonPlatformSSOAccounts' | grep '"' | sed 's/.*"\\([^"]*\\)".*/\\1/' | tr '\\n' ',' | sed 's/,$//' || echo "")
            fi
            
            # Now collect per-user SSO data (only if registered)
            users_json="[]"
            if [ "$registered" = "true" ]; then
                # Get all human users on the system
                all_users=$(dscl . -list /Users | grep -v "^_" | grep -v "daemon\\|nobody\\|root\\|Guest" || echo "")
                
                users_json="["
                first_user="true"
                
                for user in $all_users; do
                    # Get user's home directory to check if real user
                    user_home=$(dscl . -read /Users/"$user" NFSHomeDirectory 2>/dev/null | awk '{print $2}' || echo "")
                    if [ ! -d "$user_home" ] || [ "$user_home" = "/var/empty" ]; then
                        continue
                    fi
                    
                    # Get SSO state for this user
                    user_sso=$(sudo -u "$user" app-sso platform -s 2>/dev/null || echo "")
                    
                    user_registered="false"
                    user_upn=""
                    user_email=""
                    user_tokens="false"
                    user_last_login=""
                    user_state=""
                    token_received=""
                    token_expiration=""
                    
                    if [ -n "$user_sso" ]; then
                        # Check User Configuration section for this user's SSO data
                        if echo "$user_sso" | grep -q "User Configuration:"; then
                            # Extract UPN (prefer clean one without KERBEROS suffix)
                            user_upn=$(echo "$user_sso" | grep '"upn"' | grep -v "KERBEROS" | head -1 | sed 's/.*: *"\\([^"]*\\)".*/\\1/' || echo "")
                            if [ -z "$user_upn" ]; then
                                user_upn=$(echo "$user_sso" | grep '"upn"' | head -1 | sed 's/.*: *"\\([^@]*@[^@]*\\)@.*/\\1/' | sed 's/\\\\\\\\@/@/' || echo "")
                            fi
                            
                            # Extract loginUserName (may be masked)
                            user_email=$(echo "$user_sso" | grep '"loginUserName"' | head -1 | sed 's/.*: *"\\([^"]*\\)".*/\\1/' || echo "")
                            
                            # Prefer UPN if email is masked
                            if [ -n "$user_upn" ]; then
                                if [ -z "$user_email" ] || echo "$user_email" | grep -q '\\*\\*\\*'; then
                                    user_email="$user_upn"
                                fi
                            fi
                            
                            # If we have UPN or email, user is registered
                            if [ -n "$user_upn" ] || [ -n "$user_email" ]; then
                                user_registered="true"
                            fi
                            
                            # Extract last login date
                            user_last_login=$(echo "$user_sso" | grep '"lastLoginDate"' | head -1 | sed 's/.*: *"\\([^"]*\\)".*/\\1/' || echo "")
                            
                            # Extract user state
                            user_state=$(echo "$user_sso" | grep '"state"' | head -1 | sed 's/.*: *"\\([^"]*\\)".*/\\1/' || echo "")
                        fi
                        
                        # Check for SSO Tokens section (appears at end of output, not in JSON format)
                        # Format is:
                        # SSO Tokens:
                        # Received:
                        # 2026-01-16T17:48:17Z
                        # Expiration:
                        # 2026-01-30T17:48:16Z (Not Expired)
                        if echo "$user_sso" | grep -q "^SSO Tokens:"; then
                            # Extract the token received timestamp (line after "Received:")
                            token_received=$(echo "$user_sso" | awk '/^Received:/{getline; print; exit}' | tr -d ' ')
                            # Extract the token expiration (line after "Expiration:")
                            token_expiration=$(echo "$user_sso" | awk '/^Expiration:/{getline; print; exit}' | sed 's/ *(.*$//' | tr -d ' ')
                            
                            # If we have a received timestamp, tokens are present
                            if [ -n "$token_received" ] && [ "$token_received" != "" ]; then
                                user_tokens="true"
                            fi
                        fi
                    fi
                    
                    # Add user to JSON array if they have any SSO data
                    if [ "$user_registered" = "true" ] || [ -n "$user_upn" ] || [ -n "$user_email" ]; then
                        if [ "$first_user" = "true" ]; then
                            first_user="false"
                        else
                            users_json="$users_json,"
                        fi
                        
                        # Convert boolean to integer for tokensPresent (1 or 0)
                        if [ "$user_tokens" = "true" ]; then
                            tokens_val=1
                        else
                            tokens_val=0
                        fi
                        
                        # Convert registered boolean to integer
                        if [ "$user_registered" = "true" ]; then
                            registered_val=1
                        else
                            registered_val=0
                        fi
                        
                        users_json="$users_json{"
                        users_json="$users_json\\"username\\": \\"$user\\","
                        users_json="$users_json\\"registered\\": $registered_val,"
                        users_json="$users_json\\"upn\\": \\"$user_upn\\","
                        users_json="$users_json\\"loginEmail\\": \\"$user_email\\","
                        users_json="$users_json\\"lastLogin\\": \\"$user_last_login\\","
                        users_json="$users_json\\"state\\": \\"$user_state\\","
                        users_json="$users_json\\"tokensPresent\\": $tokens_val,"
                        users_json="$users_json\\"tokenReceived\\": \\"$token_received\\","
                        users_json="$users_json\\"tokenExpiration\\": \\"$token_expiration\\""
                        users_json="$users_json}"
                    fi
                done
                users_json="$users_json]"
            fi
            
            # Fallback: Check for SSO provider via profile if not found
            if [ "$sso_provider" = "" ] && [ "$registered" = "false" ]; then
                azure_check=$(profiles show -type configuration 2>/dev/null | grep -i "microsoft\\|azure\\|entra" || echo "")
                okta_check=$(profiles show -type configuration 2>/dev/null | grep -i "okta" || echo "")
                jamf_check=$(profiles show -type configuration 2>/dev/null | grep -i "jamf connect" || echo "")
                
                if [ -n "$azure_check" ]; then
                    sso_provider="Microsoft Entra ID"
                elif [ -n "$okta_check" ]; then
                    sso_provider="Okta"
                elif [ -n "$jamf_check" ]; then
                    sso_provider="Jamf Connect"
                fi
            fi
            
            # Convert device-level registered to integer
            if [ "$registered" = "true" ]; then
                registered_int=1
            else
                registered_int=0
            fi
            
            echo "{"
            echo "  \\"supported\\": 1,"
            echo "  \\"registered\\": $registered_int,"
            echo "  \\"provider\\": \\"$sso_provider\\","
            echo "  \\"method\\": \\"$method\\","
            echo "  \\"extensionIdentifier\\": \\"$extension_id\\","
            echo "  \\"organizationName\\": \\"$org_name\\","
            echo "  \\"loginFrequency\\": $login_freq,"
            echo "  \\"offlineGracePeriod\\": \\"$offline_grace\\","
            echo "  \\"nonPlatformSSOAccounts\\": \\"$non_psso_accounts\\","
            echo "  \\"users\\": $users_json"
            echo "}"
        """
        
        return try await executeWithFallback(
            osquery: nil,
            bash: bashScript
        )
    }
    
    // MARK: - Authorization Database (extension: authdb)
    
    private func collectAuthDB() async throws -> [[String: Any]] {
        // macadmins extension: authdb table
        // Query common rights for security auditing
        let osqueryScript = """
            SELECT 
                name,
                rule_class,
                rule_type,
                comment,
                shared,
                timeout,
                tries
            FROM authdb
            WHERE name IN (
                'system.preferences',
                'system.preferences.security',
                'system.login.screensaver',
                'com.apple.Safari.allow-unsigned-app-launch',
                'system.install.apple-software',
                'system.install.software',
                'system.preferences.accounts',
                'system.preferences.network',
                'system.preferences.printing'
            )
            ORDER BY name;
        """
        
        let bashScript = """
            # Fallback: Check common security-related rights
            rights=(
                "system.preferences"
                "system.preferences.security"
                "system.login.screensaver"
                "system.install.software"
            )
            
            echo "["
            first=true
            for right in "${rights[@]}"; do
                if [ "$first" = true ]; then
                    first=false
                else
                    echo ","
                fi
                
                # Try to read right from authorization database
                right_info=$(security authorizationdb read "$right" 2>/dev/null || echo "")
                
                if [ -n "$right_info" ]; then
                    rule_class=$(echo "$right_info" | grep -A1 "class" | tail -1 | sed 's/[<>/ ]//g' || echo "unknown")
                    rule_type=$(echo "$right_info" | grep -A1 "rule" | tail -1 | sed 's/[<>/ ]//g' || echo "unknown")
                    
                    echo "  {"
                    echo "    \\"name\\": \\"$right\\","
                    echo "    \\"rule_class\\": \\"$rule_class\\","
                    echo "    \\"rule_type\\": \\"$rule_type\\","
                    echo "    \\"comment\\": \\"\\","
                    echo "    \\"shared\\": false,"
                    echo "    \\"timeout\\": 0,"
                    echo "    \\"tries\\": 0"
                    echo -n "  }"
                fi
            done
            echo
            echo "]"
        """
        
        let result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript
        )
        
        if let items = result["items"] as? [[String: Any]] {
            return items
        }
        
        return []
    }
    
    // MARK: - SOFA Unpatched CVEs (extension: sofa_unpatched_cves)
    
    private func collectSofaUnpatchedCVEs() async throws -> [[String: Any]] {
        // macadmins extension: sofa_unpatched_cves table
        // Columns: os_version, cve, patched_version, actively_exploited, url
        let osqueryScript = """
            SELECT 
                os_version,
                cve,
                patched_version,
                actively_exploited,
                url
            FROM sofa_unpatched_cves
            ORDER BY actively_exploited DESC
            LIMIT 50;
        """
        
        let bashScript = """
            # Fallback: Use softwareupdate to check for security updates
            os_version=$(sw_vers -productVersion)
            
            echo "["
            
            # Check for available security updates
            updates=$(softwareupdate --list --no-scan 2>/dev/null || echo "")
            
            if echo "$updates" | grep -qi "security"; then
                first=true
                while IFS= read -r line; do
                    if echo "$line" | grep -qi "security"; then
                        if [ "$first" = true ]; then
                            first=false
                        else
                            echo ","
                        fi
                        
                        update_name=$(echo "$line" | sed 's/^[* ]*//' | sed 's/-.*//')
                        
                        echo "  {"
                        echo "    \\"os_version\\": \\"$os_version\\","
                        echo "    \\"cve\\": \\"Unknown\\","
                        echo "    \\"product_name\\": \\"$update_name\\","
                        echo "    \\"actively_exploited\\": false,"
                        echo "    \\"release_date\\": \\"\\""
                        echo -n "  }"
                    fi
                done <<< "$updates"
            fi
            
            echo
            echo "]"
        """
        
        let result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript
        )
        
        if let items = result["items"] as? [[String: Any]] {
            return items
        }
        
        return []
    }
    
    // MARK: - SOFA Security Release Info (extension: sofa_security_release_info)
    
    private func collectSofaSecurityReleaseInfo() async throws -> [String: Any] {
        // macadmins extension: sofa_security_release_info table
        // Columns: update_name, product_version, release_date, security_info, unique_cves_count, days_since_previous_release, os_version, url
        let osqueryScript = """
            SELECT 
                update_name,
                product_version,
                os_version,
                release_date,
                security_info,
                unique_cves_count,
                days_since_previous_release,
                url
            FROM sofa_security_release_info
            LIMIT 1;
        """
        
        let bashScript = """
            os_version=$(sw_vers -productVersion)
            build_version=$(sw_vers -buildVersion)
            
            # Check for available updates
            updates=$(softwareupdate --list --no-scan 2>/dev/null || echo "")
            update_available=false
            
            if echo "$updates" | grep -qi "software update"; then
                update_available=true
            fi
            
            echo "{"
            echo "  \\"os_version\\": \\"$os_version\\","
            echo "  \\"release_date\\": \\"\\","
            echo "  \\"security_release\\": \\"$build_version\\","
            echo "  \\"days_since_release\\": 0,"
            echo "  \\"actively_exploited_count\\": 0,"
            echo "  \\"total_cve_count\\": 0,"
            echo "  \\"update_available\\": $update_available"
            echo "}"
        """
        
        return try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript
        )
    }
    
    // MARK: - Certificates (osquery: certificates table + security command)
    
    private func collectCertificates() async throws -> [[String: Any]] {
        // osquery: certificates table provides system keychain certificates
        // Collects from System.keychain and login.keychain
        let osqueryScript = """
            SELECT 
                common_name,
                subject,
                issuer,
                ca,
                self_signed,
                not_valid_before,
                not_valid_after,
                signing_algorithm,
                key_algorithm,
                key_strength,
                key_usage,
                serial,
                path
            FROM certificates
            WHERE path LIKE '/Library/Keychains/%' 
               OR path LIKE '/Users/%/Library/Keychains/%'
               OR path LIKE '/System/Library/Keychains/%'
            ORDER BY not_valid_after DESC;
        """
        
        let bashScript = """
            # Fallback: Use security command to list certificates
            # Get certificates from System keychain and user's login keychain
            
            now_epoch=$(date +%s)
            thirty_days_ahead=$((now_epoch + 30*24*60*60))
            
            output="["
            first=true
            
            # Function to process certificates from a keychain
            process_keychain() {
                keychain="$1"
                store_name="$2"
                
                # List all certificates with their details
                security find-certificate -a -p "$keychain" 2>/dev/null | while IFS= read -r line; do
                    echo "$line"
                done | openssl crl2pkcs7 -nocrl -certfile /dev/stdin 2>/dev/null | \
                openssl pkcs7 -print_certs -text -noout 2>/dev/null | \
                awk -v store="$store_name" -v now="$now_epoch" -v soon="$thirty_days_ahead" '
                    BEGIN { cert_count=0; first=1 }
                    /Certificate:/ { 
                        if (cert_count > 0 && subject != "") {
                            # Output previous certificate
                            if (!first) print ","
                            first=0
                            is_expired = (not_after_epoch != "" && not_after_epoch < now) ? "true" : "false"
                            is_expiring_soon = (not_after_epoch != "" && not_after_epoch >= now && not_after_epoch <= soon) ? "true" : "false"
                            days_until = (not_after_epoch != "") ? int((not_after_epoch - now) / 86400) : 0
                            status = (is_expired == "true") ? "Expired" : ((is_expiring_soon == "true") ? "ExpiringSoon" : "Valid")
                            
                            print "{"
                            print "  \\"commonName\\": \\"" common_name "\\","
                            print "  \\"subject\\": \\"" subject "\\","
                            print "  \\"issuer\\": \\"" issuer "\\","
                            print "  \\"serialNumber\\": \\"" serial "\\","
                            print "  \\"storeName\\": \\"" store "\\","
                            print "  \\"storeLocation\\": \\"System\\","
                            print "  \\"notBefore\\": \\"" not_before "\\","
                            print "  \\"notAfter\\": \\"" not_after "\\","
                            print "  \\"keyAlgorithm\\": \\"" key_algo "\\","
                            print "  \\"signingAlgorithm\\": \\"" sig_algo "\\","
                            print "  \\"isSelfSigned\\": " is_self_signed ","
                            print "  \\"isExpired\\": " is_expired ","
                            print "  \\"isExpiringSoon\\": " is_expiring_soon ","
                            print "  \\"daysUntilExpiry\\": " days_until ","
                            print "  \\"status\\": \\"" status "\\""
                            print -n "}"
                        }
                        cert_count++
                        common_name=""; subject=""; issuer=""; serial=""
                        not_before=""; not_after=""; key_algo=""; sig_algo=""
                        not_after_epoch=""; is_self_signed="false"
                    }
                    /Subject:/ { 
                        gsub(/^.*Subject: */, "")
                        subject=$0
                        # Extract CN from subject
                        if (match($0, /CN ?= ?[^,]+/)) {
                            common_name = substr($0, RSTART+3, RLENGTH-3)
                            gsub(/^ +| +$/, "", common_name)
                        }
                    }
                    /Issuer:/ { 
                        gsub(/^.*Issuer: */, "")
                        issuer=$0
                        # Check if self-signed (issuer == subject)
                        if (issuer == subject) is_self_signed="true"
                    }
                    /Serial Number:/ { 
                        gsub(/^.*Serial Number: */, "")
                        serial=$0
                    }
                    /Not Before:/ { 
                        gsub(/^.*Not Before: */, "")
                        not_before=$0
                    }
                    /Not After *:/ { 
                        gsub(/^.*Not After *: */, "")
                        not_after=$0
                        # Try to convert to epoch for comparison
                        cmd = "date -j -f \"%b %d %H:%M:%S %Y\" \"" not_after "\" +%s 2>/dev/null"
                        cmd | getline not_after_epoch
                        close(cmd)
                    }
                    /Public Key Algorithm:/ { 
                        gsub(/^.*Public Key Algorithm: */, "")
                        key_algo=$0
                    }
                    /Signature Algorithm:/ && sig_algo=="" { 
                        gsub(/^.*Signature Algorithm: */, "")
                        sig_algo=$0
                    }
                    END {
                        if (cert_count > 0 && subject != "") {
                            if (!first) print ","
                            is_expired = (not_after_epoch != "" && not_after_epoch < now) ? "true" : "false"
                            is_expiring_soon = (not_after_epoch != "" && not_after_epoch >= now && not_after_epoch <= soon) ? "true" : "false"
                            days_until = (not_after_epoch != "") ? int((not_after_epoch - now) / 86400) : 0
                            status = (is_expired == "true") ? "Expired" : ((is_expiring_soon == "true") ? "ExpiringSoon" : "Valid")
                            
                            print "{"
                            print "  \\"commonName\\": \\"" common_name "\\","
                            print "  \\"subject\\": \\"" subject "\\","
                            print "  \\"issuer\\": \\"" issuer "\\","
                            print "  \\"serialNumber\\": \\"" serial "\\","
                            print "  \\"storeName\\": \\"" store "\\","
                            print "  \\"storeLocation\\": \\"System\\","
                            print "  \\"notBefore\\": \\"" not_before "\\","
                            print "  \\"notAfter\\": \\"" not_after "\\","
                            print "  \\"keyAlgorithm\\": \\"" key_algo "\\","
                            print "  \\"signingAlgorithm\\": \\"" sig_algo "\\","
                            print "  \\"isSelfSigned\\": " is_self_signed ","
                            print "  \\"isExpired\\": " is_expired ","
                            print "  \\"isExpiringSoon\\": " is_expiring_soon ","
                            print "  \\"daysUntilExpiry\\": " days_until ","
                            print "  \\"status\\": \\"" status "\\""
                            print -n "}"
                        }
                    }
                '
            }
            
            # Process System keychain
            system_certs=$(process_keychain "/Library/Keychains/System.keychain" "System")
            
            # Process user login keychain if it exists
            user_keychain="$HOME/Library/Keychains/login.keychain-db"
            if [ ! -f "$user_keychain" ]; then
                user_keychain="$HOME/Library/Keychains/login.keychain"
            fi
            
            user_certs=""
            if [ -f "$user_keychain" ]; then
                user_certs=$(process_keychain "$user_keychain" "User")
            fi
            
            # Combine results
            if [ -n "$system_certs" ] && [ -n "$user_certs" ]; then
                echo "[$system_certs,$user_certs]"
            elif [ -n "$system_certs" ]; then
                echo "[$system_certs]"
            elif [ -n "$user_certs" ]; then
                echo "[$user_certs]"
            else
                echo "[]"
            fi
        """
        
        let result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript
        )
        
        // Process results into certificate array
        var certificates: [[String: Any]] = []
        let now = Date()
        let thirtyDaysFromNow = Calendar.current.date(byAdding: .day, value: 30, to: now)!
        
        if let items = result["items"] as? [[String: Any]] {
            ConsoleFormatter.writeDebug("Certificate collection: found \(items.count) raw certificates from osquery")
            
            for item in items {
                var cert: [String: Any] = [:]
                
                cert["commonName"] = item["common_name"] as? String ?? ""
                cert["subject"] = item["subject"] as? String ?? ""
                cert["issuer"] = item["issuer"] as? String ?? ""
                cert["serialNumber"] = item["serial"] as? String ?? ""
                cert["keyAlgorithm"] = item["key_algorithm"] as? String ?? ""
                cert["signingAlgorithm"] = item["signing_algorithm"] as? String ?? ""
                cert["keyLength"] = item["key_strength"] as? Int ?? 0
                cert["isSelfSigned"] = (item["self_signed"] as? String == "1") || (item["self_signed"] as? Int == 1)
                
                // Parse store info from path - INCLUDE the actual path for keychain identification
                if let path = item["path"] as? String {
                    cert["path"] = path  // Include actual path/keychain location
                    if path.contains("/Users/") {
                        cert["storeLocation"] = "User"
                    } else {
                        cert["storeLocation"] = "System"
                    }
                }
                
                // Parse dates - osquery returns Unix timestamps (can be String or Int)
                // Helper to get timestamp from either String or numeric type
                func getTimestamp(_ value: Any?) -> Double? {
                    if let str = value as? String, let ts = Double(str) {
                        return ts
                    } else if let intVal = value as? Int64 {
                        return Double(intVal)
                    } else if let intVal = value as? Int {
                        return Double(intVal)
                    } else if let dblVal = value as? Double {
                        return dblVal
                    }
                    return nil
                }
                
                if let notBeforeTimestamp = getTimestamp(item["not_valid_before"]) {
                    let notBefore = Date(timeIntervalSince1970: notBeforeTimestamp)
                    cert["notBefore"] = ISO8601DateFormatter().string(from: notBefore)
                }
                
                if let notAfterTimestamp = getTimestamp(item["not_valid_after"]) {
                    let notAfter = Date(timeIntervalSince1970: notAfterTimestamp)
                    cert["notAfter"] = ISO8601DateFormatter().string(from: notAfter)
                    
                    // Calculate expiry status
                    let daysUntilExpiry = Calendar.current.dateComponents([.day], from: now, to: notAfter).day ?? 0
                    cert["daysUntilExpiry"] = daysUntilExpiry
                    cert["isExpired"] = notAfter < now
                    cert["isExpiringSoon"] = notAfter >= now && notAfter <= thirtyDaysFromNow
                    
                    if notAfter < now {
                        cert["status"] = "Expired"
                    } else if notAfter <= thirtyDaysFromNow {
                        cert["status"] = "ExpiringSoon"
                    } else {
                        cert["status"] = "Valid"
                    }
                } else {
                    cert["status"] = "Unknown"
                    cert["isExpired"] = false
                    cert["isExpiringSoon"] = false
                    cert["daysUntilExpiry"] = 0
                }
                
                certificates.append(cert)
            }
            
            // Debug logging: status breakdown
            let validCount = certificates.filter { ($0["status"] as? String) == "Valid" }.count
            let expiredCount = certificates.filter { ($0["status"] as? String) == "Expired" }.count
            let expiringCount = certificates.filter { ($0["status"] as? String) == "ExpiringSoon" }.count
            let unknownCount = certificates.filter { ($0["status"] as? String) == "Unknown" }.count
            ConsoleFormatter.writeDebug("Certificate processing complete: \(certificates.count) total - Valid: \(validCount), Expired: \(expiredCount), ExpiringSoon: \(expiringCount), Unknown: \(unknownCount)")
        } else {
            ConsoleFormatter.writeDebug("Certificate collection: no 'items' key in result, keys: \(result.keys)")
        }
        
        return certificates
    }
    
    // MARK: - EDR Products (Microsoft Defender, CrowdStrike, SentinelOne, Carbon Black)
    
    /// Collect EDR/AV product details for security analyst reporting
    /// Detects installed EDR products and collects health/status information
    private func collectEDRProducts() async throws -> [String: Any] {
        var products: [[String: Any]] = []
        
        // Microsoft Defender for Endpoint (mdatp)
        let defender = try await collectMicrosoftDefender()
        if !defender.isEmpty {
            products.append(defender)
        }
        
        // CrowdStrike Falcon Sensor
        let crowdstrike = try await collectCrowdStrike()
        if !crowdstrike.isEmpty {
            products.append(crowdstrike)
        }
        
        // SentinelOne
        let sentinelone = try await collectSentinelOne()
        if !sentinelone.isEmpty {
            products.append(sentinelone)
        }
        
        ConsoleFormatter.writeDebug("EDR products: found \(products.count) installed products")
        
        return [
            "products": products,
            "count": products.count,
            "hasEDR": !products.isEmpty
        ]
    }
    
    /// Simple bash command execution helper for EDR collection
    private func executeBashScript(_ script: String) async throws -> String {
        let process = Process()
        let pipe = Pipe()
        
        process.standardOutput = pipe
        process.standardError = pipe
        process.executableURL = URL(fileURLWithPath: "/bin/bash")
        process.arguments = ["-c", script]
        
        try process.run()
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8) ?? ""
    }
    
    /// Collect Microsoft Defender for Endpoint status via mdatp CLI
    private func collectMicrosoftDefender() async throws -> [String: Any] {
        // Check if mdatp is installed
        let checkOutput = try await executeBashScript("[ -x /usr/local/bin/mdatp ] && echo 'installed' || echo 'not_installed'")
        guard checkOutput.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines) == "installed" else {
            ConsoleFormatter.writeDebug("Microsoft Defender: mdatp CLI not installed")
            return [:]
        }
        
        ConsoleFormatter.writeDebug("Microsoft Defender: mdatp CLI found, collecting health data")
        
        do {
            // Get health status
            let healthOutput = try await executeBashScript("/usr/local/bin/mdatp health --output json 2>/dev/null || echo '{}'")
            
            guard let healthData = healthOutput.data(using: .utf8),
                  let healthJson = try? JSONSerialization.jsonObject(with: healthData) as? [String: Any] else {
                ConsoleFormatter.writeDebug("Microsoft Defender: failed to parse health JSON")
                return [:]
            }
            
            // Get scan list - use jq to extract just last scan and threat count to reduce output size
            let scanSummaryScript = """
            /usr/local/bin/mdatp scan list --output json 2>/dev/null | python3 -c '
import json,sys
try:
    scans = json.load(sys.stdin)
    last = scans[-1] if scans else {}
    threats = sum(len(s.get("threats",[]) or []) for s in scans)
    print(json.dumps({"lastScan": last, "totalThreats": threats}))
except: print("{}")
' || echo '{}'
"""
            let scanSummaryOutput = try await executeBashScript(scanSummaryScript)
            
            var lastScan: [String: Any]? = nil
            var totalThreatsDetected = 0
            
            if let summaryData = scanSummaryOutput.data(using: .utf8),
               let summaryJson = try? JSONSerialization.jsonObject(with: summaryData) as? [String: Any] {
                lastScan = summaryJson["lastScan"] as? [String: Any]
                totalThreatsDetected = summaryJson["totalThreats"] as? Int ?? 0
            }
            
            // Parse health data for key fields
            let realTimeEnabled = parseDefenderBool(healthJson["realTimeProtectionEnabled"])
            let cloudEnabled = parseDefenderBool(healthJson["cloudEnabled"])
            let tamperProtection = parseDefenderValue(healthJson["tamperProtection"])
            let behaviorMonitoring = parseDefenderBool(healthJson["behaviorMonitoring"])
            
            // Parse definitions update time (milliseconds since epoch)
            var definitionsUpdated: String? = nil
            if let defUpdatedMs = healthJson["definitionsUpdated"] as? String,
               let ms = Int64(defUpdatedMs) {
                let date = Date(timeIntervalSince1970: Double(ms) / 1000.0)
                let formatter = ISO8601DateFormatter()
                definitionsUpdated = formatter.string(from: date)
            }
            
            // Parse last scan time
            var lastScanTime: String? = nil
            var lastScanType: String? = nil
            var lastScanFilesScanned: Int? = nil
            if let scan = lastScan {
                if let startMs = scan["startTime"] as? Int64 {
                    let date = Date(timeIntervalSince1970: Double(startMs) / 1000.0)
                    let formatter = ISO8601DateFormatter()
                    lastScanTime = formatter.string(from: date)
                } else if let startStr = scan["startTime"] as? String, let startMs = Int64(startStr) {
                    let date = Date(timeIntervalSince1970: Double(startMs) / 1000.0)
                    let formatter = ISO8601DateFormatter()
                    lastScanTime = formatter.string(from: date)
                }
                lastScanType = scan["type"] as? String
                if let files = scan["filesScanned"] as? Int {
                    lastScanFilesScanned = files
                } else if let filesStr = scan["filesScanned"] as? String, let files = Int(filesStr) {
                    lastScanFilesScanned = files
                }
            }
            
            // Health issues
            let healthIssues = healthJson["healthIssues"] as? [String] ?? []
            let isHealthy = healthJson["healthy"] as? Bool ?? false
            
            ConsoleFormatter.writeDebug("Microsoft Defender: healthy=\(isHealthy), realTime=\(realTimeEnabled), threats=\(totalThreatsDetected)")
            
            return [
                "name": "Microsoft Defender for Endpoint",
                "vendor": "Microsoft",
                "identifier": "com.microsoft.wdav",
                "installed": true,
                "version": healthJson["appVersion"] as? String ?? "",
                "engineVersion": healthJson["engineVersion"] as? String ?? "",
                "definitionsVersion": healthJson["definitionsVersion"] as? String ?? "",
                "definitionsUpdated": definitionsUpdated ?? "",
                "realTimeProtection": realTimeEnabled,
                "cloudProtection": cloudEnabled,
                "tamperProtection": tamperProtection == "block",
                "behaviorMonitoring": behaviorMonitoring,
                "healthy": isHealthy,
                "healthIssues": healthIssues,
                "licensed": healthJson["licensed"] as? Bool ?? false,
                "orgId": healthJson["orgId"] as? String ?? "",
                "machineId": healthJson["edrMachineId"] as? String ?? "",
                "releaseRing": healthJson["releaseRing"] as? String ?? "",
                "lastScanTime": lastScanTime ?? "",
                "lastScanType": lastScanType ?? "",
                "lastScanFilesScanned": lastScanFilesScanned ?? 0,
                "totalThreatsDetected": totalThreatsDetected,
                "networkProtection": parseDefenderValue(healthJson["networkProtectionEnforcementLevel"]),
                "deviceControl": healthJson["deviceControlEnforcementLevel"] as? String ?? "",
                "fullDiskAccess": healthJson["fullDiskAccessEnabled"] as? Bool ?? false
            ]
        } catch {
            ConsoleFormatter.writeDebug("Failed to collect Microsoft Defender status: \(error.localizedDescription)")
            return [:]
        }
    }
    
    /// Parse Defender boolean values (handles nested managed value structure)
    private func parseDefenderBool(_ value: Any?) -> Bool {
        if let dict = value as? [String: Any] {
            if let v = dict["value"] as? Bool { return v }
            if let v = dict["value"] as? String { return v == "enabled" || v == "true" }
        }
        if let b = value as? Bool { return b }
        if let s = value as? String { return s == "enabled" || s == "true" }
        return false
    }
    
    /// Parse Defender string values (handles nested managed value structure)
    private func parseDefenderValue(_ value: Any?) -> String {
        if let dict = value as? [String: Any] {
            if let v = dict["value"] as? String { return v }
            if let v = dict["value"] as? Bool { return v ? "enabled" : "disabled" }
        }
        if let s = value as? String { return s }
        if let b = value as? Bool { return b ? "enabled" : "disabled" }
        return ""
    }
    
    /// Collect CrowdStrike Falcon sensor status
    private func collectCrowdStrike() async throws -> [String: Any] {
        // Check if CrowdStrike is installed
        let checkOutput = try await executeBashScript("[ -x /Applications/Falcon.app/Contents/Resources/falconctl ] && echo 'installed' || echo 'not_installed'")
        guard checkOutput.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines) == "installed" else {
            return [:]
        }
        
        do {
            // Get Falcon sensor stats (note: requires sudo in most cases)
            let statsOutput = try await executeBashScript("/Applications/Falcon.app/Contents/Resources/falconctl stats 2>/dev/null || echo ''")
            
            // Parse version
            var version = ""
            var agentId = ""
            var customerId = ""
            var state = "unknown"
            
            for line in statsOutput.components(separatedBy: "\n") {
                let trimmed = line.trimmingCharacters(in: CharacterSet.whitespaces)
                if trimmed.hasPrefix("version:") {
                    version = trimmed.replacingOccurrences(of: "version:", with: "").trimmingCharacters(in: CharacterSet.whitespaces)
                } else if trimmed.hasPrefix("agentID:") {
                    agentId = trimmed.replacingOccurrences(of: "agentID:", with: "").trimmingCharacters(in: CharacterSet.whitespaces)
                } else if trimmed.hasPrefix("customerID:") {
                    customerId = trimmed.replacingOccurrences(of: "customerID:", with: "").trimmingCharacters(in: CharacterSet.whitespaces)
                } else if trimmed.hasPrefix("State:") {
                    state = trimmed.replacingOccurrences(of: "State:", with: "").trimmingCharacters(in: CharacterSet.whitespaces).lowercased()
                }
            }
            
            return [
                "name": "CrowdStrike Falcon",
                "vendor": "CrowdStrike",
                "identifier": "com.crowdstrike.falcon",
                "installed": true,
                "version": version,
                "agentId": agentId,
                "customerId": customerId,
                "state": state,
                "running": state == "connected" || state == "running"
            ]
        } catch {
            ConsoleFormatter.writeDebug("Failed to collect CrowdStrike status: \(error.localizedDescription)")
            return [:]
        }
    }
    
    /// Collect SentinelOne agent status
    private func collectSentinelOne() async throws -> [String: Any] {
        // Check if SentinelOne is installed
        let checkOutput = try await executeBashScript("[ -d '/Library/Sentinel/sentinel-agent.bundle' ] && echo 'installed' || echo 'not_installed'")
        guard checkOutput.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines) == "installed" else {
            return [:]
        }
        
        do {
            // Get SentinelOne agent version from bundle
            let versionOutput = try await executeBashScript("defaults read '/Library/Sentinel/sentinel-agent.bundle/Contents/Info.plist' CFBundleShortVersionString 2>/dev/null || echo ''")
            
            // Check if agent is running
            let runningOutput = try await executeBashScript("pgrep -x 'sentineld' >/dev/null && echo 'running' || echo 'stopped'")
            
            let version = versionOutput.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
            let isRunning = runningOutput.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines) == "running"
            
            return [
                "name": "SentinelOne",
                "vendor": "SentinelOne",
                "identifier": "com.sentinelone.sentinel-agent",
                "installed": true,
                "version": version,
                "running": isRunning,
                "state": isRunning ? "connected" : "stopped"
            ]
        } catch {
            ConsoleFormatter.writeDebug("Failed to collect SentinelOne status: \(error.localizedDescription)")
            return [:]
        }
    }
    
    // MARK: - Endpoint Security Extensions (systemextensionsctl list)
    
    /// Collect endpoint security extensions using systemextensionsctl
    /// This detects EDR/security products like CrowdStrike, SentinelOne, Carbon Black
    private func collectEndpointSecurityExtensions() async throws -> [String: Any] {
        // Parse systemextensionsctl output for endpoint security extensions
        // The output format has category headers like "--- com.apple.system_extension.endpoint_security"
        // followed by extension lines
        let bashScript = """
#!/bin/bash
# Parse systemextensionsctl list output for endpoint security extensions

output=$(systemextensionsctl list 2>&1)

echo "{"
echo "  \\"items\\": ["

first=true
current_category=""

while IFS= read -r line; do
    # Detect category headers
    if [[ "$line" =~ ^---\\ com\\.apple\\.system_extension\\.([a-z_]+) ]]; then
        current_category="${BASH_REMATCH[1]}"
        continue
    fi
    
    # Skip headers and empty lines
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^enabled ]] && continue
    [[ "$line" =~ ^[0-9]+\\ extension ]] && continue
    
    # Parse extension lines with bundleId
    bundleId=$(echo "$line" | grep -oE 'com\\.[a-zA-Z0-9._-]+' | head -1)
    [[ -z "$bundleId" ]] && continue
    
    # Extract version from parentheses
    version=$(echo "$line" | grep -oE '\\([0-9.]+[^)]*\\)' | head -1 | tr -d '()')
    
    # Extract state from brackets at end
    state=$(echo "$line" | grep -oE '\\[[^]]+\\]$' | tr -d '[]')
    
    # Extract teamId (10 char alphanumeric)
    teamId=$(echo "$line" | grep -oE '[A-Z0-9]{10}' | head -1)
    
    # Check enabled/active markers
    enabled="false"
    active="false"
    [[ "$line" =~ ^\\*[[:space:]] ]] && enabled="true"
    [[ "$line" =~ ^\\*[[:space:]]\\*[[:space:]] ]] && active="true"
    
    # Extract name - text between version parens and state bracket
    name=$(echo "$line" | sed -E 's/.*\\([^)]+\\)[[:space:]]*//' | sed -E 's/[[:space:]]*\\[.*$//')
    
    if [[ "$first" == "true" ]]; then
        first=false
    else
        echo ","
    fi
    
    echo "    { \\"identifier\\": \\"$bundleId\\", \\"teamId\\": \\"$teamId\\", \\"name\\": \\"$name\\", \\"version\\": \\"$version\\", \\"category\\": \\"$current_category\\", \\"enabled\\": $enabled, \\"active\\": $active, \\"state\\": \\"$state\\" }"
    
done <<< "$output"

echo "  ]"
echo "}"
"""
        
        do {
            let result = try await executeWithFallback(osquery: nil, bash: bashScript)
            
            // Extract extensions array from result
            var extensions: [[String: Any]] = []
            if let items = result["items"] as? [[String: Any]] {
                extensions = items
            }
            
            // Filter to only endpoint_security and network_extension categories (common for EDR)
            let endpointSecurityExtensions = extensions.filter { ext in
                let cat = ext["category"] as? String ?? ""
                return cat == "endpoint_security" || cat == "network_extension"
            }
            
            ConsoleFormatter.writeDebug("Endpoint security extensions: found \(endpointSecurityExtensions.count) relevant extensions out of \(extensions.count) total")
            
            return [
                "extensions": endpointSecurityExtensions,
                "allExtensions": extensions,
                "count": endpointSecurityExtensions.count,
                "error": ""
            ]
        } catch {
            ConsoleFormatter.writeDebug("Failed to collect endpoint security extensions: \(error.localizedDescription)")
            return [
                "extensions": [] as [[String: Any]],
                "count": 0,
                "error": error.localizedDescription
            ]
        }
    }
}
