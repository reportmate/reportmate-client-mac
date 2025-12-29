import Foundation

/// Security module processor - uses osquery first with bash fallback
/// Based on MunkiReport patterns for security status collection
/// Reference: https://github.com/munkireport/security
/// No Python - uses osquery for: sip_config, gatekeeper, alf, disk_encryption, xprotect_entries
/// Bash fallback for: SecureEnclave, ActivationLock, SecureBoot, MRT status
public class SecurityModuleProcessor: BaseModuleProcessor, @unchecked Sendable {
    
    public init(configuration: ReportMateConfiguration) {
        super.init(moduleId: "security", configuration: configuration)
    }
    
    public override func collectData() async throws -> ModuleData {
        // Collect security data using parallel async calls
        async let sipStatus = collectSIPStatus()
        async let gatekeeperStatus = collectGatekeeperStatus()
        async let firewallStatus = collectFirewallStatus()
        async let fileVaultStatus = collectFileVaultStatus()
        async let xprotectStatus = collectXProtectStatus()
        async let sshStatus = collectSSHStatus()
        async let secureBootStatus = collectSecureBootStatus()
        async let firmwarePasswordStatus = collectFirmwarePasswordStatus()
        async let rootUserStatus = collectRootUserStatus()
        async let mrtStatus = collectMRTStatus()
        async let secureEnclaveStatus = collectSecureEnclaveStatus()
        async let activationLockStatus = collectActivationLockStatus()
        async let fileVaultUsers = collectFileVaultUsers()
        async let authdbData = collectAuthDB()
        async let sofaUnpatchedCVEs = collectSofaUnpatchedCVEs()
        async let sofaSecurityRelease = collectSofaSecurityReleaseInfo()
        
        // Await all results
        let sip = try await sipStatus
        let gatekeeper = try await gatekeeperStatus
        let firewall = try await firewallStatus
        let fileVault = try await fileVaultStatus
        let xprotect = try await xprotectStatus
        let ssh = try await sshStatus
        let secureBoot = try await secureBootStatus
        let firmwarePassword = try await firmwarePasswordStatus
        let rootUser = try await rootUserStatus
        let mrt = try await mrtStatus
        let secureEnclave = try await secureEnclaveStatus
        let activationLock = try await activationLockStatus
        let fvUsers = try await fileVaultUsers
        let authdb = try await authdbData
        let unpatchedCVEs = try await sofaUnpatchedCVEs
        let securityRelease = try await sofaSecurityRelease
        
        // Build security data dictionary
        let securityData: [String: Any] = [
            "systemIntegrityProtection": sip,
            "gatekeeper": gatekeeper,
            "firewall": firewall,
            "fileVault": fileVault,
            "fileVaultUsers": fvUsers,
            "xprotect": xprotect,
            "ssh": ssh,
            "secureBoot": secureBoot,
            "firmwarePassword": firmwarePassword,
            "rootUser": rootUser,
            "mrt": mrt,
            "secureEnclave": secureEnclave,
            "activationLock": activationLock,
            "authorizationDB": authdb,
            "unpatchedCVEs": unpatchedCVEs,
            "securityReleaseInfo": securityRelease
        ]
        
        return BaseModuleData(moduleId: moduleId, data: securityData)
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
            bash: nil,
            python: nil
        )
        
        // Always get bash result for main status
        let bashResult = try await executeWithFallback(
            osquery: nil,
            bash: bashScript,
            python: nil
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
            bash: bashScript,
            python: nil
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
            bash: bashScript,
            python: nil
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
            
            # Get enabled users
            enabled_users=""
            if [ "$enabled" = "true" ]; then
                enabled_users=$(fdesetup list 2>/dev/null | cut -d',' -f1 | tr '\\n' ',' | sed 's/,$//')
            fi
            
            echo "{"
            echo "  \\"enabled\\": $enabled,"
            echo "  \\"status\\": \\"$status\\","
            echo "  \\"deferred\\": $deferred,"
            echo "  \\"enabledUsers\\": \\"$enabled_users\\""
            echo "}"
        """
        
        let result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript,
            python: nil
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
        
        // Parse enabled users
        var enabledUsers: [String] = []
        if let users = result["enabledUsers"] as? String, !users.isEmpty {
            enabledUsers = users.components(separatedBy: ",").filter { !$0.isEmpty }
        }
        
        return [
            "enabled": enabled,
            "status": status,
            "deferred": deferred,
            "enabledUsers": enabledUsers
        ]
    }
    
    // MARK: - FileVault Users (macadmins extension: filevault_users)
    
    private func collectFileVaultUsers() async throws -> [[String: Any]] {
        // macadmins extension: filevault_users table provides detailed user information
        let osqueryScript = """
            SELECT 
                username,
                uid,
                user_guid,
                user_uuid,
                passphrase_required
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
            bash: bashScript,
            python: nil
        )
        
        // Return users array
        if let items = result["items"] as? [[String: Any]] {
            return items
        }
        
        return []
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
            bash: nil,
            python: nil
        )
        
        // Get version and status from bash
        let bashResult = try await executeWithFallback(
            osquery: nil,
            bash: bashScript,
            python: nil
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
            bash: bashScript,
            python: nil
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
            bash: bashScript,
            python: nil
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
            bash: bashScript,
            python: nil
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
            bash: bashScript,
            python: nil
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
            bash: bashScript,
            python: nil
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
            bash: bashScript,
            python: nil
        )
    }
    
    // MARK: - Activation Lock Status (bash)
    
    private func collectActivationLockStatus() async throws -> [String: Any] {
        let bashScript = """
            # Check Activation Lock status
            # This requires MDM enrollment to be truly accurate
            
            activation_lock="Unknown"
            find_my_mac="Unknown"
            
            # Try to get from system_profiler
            hw_info=$(system_profiler SPHardwareDataType 2>/dev/null || echo "")
            
            if echo "$hw_info" | grep -qi "Activation Lock Status: Enabled"; then
                activation_lock="Enabled"
            elif echo "$hw_info" | grep -qi "Activation Lock Status: Disabled"; then
                activation_lock="Disabled"
            fi
            
            # Check Find My Mac status
            fmm_plist="/Library/Preferences/com.apple.findmy.plist"
            if [ -f "$fmm_plist" ]; then
                fmm_enabled=$(/usr/libexec/PlistBuddy -c "Print :FMMEnabled" "$fmm_plist" 2>/dev/null || echo "")
                if [ "$fmm_enabled" = "true" ]; then
                    find_my_mac="Enabled"
                elif [ "$fmm_enabled" = "false" ]; then
                    find_my_mac="Disabled"
                fi
            fi
            
            # Alternative: check via nvram (less reliable)
            if [ "$activation_lock" = "Unknown" ]; then
                nvram_fmm=$(nvram -p 2>/dev/null | grep -i "fmm-" || echo "")
                if [ -n "$nvram_fmm" ]; then
                    find_my_mac="Likely Enabled"
                fi
            fi
            
            echo "{"
            echo "  \\"status\\": \\"$activation_lock\\","
            echo "  \\"findMyMac\\": \\"$find_my_mac\\""
            echo "}"
        """
        
        return try await executeWithFallback(
            osquery: nil,
            bash: bashScript,
            python: nil
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
        // Provides CVE information for unpatched vulnerabilities
        let osqueryScript = """
            SELECT 
                os_version,
                cve,
                product_name,
                actively_exploited,
                release_date
            FROM sofa_unpatched_cves
            ORDER BY actively_exploited DESC, release_date DESC
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
        // Provides information about security releases for the current OS
        let osqueryScript = """
            SELECT 
                os_version,
                release_date,
                security_release,
                days_since_release,
                actively_exploited_count,
                total_cve_count,
                update_available
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
}
