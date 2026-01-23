import Foundation

/// Identity module processor - collects user accounts, sessions, and identity management data
/// Based on MunkiReport patterns for user/account collection
/// Reference: https://github.com/munkireport/users, https://github.com/munkireport/user_sessions
/// Collects: local users, group memberships, login sessions, Platform SSO user data,
///           background task management database health (critical for shared Mac environments)
public class IdentityModuleProcessor: BaseModuleProcessor, @unchecked Sendable {
    
    public init(configuration: ReportMateConfiguration) {
        super.init(moduleId: "identity", configuration: configuration)
    }
    
    public override func collectData() async throws -> ModuleData {
        // Total collection steps for progress tracking
        let totalSteps = 8
        
        // Collect identity data sequentially with progress tracking
        ConsoleFormatter.writeQueryProgress(queryName: "user_accounts", current: 1, total: totalSteps)
        let userAccounts = try await collectUserAccounts()
        
        ConsoleFormatter.writeQueryProgress(queryName: "groups", current: 2, total: totalSteps)
        let groups = try await collectGroups()
        
        ConsoleFormatter.writeQueryProgress(queryName: "logged_in_users", current: 3, total: totalSteps)
        let loggedInUsers = try await collectLoggedInUsers()
        
        ConsoleFormatter.writeQueryProgress(queryName: "login_history", current: 4, total: totalSteps)
        let loginHistory = try await collectLoginHistory()
        
        ConsoleFormatter.writeQueryProgress(queryName: "btmdb_health", current: 5, total: totalSteps)
        let btmdbHealth = try await collectBTMDBHealth()
        
        ConsoleFormatter.writeQueryProgress(queryName: "directory_services", current: 6, total: totalSteps)
        let directoryServices = try await collectDirectoryServices()
        
        ConsoleFormatter.writeQueryProgress(queryName: "secure_token_users", current: 7, total: totalSteps)
        let secureTokenUsers = try await collectSecureTokenUsers()
        
        ConsoleFormatter.writeQueryProgress(queryName: "platform_sso_users", current: 8, total: totalSteps)
        let platformSSOUsers = try await collectPlatformSSOUsers()
        
        // Build identity data dictionary
        let identityData: [String: Any] = [
            "users": userAccounts,
            "groups": groups,
            "loggedInUsers": loggedInUsers,
            "loginHistory": loginHistory,
            "btmdbHealth": btmdbHealth,
            "directoryServices": directoryServices,
            "secureTokenUsers": secureTokenUsers,
            "platformSSOUsers": platformSSOUsers,
            "summary": buildSummary(
                users: userAccounts,
                loggedIn: loggedInUsers,
                btmdb: btmdbHealth
            )
        ]
        
        return BaseModuleData(moduleId: moduleId, data: identityData)
    }
    
    // MARK: - User Accounts Collection
    
    /// Collect comprehensive user account information
    /// Uses dscl for rich data (admin status, SSH access, last logon, group membership, linked Apple ID)
    /// NOTE: We intentionally skip osquery users table as it lacks admin status and other critical fields
    private func collectUserAccounts() async throws -> [[String: Any]] {
        // Bash provides comprehensive dscl data matching MunkiReport users module
        // osquery users table is too limited (no admin status, SSH access, etc.)
        let bashScript = """
            # Collect comprehensive user account data using dscl
            # Matches MunkiReport users module fields
            
            users_json="["
            first=true
            
            # Get all local users with UID >= 500 (excluding system accounts)
            for user in $(dscl . -list /Users UniqueID 2>/dev/null | awk '$2 >= 500 && $2 < 65534 {print $1}'); do
                user_path="/Users/$user"
                
                # Get user attributes from dscl
                uid=$(dscl . -read "$user_path" UniqueID 2>/dev/null | awk '{print $2}' || echo "")
                gid=$(dscl . -read "$user_path" PrimaryGroupID 2>/dev/null | awk '{print $2}' || echo "20")
                real_name=$(dscl . -read "$user_path" RealName 2>/dev/null | sed '1d' | xargs || echo "")
                [ -z "$real_name" ] && real_name=$(dscl . -read "$user_path" RealName 2>/dev/null | awk -F': ' '{print $2}' || echo "")
                home_dir=$(dscl . -read "$user_path" NFSHomeDirectory 2>/dev/null | awk '{print $2}' || echo "")
                shell=$(dscl . -read "$user_path" UserShell 2>/dev/null | awk '{print $2}' || echo "")
                uuid=$(dscl . -read "$user_path" GeneratedUID 2>/dev/null | awk '{print $2}' || echo "")
                
                # Check if admin (member of admin group)
                is_admin="false"
                if dscl . -read /Groups/admin GroupMembership 2>/dev/null | grep -qw "$user"; then
                    is_admin="true"
                fi
                
                # Check SSH access (member of com.apple.access_ssh or SSH enabled for all)
                ssh_access="false"
                if dscl . -read /Groups/com.apple.access_ssh GroupMembership 2>/dev/null | grep -qw "$user"; then
                    ssh_access="true"
                elif [ "$is_admin" = "true" ]; then
                    # Admins often have SSH access if Remote Login is enabled
                    if systemsetup -getremotelogin 2>/dev/null | grep -qi "On"; then
                        ssh_access="true"
                    fi
                fi
                
                # Check Screen Sharing access
                screen_sharing="false"
                if dscl . -read /Groups/com.apple.access_screensharing GroupMembership 2>/dev/null | grep -qw "$user"; then
                    screen_sharing="true"
                fi
                
                # Check auto-login
                auto_login="false"
                auto_login_user=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null || echo "")
                if [ "$auto_login_user" = "$user" ]; then
                    auto_login="true"
                fi
                
                # Password hint
                password_hint=$(dscl . -read "$user_path" AuthenticationHint 2>/dev/null | sed '1d' | xargs || echo "")
                
                # Account creation time
                # dsAttrTypeNative:accountPolicyData contains account creation time
                creation_time=""
                password_last_set=""
                failed_login_count="0"
                last_failed_login=""
                
                # Try to get account policy data (contains timestamps)
                policy_data=$(dscl . -read "$user_path" accountPolicyData 2>/dev/null || echo "")
                if [ -n "$policy_data" ]; then
                    # Extract creationTime (Unix timestamp)
                    creation_ts=$(echo "$policy_data" | grep -o 'creationTime = [0-9.]*' | awk '{print $3}' | cut -d'.' -f1)
                    if [ -n "$creation_ts" ] && [ "$creation_ts" != "0" ]; then
                        creation_time=$(date -r "$creation_ts" -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "")
                    fi
                    
                    # Extract passwordLastSetTime
                    pwd_ts=$(echo "$policy_data" | grep -o 'passwordLastSetTime = [0-9.]*' | awk '{print $3}' | cut -d'.' -f1)
                    if [ -n "$pwd_ts" ] && [ "$pwd_ts" != "0" ]; then
                        password_last_set=$(date -r "$pwd_ts" -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "")
                    fi
                    
                    # Extract failed login count
                    failed_count=$(echo "$policy_data" | grep -o 'failedLoginCount = [0-9]*' | awk '{print $3}')
                    [ -n "$failed_count" ] && failed_login_count="$failed_count"
                    
                    # Extract last failed login timestamp
                    failed_ts=$(echo "$policy_data" | grep -o 'failedLoginTimestamp = [0-9.]*' | awk '{print $3}' | cut -d'.' -f1)
                    if [ -n "$failed_ts" ] && [ "$failed_ts" != "0" ]; then
                        last_failed_login=$(date -r "$failed_ts" -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "")
                    fi
                fi
                
                # Last login time (from wtmp/utmpx)
                last_logon=$(last -1 "$user" 2>/dev/null | head -1 | awk '{
                    if (NF >= 5) {
                        # Format: user tty host day mon date time
                        printf "%s %s %s %s", $4, $5, $6, $7
                    }
                }' || echo "")
                if [ -n "$last_logon" ]; then
                    # Convert to ISO format
                    last_logon_iso=$(date -j -f "%a %b %d %H:%M" "$last_logon" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "$last_logon")
                else
                    last_logon_iso=""
                fi
                
                # Linked Apple ID (from MobileMeAccounts)
                linked_apple_id=""
                linked_date=""
                if [ -f "$home_dir/Library/Preferences/MobileMeAccounts.plist" ]; then
                    linked_apple_id=$(defaults read "$home_dir/Library/Preferences/MobileMeAccounts" Accounts 2>/dev/null | awk -F'"' '/AccountID/ {print $2; exit}' || echo "")
                    # Try to get linked date from plist modification time
                    if [ -n "$linked_apple_id" ]; then
                        linked_date=$(stat -f "%Sm" -t "%Y-%m-%dT%H:%M:%SZ" "$home_dir/Library/Preferences/MobileMeAccounts.plist" 2>/dev/null || echo "")
                    fi
                fi
                
                # Get group memberships
                group_memberships=""
                for group in $(dscl . -list /Groups 2>/dev/null); do
                    if dscl . -read "/Groups/$group" GroupMembership 2>/dev/null | grep -qw "$user"; then
                        [ -n "$group_memberships" ] && group_memberships="$group_memberships, "
                        group_memberships="$group_memberships$group"
                    fi
                done
                
                # Check if account is disabled
                is_disabled="false"
                auth_authority=$(dscl . -read "$user_path" AuthenticationAuthority 2>/dev/null || echo "")
                if echo "$auth_authority" | grep -qi "DisabledUser"; then
                    is_disabled="true"
                fi
                
                # Build JSON for this user
                if [ "$first" = "true" ]; then
                    first=false
                else
                    users_json="$users_json,"
                fi
                
                # Escape quotes in strings
                real_name_escaped=$(echo "$real_name" | sed 's/"/\\\\"/g')
                password_hint_escaped=$(echo "$password_hint" | sed 's/"/\\\\"/g')
                group_memberships_escaped=$(echo "$group_memberships" | sed 's/"/\\\\"/g')
                
                users_json="$users_json{"
                users_json="$users_json\\"username\\": \\"$user\\","
                users_json="$users_json\\"realName\\": \\"$real_name_escaped\\","
                users_json="$users_json\\"uid\\": $uid,"
                users_json="$users_json\\"gid\\": $gid,"
                users_json="$users_json\\"homeDirectory\\": \\"$home_dir\\","
                users_json="$users_json\\"shell\\": \\"$shell\\","
                users_json="$users_json\\"uuid\\": \\"$uuid\\","
                users_json="$users_json\\"isAdmin\\": $is_admin,"
                users_json="$users_json\\"sshAccess\\": $ssh_access,"
                users_json="$users_json\\"screenSharingAccess\\": $screen_sharing,"
                users_json="$users_json\\"autoLoginEnabled\\": $auto_login,"
                users_json="$users_json\\"passwordHint\\": \\"$password_hint_escaped\\","
                users_json="$users_json\\"creationTime\\": \\"$creation_time\\","
                users_json="$users_json\\"passwordLastSet\\": \\"$password_last_set\\","
                users_json="$users_json\\"lastLogon\\": \\"$last_logon_iso\\","
                users_json="$users_json\\"failedLoginCount\\": $failed_login_count,"
                users_json="$users_json\\"lastFailedLogin\\": \\"$last_failed_login\\","
                users_json="$users_json\\"linkedAppleId\\": \\"$linked_apple_id\\","
                users_json="$users_json\\"linkedDate\\": \\"$linked_date\\","
                users_json="$users_json\\"groupMembership\\": \\"$group_memberships_escaped\\","
                users_json="$users_json\\"isDisabled\\": $is_disabled"
                users_json="$users_json}"
            done
            
            users_json="$users_json]"
            echo "$users_json"
        """
        
        // Only use bash script - osquery users table lacks admin status and other critical fields
        let result = try await executeWithFallback(
            osquery: nil,
            bash: bashScript
        )
        
        // Handle multiple results wrapped in "items"
        if let items = result["items"] as? [[String: Any]] {
            return items
        }
        
        // Handle single result returned directly (osquery with 1 user)
        // Check if this looks like a user object (has username or uid)
        if result["username"] != nil || result["uid"] != nil {
            return [result]
        }
        
        return []
    }
    
    // MARK: - Groups Collection
    
    private func collectGroups() async throws -> [[String: Any]] {
        let osqueryScript = """
            SELECT 
                gid,
                groupname,
                group_sid,
                comment
            FROM groups
            WHERE gid >= 500 OR groupname IN ('admin', 'staff', 'wheel', 'com.apple.access_ssh', 'com.apple.access_screensharing');
        """
        
        let bashScript = """
            echo "["
            first=true
            
            # Get key groups
            for group in admin staff wheel com.apple.access_ssh com.apple.access_screensharing; do
                gid=$(dscl . -read "/Groups/$group" PrimaryGroupID 2>/dev/null | awk '{print $2}' || echo "")
                [ -z "$gid" ] && continue
                
                members=$(dscl . -read "/Groups/$group" GroupMembership 2>/dev/null | sed 's/GroupMembership: //' || echo "")
                
                if [ "$first" = "true" ]; then
                    first=false
                else
                    echo ","
                fi
                
                echo "{\\"groupname\\": \\"$group\\", \\"gid\\": $gid, \\"members\\": \\"$members\\"}"
            done
            
            echo "]"
        """
        
        let result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript
        )
        
        // Handle multiple results wrapped in "items"
        if let items = result["items"] as? [[String: Any]] {
            return items
        }
        
        // Handle single result returned directly
        if result["groupname"] != nil || result["gid"] != nil {
            return [result]
        }
        
        return []
    }
    
    // MARK: - Logged In Users
    
    private func collectLoggedInUsers() async throws -> [[String: Any]] {
        let osqueryScript = """
            SELECT 
                user,
                tty,
                host,
                time,
                pid
            FROM logged_in_users;
        """
        
        let bashScript = """
            echo "["
            first=true
            
            who 2>/dev/null | while read -r line; do
                user=$(echo "$line" | awk '{print $1}')
                tty=$(echo "$line" | awk '{print $2}')
                login_time=$(echo "$line" | awk '{print $3, $4, $5}')
                
                if [ "$first" = "true" ]; then
                    first=false
                else
                    echo ","
                fi
                
                echo "{\\"user\\": \\"$user\\", \\"tty\\": \\"$tty\\", \\"loginTime\\": \\"$login_time\\"}"
            done
            
            echo "]"
        """
        
        let result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript
        )
        
        // Handle multiple results wrapped in "items"
        if let items = result["items"] as? [[String: Any]] {
            return items
        }
        
        // Handle single result returned directly
        if result["user"] != nil || result["tty"] != nil {
            return [result]
        }
        
        return []
    }
    
    // MARK: - Login History
    
    private func collectLoginHistory() async throws -> [[String: Any]] {
        // Get last 50 login events
        let osqueryScript = """
            SELECT 
                username,
                tty,
                pid,
                type,
                time
            FROM last
            WHERE username != '' AND username != 'reboot' AND username != 'shutdown'
            ORDER BY time DESC
            LIMIT 50;
        """
        
        let bashScript = """
            echo "["
            first=true
            
            last -50 2>/dev/null | grep -v "^$" | grep -v "^wtmp" | grep -v "reboot" | grep -v "shutdown" | while read -r line; do
                user=$(echo "$line" | awk '{print $1}')
                tty=$(echo "$line" | awk '{print $2}')
                login_time=$(echo "$line" | awk '{print $3, $4, $5, $6}')
                duration=$(echo "$line" | awk '{print $(NF-1), $NF}')
                
                [ -z "$user" ] && continue
                
                if [ "$first" = "true" ]; then
                    first=false
                else
                    echo ","
                fi
                
                echo "{\\"username\\": \\"$user\\", \\"tty\\": \\"$tty\\", \\"loginTime\\": \\"$login_time\\", \\"duration\\": \\"$duration\\"}"
            done
            
            echo "]"
        """
        
        let result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript
        )
        
        // Handle multiple results wrapped in "items"
        if let items = result["items"] as? [[String: Any]] {
            return items
        }
        
        // Handle single result returned directly
        if result["username"] != nil || result["tty"] != nil {
            return [result]
        }
        
        return []
    }
    
    // MARK: - BTM Database Health (Critical for Shared Macs)
    
    /// Collects background task management database health metrics
    /// Critical for shared Mac environments where BTMDB can exceed 4MB limit
    /// causing loginwindow deadlocks and system freezes
    private func collectBTMDBHealth() async throws -> [String: Any] {
        let bashScript = """
            # Background Task Management Database Health Check
            # Critical for shared Mac environments (labs, classrooms)
            # BTMDB can't exceed ~4MB as of macOS Tahoe - causes loginwindow deadlocks
            
            btmdb_path="/private/var/db/com.apple.backgroundtaskmanagement"
            
            # Get database size - the physical directory may be empty on modern macOS
            # because the actual data is managed by the system. Use sfltool output
            # size as a proxy for the effective database size.
            db_size_bytes=0
            db_size_mb="0.00"
            db_exists=false
            
            if [ -d "$btmdb_path" ]; then
                db_exists=true
                
                # First try file-based size (traditional approach)
                raw_size=$(find "$btmdb_path" -type f -exec stat -f%z {} + 2>/dev/null | awk '{s+=$1} END {print s+0}')
                file_size_bytes=$((${raw_size:-0} + 0))
                
                # If directory is empty, use sfltool dumpbtm output size as proxy
                # This represents the actual data managed by the BTM service
                if [ "$file_size_bytes" -eq 0 ]; then
                    btm_dump_size=$(sfltool dumpbtm 2>/dev/null | wc -c | tr -d ' ')
                    db_size_bytes=$((${btm_dump_size:-0} + 0))
                else
                    db_size_bytes=$file_size_bytes
                fi
                
                # Calculate MB with awk for reliability (bc may not be available)
                db_size_mb=$(awk "BEGIN {printf \\"%.2f\\", $db_size_bytes / 1048576}")
            fi
            
            # Determine health status based on size thresholds
            # Warning: 3MB, Critical: 3.5MB, Failure likely: 4MB+
            status="healthy"
            status_message="Database size within normal limits"
            
            if [ "$db_size_bytes" -gt 4194304 ] 2>/dev/null; then
                status="critical"
                status_message="Database exceeds 4MB - loginwindow deadlocks likely"
            elif [ "$db_size_bytes" -gt 3670016 ] 2>/dev/null; then
                status="critical"
                status_message="Database exceeds 3.5MB - approaching failure threshold"
            elif [ "$db_size_bytes" -gt 3145728 ] 2>/dev/null; then
                status="warning"
                status_message="Database exceeds 3MB - monitoring recommended"
            fi
            
            # Count jetsam kills in last 7 days (backgroundtaskmanagementd memory limit exceeded)
            jetsam_count=0
            last_jetsam=""
            
            jetsam_output=$(log show --predicate 'eventMessage CONTAINS "backgroundtaskmanagementd" AND eventMessage CONTAINS "jetsam reason per-process-limit"' --style syslog --info --last 7d 2>/dev/null || echo "")
            
            if [ -n "$jetsam_output" ]; then
                raw_jetsam_count=$(echo "$jetsam_output" | grep -c "jetsam reason per-process-limit" 2>/dev/null || echo "0")
                # Ensure it's a valid integer
                jetsam_count=$((raw_jetsam_count + 0))
                last_jetsam=$(echo "$jetsam_output" | tail -1 | awk '{print $1, $2}' || echo "")
            fi
            
            # If high jetsam count, escalate status
            if [ "$jetsam_count" -gt 100 ] 2>/dev/null && [ "$status" = "healthy" ]; then
                status="warning"
                status_message="High backgroundtaskmanagementd jetsam kill rate ($jetsam_count in 7 days)"
            elif [ "$jetsam_count" -gt 200 ] 2>/dev/null; then
                status="critical"
                status_message="Critical backgroundtaskmanagementd instability ($jetsam_count jetsam kills in 7 days)"
            fi
            
            # Get number of registered background items
            item_count=0
            if [ -d "$btmdb_path" ]; then
                raw_item_count=$(sfltool dumpbtm 2>/dev/null | grep -c "Name:" || echo "0")
                item_count=$((raw_item_count + 0))
            fi
            
            # Get number of local user accounts (correlates with BTM growth)
            raw_user_count=$(dscl . -list /Users UniqueID 2>/dev/null | awk '$2 >= 500 && $2 < 65534' | wc -l | tr -d ' ')
            user_count=$((raw_user_count + 0))
            
            # Output proper JSON with unquoted booleans and numbers
            echo "{"
            echo "  \\"exists\\": $db_exists,"
            echo "  \\"path\\": \\"$btmdb_path\\","
            echo "  \\"sizeBytes\\": $db_size_bytes,"
            echo "  \\"sizeMB\\": $db_size_mb,"
            echo "  \\"status\\": \\"$status\\","
            echo "  \\"statusMessage\\": \\"$status_message\\","
            echo "  \\"jetsamKillsLast7Days\\": $jetsam_count,"
            echo "  \\"lastJetsamEvent\\": \\"$last_jetsam\\","
            echo "  \\"registeredItemCount\\": $item_count,"
            echo "  \\"localUserCount\\": $user_count,"
            echo "  \\"thresholds\\": {"
            echo "    \\"warningMB\\": 3.0,"
            echo "    \\"criticalMB\\": 3.5,"
            echo "    \\"failureMB\\": 4.0"
            echo "  }"
            echo "}"
        """
        
        return try await executeWithFallback(
            osquery: nil,
            bash: bashScript
        )
    }
    
    // MARK: - Directory Services
    
    private func collectDirectoryServices() async throws -> [String: Any] {
        let bashScript = """
            # Check directory service bindings
            ad_bound="false"
            ad_domain=""
            ldap_bound="false"
            ldap_server=""
            
            # Check Active Directory binding
            ad_info=$(dsconfigad -show 2>/dev/null || echo "")
            if echo "$ad_info" | grep -q "Active Directory Domain"; then
                ad_bound="true"
                ad_domain=$(echo "$ad_info" | grep "Active Directory Domain" | awk -F'= ' '{print $2}')
            fi
            
            # Check LDAP
            ldap_info=$(dscl /LDAPv3 -list / 2>/dev/null || echo "")
            if [ -n "$ldap_info" ]; then
                ldap_bound="true"
                ldap_server=$(echo "$ldap_info" | head -1)
            fi
            
            # Check local directory nodes
            nodes=$(dscl -list / 2>/dev/null | tr '\\n' ',' | sed 's/,$//')
            
            echo "{"
            echo "  \\"activeDirectory\\": {"
            echo "    \\"bound\\": $ad_bound,"
            echo "    \\"domain\\": \\"$ad_domain\\""
            echo "  },"
            echo "  \\"ldap\\": {"
            echo "    \\"bound\\": $ldap_bound,"
            echo "    \\"server\\": \\"$ldap_server\\""
            echo "  },"
            echo "  \\"directoryNodes\\": \\"$nodes\\""
            echo "}"
        """
        
        return try await executeWithFallback(
            osquery: nil,
            bash: bashScript
        )
    }
    
    // MARK: - Secure Token Users (for MDM workflows)
    
    private func collectSecureTokenUsers() async throws -> [String: Any] {
        let bashScript = """
            users_with_token=()
            users_without_token=()
            total_checked=0
            
            # Get all local users with UID >= 500
            for user in $(dscl . -list /Users UniqueID | awk '$2 >= 500 && $2 < 65534 {print $1}'); do
                total_checked=$((total_checked + 1))
                status=$(sysadminctl -secureTokenStatus "$user" 2>&1 || echo "Unknown")
                
                if echo "$status" | grep -qi "enabled"; then
                    users_with_token+=("$user")
                elif echo "$status" | grep -qi "disabled"; then
                    users_without_token+=("$user")
                fi
            done
            
            # Build JSON arrays
            with_token_json="["
            first=true
            for u in "${users_with_token[@]}"; do
                [ "$first" = false ] && with_token_json="$with_token_json,"
                first=false
                with_token_json="$with_token_json\\"$u\\""
            done
            with_token_json="$with_token_json]"
            
            without_token_json="["
            first=true
            for u in "${users_without_token[@]}"; do
                [ "$first" = false ] && without_token_json="$without_token_json,"
                first=false
                without_token_json="$without_token_json\\"$u\\""
            done
            without_token_json="$without_token_json]"
            
            echo "{"
            echo "  \\"usersWithToken\\": $with_token_json,"
            echo "  \\"usersWithoutToken\\": $without_token_json,"
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
    
    // MARK: - Platform SSO Users (user-level SSO registration status)
    
    /// Collects Platform SSO user registration status
    /// This focuses on per-user SSO registration, complementing the device-level config in Security module
    private func collectPlatformSSOUsers() async throws -> [String: Any] {
        let bashScript = """
            # Platform SSO user registration status (macOS 13+ Ventura)
            # Focuses on per-user SSO registration for Identity module
            
            # Check macOS version (Platform SSO requires 13+)
            os_version=$(sw_vers -productVersion | cut -d. -f1)
            if [ "$os_version" -lt 13 ]; then
                echo "{"
                echo "  \\"supported\\": false,"
                echo "  \\"users\\": []"
                echo "}"
                exit 0
            fi
            
            # Get device SSO state to check if Platform SSO is configured
            sso_state=$(app-sso platform -s 2>/dev/null || echo "")
            registered="false"
            
            if [ -n "$sso_state" ]; then
                if echo "$sso_state" | grep -q '"registrationCompleted" *: *true'; then
                    registered="true"
                fi
            fi
            
            if [ "$registered" != "true" ]; then
                echo "{"
                echo "  \\"supported\\": true,"
                echo "  \\"deviceRegistered\\": false,"
                echo "  \\"users\\": []"
                echo "}"
                exit 0
            fi
            
            # Collect per-user SSO registration status
            users_json="["
            first_user="true"
            registered_count=0
            unregistered_count=0
            
            # Get all human users
            for user in $(dscl . -list /Users | grep -v "^_" | grep -v "daemon\\|nobody\\|root\\|Guest"); do
                user_home=$(dscl . -read /Users/"$user" NFSHomeDirectory 2>/dev/null | awk '{print $2}' || echo "")
                if [ ! -d "$user_home" ] || [ "$user_home" = "/var/empty" ]; then
                    continue
                fi
                
                # Run app-sso as the user to get their SSO status
                user_sso=$(sudo -u "$user" app-sso platform -s 2>/dev/null || echo "")
                
                user_registered="false"
                user_upn=""
                last_auth=""
                
                if [ -n "$user_sso" ]; then
                    if echo "$user_sso" | grep -q '"registrationCompleted" *: *true'; then
                        user_registered="true"
                        registered_count=$((registered_count + 1))
                    else
                        unregistered_count=$((unregistered_count + 1))
                    fi
                    
                    # Try to extract user principal name
                    user_upn=$(echo "$user_sso" | grep '"userPrincipalName"' | head -1 | sed 's/.*: *"\\([^"]*\\)".*/\\1/' || echo "")
                else
                    unregistered_count=$((unregistered_count + 1))
                fi
                
                if [ "$first_user" = "true" ]; then
                    first_user="false"
                else
                    users_json="$users_json,"
                fi
                
                users_json="$users_json{"
                users_json="$users_json\\"username\\": \\"$user\\","
                users_json="$users_json\\"registered\\": $user_registered,"
                users_json="$users_json\\"userPrincipalName\\": \\"$user_upn\\""
                users_json="$users_json}"
            done
            
            users_json="$users_json]"
            
            echo "{"
            echo "  \\"supported\\": true,"
            echo "  \\"deviceRegistered\\": true,"
            echo "  \\"registeredUserCount\\": $registered_count,"
            echo "  \\"unregisteredUserCount\\": $unregistered_count,"
            echo "  \\"users\\": $users_json"
            echo "}"
        """
        
        return try await executeWithFallback(
            osquery: nil,
            bash: bashScript
        )
    }
    
    // MARK: - Summary Builder
    
    private func buildSummary(
        users: [[String: Any]],
        loggedIn: [[String: Any]],
        btmdb: [String: Any]
    ) -> [String: Any] {
        let totalUsers = users.count
        let adminCount = users.filter { ($0["isAdmin"] as? Bool) == true || ($0["is_admin"] as? Bool) == true }.count
        let disabledCount = users.filter { ($0["isDisabled"] as? Bool) == true || ($0["is_disabled"] as? Bool) == true }.count
        
        // Count unique non-empty usernames from logged-in sessions (not total sessions)
        let uniqueLoggedInUsers = Set(loggedIn.compactMap { session -> String? in
            if let user = session["user"] as? String, !user.isEmpty {
                return user
            }
            return nil
        })
        let loggedInCount = uniqueLoggedInUsers.count
        
        let btmdbStatus = btmdb["status"] as? String ?? "unknown"
        
        return [
            "totalUsers": totalUsers,
            "adminUsers": adminCount,
            "disabledUsers": disabledCount,
            "currentlyLoggedIn": loggedInCount,
            "btmdbStatus": btmdbStatus
        ]
    }
}
