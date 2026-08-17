import Foundation

/// Identity module processor - collects user accounts, sessions, and identity management data
/// Based on MunkiReport patterns for user/account collection
/// Reference: https://github.com/munkireport/users, https://github.com/munkireport/user_sessions
/// Collects: local users, group memberships, login sessions, Platform SSO user data
public class IdentityModuleProcessor: BaseModuleProcessor, @unchecked Sendable {

    public init(configuration: ReportMateConfiguration) {
        super.init(moduleId: "identity", configuration: configuration)
    }

    public override func collectData() async throws -> ModuleData {
        // Total collection steps for progress tracking
        let totalSteps = 7
        
        // Collect identity data sequentially with progress tracking
        ConsoleFormatter.writeQueryProgress(queryName: "user_accounts", current: 1, total: totalSteps)
        let userAccounts = try await collectUserAccounts()
        
        ConsoleFormatter.writeQueryProgress(queryName: "groups", current: 2, total: totalSteps)
        let groups = try await collectGroups()
        
        ConsoleFormatter.writeQueryProgress(queryName: "logged_in_users", current: 3, total: totalSteps)
        let loggedInUsers = try await collectLoggedInUsers()
        
        ConsoleFormatter.writeQueryProgress(queryName: "login_history", current: 4, total: totalSteps)
        let loginHistory = try await collectLoginHistory()
        
        ConsoleFormatter.writeQueryProgress(queryName: "directory_services", current: 5, total: totalSteps)
        let directoryServices = try await collectDirectoryServices()

        ConsoleFormatter.writeQueryProgress(queryName: "secure_token_users", current: 6, total: totalSteps)
        let secureTokenUsers = try await collectSecureTokenUsers()

        ConsoleFormatter.writeQueryProgress(queryName: "platform_sso_users", current: 7, total: totalSteps)
        let platformSSOUsers = try await collectPlatformSSOUsers()

        // Build identity data dictionary
        let identityData: [String: Any] = [
            "users": userAccounts,
            "groups": groups,
            "loggedInUsers": loggedInUsers,
            "loginHistory": loginHistory,
            "directoryServices": directoryServices,
            "secureTokenUsers": secureTokenUsers,
            "platformSSOUsers": platformSSOUsers,
            "summary": buildSummary(
                users: userAccounts,
                loggedIn: loggedInUsers
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
    
    /// Collects Platform SSO per-user registration and token state.
    ///
    /// `app-sso platform -s` prints four sections: a device-level `Device Configuration`
    /// block, a `Login Configuration` block, a per-user `User Configuration` block, and a
    /// plain-text `SSO Tokens` trailer. Two properties of that output drive this collector:
    ///
    /// 1. `registrationCompleted` is device-level. It prints identically for every account,
    ///    including accounts that have never registered, so it can never be used to decide
    ///    whether a *user* is registered. Per-user truth is a populated `User Configuration`
    ///    block, and the token state is the `SSO Tokens` trailer.
    /// 2. Platform SSO state is only reachable inside the user's Aqua session. Probing a user
    ///    with no GUI session blocks indefinitely, so every account is gated on an active
    ///    `gui/<uid>` launchd domain and every invocation carries a hard timeout.
    private func collectPlatformSSOUsers() async throws -> [String: Any] {
        let bashScript = """
            # Platform SSO per-user registration and token state (macOS 13+ Ventura)
            set -m

            APPSSO="/usr/bin/app-sso"

            emit_unsupported() {
                echo "{"
                echo "  \\"supported\\": false,"
                echo "  \\"deviceRegistered\\": false,"
                echo "  \\"provider\\": \\"\\","
                echo "  \\"method\\": \\"\\","
                echo "  \\"extensionIdentifier\\": \\"\\","
                echo "  \\"organizationName\\": \\"\\","
                echo "  \\"loginFrequency\\": 0,"
                echo "  \\"offlineGracePeriod\\": \\"\\","
                echo "  \\"registeredUserCount\\": 0,"
                echo "  \\"unregisteredUserCount\\": 0,"
                echo "  \\"tokenPresentCount\\": 0,"
                echo "  \\"nonPlatformSSOAccounts\\": [],"
                echo "  \\"users\\": []"
                echo "}"
            }

            os_major=$(sw_vers -productVersion 2>/dev/null | cut -d. -f1)
            case "$os_major" in
                ''|*[!0-9]*) emit_unsupported; exit 0 ;;
            esac
            if [ "$os_major" -lt 13 ] || [ ! -x "$APPSSO" ]; then
                emit_unsupported
                exit 0
            fi

            # Run a command under a hard wall-clock limit, killing its whole process group on
            # expiry. app-sso blocks forever against a user with no GUI session, and output is
            # staged through a temp file so a surviving grandchild can never hold our stdout
            # pipe open.
            run_with_timeout() {
                _limit=$1
                shift
                _out=$(mktemp /tmp/reportmate-psso.XXXXXX) || return 1
                "$@" >"$_out" 2>/dev/null &
                _pid=$!
                _waited=0
                while kill -0 "$_pid" 2>/dev/null; do
                    if [ "$_waited" -ge "$_limit" ]; then
                        kill -9 -"$_pid" 2>/dev/null
                        kill -9 "$_pid" 2>/dev/null
                        wait "$_pid" 2>/dev/null
                        rm -f "$_out"
                        return 124
                    fi
                    sleep 1
                    _waited=$((_waited + 1))
                done
                wait "$_pid" 2>/dev/null
                cat "$_out"
                rm -f "$_out"
                return 0
            }

            # Values here are UPNs, UUIDs, ISO dates and enum strings. None legitimately
            # contain a quote or backslash once unescaped, so dropping those keeps the
            # hand-assembled JSON well formed.
            json_scrub() {
                printf '%s' "$1" | tr -d '\\\\"' | tr -d '\\r\\n\\t'
            }

            # First "key" : "value" pair in the text on stdin.
            json_string() {
                grep "\\"$1\\"" | head -1 | sed 's/.*: *"\\(.*\\)".*/\\1/'
            }

            running_uid=$(id -u)

            # --- Device configuration ---------------------------------------------
            device_state=$(run_with_timeout 20 "$APPSSO" platform -s)
            device_section=$(printf '%s\\n' "$device_state" | awk '/^Device Configuration:/{f=1;next} f&&/^Login Configuration:/{f=0} f')

            device_registered="false"
            if printf '%s\\n' "$device_section" | grep -q '"registrationCompleted" *: *true'; then
                device_registered="true"
            fi

            extension_id=$(printf '%s\\n' "$device_section" | json_string extensionIdentifier)
            org_name=$(printf '%s\\n' "$device_section" | json_string accountDisplayName)
            offline_grace=$(printf '%s\\n' "$device_section" | json_string offlineGracePeriod)
            login_freq=$(printf '%s\\n' "$device_section" | grep '"loginFrequency"' | head -1 | sed 's/[^0-9]//g')
            [ -z "$login_freq" ] && login_freq=0

            # Identify the IdP from the extension bundle id, falling back to the account
            # display name. The extension id is the reliable signal.
            provider=""
            case "$extension_id" in
                *microsoft*|*Microsoft*) provider="Microsoft Entra ID" ;;
                *okta*|*Okta*)           provider="Okta" ;;
                *jamf*|*Jamf*)           provider="Jamf Connect" ;;
                *google*|*Google*)       provider="Google" ;;
            esac
            if [ -z "$provider" ]; then
                case "$org_name" in
                    *Entra*|*Microsoft*) provider="Microsoft Entra ID" ;;
                    *Okta*)              provider="Okta" ;;
                    *Jamf*)              provider="Jamf Connect" ;;
                    *Google*)            provider="Google" ;;
                esac
            fi

            # Device-wide authentication method from the configured login type.
            device_login_type=$(printf '%s\\n' "$device_section" | json_string loginType)
            method="Unknown"
            case "$device_login_type" in
                *SecureEnclaveKey*) method="Secure enclave key" ;;
                *SmartCard*)        method="Smart card" ;;
                *Password*)         method="Password" ;;
            esac

            # Accounts the PSSO payload exempts by policy. Never probe these: they have no SSO
            # agent, so app-sso would hang against them.
            non_psso_accounts=$(printf '%s\\n' "$device_section" \\
                | sed -n '/"nonPlatformSSOAccounts"/,/]/p' \\
                | grep -v 'nonPlatformSSOAccounts' \\
                | sed -n 's/.*"\\([^"]*\\)".*/\\1/p')

            non_psso_json="["
            first_np="true"
            for acct in $non_psso_accounts; do
                [ "$first_np" = "true" ] && first_np="false" || non_psso_json="$non_psso_json,"
                non_psso_json="$non_psso_json\\"$(json_scrub "$acct")\\""
            done
            non_psso_json="$non_psso_json]"

            is_non_psso_account() {
                for acct in $non_psso_accounts; do
                    [ "$acct" = "$1" ] && return 0
                done
                return 1
            }

            has_gui_session() {
                if [ "$running_uid" = "$1" ]; then
                    return 0
                fi
                launchctl print "gui/$1" >/dev/null 2>&1
            }

            appsso_for_user() {
                if [ "$running_uid" = "0" ]; then
                    run_with_timeout 20 launchctl asuser "$2" sudo -u "$1" "$APPSSO" platform -s
                elif [ "$running_uid" = "$2" ]; then
                    run_with_timeout 20 "$APPSSO" platform -s
                else
                    return 1
                fi
            }

            users_json="["
            first_user="true"
            registered_count=0
            unregistered_count=0
            token_count=0

            for user in $(dscl . -list /Users UniqueID 2>/dev/null | awk '$2 >= 500 && $2 < 65534 {print $1}'); do
                uid=$(dscl . -read "/Users/$user" UniqueID 2>/dev/null | awk '{print $2}')
                [ -z "$uid" ] && continue

                home=$(dscl . -read "/Users/$user" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
                case "$home" in
                    ''|/var/empty|/dev/null) continue ;;
                esac

                registered="false"
                upn=""
                login_user_name=""
                unique_id=""
                user_state=""
                login_type=""
                last_login=""
                token_received=""
                token_expiration=""
                token_expired="null"
                has_tokens="false"
                probe_status="ok"

                if is_non_psso_account "$user"; then
                    probe_status="excluded"
                elif [ "$device_registered" != "true" ]; then
                    probe_status="device-not-registered"
                elif ! has_gui_session "$uid"; then
                    probe_status="no-session"
                else
                    user_output=$(appsso_for_user "$user" "$uid")
                    if [ $? -ne 0 ] || [ -z "$user_output" ]; then
                        probe_status="probe-failed"
                    else
                        user_section=$(printf '%s\\n' "$user_output" \\
                            | awk '/^User Configuration:/{f=1;next} f&&/^SSO Tokens:/{f=0} f')
                        token_section=$(printf '%s\\n' "$user_output" | sed -n '/^SSO Tokens:/,$p')

                        unique_id=$(printf '%s\\n' "$user_section" | json_string uniqueIdentifier)
                        user_state=$(printf '%s\\n' "$user_section" | json_string state)
                        login_type=$(printf '%s\\n' "$user_section" | json_string loginType)
                        last_login=$(printf '%s\\n' "$user_section" | json_string lastLoginDate)
                        login_user_name=$(printf '%s\\n' "$user_section" | json_string loginUserName)

                        # The real UPN lives in kerberosStatus, not in a userPrincipalName key
                        # (no such key exists). Prefer the on-prem realm entry; the cloud entry
                        # escapes the local part and appends the Kerberos realm, so unwrap it
                        # as a fallback.
                        upn=$(printf '%s\\n' "$user_section" | grep '"upn"' \\
                            | grep -v 'KERBEROS.MICROSOFTONLINE.COM' | head -1 \\
                            | sed 's/.*: *"\\(.*\\)".*/\\1/')
                        if [ -z "$upn" ]; then
                            upn=$(printf '%s\\n' "$user_section" | grep '"upn"' | head -1 \\
                                | sed 's/.*: *"\\(.*\\)".*/\\1/' \\
                                | sed 's/@KERBEROS\\.MICROSOFTONLINE\\.COM$//' \\
                                | sed 's/\\\\@/@/g')
                        fi

                        # A populated User Configuration block is the only per-user proof of
                        # registration.
                        if [ -n "$unique_id" ] || [ -n "$login_user_name" ]; then
                            registered="true"
                        fi

                        # SSO Tokens trailer is plain text, not JSON:
                        #   SSO Tokens:
                        #   Received:
                        #   2026-08-14T00:18:46Z
                        #   Expiration:
                        #   2026-08-28T00:18:45Z (Not Expired)
                        if printf '%s\\n' "$token_section" | grep -q '^Received:'; then
                            token_received=$(printf '%s\\n' "$token_section" \\
                                | awk '/^Received:/{getline; gsub(/^[ \\t]+|[ \\t]+$/,""); print; exit}')
                            token_expiration_raw=$(printf '%s\\n' "$token_section" \\
                                | awk '/^Expiration:/{getline; gsub(/^[ \\t]+|[ \\t]+$/,""); print; exit}')
                            token_expiration=$(printf '%s' "$token_expiration_raw" | sed 's/ *(.*$//')
                            case "$token_expiration_raw" in
                                *"Not Expired"*) token_expired="false" ;;
                                *"Expired"*)     token_expired="true" ;;
                            esac
                            if [ -n "$token_received" ]; then
                                has_tokens="true"
                            fi
                        fi
                    fi
                fi

                if [ "$registered" = "true" ]; then
                    registered_count=$((registered_count + 1))
                else
                    unregistered_count=$((unregistered_count + 1))
                fi
                if [ "$has_tokens" = "true" ]; then
                    token_count=$((token_count + 1))
                fi

                [ "$first_user" = "true" ] && first_user="false" || users_json="$users_json,"
                users_json="$users_json{"
                users_json="$users_json\\"username\\": \\"$(json_scrub "$user")\\","
                users_json="$users_json\\"uid\\": $uid,"
                users_json="$users_json\\"registered\\": $registered,"
                users_json="$users_json\\"userPrincipalName\\": \\"$(json_scrub "$upn")\\","
                users_json="$users_json\\"loginUserName\\": \\"$(json_scrub "$login_user_name")\\","
                users_json="$users_json\\"uniqueIdentifier\\": \\"$(json_scrub "$unique_id")\\","
                users_json="$users_json\\"state\\": \\"$(json_scrub "$user_state")\\","
                users_json="$users_json\\"loginType\\": \\"$(json_scrub "$login_type")\\","
                users_json="$users_json\\"lastLoginDate\\": \\"$(json_scrub "$last_login")\\","
                users_json="$users_json\\"tokensPresent\\": $has_tokens,"
                users_json="$users_json\\"tokenReceived\\": \\"$(json_scrub "$token_received")\\","
                users_json="$users_json\\"tokenExpiration\\": \\"$(json_scrub "$token_expiration")\\","
                users_json="$users_json\\"tokenExpired\\": $token_expired,"
                users_json="$users_json\\"probeStatus\\": \\"$probe_status\\""
                users_json="$users_json}"
            done
            users_json="$users_json]"

            echo "{"
            echo "  \\"supported\\": true,"
            echo "  \\"deviceRegistered\\": $device_registered,"
            echo "  \\"provider\\": \\"$(json_scrub "$provider")\\","
            echo "  \\"method\\": \\"$(json_scrub "$method")\\","
            echo "  \\"extensionIdentifier\\": \\"$(json_scrub "$extension_id")\\","
            echo "  \\"organizationName\\": \\"$(json_scrub "$org_name")\\","
            echo "  \\"loginFrequency\\": $login_freq,"
            echo "  \\"offlineGracePeriod\\": \\"$(json_scrub "$offline_grace")\\","
            echo "  \\"registeredUserCount\\": $registered_count,"
            echo "  \\"unregisteredUserCount\\": $unregistered_count,"
            echo "  \\"tokenPresentCount\\": $token_count,"
            echo "  \\"nonPlatformSSOAccounts\\": $non_psso_json,"
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
        loggedIn: [[String: Any]]
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

        return [
            "totalUsers": totalUsers,
            "adminUsers": adminCount,
            "disabledUsers": disabledCount,
            "currentlyLoggedIn": loggedInCount
        ]
    }
}
