import SwiftUI
import ReportMateKit

/// Identity & Users: summary cards, the BTMDB footnote, and the account,
/// session and history tables. Port of `IdentityTab.tsx`.
struct IdentityTabView: View {
    let device: DeviceDetail

    enum TableKind: String, CaseIterable { case users, sessions, history, sessionHistory }
    enum UserSort: String { case username, realName, uid, isAdmin, lastLogon }

    @State private var table: TableKind = .users
    @State private var userSearch = ""
    @State private var adminsOnly = false
    @State private var expandedUsers: Set<String> = []
    @State private var sortColumn: UserSort = .lastLogon
    @State private var sortAscending = false

    private static let cardColumns = [GridItem(.adaptive(minimum: 280), spacing: 12, alignment: .top)]

    var body: some View {
        let identity = IdentityInfo(modules: device.asJSON["modules"], platform: device.platform)
        VStack(alignment: .leading, spacing: 20) {
            if !identity.hasData, identity.users.isEmpty {
                Card { EmptyStateView(title: "No Identity Data", message: "User account information is not available for this device.", systemImage: "person.2") }
            } else {
                header(identity)
                LazyVGrid(columns: Self.cardColumns, spacing: 12) {
                    usersCard(identity)
                    if identity.isMac, let ds = identity.directoryServices, ds.hasMacBinding { directoryCard(ds) }
                    if !identity.isMac { windowsAuthenticationCard(identity) }
                    if !identity.isMac { domainsCard(identity) }
                    if identity.isMac, identity.platformSSO != nil || !identity.activationLock.isNull { macAuthenticationCard(identity) }
                    if identity.isMac, identity.secureTokenUsers != nil || !identity.bootstrapToken.isNull { tokensCard(identity) }
                }
                if identity.isMac, let btm = identity.btmdbHealth { btmdbFootnote(btm) }
                tablePicker(identity)
                switch table {
                case .users: usersTable(identity)
                case .sessions: sessionsTable(identity)
                case .history: historyTable(identity)
                case .sessionHistory: sessionHistory(identity)
                }
            }
            JSONTreeView(value: device[.identity], label: "device.modules.identity")
        }
    }

    // MARK: Header

    private func header(_ identity: IdentityInfo) -> some View {
        HStack {
            HStack(spacing: 12) {
                ZStack {
                    RoundedRectangle(cornerRadius: 10).fill(Color.blue.opacity(0.15))
                    Image(systemName: "person.2").foregroundStyle(.blue).appFont(fixed: 20)
                }
                .frame(width: 44, height: 44)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Identity & Users").appFont(.title2, weight: .bold)
                    Text("\(identity.isMac ? "macOS" : "Windows") user accounts and sessions").appFont(.callout).foregroundStyle(.secondary)
                }
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 2) {
                Text("User Accounts").appFont(.caption).foregroundStyle(.secondary)
                Text("\(identity.users.count)").appFont(.title2, weight: .bold)
            }
        }
    }

    // MARK: Cards

    private func card<Content: View>(_ title: String, icon: String, tone: Tone, @ViewBuilder content: () -> Content) -> some View {
        Card {
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 6) {
                    Image(systemName: icon).foregroundStyle(tone.color).appFont(.caption)
                    Text(title).appFont(.callout, weight: .semibold)
                }
                .padding(.bottom, 4)
                content()
            }
            .padding(14)
        }
    }

    private func usersCard(_ i: IdentityInfo) -> some View {
        card("Users", icon: "person", tone: .blue) {
            IdentityRow("Total Users", "\(i.summary.totalUsers)")
            IdentityRow("Admin Users", "\(i.summary.adminUsers)", tone: i.summary.adminUsers > 0 ? .yellow : .green)
            IdentityRow("Disabled", "\(i.summary.disabledUsers)", tone: i.summary.disabledUsers > 0 ? .gray : .green)
            if !i.isMac, let n = i.summary.localUsers { IdentityRow("Local", "\(n)") }
            if !i.isMac, let n = i.summary.domainUsers { IdentityRow("Domain", "\(n)") }
        }
    }

    private func directoryCard(_ ds: IdentityInfo.DirectoryServices) -> some View {
        card("Directory Services", icon: "network", tone: .green) {
            IdentityRow("Active Directory", ds.adBound ? "Bound" : "Not Bound", tone: ds.adBound ? .green : .gray)
            if let d = ds.adDomain { IdentityRow("AD Domain", d) }
            IdentityRow("LDAP", ds.ldapBound ? "Bound" : "Not Bound", tone: ds.ldapBound ? .green : .gray)
        }
    }

    private func windowsAuthenticationCard(_ i: IdentityInfo) -> some View {
        let hello = i.windowsHello
        let status = hello["statusDisplay"].string ?? ""
        return card("Authentication", icon: "touchid", tone: .indigo) {
            if !hello.isNull {
                let value = status.contains("Enabled") ? "Enabled" : status.contains("Partially") ? "Partial" : "Disabled"
                IdentityRow("Windows Hello", value, tone: status.contains("Enabled") ? .green : status.contains("Partially") ? .yellow : .gray)
                let providers = hello["credentialProviders"]
                if !providers.isNull {
                    enabledRow("PIN", providers["pinEnabled"].boolish)
                    enabledRow("Fingerprint", providers["fingerprintEnabled"].boolish)
                    enabledRow("Face Recognition", providers["faceRecognitionEnabled"].boolish)
                }
                if !hello["credentialGuard"].isNull { enabledRow("Credential Guard", hello["credentialGuard"]["isEnabled"].boolish) }
            } else {
                IdentityRow("Windows Hello", "Not configured", tone: .gray)
            }
            let tpm = i.tpmOwnership
            if !tpm.isNull, tpm["isOwned"].boolishIfPresent != nil || tpm["isReady"].boolishIfPresent != nil {
                let ready = tpm["isReady"].boolish, owned = tpm["isOwned"].boolish
                IdentityRow("TPM", ready ? "Owned & Ready" : owned ? "Owned" : "Not Owned", tone: ready ? .green : owned ? .yellow : .gray)
            }
            if let level = i.uac["level"].nonEmptyString {
                IdentityRow("UAC", uacLabel(level), tone: (level == "NeverNotify" || level == "Disabled") ? .red : level == "NotifyChangesNoDim" ? .yellow : .green)
            }
            if i.summary.failedLoginsLast7Days != nil || !i.passwordPolicy.isNull || !i.laps.isNull || !i.autoLogin.isNull {
                Divider().padding(.vertical, 4)
                HStack(spacing: 6) {
                    Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange).appFont(.caption2)
                    SectionLabel("Login Security")
                }
                if let failed = i.summary.failedLoginsLast7Days {
                    IdentityRow("Failed Logins (7d)", "\(failed)", tone: failed > 10 ? .red : failed > 5 ? .yellow : .green)
                    IdentityRow("Currently Logged In", "\(i.summary.currentlyLoggedIn)")
                }
                let pp = i.passwordPolicy
                if !pp.isNull {
                    if i.summary.failedLoginsLast7Days != nil { Divider().padding(.vertical, 2) }
                    if let n = pp["minPasswordLength"].int { IdentityRow("Min Password Length", "\(n)", tone: n == 0 ? .yellow : n >= 8 ? .green : nil) }
                    if let n = pp["maxPasswordAgeDays"].int { IdentityRow("Max Password Age", n == 0 ? "Never expires" : "\(n) days") }
                    if let n = pp["lockoutThreshold"].int { IdentityRow("Lockout Threshold", n == 0 ? "No lockout" : "\(n) attempts", tone: n == 0 ? .yellow : nil) }
                    if let c = pp["complexityRequired"].boolishIfPresent { IdentityRow("Complexity", c ? "Required" : "Not Required", tone: c ? .green : .gray) }
                }
                let laps = i.laps
                if !laps.isNull {
                    Divider().padding(.vertical, 2)
                    let winLaps = laps["windowsLapsConfigured"].boolish, legacy = laps["legacyLapsInstalled"].boolish
                    let dir = laps["backupDirectory"].nonEmptyString.map { " (\($0))" } ?? ""
                    IdentityRow("LAPS", winLaps ? "Windows LAPS\(dir)" : legacy ? "Legacy LAPS" : "Not Configured", tone: (winLaps || legacy) ? .green : .gray)
                }
                let auto = i.autoLogin
                if !auto.isNull {
                    Divider().padding(.vertical, 2)
                    let on = auto["autoAdminLogon"].boolish
                    IdentityRow("Auto Admin Logon", on ? "Enabled" : "Disabled", tone: on ? .red : .green)
                    if auto["hasDefaultPassword"].boolish { IdentityRow("Stored Password", "Present", tone: .red) }
                }
            }
        }
    }

    private func uacLabel(_ level: String) -> String {
        switch level {
        case "NeverNotify": return "Never Notify"
        case "Disabled": return "Disabled"
        case "NotifyChangesNoDim": return "Notify (no dim)"
        case "NotifyChangesSecure": return "Notify on changes"
        case "AlwaysNotify": return "Always Notify"
        default: return level
        }
    }

    private func enabledRow(_ label: String, _ on: Bool) -> some View {
        IdentityRow(label, on ? "Enabled" : "Disabled", tone: on ? .green : .gray)
    }

    private func domainsCard(_ i: IdentityInfo) -> some View {
        card("Domains & Tokens", icon: "key", tone: .yellow) {
            if let w = i.windowsEnrollment {
                IdentityRow("Type", w.enrollmentType, tone: (w.enrollmentType == "Entra Joined" || w.enrollmentType == "Hybrid Entra Join") ? .green : .gray)
                if w.domainJoined, !w.domainName.isEmpty { IdentityRow("Domain", w.domainName) }
                if !w.workgroup.isEmpty, w.workgroup.uppercased() != "WORKGROUP", !w.entraJoined, !w.domainJoined { IdentityRow("Workgroup", w.workgroup) }
                if !w.tenantName.isEmpty { IdentityRow("Tenant", w.tenantName) }
                if !w.entraDeviceId.isEmpty { IdentityRow("Device ID", w.entraDeviceId) }
                if let auth = i.directoryServices?.azureAD?.deviceAuthStatus { IdentityRow("Device Auth", auth, tone: auth == "SUCCESS" ? .green : .yellow) }
                if w.entraRegistered, !w.entraJoined { IdentityRow("Registration", "Registered (BYOD)", tone: .gray) }
                if let mdm = w.mdmProvider { IdentityRow("MDM", mdm) }
                if let sso = i.ssoState {
                    Divider().padding(.vertical, 2)
                    IdentityRow("Entra PRT", sso.entraPrt ? "Active" : "Not Present", tone: sso.entraPrt ? .green : .yellow)
                    if let exp = sso.entraPrtExpiryTime { IdentityRow("PRT Expiry", TimeFormatting.shortDate(exp)) }
                    IdentityRow("Cloud TGT", sso.cloudTgt ? "Present" : "Not Present", tone: sso.cloudTgt ? .green : .gray)
                    IdentityRow("On-Prem TGT", sso.onPremTgt ? "Present" : "Not Present", tone: sso.onPremTgt ? .green : .gray)
                }
                if let trust = i.domainTrust, trust.trustStatus != "Not Applicable" {
                    Divider().padding(.vertical, 2)
                    IdentityRow("Domain Trust", trust.trustStatus, tone: trust.trustStatus == "Healthy" ? .green : trust.trustStatus == "Broken" ? .red : .yellow)
                    if let dc = trust.domainController, dc != "Unknown" { IdentityRow("DC", dc) }
                }
            } else {
                IdentityRow("Status", "No data", tone: .gray)
            }
            let ngc = i.windowsHello["ngcKeyStorage"]
            if ngc["isConfigured"].boolish {
                Divider().padding(.vertical, 2)
                IdentityRow("NGC Key Storage", "Configured", tone: .green)
                let providers = ngc["providers"].elements
                if !providers.isEmpty {
                    let names = providers.prefix(2).map { $0["name"].string ?? $0["type"].string ?? "" }.joined(separator: ", ")
                    IdentityRow("Providers", names + (providers.count > 2 ? " +\(providers.count - 2) more" : ""))
                }
            }
            if i.windowsHello["webAuthN"]["isEnabled"].boolish { IdentityRow("WebAuthN / FIDO2", "Enabled", tone: .green) }
        }
    }

    private func macAuthenticationCard(_ i: IdentityInfo) -> some View {
        card("Authentication", icon: "touchid", tone: .indigo) {
            if let psso = i.platformSSO {
                IdentityRow("Platform SSO", psso.provider ?? "Not configured")
                IdentityRow("Registration", psso.deviceRegistered ? "Registered" : "Not Registered", tone: psso.deviceRegistered ? .green : .yellow)
                let user = psso.primaryUser
                if let name = user?.displayName { IdentityRow("SSO User", name) }
                if !psso.users.isEmpty {
                    let tokens = user?.tokensPresent ?? false
                    IdentityRow("SSO Token", tokens ? "Present" : "Missing", tone: tokens ? .green : .yellow)
                }
                if let user, user.tokensPresent, let exp = user.tokenExpiration {
                    IdentityRow("Token Expires", exp, tone: user.tokenExpired == true ? .yellow : .green)
                }
            }
            let lock = i.activationLock
            if !lock.isNull {
                if i.platformSSO != nil { Divider().padding(.vertical, 2) }
                let status = lock["status"].string ?? ""
                let locked = status == "Enabled" || status == "Likely Enabled"
                IdentityRow("Activation Lock", locked ? "Locked" : "Unlocked", tone: locked ? .yellow : .green)
                let findMy = lock["findMyMac"].string == "Enabled"
                IdentityRow("Find My Mac", findMy ? "Enabled" : "Disabled", tone: findMy ? .green : .gray)
                if let account = lock["email"].nonEmptyString ?? lock["ownerDisplayName"].nonEmptyString { IdentityRow("iCloud Account", account) }
            }
        }
    }

    private func tokensCard(_ i: IdentityInfo) -> some View {
        card("Tokens", icon: "key", tone: .yellow) {
            let bt = i.bootstrapToken
            if !bt.isNull {
                let escrowed = bt["escrowed"].boolish, supported = bt["supported"].boolish
                IdentityRow("Bootstrap Token", escrowed ? "Escrowed" : supported ? "Not Escrowed" : "Not Supported", tone: escrowed ? .green : supported ? .yellow : .gray)
            }
            if let st = i.secureTokenUsers {
                IdentityRow("Secure Token Users", "\(st.tokenGrantedCount) of \(st.totalUsersChecked)", tone: st.tokenMissingCount > 0 ? .yellow : .green)
            }
            let fv = i.fileVault
            if !fv.isNull {
                Divider().padding(.vertical, 2)
                let prk = SecurityInfo.on(fv["personalRecoveryKey"]), irk = SecurityInfo.on(fv["institutionalRecoveryKey"])
                IdentityRow("Personal Recovery Key", prk ? "Escrowed" : "Not Escrowed", tone: prk ? .green : .yellow)
                IdentityRow("Institutional Recovery Key", irk ? "Escrowed" : "Not Escrowed", tone: irk ? .green : .gray)
            }
            if let st = i.secureTokenUsers, !st.usersWithoutToken.isEmpty {
                let names = st.usersWithoutToken.prefix(3).joined(separator: ", ") + (st.usersWithoutToken.count > 3 ? " +\(st.usersWithoutToken.count - 3) more" : "")
                Text("Missing token: \(names)")
                    .appFont(.caption).foregroundStyle(.yellow)
                    .padding(8).frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.yellow.opacity(0.1), in: RoundedRectangle(cornerRadius: 6))
                    .padding(.top, 4)
            }
        }
    }

    private func btmdbFootnote(_ b: IdentityInfo.BTMDBHealth) -> some View {
        let tone: Tone = b.status == "healthy" ? .green : b.status == "warning" ? .yellow : b.status == "critical" ? .red : .gray
        return DisclosureGroup {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 24) {
                    labeled("Status", b.status.prefix(1).uppercased() + b.status.dropFirst(), tone: tone)
                    labeled("Jetsam Kills (7d)", "\(b.jetsamKillsLast7Days)", tone: b.jetsamKillsLast7Days > 100 ? .red : b.jetsamKillsLast7Days > 50 ? .yellow : nil)
                    labeled("Registered Items", "\(b.registeredItemCount)")
                    labeled("Local Users", "\(b.localUserCount)")
                }
                if b.status == "critical", !b.statusMessage.isEmpty { Text(b.statusMessage).appFont(.caption).foregroundStyle(.red) }
                Text("Thresholds: Warning >3MB, Critical >3.5MB, Failure >4MB").appFont(.caption2).foregroundStyle(.secondary)
            }
            .padding(.top, 8)
        } label: {
            HStack(spacing: 6) {
                Image(systemName: "cylinder").foregroundStyle(.secondary)
                Text("Background Task Management DB:").appFont(.callout, weight: .medium)
                Text(String(format: "%.2f MB", b.sizeMB)).appFont(.callout, weight: .medium).foregroundStyle(tone.color)
                if b.status != "healthy" { Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(b.status == "critical" ? .red : .yellow).appFont(.caption) }
            }
        }
        .padding(12)
        .background(tone == .red ? Color.red.opacity(0.06) : tone == .yellow ? Color.yellow.opacity(0.08) : Color.subtleBackground, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(tone.color.opacity(tone == .gray ? 0.2 : 0.35)))
    }

    private func labeled(_ label: String, _ value: String, tone: Tone? = nil) -> some View {
        HStack(spacing: 4) {
            Text("\(label):").appFont(.caption).foregroundStyle(.secondary)
            Text(value).appFont(.caption, weight: .medium).foregroundStyle(tone?.color ?? .primary)
        }
    }

    // MARK: Table picker

    private func tablePicker(_ i: IdentityInfo) -> some View {
        HStack(spacing: 20) {
            tabButton(.users, icon: "person", label: "User Accounts (\(filteredUsers(i).count))")
            tabButton(.sessions, icon: "arrow.right.square", label: "Active Sessions (\(i.activeUserSessions.count))")
            tabButton(.history, icon: "clock.arrow.circlepath", label: "Login History (\(i.loginHistory.count))")
            if !i.sessionHistory.isEmpty { tabButton(.sessionHistory, icon: "clock", label: "Session History (\(i.sessionHistory.count))") }
            Spacer()
        }
        .overlay(alignment: .bottom) { Divider() }
    }

    private func tabButton(_ t: TableKind, icon: String, label: String) -> some View {
        Button { table = t } label: {
            HStack(spacing: 6) {
                Image(systemName: icon).appFont(.caption)
                Text(label).appFont(.callout, weight: .medium)
            }
            .foregroundStyle(table == t ? Color.blue : Color.secondary)
            .padding(.vertical, 8)
            .overlay(alignment: .bottom) { Rectangle().fill(table == t ? Color.blue : Color.clear).frame(height: 2) }
        }
        .buttonStyle(.plain)
    }

    // MARK: Users

    private func filteredUsers(_ i: IdentityInfo) -> [IdentityInfo.UserAccount] {
        let q = userSearch.lowercased()
        let list = i.visibleUsers.filter { u in
            let matches = q.isEmpty || u.username.lowercased().contains(q) || (u.realName ?? "").lowercased().contains(q)
            return matches && (!adminsOnly || u.isAdmin)
        }
        return list.sorted { a, b in
            let aIn = i.isLoggedIn(a), bIn = i.isLoggedIn(b)
            if aIn != bIn { return aIn }
            switch sortColumn {
            case .username: return order(a.username.lowercased(), b.username.lowercased())
            case .realName: return order((a.realName ?? "").lowercased(), (b.realName ?? "").lowercased())
            case .uid: return sortAscending ? a.uid < b.uid : a.uid > b.uid
            case .isAdmin: return sortAscending ? (a.isAdmin ? 1 : 0) < (b.isAdmin ? 1 : 0) : (a.isAdmin ? 1 : 0) > (b.isAdmin ? 1 : 0)
            case .lastLogon: return order(a.lastLogon ?? "", b.lastLogon ?? "")
            }
        }
    }

    private func order(_ a: String, _ b: String) -> Bool {
        let c = a.compare(b)
        return sortAscending ? c == .orderedAscending : c == .orderedDescending
    }

    private func sortHeader(_ title: String, _ column: UserSort, width: CGFloat? = nil) -> some View {
        Button {
            if sortColumn == column { sortAscending.toggle() } else { sortColumn = column; sortAscending = true }
        } label: {
            HStack(spacing: 4) {
                Text(title.uppercased()).appFont(.caption2, weight: .semibold).foregroundStyle(.secondary)
                SortIndicator(active: sortColumn == column, ascending: sortAscending)
            }
            .frame(width: width, alignment: .leading)
            .frame(maxWidth: width == nil ? .infinity : nil, alignment: .leading)
        }
        .buttonStyle(.plain)
    }

    private func usersTable(_ i: IdentityInfo) -> some View {
        let users = filteredUsers(i)
        let showBootstrap = i.isMac && !i.bootstrapToken.isNull
        return Card {
            VStack(spacing: 0) {
                HStack(spacing: 12) {
                    TextField("Search users...", text: $userSearch).textFieldStyle(.roundedBorder).frame(maxWidth: 260)
                    Toggle(isOn: $adminsOnly) { Label("Admins", systemImage: "shield") }.toggleStyle(.button)
                    Spacer()
                }
                .padding(12)
                Divider()
                HStack(spacing: 12) {
                    sortHeader("Display Name", .realName)
                    if i.isMac { sortHeader("UID", .uid, width: 60) }
                    sortHeader("Admin", .isAdmin, width: 70)
                    Text("SESSION").appFont(.caption2, weight: .semibold).foregroundStyle(.secondary).frame(width: 70, alignment: .leading)
                    sortHeader("Username", .username)
                    sortHeader("Last Login", .lastLogon, width: 150)
                    if i.isMac { Text("SECURE TOKEN").appFont(.caption2, weight: .semibold).foregroundStyle(.secondary).frame(width: 90, alignment: .leading) }
                    if showBootstrap { Text("BOOTSTRAP").appFont(.caption2, weight: .semibold).foregroundStyle(.secondary).frame(width: 80, alignment: .leading) }
                    Color.clear.frame(width: 16)
                }
                .padding(.horizontal, 12).padding(.vertical, 8)
                .background(Color.subtleBackground)
                Divider()
                if users.isEmpty {
                    Text("No users found matching your criteria").appFont(.callout).foregroundStyle(.secondary).padding(24)
                } else {
                    ForEach(users) { user in
                        userRow(user, identity: i, showBootstrap: showBootstrap)
                        Divider()
                    }
                }
            }
        }
    }

    private func userRow(_ user: IdentityInfo.UserAccount, identity i: IdentityInfo, showBootstrap: Bool) -> some View {
        let expanded = expandedUsers.contains(user.id)
        let login = LoginTime.parse(user.lastLogon)
        let loggedIn = i.isLoggedIn(user)
        return VStack(spacing: 0) {
            Button {
                if expanded { expandedUsers.remove(user.id) } else { expandedUsers.insert(user.id) }
            } label: {
                HStack(spacing: 12) {
                    Text(user.realName ?? "—").appFont(.callout).frame(maxWidth: .infinity, alignment: .leading).lineLimit(1)
                    if i.isMac { Text("\(user.uid)").appFont(.caption, design: .monospaced).foregroundStyle(.secondary).frame(width: 60, alignment: .leading) }
                    Group { if user.isAdmin { Pill("Admin", tone: .yellow) } else { Text("—").foregroundStyle(.tertiary) } }.frame(width: 70, alignment: .leading)
                    Group {
                        if loggedIn {
                            HStack(spacing: 4) { Circle().fill(Color.green).frame(width: 6, height: 6); Text("Active").appFont(.caption, weight: .medium).foregroundStyle(.green) }
                        } else { Text("—").foregroundStyle(.tertiary) }
                    }.frame(width: 70, alignment: .leading)
                    HStack(spacing: 6) {
                        Text(user.username).appFont(.callout, weight: .medium, design: .monospaced).foregroundStyle(user.isDisabled ? .secondary : .primary)
                        if user.isDisabled { Pill("Disabled", tone: .gray) }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    Text(user.lastLogon == nil ? "Never" : login.text).appFont(.caption).foregroundStyle(.secondary).frame(width: 150, alignment: .leading).lineLimit(1)
                    if i.isMac { checkMark(i.hasSecureToken(user)).frame(width: 90, alignment: .leading) }
                    if showBootstrap { checkMark(i.bootstrapToken["escrowed"].boolish).frame(width: 80, alignment: .leading) }
                    Image(systemName: "chevron.down").rotationEffect(.degrees(expanded ? 180 : 0)).foregroundStyle(.tertiary).appFont(.caption).frame(width: 16)
                }
                .padding(.horizontal, 12).padding(.vertical, 8)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            if expanded {
                HStack(alignment: .top, spacing: 24) {
                    VStack(alignment: .leading, spacing: 6) {
                        SectionLabel("Account Details")
                        kv("Username", user.username, mono: true)
                        kv("UID", "\(user.uid)", mono: true)
                        if user.gid != 0 { kv("GID", "\(user.gid)", mono: true) }
                        if let r = user.realName { kv("Full Name", r) }
                        if let h = user.homeDirectory { kv("Home", h, mono: true) }
                        if let s = user.shell { kv("Shell", s, mono: true) }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    VStack(alignment: .leading, spacing: 6) {
                        SectionLabel("Login & Security")
                        kv("Last Login", user.lastLogon == nil ? "Never" : login.text, tone: loggedIn ? .green : nil)
                        kv("Status", user.isDisabled ? "Disabled" : "Active", tone: user.isDisabled ? .gray : .green)
                        kv("Admin", user.isAdmin ? "Yes" : "No", tone: user.isAdmin ? .yellow : nil)
                        if i.isMac, let a = user.linkedAppleId { kv("Apple ID", a) }
                        if let p = user.passwordLastSet { kv("Password Set", LoginTime.parse(p).text) }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    VStack(alignment: .leading, spacing: 6) {
                        SectionLabel("Group Membership")
                        if user.groups.isEmpty {
                            Text("No group memberships").appFont(.caption).foregroundStyle(.tertiary)
                        } else {
                            FlowLayout(spacing: 4) { ForEach(user.groups, id: \.self) { Pill($0, tone: .blue) } }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding(12)
                .background(Color.subtleBackground)
            }
        }
    }

    private func checkMark(_ on: Bool) -> some View {
        Image(systemName: on ? "checkmark.circle.fill" : "xmark.circle").foregroundStyle(on ? Color.green : Color.secondary.opacity(0.5))
    }

    private func kv(_ label: String, _ value: String, mono: Bool = false, tone: Tone? = nil) -> some View {
        HStack {
            Text("\(label):").appFont(.caption).foregroundStyle(.secondary)
            Spacer()
            Text(value).appFont(.caption, design: mono ? .monospaced : .default).foregroundStyle(tone?.color ?? .primary).lineLimit(1).truncationMode(.middle).help(value)
        }
    }

    // MARK: Sessions

    private func sessionsTable(_ i: IdentityInfo) -> some View {
        Card {
            if i.activeUserSessions.isEmpty {
                Text("No active sessions").appFont(.callout).foregroundStyle(.secondary).padding(24).frame(maxWidth: .infinity)
            } else {
                Table(i.activeUserSessions) {
                    TableColumn("User") { s in
                        HStack(spacing: 8) {
                            Image(systemName: "person.crop.circle.badge.checkmark").foregroundStyle(.green)
                            Text(s.user).appFont(.callout, weight: .medium)
                        }
                    }
                    TableColumn("TTY") { s in Text(s.tty ?? "—").appFont(.caption, design: .monospaced).foregroundStyle(.secondary) }.width(min: 60, ideal: 90)
                    TableColumn("Host") { s in Text(s.host ?? "localhost").appFont(.caption).foregroundStyle(.secondary) }
                    TableColumn("Login Time") { s in Text(s.loginTime != nil ? LoginTime.parse(s.loginTime).text : (s.time ?? "—")).appFont(.caption).foregroundStyle(.secondary) }
                    TableColumn("Type") { s in Text(i.isMac ? "" : (s.logonType ?? "—")).appFont(.caption).foregroundStyle(.secondary) }.width(i.isMac ? 0 : nil)
                    TableColumn("PID") { s in Text(s.pid.map { String($0) } ?? "—").appFont(.caption, design: .monospaced).foregroundStyle(.secondary) }.width(min: 50, ideal: 70)
                }
                .frame(minHeight: CGFloat(min(12, i.activeUserSessions.count + 1)) * 30 + 12)
            }
        }
    }

    // MARK: History

    private func eventPill(_ type: String?) -> some View {
        Group {
            switch type {
            case "Failed": Pill("Failed", tone: .red)
            case "Logoff": Pill("Logoff", tone: .gray)
            case "Disconnect": Pill("Disconnect", tone: .gray)
            case "Active": Pill("Active", tone: .blue)
            case "Reconnect": Pill("Reconnect", tone: .yellow)
            default: Pill("Logon", tone: .green)
            }
        }
    }

    private func historyTable(_ i: IdentityInfo) -> some View {
        Card {
            if i.loginHistory.isEmpty {
                Text("No login history available").appFont(.callout).foregroundStyle(.secondary).padding(24).frame(maxWidth: .infinity)
            } else {
                Table(i.loginHistory) {
                    TableColumn("User") { e in Text(e.username).appFont(.callout, weight: .medium) }
                    TableColumn("Event") { e in eventPill(e.eventType) }.width(min: 80, ideal: 100)
                    TableColumn("Time") { e in Text(e.loginTime != nil ? LoginTime.parse(e.loginTime).text : "—").appFont(.caption).foregroundStyle(.secondary) }
                    TableColumn("Duration") { e in Text(e.duration ?? "—").appFont(.caption).foregroundStyle(.secondary) }.width(min: 70, ideal: 90)
                    TableColumn("Type") { e in Text(i.isMac ? "" : (e.logonType ?? "—")).appFont(.caption).foregroundStyle(.secondary) }.width(i.isMac ? 0 : nil)
                    TableColumn("Source") { e in Text(e.sourceIp ?? e.tty ?? "—").appFont(.caption).foregroundStyle(.secondary) }
                }
                .frame(minHeight: CGFloat(min(15, i.loginHistory.count + 1)) * 30 + 12)
            }
        }
    }

    private func sessionHistory(_ i: IdentityInfo) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            if let s = i.sessionSummary {
                Card {
                    VStack(alignment: .leading, spacing: 10) {
                        HStack(spacing: 6) { Image(systemName: "clock").appFont(.caption); Text("Session Utilization").appFont(.callout, weight: .semibold) }
                        HStack(alignment: .top, spacing: 24) {
                            bigStat("\(s.totalSessions)", "Total Sessions")
                            bigStat("\(s.uniqueUsers)", "Unique Users")
                            bigStat(IdentityInfo.minutes(s.avgSessionMinutes), "Avg Duration")
                            bigStat(IdentityInfo.minutes(s.medianSessionMinutes), "Median Duration")
                        }
                        if !s.sessionsByHour.isEmpty {
                            Divider()
                            SectionLabel("Peak Hours")
                            FlowLayout(spacing: 4) {
                                ForEach(s.peakHours, id: \.hour) { Pill("\($0.hour):00 (\($0.count))", tone: .blue) }
                            }
                        }
                    }
                    .padding(14)
                }
            }
            Card {
                Table(i.sessionHistory) {
                    TableColumn("User") { e in Text(e.username).appFont(.callout, weight: .medium) }
                    TableColumn("Event") { e in eventPill(e.eventType) }.width(min: 80, ideal: 100)
                    TableColumn("Start") { e in Text(e.timestamp.isEmpty ? "—" : LoginTime.parse(e.timestamp).text).appFont(.caption).foregroundStyle(.secondary) }
                    TableColumn("End") { e in
                        if let end = e.endTime { Text(LoginTime.parse(end).text).appFont(.caption).foregroundStyle(.secondary) }
                        else if e.eventType == "Active" { Text("Active").appFont(.caption, weight: .medium).foregroundStyle(.blue) }
                        else { Text("—").appFont(.caption).foregroundStyle(.secondary) }
                    }
                    TableColumn("Duration") { e in Text(e.durationText).appFont(.caption).foregroundStyle(.secondary) }.width(min: 70, ideal: 90)
                    TableColumn("Source") { e in Text(e.sourceAddress ?? "—").appFont(.caption).foregroundStyle(.secondary) }
                }
                .frame(minHeight: CGFloat(min(15, i.sessionHistory.count + 1)) * 30 + 12)
            }
        }
    }

    private func bigStat(_ value: String, _ label: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(value).appFont(.title2, weight: .bold)
            Text(label).appFont(.caption).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// Label left, value right, optionally coloured. The Identity tab's `DetailRow`.
struct IdentityRow: View {
    let label: String
    let value: String
    var tone: Tone? = nil
    init(_ label: String, _ value: String, tone: Tone? = nil) { self.label = label; self.value = value; self.tone = tone }
    var body: some View {
        HStack(alignment: .top) {
            Text(label).appFont(.caption).foregroundStyle(.secondary)
            Spacer(minLength: 12)
            Text(value).appFont(.caption, weight: .medium).foregroundStyle(tone?.color ?? .primary).multilineTextAlignment(.trailing).textSelection(.enabled)
        }
        .padding(.vertical, 2)
    }
}
