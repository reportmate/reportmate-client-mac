import SwiftUI
import ReportMateKit

/// Security overview: the six posture cards, then certificates, CVEs and
/// threat detections. Port of `SecurityTab.tsx`.
struct SecurityTabView: View {
    @Environment(AppState.self) private var appState
    let device: DeviceDetail

    enum CertFilter: String { case all, valid, expiringsoon, expired }
    enum CVEFilter: String { case all, unpatched, patched }

    @State private var certFilter: CertFilter = .all
    @State private var storeFilter: String? = nil
    @State private var selfSignedOnly = false
    @State private var showOsRoots = false
    @State private var certSearch = ""
    @State private var expandedStores: Set<String> = []
    @State private var cveFilter: CVEFilter = .all
    @State private var expandedDetections: Set<String> = []
    @State private var expandedAsr = false
    @State private var expandedAudit = false
    @State private var expandedExclusions = false

    private static let cardColumns = [GridItem(.adaptive(minimum: 300), spacing: 12, alignment: .top)]

    var body: some View {
        let s = SecurityInfo(modules: device.asJSON["modules"], platform: device.platform, settings: appState.settings)
        VStack(alignment: .leading, spacing: 20) {
            if !s.hasData {
                Card { EmptyStateView(title: "No Security Data", message: "Security information is not available for this device.", systemImage: "lock") }
            } else {
                header(s)
                LazyVGrid(columns: Self.cardColumns, spacing: 12) {
                    tamperingCard(s)
                    protectionCard(s)
                    detectionCard(s)
                    encryptionCard(s)
                    firewallCard(s)
                    remoteAccessCard(s)
                }
                certificates(s)
                cves(s)
                detections(s)
            }
            JSONTreeView(value: device[.security], label: "device.modules.security")
        }
    }

    // MARK: Header

    private func header(_ s: SecurityInfo) -> some View {
        HStack {
            HStack(spacing: 12) {
                ZStack {
                    RoundedRectangle(cornerRadius: 10).fill(Color.red.opacity(0.15))
                    Image(systemName: "lock").foregroundStyle(.red).appFont(fixed: 20)
                }
                .frame(width: 44, height: 44)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Security Overview").appFont(.title2, weight: .bold)
                    Text("\(s.isMac ? "macOS" : "Windows") protection and compliance status").appFont(.callout).foregroundStyle(.secondary)
                }
            }
            Spacer()
            if let scan = s.lastScan {
                VStack(alignment: .trailing, spacing: 2) {
                    Text("Last Scan").appFont(.caption).foregroundStyle(.secondary)
                    Text(TimeFormatting.exact(scan)).appFont(.headline)
                }
            }
        }
    }

    // MARK: Row helpers

    private func card<Content: View>(_ title: String, icon: String, tone: Tone, @ViewBuilder content: () -> Content) -> some View {
        Card {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 10) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 8).fill(tone.color.opacity(0.15))
                        Image(systemName: icon).foregroundStyle(tone.color).appFont(.callout)
                    }
                    .frame(width: 32, height: 32)
                    Text(title).appFont(.title3, weight: .semibold)
                }
                .padding(.bottom, 8)
                content()
            }
            .padding(16)
        }
    }

    private func groupTitle(_ text: String) -> some View {
        Text(text).appFont(.callout, weight: .medium).padding(.bottom, 4)
    }

    private func row(_ label: String, _ value: String?, mono: Bool = false) -> some View {
        SecurityRow(label: label, value: value ?? "Unknown", tone: nil, mono: mono)
    }

    /// `StatusBadge` semantics: unknown grey, severity colour wins, else danger red, neutral plain, enabled green.
    private func status(_ label: String, _ enabled: Bool?, on: String = "Enabled", off: String = "Disabled", neutral: Bool = false, danger: Bool = false, severity: Severity? = nil) -> some View {
        var tone: Tone? = nil
        var text = "Unknown"
        if let enabled {
            text = enabled ? on : off
            if let severity, severity != .unknown {
                tone = severity == .neutral ? nil : Tone.forSeverity(severity)
            } else if !enabled {
                tone = danger ? .red : nil
            } else {
                tone = neutral ? nil : .green
            }
        } else {
            tone = .gray
        }
        return SecurityRow(label: label, value: text, tone: tone, mono: false)
    }

    private func divider() -> some View { Divider().padding(.vertical, 4) }

    // MARK: Cards

    private func tamperingCard(_ s: SecurityInfo) -> some View {
        let sec = s.security
        return card("Tampering", icon: s.isMac ? "checkmark.shield" : "cpu", tone: .orange) {
            if s.isMac {
                status("System Integrity Protection", s.sipEnabled, severity: s.severity("sip", s.sipEnabled))
                let enclave = SecurityInfo.on(sec["secureEnclave"]["present"])
                status("Secure Enclave", enclave, on: "Present", off: "Not Present", neutral: true)
                let touch = SecurityInfo.on(sec["secureEnclave"]["touchIdSupported"])
                status("Biometric", touch, on: "Supported", off: "Not Supported", neutral: true)
                if let ext = sec["secureBoot"]["externalBootAllowed"].nonEmptyString { row("External Boot", ext) }
                divider()
                let root = SecurityInfo.on(sec["rootUser"]["enabled"])
                status("Root User", !root, on: "Disabled", off: "Enabled", neutral: true)
                let flags = sec["systemIntegrityProtection"]["configFlags"]
                let unauth = flags["allowUnauthenticatedRoot"].int == 1 || flags["allow_unauthenticated_root"].int == 1
                status("Authenticated Root", !unauth, on: "Required", off: "Allowed", neutral: true)
            } else {
                let tpm = sec["tpm"]
                groupTitle("Trusted Platform Module")
                status("Present", tpm["isPresent"].boolishIfPresent)
                status("Enabled", tpm["isEnabled"].boolishIfPresent)
                status("Activated", tpm["isActivated"].boolishIfPresent)
                row("Version", tpm["version"].nonEmptyString)
                row("Manufacturer", tpm["manufacturer"].nonEmptyString)
                if let tp = sec["tamperProtection"]["isTamperProtected"].boolishIfPresent {
                    status("Tamper Protection", tp, severity: s.severity("tamperProtection", tp))
                }
                divider()
                status("Secure Boot", sec["secureBoot"]["isEnabled"].boolishIfPresent, danger: true)
                certList("Secure Boot DB", sec["secureBoot"]["dbCertificates"].elements)
                certList("Key Exchange Keys", sec["secureBoot"]["kekCertificates"].elements)
                let ha = sec["healthAttestation"]
                if !ha.isNull {
                    status("Code Integrity", ha["codeIntegrityEnabled"].boolishIfPresent)
                    let debug = ha["bootDebuggingEnabled"].boolish
                    status("Boot Debugging", !debug, on: "Disabled", off: "Enabled", neutral: true)
                }
                let fw = sec["firmwarePassword"]
                if !fw.isNull {
                    divider()
                    let display = fw["statusDisplay"].nonEmptyString
                    let enabled: Bool? = display == "Set" ? true : display == "Not Set" ? false : nil
                    status("Firmware Password", enabled, on: display ?? "Set", off: display ?? "Unknown", danger: display == "Not Set")
                    if let v = fw["adminPasswordSet"].boolishIfPresent { status("Admin / Supervisor", v, on: "Set", off: "Not Set", danger: true) }
                    if let v = fw["powerOnPasswordSet"].boolishIfPresent { status("Power-on Password", v, on: "Set", off: "Not Set", danger: true) }
                    if let v = fw["hddPasswordSet"].boolishIfPresent { status("HDD Password", v, on: "Set", off: "Not Set", danger: true) }
                    if let src = fw["source"].nonEmptyString { row("Source", src) }
                }
            }
        }
    }

    @ViewBuilder
    private func certList(_ title: String, _ certs: [JSONValue]) -> some View {
        if !certs.isEmpty {
            VStack(alignment: .leading, spacing: 3) {
                Text("\(title) (\(certs.count))").appFont(.caption2, weight: .medium).foregroundStyle(.secondary)
                ForEach(Array(certs.enumerated()), id: \.offset) { _, c in
                    HStack(spacing: 4) {
                        Text(c["commonName"].nonEmptyString ?? c["subject"].nonEmptyString ?? "Unknown").appFont(.caption2, weight: .medium)
                        if let t = c["thumbprint"].nonEmptyString { Text(String(t.prefix(8)) + "...").appFont(.caption2, design: .monospaced).foregroundStyle(.tertiary).help(t) }
                    }
                }
            }
            .padding(.top, 4)
        }
    }

    private func protectionCard(_ s: SecurityInfo) -> some View {
        let sec = s.security
        return card("Protection", icon: "shield", tone: .green) {
            groupTitle("Built-in Defenses")
            if s.isMac {
                status("Gatekeeper", s.gatekeeperEnabled)
                row("Allow Apps From", SecurityInfo.on(sec["gatekeeper"]["developerIdEnabled"]) ? "App Store & Known Developers" : "Anywhere")
                divider()
                let xp = SecurityInfo.on(sec["xprotect"]["enabled"])
                status("XProtect", xp, on: "Active", off: "Inactive")
                row("XProtect Version", sec["xprotect"]["version"].nonEmptyString, mono: true)
                row("Signatures", sec["xprotect"]["signatureCount"].string, mono: true)
                divider()
                let mrt = SecurityInfo.on(sec["mrt"]["enabled"])
                status("MRT (Malware Removal)", mrt, on: "Installed", off: "Not Installed")
                row("MRT Version", sec["mrt"]["version"].nonEmptyString, mono: true)
            } else {
                let dg = sec["deviceGuard"]
                if dg["smartAppControlAvailable"].boolish || !sec["smartAppControl"].isNull {
                    let on = dg["smartAppControlState"].string == "On" || sec["smartAppControl"]["enabled"].boolish || sec["smartAppControl"]["state"].string == "On"
                    let value = dg["smartAppControlState"].nonEmptyString ?? sec["smartAppControl"]["state"].nonEmptyString ?? (sec["smartAppControl"]["enabled"].boolish ? "On" : "Off")
                    status("Smart App Control", on, on: value, off: value)
                }
                if dg["coreIsolationStatus"].string != "Not supported" {
                    let on = dg["coreIsolationEnabled"].boolish || sec["coreIsolation"]["memoryIntegrity"].boolish || sec["coreIsolation"]["enabled"].boolish
                    let value = dg["coreIsolationStatus"].nonEmptyString ?? (on ? "Enabled" : "Disabled")
                    status("Core Isolation", on, on: value, off: dg["coreIsolationStatus"].nonEmptyString ?? "Disabled")
                }
                if dg["memoryIntegrityStatus"].string != "Not supported", dg["memoryIntegrityEnabled"].boolishIfPresent != nil || dg["memoryIntegrityStatus"].nonEmptyString != nil || sec["coreIsolation"]["memoryIntegrity"].boolishIfPresent != nil {
                    let on = dg["memoryIntegrityEnabled"].boolish || sec["coreIsolation"]["memoryIntegrity"].boolish
                    status("Memory Integrity (HVCI)", on, off: dg["memoryIntegrityStatus"].nonEmptyString ?? "Disabled")
                }
                if let dma = dg["kernelDmaProtectionEnabled"].boolishIfPresent { status("Kernel DMA Protection", dma) }
                divider()
                let vbs = dg["vbsEnabled"].boolish || sec["vbs"]["enabled"].boolish || sec["virtualizationBasedSecurity"]["enabled"].boolish
                status("VBS (Virtualization-based Security)", vbs, on: dg["vbsStatus"].nonEmptyString ?? "Running", off: dg["vbsStatus"].nonEmptyString ?? "Not configured")
                if let sup = dg["vbsSupported"].boolishIfPresent, !dg["vbsEnabled"].boolish { status("VBS Hardware Support", sup, on: "Supported", off: "Not supported") }
                let services = dg["vbsServices"].elements.compactMap(\.string) + sec["vbs"]["securityServicesRunning"].elements.compactMap(\.string) + sec["virtualizationBasedSecurity"]["services"].elements.compactMap(\.string)
                if !services.isEmpty { row("VBS Services", services.joined(separator: ", ")) }
                divider()
                let ep = dg["exploitProtection"]
                let epOn = ep["systemStatus"].string == "Configured" || sec["exploitProtection"]["enabled"].boolishIfPresent != false
                status("Exploit Protection", epOn, on: ep["systemStatus"].nonEmptyString ?? "Enabled", off: ep["systemStatus"].nonEmptyString ?? "Disabled")
                if let dep = ep["depEnabled"].boolishIfPresent ?? sec["exploitProtection"]["dep"].boolishIfPresent { status("DEP", dep) }
                if let aslr = ep["aslrEnabled"].boolishIfPresent ?? sec["exploitProtection"]["aslr"].boolishIfPresent { status("ASLR", aslr) }
                if let cfg = ep["cfgEnabled"].boolishIfPresent { status("CFG", cfg) }
                let lsa = sec["lsaProtection"]
                if lsa["enabled"].boolishIfPresent != nil || lsa["mode"].nonEmptyString != nil {
                    divider()
                    let on = lsa["enabled"].boolish
                    status("LSA Protection", on, on: lsa["mode"].string == "PPLBoot" ? "Enabled (UEFI Lock)" : "Enabled", severity: s.severity("lsaProtection", on))
                }
                let rules = sec["asrRules"].elements
                if !rules.isEmpty {
                    let block = rules.filter { $0["state"].string == "Block" }.count
                    let audit = rules.filter { $0["state"].string == "Audit" }.count
                    let warn = rules.filter { $0["state"].string == "Warn" }.count
                    collapsible("Attack Surface Reduction", value: "\(block)/\(rules.count) Block" + (audit > 0 ? ", \(audit) Audit" : "") + (warn > 0 ? ", \(warn) Warn" : ""), expanded: $expandedAsr) {
                        ForEach(Array(rules.enumerated()), id: \.offset) { _, r in
                            HStack {
                                Text(r["name"].string ?? "").appFont(.caption2).foregroundStyle(.secondary).lineLimit(1).help(r["name"].string ?? "")
                                Spacer()
                                let st = r["state"].string ?? ""
                                Text(st).appFont(.caption2, weight: .medium).foregroundStyle(st == "Block" ? Color.green : st == "Audit" ? Color.orange : Color.secondary)
                            }
                        }
                    }
                }
                let al = sec["appLocker"]
                if al["wdacEnabled"].boolishIfPresent != nil || al["policyConfigured"].boolishIfPresent != nil {
                    let wdac = al["wdacEnabled"].boolish, auditMode = al["wdacAuditMode"].boolish
                    status("App Control (WDAC)", wdac, on: auditMode ? "Audit Mode" : "Enforced", off: "Off", severity: wdac ? (auditMode ? .warning : .ok) : .neutral)
                    row("AppLocker", al["policyConfigured"].boolish ? (al["effectivePolicySummary"].nonEmptyString ?? "Configured") : "Not Configured")
                }
                if let ss = sec["smartScreen"]["windowsState"].nonEmptyString { row("SmartScreen", ss) }
            }
        }
    }

    private func collapsible<Content: View>(_ label: String, value: String, expanded: Binding<Bool>, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Button { expanded.wrappedValue.toggle() } label: {
                HStack {
                    Text(label).appFont(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Text(value).appFont(.caption, weight: .medium)
                    Image(systemName: "chevron.down").rotationEffect(.degrees(expanded.wrappedValue ? 180 : 0)).appFont(.caption2).foregroundStyle(.secondary)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            if expanded.wrappedValue {
                ScrollView { VStack(alignment: .leading, spacing: 2) { content() } }
                    .frame(maxHeight: 220)
                    .padding(.leading, 8)
            }
        }
        .padding(.vertical, 2)
    }

    private func detectionCard(_ s: SecurityInfo) -> some View {
        let sec = s.security
        return card("Detection", icon: "magnifyingglass", tone: .indigo) {
            if s.isMac {
                let products = s.edrProducts
                if !products.isEmpty {
                    ForEach(Array(products.enumerated()), id: \.offset) { i, p in
                        if i > 0 { divider() }
                        HStack {
                            Text(p.name).appFont(.callout, weight: .medium)
                            Spacer()
                            Pill(p.healthLabel, tone: p.healthy == true || p.running == true ? .green : p.healthy == false ? .yellow : .gray)
                        }
                        .padding(.bottom, 4)
                        let j = p.json
                        switch p.identifier {
                        case "com.microsoft.wdav":
                            status("Real-time Protection", j["realTimeProtection"].boolishIfPresent)
                            status("Cloud Protection", j["cloudProtection"].boolishIfPresent)
                            status("Tamper Protection", j["tamperProtection"].boolishIfPresent)
                            status("Behavior Monitoring", j["behaviorMonitoring"].boolishIfPresent)
                            row("App Version", j["version"].nonEmptyString)
                            row("Engine", j["engineVersion"].nonEmptyString)
                            row("Definitions", j["definitionsVersion"].nonEmptyString)
                            row("Definitions Updated", TimeFormatting.exact(j["definitionsUpdated"].nonEmptyString))
                            row("Last Scan", j["lastScanTime"].nonEmptyString.map { "\(TimeFormatting.exact($0)) (\(j["lastScanType"].nonEmptyString ?? "unknown"))" } ?? "Never")
                            if let n = j["lastScanFilesScanned"].int, n > 0 { row("Files Scanned", ByteFormatting.count(n)) }
                            row("Threats Detected", String(j["totalThreatsDetected"].int ?? 0))
                            status("Licensed", j["licensed"].boolishIfPresent)
                            status("Full Disk Access", j["fullDiskAccess"].boolishIfPresent, on: "Granted", off: "Not Granted")
                            let issues = j["healthIssues"].elements.compactMap(\.string)
                            if !issues.isEmpty {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("Health Issues:").appFont(.caption2, weight: .medium)
                                    ForEach(issues, id: \.self) { Text("• \($0)").appFont(.caption2) }
                                }
                                .foregroundStyle(.yellow)
                                .padding(8).frame(maxWidth: .infinity, alignment: .leading)
                                .background(Color.yellow.opacity(0.1), in: RoundedRectangle(cornerRadius: 6))
                            }
                        case "com.crowdstrike.falcon":
                            row("Version", p.version)
                            row("State", j["state"].nonEmptyString)
                            row("Agent ID", j["agentId"].nonEmptyString, mono: true)
                        default:
                            row("Version", p.version)
                            status("Running", p.running)
                        }
                    }
                } else if !sec["endpointSecurity"]["extensions"].elements.isEmpty {
                    let exts = sec["endpointSecurity"]["extensions"].elements
                    groupTitle("Endpoint Security Extensions")
                    ForEach(Array(exts.prefix(3).enumerated()), id: \.offset) { _, e in
                        let active = e["enabled"].boolish || e["active"].boolish || (e["state"].string ?? "").contains("enabled")
                        VStack(alignment: .leading, spacing: 2) {
                            HStack {
                                Text(e["name"].nonEmptyString ?? e["identifier"].nonEmptyString ?? "Unknown").appFont(.callout, weight: .medium)
                                Spacer()
                                Pill(active ? "Active" : "Inactive", tone: active ? .green : .gray)
                            }
                            HStack(spacing: 8) {
                                if let v = e["version"].nonEmptyString { Text(v).appFont(.caption2).foregroundStyle(.secondary) }
                                if let t = e["teamId"].nonEmptyString { Text(t).appFont(.caption2, design: .monospaced).foregroundStyle(.secondary) }
                            }
                        }
                        .padding(.vertical, 2)
                    }
                    if exts.count > 3 { Text("+\(exts.count - 3) more extensions").appFont(.caption2).foregroundStyle(.secondary) }
                } else {
                    Text("No EDR products detected").appFont(.callout).foregroundStyle(.secondary)
                }
            } else {
                let av = sec["antivirus"]
                groupTitle(av["name"].nonEmptyString ?? "Windows Security")
                status("Real-time Protection", av["realTimeProtection"].boolishIfPresent ?? av["isEnabled"].boolishIfPresent)
                row("Version", av["version"].nonEmptyString)
                row("Definitions", av["isUpToDate"].boolish ? "Up to date" : "Needs update")
                row("Last Update", TimeFormatting.exact(av["lastUpdate"].nonEmptyString))
                row("Last Scan", TimeFormatting.exact(av["lastScan"].nonEmptyString) + (av["scanType"].nonEmptyString.map { " (\($0))" } ?? ""))
                let dv = sec["defenderVersions"]
                if let engine = dv["amEngineVersion"].nonEmptyString {
                    divider()
                    row("Engine Version", engine, mono: true)
                    if let p = dv["amProductVersion"].nonEmptyString { row("Platform Version", p, mono: true) }
                    if let sig = dv["antivirusSignatureVersion"].nonEmptyString { row("Signatures", sig, mono: true) }
                }
                if s.defenderExclusionCount > 0 {
                    collapsible("Defender Exclusions", value: "\(s.defenderExclusionCount)", expanded: $expandedExclusions) {
                        ForEach(Array(s.defenderExclusions.enumerated()), id: \.offset) { _, ex in
                            Text(ex).appFont(.caption2, design: .monospaced).foregroundStyle(.secondary).lineLimit(1).help(ex)
                        }
                    }
                }
                let edrs = s.windowsEdrProducts
                if !edrs.isEmpty {
                    divider()
                    ForEach(Array(edrs.enumerated()), id: \.offset) { _, e in
                        let running = e["serviceRunning"].boolish
                        status(e["name"].nonEmptyString ?? e["vendor"].nonEmptyString ?? "EDR", running, on: "Running", off: "Stopped", neutral: !running)
                    }
                }
                let cats = sec["auditPolicy"]["categories"].elements
                if !cats.isEmpty {
                    divider()
                    let audited = cats.filter { ($0["setting"].nonEmptyString ?? "No Auditing") != "No Auditing" }.count
                    collapsible("Audit Policy", value: "\(audited)/\(cats.count) audited", expanded: $expandedAudit) {
                        ForEach(Array(cats.enumerated()), id: \.offset) { _, c in
                            HStack {
                                Text(c["subcategory"].string ?? "").appFont(.caption2).foregroundStyle(.secondary).lineLimit(1)
                                Spacer()
                                let setting = c["setting"].nonEmptyString
                                Text(setting ?? "—").appFont(.caption2, weight: .medium).foregroundStyle(setting == nil || setting == "No Auditing" ? Color.secondary.opacity(0.6) : Color.green)
                            }
                        }
                    }
                }
                let more = sec["endpointDetection"].elements
                if !more.isEmpty {
                    divider()
                    ForEach(Array(more.enumerated()), id: \.offset) { _, e in
                        let running = e["running"].boolish || e["isRunning"].boolish
                        status(e["name"].nonEmptyString ?? "EDR", running, on: "Active", off: "Inactive")
                    }
                }
            }
        }
    }

    private func encryptionCard(_ s: SecurityInfo) -> some View {
        let sec = s.security
        return card("Encryption", icon: "internaldrive", tone: .purple) {
            if s.isMac {
                groupTitle("FileVault Disk Encryption")
                let volumes = sec["fileVault"]["encryptedVolumes"].elements.map { $0["name"].nonEmptyString ?? $0["volumeName"].nonEmptyString ?? $0.string ?? "" }.filter { !$0.isEmpty }
                row("Encrypted Volumes", volumes.isEmpty ? (s.fileVaultEnabled ? "System Volume" : "None") : volumes.joined(separator: ", "))
                status("Status", s.fileVaultEnabled, on: "Encrypted", off: "Not Encrypted", severity: s.severity("encryption", s.fileVaultEnabled))
            } else {
                groupTitle("BitLocker Drive Encryption")
                let bl = sec["encryption"]["bitLocker"]
                let drives = bl["encryptedDrives"].elements.compactMap(\.string)
                row("Drives", drives.isEmpty ? "None encrypted" : drives.joined(separator: ", "))
                row("Method", sec["encryption"]["encryptedVolumes"][0]["encryptionMethod"].nonEmptyString ?? "XTS-AES")
                let on = bl["isEnabled"].boolish
                let label = bl["status"].nonEmptyString ?? (on ? "Enabled" : "Disabled")
                status("Status", on, on: label, off: label, severity: s.severity("encryption", on))
            }
        }
    }

    private func firewallCard(_ s: SecurityInfo) -> some View {
        let fw = s.security["firewall"]
        return card("Firewall", icon: "square.grid.3x3", tone: .blue) {
            if s.isMac {
                status("Global State", s.firewallEnabled, on: "On", off: "Off", severity: s.severity("firewall", s.firewallEnabled))
                status("Stealth Mode", SecurityInfo.on(fw["stealthMode"]), neutral: true)
                status("Logging", SecurityInfo.on(fw["loggingEnabled"]), neutral: true)
                status("Allow Signed Apps", SecurityInfo.on(fw["allowSignedSoftware"]), on: "Allowed", off: "Blocked", neutral: true)
            } else {
                groupTitle("Windows Firewall")
                row("Profile", fw["profile"].nonEmptyString ?? "Domain/Private/Public")
                row("Inbound Rules", fw["inboundRules"].string ?? "Active")
                row("Outbound Rules", fw["outboundRules"].string ?? "Active")
            }
        }
    }

    private func remoteAccessCard(_ s: SecurityInfo) -> some View {
        let sec = s.security
        let rm = s.remoteManagement
        return card("Remote Access", icon: "terminal", tone: .gray) {
            if s.isMac {
                status("Secure Shell (Remote Login)", s.sshEnabled, severity: s.severity("ssh", s.sshEnabled))
                if SecurityInfo.on(sec["ssh"]["enabled"]) {
                    let users = sec["ssh"]["authorizedUsers"].nonEmptyString
                    row("Authorized Users", users == "all" ? "All" : (users ?? "Not set"))
                    let pub = sec["ssh"]["pubkeyAuthentication"].string == "yes", pw = sec["ssh"]["passwordAuthentication"].string == "yes"
                    if pub || pw { row("Authentication", [pub ? "Public Key" : nil, pw ? "Password" : nil].compactMap { $0 }.joined(separator: ", ")) }
                }
                divider()
                status("Remote Management", s.ardEnabled, neutral: true)
                status("Screen Sharing", s.screenSharingEnabled, neutral: true)
                let allowed = rm["ardAllowedUsers"].nonEmptyString ?? rm["ard_allowed_users"].nonEmptyString
                if let allowed { row("Allowed Users", allowed == "true" ? "All Users" : allowed) }
            } else {
                let rdp = sec["rdp"]
                let rdpOn = rdp["isEnabled"].boolish
                status("Remote Desktop (RDP)", rdpOn, severity: s.severity("rdp", rdpOn))
                row("RDP Port", rdp["port"].string ?? "3389")
                status("Network Level Auth", rdp["nlaEnabled"].boolishIfPresent)
                divider()
                let ssh = sec["secureShell"]
                status("OpenSSH Installed", ssh["isInstalled"].boolishIfPresent)
                status("Secure Shell Service", ssh["isServiceRunning"].boolishIfPresent)
                status("Secure Shell Firewall Rule", ssh["isFirewallRulePresent"].boolishIfPresent)
            }
        }
    }

    // MARK: Certificates

    private func certificates(_ s: SecurityInfo) -> some View {
        let all = s.certificates
        let visible = showOsRoots ? all : all.filter { !($0.isOsTrustedRoot && $0.isExpired) }
        let expired = (!showOsRoots ? s.userExpiredCount : nil) ?? visible.filter(\.isExpired).count
        let expiring = visible.filter { $0.status == .expiringSoon }.count
        let valid = visible.filter { $0.status == .valid }.count
        let selfSigned = visible.filter(\.isSelfSigned).count
        let osRootExpired = s.osRootExpiredCount
        let stores = Array(Set(visible.map(\.store))).sorted()
        let q = certSearch.trimmingCharacters(in: .whitespaces).lowercased()
        let filtered = visible.filter { c in
            switch certFilter {
            case .all: break
            case .valid: if c.status != .valid { return false }
            case .expiringsoon: if c.status != .expiringSoon { return false }
            case .expired: if c.status != .expired { return false }
            }
            if let storeFilter, c.store != storeFilter { return false }
            if selfSignedOnly, !c.isSelfSigned { return false }
            if !q.isEmpty, !c.matches(q) { return false }
            return true
        }
        let grouped = Dictionary(grouping: filtered, by: \.store).sorted { $0.key < $1.key }
        let anyFilter = certFilter != .all || storeFilter != nil || selfSignedOnly || showOsRoots || !q.isEmpty

        return Card {
            VStack(spacing: 0) {
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        HStack(spacing: 10) {
                            ZStack {
                                RoundedRectangle(cornerRadius: 8).fill(Color.teal.opacity(0.15))
                                Image(systemName: "rosette").foregroundStyle(.teal)
                            }
                            .frame(width: 32, height: 32)
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Certificates").appFont(.title3, weight: .semibold)
                                Text("\(visible.count) certificates" + (!showOsRoots && osRootExpired > 0 ? " (\(osRootExpired) expired OS roots hidden)" : "")).appFont(.caption).foregroundStyle(.secondary)
                            }
                        }
                        Spacer()
                        TextField("Search certificates...", text: $certSearch).textFieldStyle(.roundedBorder).frame(width: 220)
                    }
                    if !all.isEmpty {
                        HStack {
                            FlowLayout(spacing: 6) {
                                if stores.count > 1 {
                                    ForEach(stores, id: \.self) { store in
                                        FilterPill(text: "\(store) (\(visible.filter { $0.store == store }.count))", selected: storeFilter == store, tone: .blue) {
                                            storeFilter = storeFilter == store ? nil : store; expandedStores = Set(stores)
                                        }
                                    }
                                }
                                FilterPill(text: "Valid (\(valid))", selected: certFilter == .valid, tone: .green) { certFilter = certFilter == .valid ? .all : .valid; expandedStores = Set(stores) }
                                FilterPill(text: "Expiring Soon (\(expiring))", selected: certFilter == .expiringsoon, tone: .orange) { certFilter = certFilter == .expiringsoon ? .all : .expiringsoon; expandedStores = Set(stores) }
                                FilterPill(text: "Expired (\(expired))", selected: certFilter == .expired, tone: .red) { certFilter = certFilter == .expired ? .all : .expired; expandedStores = Set(stores) }
                                FilterPill(text: "Self-signed (\(selfSigned))", selected: selfSignedOnly, tone: .blue) { selfSignedOnly.toggle(); expandedStores = Set(stores) }
                                if osRootExpired > 0 {
                                    FilterPill(text: "\(showOsRoots ? "Hide" : "Show") expired OS roots (\(osRootExpired))", selected: showOsRoots, tone: .gray) { showOsRoots.toggle(); expandedStores = Set(stores) }
                                }
                            }
                            Spacer()
                            if anyFilter {
                                Button { certFilter = .all; storeFilter = nil; selfSignedOnly = false; showOsRoots = false; certSearch = "" } label: { Label("Clear Filters", systemImage: "xmark") }
                                    .buttonStyle(.plain).appFont(.caption, weight: .medium).foregroundStyle(.yellow)
                            }
                        }
                    }
                }
                .padding(16)
                Divider()
                if all.isEmpty {
                    VStack(spacing: 4) {
                        Image(systemName: "rosette").font(.system(size: 28)).foregroundStyle(.tertiary)
                        Text("No certificates collected").appFont(.callout).foregroundStyle(.secondary)
                        Text("Certificate data will appear after the next device check-in").appFont(.caption2).foregroundStyle(.tertiary)
                    }
                    .padding(24).frame(maxWidth: .infinity)
                } else if filtered.isEmpty {
                    Text("No certificates match the selected filters").appFont(.callout).foregroundStyle(.secondary).padding(24).frame(maxWidth: .infinity)
                } else {
                    ForEach(grouped, id: \.key) { store, certs in
                        let open = expandedStores.contains(store)
                        Button {
                            if open { expandedStores.remove(store) } else { expandedStores.insert(store) }
                        } label: {
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(store).appFont(.callout, weight: .medium)
                                    Text("\(certs.count) certificate\(certs.count == 1 ? "" : "s")").appFont(.caption).foregroundStyle(.secondary)
                                }
                                Spacer()
                                Image(systemName: "chevron.down").rotationEffect(.degrees(open ? 180 : 0)).foregroundStyle(.secondary)
                            }
                            .padding(.horizontal, 16).padding(.vertical, 12)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        if open { certTable(certs) }
                        Divider()
                    }
                }
            }
        }
    }

    private func certTable(_ certs: [SecurityInfo.Certificate]) -> some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Text("NAME / SUBJECT / ISSUER").frame(maxWidth: .infinity, alignment: .leading)
                Text("STATUS").frame(width: 90, alignment: .leading)
                Text("VALID FROM").frame(width: 100, alignment: .leading)
                Text("EXPIRES").frame(width: 100, alignment: .leading)
                Text("KEYCHAIN").frame(width: 140, alignment: .leading)
            }
            .appFont(.caption2, weight: .semibold).foregroundStyle(.secondary)
            .padding(.horizontal, 16).padding(.vertical, 6)
            .background(Color.subtleBackground)
            ForEach(certs) { c in
                HStack(alignment: .top, spacing: 12) {
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            Text(c.displayName).appFont(.callout, weight: .medium).lineLimit(1)
                            if c.isSelfSigned { Text("(self-signed)").appFont(.caption2).foregroundStyle(.secondary) }
                        }
                        if !c.issuer.isEmpty { Text(c.displayIssuer).appFont(.caption2).foregroundStyle(.secondary).lineLimit(1).help(c.issuer) }
                        if !c.thumbprint.isEmpty { Text(String(c.thumbprint.prefix(20)) + "...").appFont(.caption2, design: .monospaced).foregroundStyle(.secondary).help(c.thumbprint) }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    Group {
                        switch c.status {
                        case .expired: Pill("Expired", tone: .red)
                        case .expiringSoon: Pill(c.daysUntilExpiry.map { "\($0)d" } ?? "Expiring", tone: .orange)
                        case .valid: Pill("Valid", tone: .green)
                        }
                    }
                    .frame(width: 90, alignment: .leading)
                    Text(c.notBefore.isEmpty ? "—" : TimeFormatting.shortDate(c.notBefore)).appFont(.caption).foregroundStyle(.secondary).frame(width: 100, alignment: .leading)
                    Text(c.notAfter.isEmpty ? "—" : TimeFormatting.shortDate(c.notAfter)).appFont(.caption).foregroundStyle(.secondary).frame(width: 100, alignment: .leading)
                    Text(c.keychainName).appFont(.caption, design: .monospaced).foregroundStyle(.secondary).frame(width: 140, alignment: .leading).lineLimit(1).help(c.path)
                }
                .padding(.horizontal, 16).padding(.vertical, 8)
                Divider()
            }
        }
    }

    // MARK: CVEs

    private func cves(_ s: SecurityInfo) -> some View {
        let all = s.cves
        let unpatched = all.filter { $0.status == "Unpatched" }
        let patched = all.filter { $0.status == "Patched" }
        let exploited = unpatched.filter(\.activelyExploited).count
        let total = s.sofaRelease?.uniqueCvesCount ?? all.count
        let filtered = SecurityInfo.sortCVEs(cveFilter == .all ? all : cveFilter == .unpatched ? unpatched : patched)
        let release = s.sofaRelease

        return Card {
            VStack(spacing: 0) {
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        HStack(spacing: 10) {
                            ZStack {
                                RoundedRectangle(cornerRadius: 8).fill((unpatched.isEmpty ? Color.green : Color.red).opacity(0.15))
                                Image(systemName: unpatched.isEmpty ? "checkmark.circle" : "exclamationmark.triangle").foregroundStyle(unpatched.isEmpty ? .green : .red)
                            }
                            .frame(width: 32, height: 32)
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Common Vulnerabilities and Exposures").appFont(.title3, weight: .semibold)
                                Text("\(s.isMac ? "SOFA Security Intelligence" : "Windows Security Updates") • " + (unpatched.isEmpty ? "All patched" : "\(unpatched.count) unpatched") + (patched.isEmpty ? "" : " • \(patched.count) patched"))
                                    .appFont(.caption).foregroundStyle(.secondary)
                            }
                        }
                        Spacer()
                        HStack(spacing: 10) {
                            if s.pendingRebootRequired { Pill("Reboot Required", tone: .orange).help("A reboot is pending to finish applying updates") }
                            if exploited > 0 { Pill("\(exploited) Actively Exploited", tone: .red) }
                            if !all.isEmpty { Text("\(total) total CVEs").appFont(.caption).foregroundStyle(.secondary) }
                        }
                    }
                    if !patched.isEmpty, !unpatched.isEmpty {
                        HStack(spacing: 6) {
                            FilterPill(text: "All (\(all.count))", selected: cveFilter == .all, tone: .gray) { cveFilter = .all }
                            FilterPill(text: "Unpatched (\(unpatched.count))", selected: cveFilter == .unpatched, tone: .red) { cveFilter = cveFilter == .unpatched ? .all : .unpatched }
                            FilterPill(text: "Patched (\(patched.count))", selected: cveFilter == .patched, tone: .green) { cveFilter = cveFilter == .patched ? .all : .patched }
                        }
                    }
                    if s.isMac, let release, let name = release.updateName {
                        HStack(spacing: 16) {
                            HStack(spacing: 4) { Text("Release:").appFont(.caption, weight: .medium); Text(name).appFont(.caption) }
                            if let d = release.releaseDate { HStack(spacing: 4) { Text("Date:").appFont(.caption, weight: .medium); Text(TimeFormatting.shortDate(d)).appFont(.caption) } }
                            if let days = release.daysSincePreviousRelease { HStack(spacing: 4) { Text("Days since last:").appFont(.caption, weight: .medium); Text("\(days)").appFont(.caption) } }
                            if let info = release.securityInfo, let url = URL(string: info) { Link("Apple Security Notes →", destination: url).appFont(.caption) }
                        }
                        .foregroundStyle(.secondary)
                    }
                }
                .padding(16)
                Divider()
                if filtered.isEmpty {
                    VStack(spacing: 4) {
                        Image(systemName: "checkmark.circle").font(.system(size: 28)).foregroundStyle(.green)
                        Text(cveFilter == .patched ? "No Patched CVEs Found" : "No Unpatched Vulnerabilities").appFont(.callout, weight: .medium)
                        Text(s.isMac ? "This device is running a fully patched version of macOS" : "This device has all available security updates installed").appFont(.caption2).foregroundStyle(.secondary)
                    }
                    .padding(24).frame(maxWidth: .infinity)
                } else {
                    HStack(spacing: 12) {
                        Text("CVE ID").frame(width: 160, alignment: .leading)
                        Text("OS VERSION").frame(width: 100, alignment: .leading)
                        Text("PATCHED IN").frame(maxWidth: .infinity, alignment: .leading)
                        Text("STATUS").frame(width: 100, alignment: .leading)
                        if !s.isMac { Text("INSTALLED").frame(width: 110, alignment: .leading) }
                        Text("SOURCE").frame(width: 60, alignment: .leading)
                    }
                    .appFont(.caption2, weight: .semibold).foregroundStyle(.secondary)
                    .padding(.horizontal, 16).padding(.vertical, 6)
                    .background(Color.subtleBackground)
                    ForEach(filtered) { c in
                        HStack(spacing: 12) {
                            Group {
                                if let u = c.url, let url = URL(string: u) { Link(c.cve, destination: url).appFont(.caption, design: .monospaced) }
                                else { Text(c.cve).appFont(.caption, design: .monospaced) }
                            }
                            .frame(width: 160, alignment: .leading)
                            Text(c.osVersion.isEmpty ? "—" : c.osVersion).appFont(.caption).foregroundStyle(.secondary).frame(width: 100, alignment: .leading)
                            Text(c.patchedVersion.isEmpty ? (c.kbArticle ?? "—") : c.patchedVersion).appFont(.caption).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading).lineLimit(1)
                            Group {
                                if c.status == "Patched" { Pill("Patched", tone: .green) }
                                else if c.activelyExploited { Pill("Exploited", tone: .red) }
                                else { Pill("Unpatched", tone: .orange) }
                            }
                            .frame(width: 100, alignment: .leading)
                            if !s.isMac { Text(c.installedDate.map { TimeFormatting.exact($0) } ?? "—").appFont(.caption).foregroundStyle(.secondary).frame(width: 110, alignment: .leading).lineLimit(1) }
                            Pill(c.source.label, tone: c.source == .sofa ? .purple : .blue).frame(width: 60, alignment: .leading)
                        }
                        .padding(.horizontal, 16).padding(.vertical, 8)
                        Divider()
                    }
                }
            }
        }
    }

    // MARK: Detections

    private func detections(_ s: SecurityInfo) -> some View {
        let list = s.detections
        let summary = s.detectionSummary
        let tone: Tone = summary.hasActiveThreats ? .red : list.isEmpty ? .green : .orange
        return Card {
            VStack(spacing: 0) {
                VStack(alignment: .leading, spacing: 8) {
                    HStack(spacing: 10) {
                        ZStack {
                            RoundedRectangle(cornerRadius: 8).fill(tone.color.opacity(0.15))
                            Image(systemName: list.isEmpty ? "checkmark.shield" : "exclamationmark.triangle").foregroundStyle(tone.color)
                        }
                        .frame(width: 32, height: 32)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Threat Detections").appFont(.title3, weight: .semibold)
                            Text(list.isEmpty ? "No threats detected in the last 30 days" : "\(list.count) detection\(list.count == 1 ? "" : "s") from AV/EDR products (last 30 days)").appFont(.caption).foregroundStyle(.secondary)
                        }
                    }
                    if !list.isEmpty, summary.total30d > 0 || summary.blocked30d > 0 || summary.cleaned30d > 0 {
                        HStack(spacing: 14) {
                            Text("\(summary.total30d) total").foregroundStyle(.secondary)
                            if summary.blocked30d > 0 { Label("\(summary.blocked30d) blocked", systemImage: "shield").foregroundStyle(.blue) }
                            if summary.cleaned30d > 0 { Label("\(summary.cleaned30d) cleaned", systemImage: "checkmark.circle").foregroundStyle(.green) }
                            if summary.allowed30d > 0 { Label("\(summary.allowed30d) allowed", systemImage: "xmark.circle").foregroundStyle(.red) }
                        }
                        .appFont(.caption)
                    }
                }
                .padding(16)
                Divider()
                if list.isEmpty {
                    VStack(spacing: 4) {
                        Image(systemName: "checkmark.shield").font(.system(size: 28)).foregroundStyle(.green)
                        Text("No Threats Detected").appFont(.callout, weight: .medium)
                        Text("No malware, PUA, or security alerts in the last 30 days").appFont(.caption2).foregroundStyle(.secondary)
                    }
                    .padding(24).frame(maxWidth: .infinity)
                } else {
                    HStack(spacing: 12) {
                        Text("THREAT").frame(maxWidth: .infinity, alignment: .leading)
                        Text("SEVERITY").frame(width: 80, alignment: .leading)
                        Text("CATEGORY").frame(width: 100, alignment: .leading)
                        Text("STATUS").frame(width: 110, alignment: .leading)
                        Text("SOURCE").frame(width: 100, alignment: .leading)
                        Text("DETECTED").frame(width: 120, alignment: .leading)
                    }
                    .appFont(.caption2, weight: .semibold).foregroundStyle(.secondary)
                    .padding(.horizontal, 16).padding(.vertical, 6)
                    .background(Color.subtleBackground)
                    ForEach(list) { d in
                        let open = expandedDetections.contains(d.id)
                        Button {
                            guard d.hasDetails else { return }
                            if open { expandedDetections.remove(d.id) } else { expandedDetections.insert(d.id) }
                        } label: {
                            HStack(alignment: .top, spacing: 12) {
                                HStack(alignment: .top, spacing: 6) {
                                    if d.hasDetails { Image(systemName: "chevron.right").rotationEffect(.degrees(open ? 90 : 0)).appFont(.caption2).foregroundStyle(.secondary).padding(.top, 3) }
                                    Text(d.threatName).appFont(.callout, weight: .medium)
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                                Pill(d.severity ?? "Unknown", tone: severityTone(d.severity)).frame(width: 80, alignment: .leading)
                                Text(d.category ?? "—").appFont(.caption).foregroundStyle(.secondary).frame(width: 100, alignment: .leading).lineLimit(1)
                                HStack(spacing: 4) {
                                    statusIcon(d.statusMark)
                                    Text(d.status ?? "Unknown").appFont(.caption)
                                }
                                .frame(width: 110, alignment: .leading)
                                Pill(d.source ?? "Unknown", tone: .indigo).frame(width: 100, alignment: .leading)
                                Text(d.detectedAt.map { TimeFormatting.exact($0) } ?? "—").appFont(.caption).foregroundStyle(.secondary).frame(width: 120, alignment: .leading).lineLimit(1)
                            }
                            .padding(.horizontal, 16).padding(.vertical, 8)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        if open, d.hasDetails {
                            VStack(alignment: .leading, spacing: 4) {
                                if let v = d.threatId { detailLine("Rule ID", v, mono: true) }
                                if let v = d.filePath { detailLine("Path", v, mono: true) }
                                if let v = d.processName { detailLine("Process", v, mono: true) }
                                if let v = d.user { detailLine("User", v) }
                                if let v = d.actionTaken { detailLine("Action", v) }
                                if let v = d.description { detailLine("Details", v) }
                                if let v = d.eventId { detailLine("Event ID", v, mono: true) }
                            }
                            .padding(.horizontal, 24).padding(.vertical, 8)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color.subtleBackground)
                        }
                        Divider()
                    }
                }
            }
        }
    }

    private func detailLine(_ label: String, _ value: String, mono: Bool = false) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Text(label).appFont(.caption).foregroundStyle(.secondary).frame(width: 80, alignment: .leading)
            Text(value).appFont(.caption, design: mono ? .monospaced : .default).textSelection(.enabled)
        }
    }

    private func severityTone(_ severity: String?) -> Tone {
        switch (severity ?? "").lowercased() {
        case "severe": return .red
        case "high": return .orange
        case "moderate": return .yellow
        case "low": return .blue
        default: return .gray
        }
    }

    private func statusIcon(_ mark: SecurityInfo.Detection.StatusMark) -> some View {
        Group {
            switch mark {
            case .good: Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
            case .attention: Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.yellow)
            case .bad: Image(systemName: "xmark.circle.fill").foregroundStyle(.red)
            case .unknown: Image(systemName: "exclamationmark.triangle").foregroundStyle(.secondary)
            }
        }
        .appFont(.caption2)
    }
}

/// The Security tab's `DetailRow`: label left, value right, coloured by tone.
struct SecurityRow: View {
    let label: String
    let value: String
    var tone: Tone?
    var mono = false
    var body: some View {
        HStack(alignment: .top) {
            Text(label).appFont(.caption).foregroundStyle(.secondary)
            Spacer(minLength: 12)
            Text(value).appFont(.caption, weight: .medium, design: mono ? .monospaced : .default)
                .foregroundStyle(tone?.color ?? .primary)
                .multilineTextAlignment(.trailing).textSelection(.enabled)
        }
        .padding(.vertical, 2)
    }
}
