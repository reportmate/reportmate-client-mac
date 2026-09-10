import SwiftUI
import AppKit
import ReportMateKit

/// Device management: enrollment and certificate cards, tool logs, profiles
/// and managed preferences. Port of `ManagementTab.tsx`.
struct ManagementTabView: View {
    let device: DeviceDetail
    @State private var profileSearch = ""
    @State private var policySearch = ""
    @State private var expandedProfiles: Set<String> = []
    @State private var expandedPolicies: Set<String> = []

    var body: some View {
        let m = ManagementDetail(modules: device.asJSON["modules"], platform: device.platform)
        VStack(alignment: .leading, spacing: 20) {
            if !m.hasData {
                Card { EmptyStateView(title: "No Management Data Available", message: "This device does not have management enrollment information.", systemImage: "checkmark.shield") }
            } else {
                header(m)
                HStack(alignment: .top, spacing: 16) {
                    enrollmentCard(m).frame(maxWidth: .infinity)
                    if m.isEnrolled { certificateCard(m).frame(width: 340) }
                }
                if let logs = m.logs, !logs.roots.isEmpty { ManagementLogsSection(serialNumber: device.serialNumber, logs: logs, installs: device.asJSON["modules"]["installs"]) }
                if !m.profiles.isEmpty { profilesSection(m) }
                if m.isMac, !m.managedPolicies.isEmpty { policiesSection(m) }
            }
            JSONTreeView(value: device[.management], label: "device.modules.management")
        }
    }

    private func header(_ m: ManagementDetail) -> some View {
        HStack {
            HStack(spacing: 12) {
                ZStack {
                    RoundedRectangle(cornerRadius: 10).fill(Color.yellow.opacity(0.2))
                    Image(systemName: "checkmark.shield").foregroundStyle(.yellow).appFont(fixed: 20)
                }
                .frame(width: 44, height: 44)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Device Management Service").appFont(.title2, weight: .bold)
                    Text("Enrollment, Policies, and Identity Status").appFont(.callout).foregroundStyle(.secondary)
                }
            }
            Spacer()
            if let provider = m.provider {
                VStack(alignment: .trailing, spacing: 2) {
                    Text("Provider").appFont(.caption).foregroundStyle(.secondary)
                    Text(provider).appFont(.title2, weight: .bold).foregroundStyle(.yellow)
                }
            }
        }
    }

    // MARK: Enrollment card

    private func pillRow(_ label: String, _ text: String, tone: Tone, small: Bool = false) -> some View {
        HStack(spacing: 10) {
            Text(label).appFont(small ? .caption : .callout, weight: .medium).foregroundStyle(small ? .secondary : .primary)
            Pill(text, tone: tone)
        }
    }

    private func yesNo(_ label: String, _ on: Bool) -> some View { pillRow(label, on ? "Yes" : "No", tone: on ? .green : .gray, small: true) }

    private func labeled(_ label: String, _ value: String, mono: Bool = false, copy: Bool = false) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Text(label).appFont(.caption, weight: .medium).foregroundStyle(.secondary).frame(width: 110, alignment: .leading)
            HStack(spacing: 6) {
                Text(value).appFont(.caption, design: mono ? .monospaced : .default).lineLimit(1).truncationMode(.middle).textSelection(.enabled).help(value)
                if copy { CopyButton(value: value) }
            }
        }
    }

    private func sectionHeading(_ text: String) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Divider().padding(.vertical, 12)
            Text(text).appFont(.headline).padding(.bottom, 8)
        }
    }

    private func enrollmentCard(_ m: ManagementDetail) -> some View {
        let mdm = m.mdmEnrollment
        return Card {
            VStack(alignment: .leading, spacing: 10) {
                Text("Enrollment").appFont(.title3, weight: .bold).padding(.bottom, 6)
                pillRow("Enrollment Status", m.isEnrolled ? "Enrolled" : "Not Enrolled", tone: m.isEnrolled ? .green : .red)
                if let t = m.displayEnrollmentType { pillRow("Enrollment Type", t, tone: t == "Domain Joined" ? .yellow : .green) }
                if let auth = m.deviceAuthStatus { pillRow("Device Authentication", auth == "SUCCESS" ? "Success" : auth, tone: auth == "SUCCESS" ? .green : .red) }

                if m.isEnrolled, !m.isMac, !m.autopilot.isNull {
                    let ap = m.autopilot
                    sectionHeading("Windows Autopilot")
                    LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], alignment: .leading, spacing: 8) {
                        if ap["assigned"].boolishIfPresent != nil { yesNo("Assigned", ap["assigned"].boolish) }
                        if ap["enrollment_status_page_enabled"].boolishIfPresent != nil { yesNo("Enrollment Status Page", ap["enrollment_status_page_enabled"].boolish) }
                        if ap["activated"].boolishIfPresent != nil { yesNo("Activated", ap["activated"].boolish) }
                        if let phase = ap["deployment_phase"].nonEmptyString { pillRow("Phase", phase, tone: phase == "Completed" ? .green : .yellow, small: true) }
                    }
                    VStack(alignment: .leading, spacing: 6) {
                        if let v = ap["profile_name"].nonEmptyString { labeled("Profile", v) }
                        if let v = ap["group_tag"].nonEmptyString { labeled("Group Tag", v) }
                        if let v = ap["tenant_domain"].nonEmptyString { labeled("Tenant", v) }
                        if let v = ap["tenant_id"].nonEmptyString { labeled("Tenant ID", v, mono: true, copy: true) }
                        if let v = ap["deployment_mode"].nonEmptyString { labeled("Mode", v) }
                        if let v = ap["join_method"].nonEmptyString { labeled("Join Method", v) }
                    }
                    .padding(.top, 4)
                }

                if m.isEnrolled, m.hasDeviceDetails {
                    sectionHeading("Device Details")
                    VStack(alignment: .leading, spacing: 8) {
                        if let v = m.managementName { labeled("Management Name", v) }
                        if m.showPrimaryUser, let p = m.primaryUser { labeled("Primary User", ManagementDetail.stripTenantSuffix(p) ?? p, mono: true, copy: true) }
                        if let v = m.enrolledBy { labeled("Enrolled By", ManagementDetail.stripTenantSuffix(v) ?? v, mono: true, copy: true) }
                        if let v = m.intuneDeviceId { labeled("Intune ID", v, mono: true, copy: true) }
                        if let v = m.entraObjectId { labeled("Object ID", v, mono: true, copy: true) }
                        if let v = m.lastSync { labeled("Last Sync", TimeFormatting.shortDate(v)) }
                    }
                }

                if m.isEnrolled, m.isMac {
                    sectionHeading("Enrollment Details")
                    LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], alignment: .leading, spacing: 8) {
                        yesNo("ADE Enrolled", mdm["installed_from_dep"].boolish || mdm["installedFromDep"].boolish)
                        yesNo("User Approved", mdm["user_approved"].boolish || mdm["userApproved"].boolish)
                        yesNo("ADE Capable", mdm["dep_capable"].boolish || mdm["depCapable"].boolish)
                        pillRow("Identity Certificate", m.enrollmentMethod ?? "Unknown", tone: m.enrollmentMethod == nil ? .gray : .green, small: true)
                    }
                    if let v = m.deviceIdentifiers["uuid"].nonEmptyString { CodeRow(label: "UUID", value: v) }
                    if let url = m.serverUrl { CodeRow(label: "Server URL", value: url) }
                    if let checkin = mdm.firstString("checkin_url", "checkinUrl") { CodeRow(label: "Check-in URL", value: checkin) }
                }


                if m.isEnrolled, m.isMac, let topic = m.certificate.pushTopic {
                    sectionHeading("Push Notification")
                    CodeRow(label: "APNs Push Topic", value: topic)
                }

                if m.isEnrolled, m.isMac, m.adeActive {
                    let ade = m.adeConfiguration
                    sectionHeading("ADE Configuration")
                    LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], alignment: .leading, spacing: 8) {
                        yesNo("Assigned", ade["assigned"].boolish)
                        yesNo("Activated", ade["activated"].boolish)
                    }
                    VStack(alignment: .leading, spacing: 6) {
                        if let v = ade["organization"].nonEmptyString { labeled("Organization", v) }
                        if let v = ade["support_phone"].nonEmptyString { labeled("Support Phone", v) }
                        if let v = ade["support_email"].nonEmptyString { labeled("Support Email", v) }
                    }
                }

                if m.isDomainJoined, !m.domainTrust.isNull {
                    let t = m.domainTrust
                    sectionHeading("Domain Trust Status")
                    VStack(alignment: .leading, spacing: 8) {
                        let valid = t.first("secure_channel_valid", "secureChannelValid").boolishIfPresent
                        pillRow("Secure Channel", valid == true ? "Valid" : valid == false ? "Invalid" : "Unknown", tone: valid == true ? .green : valid == false ? .red : .gray, small: true)
                        if let v = t.firstString("domain_name", "domainName") { labeled("Domain", v) }
                        if let v = t.firstString("domain_controller", "domainController") { labeled("Domain Controller", v, mono: true) }
                        if let v = t.firstString("trust_status", "trustStatus") { pillRow("Trust Status", v, tone: ["Healthy", "Success", "Trusted"].contains(v) ? .green : .red, small: true) }
                        if let age = t.first("machine_password_age_days", "machinePasswordAgeDays").int {
                            HStack(spacing: 12) {
                                Text("Password Age").appFont(.caption, weight: .medium).foregroundStyle(.secondary).frame(width: 110, alignment: .leading)
                                Text("\(age) days").appFont(.caption, weight: .medium).foregroundStyle(age > 30 ? .yellow : .primary)
                            }
                        }
                        if let v = t.firstString("last_checked", "lastChecked") { labeled("Last Checked", TimeFormatting.shortDate(v)) }
                        if let err = t.firstString("error_message", "errorMessage") {
                            Label(err, systemImage: "xmark.circle.fill").appFont(.caption).foregroundStyle(.red)
                                .padding(8).frame(maxWidth: .infinity, alignment: .leading)
                                .background(Color.red.opacity(0.08), in: RoundedRectangle(cornerRadius: 6))
                        }
                    }
                }

                if let url = m.management["mdmEnrollment"]["managementUrl"].nonEmptyString {
                    Divider().padding(.vertical, 12)
                    CodeRow(label: "Management URL", value: url)
                }
            }
            .padding(20)
        }
    }

    // MARK: Certificate card

    private func certLabel(_ text: String) -> some View { Text(text.uppercased()).appFont(.caption2, weight: .medium).foregroundStyle(.secondary).kerning(0.5) }

    private func certificateCard(_ m: ManagementDetail) -> some View {
        Card {
            VStack(alignment: .leading, spacing: 0) {
                if m.isMac {
                    certificateBox(subtitle: "Device authentication") {
                        let c = m.certificate
                        if let n = c.name { certField("Identity") { Text(n).appFont(.callout, weight: .medium) } }
                        if let i = c.issuer { certField("Issued By") { Text(i).appFont(.callout, weight: .medium).foregroundStyle(.yellow) } }
                        if let e = c.expires {
                            certField("Valid Until") { Text(TimeFormatting.shortDate(e)).appFont(.callout, weight: .medium).foregroundStyle(expiryColor(FlexibleDate.parse(e))) }
                        }
                        if let org = m.adeConfiguration["organization"].nonEmptyString { certField("Organization") { Text(org).appFont(.callout, weight: .medium) } }
                        if let scep = c.scepUrl {
                            certField(m.enrollmentUrlLabel) {
                                HStack(spacing: 6) { Text(scep).appFont(.caption2, design: .monospaced).textSelection(.enabled); CopyButton(value: scep) }
                            }
                        }
                        if !c.hasDetails { Text("Certificate details not available").appFont(.callout).foregroundStyle(.secondary).padding(.vertical, 4) }
                    }
                    Divider().padding(.vertical, 12)
                    countRow("Configuration Profiles", m.profileCount)
                } else if let tenant = m.tenantName {
                    let dd = m.deviceDetails
                    certificateBox(subtitle: "Entra ID authentication credential") {
                        certField("Organization") { Text(tenant).appFont(.callout, weight: .medium) }
                        if let validity = dd.firstString("device_certificate_validity", "deviceCertificateValidity") {
                            let end = ManagementDetail.validityEnd(validity)
                            certField("Valid Until") { Text(end.map { TimeFormatting.shortDate($0) } ?? "Unknown").appFont(.callout, weight: .medium).foregroundStyle(expiryColor(end)) }
                        }
                        if let t = dd.firstString("thumbprint", "Thumbprint") { certField("Thumbprint") { HStack(spacing: 6) { Text(t).appFont(.caption2, design: .monospaced); CopyButton(value: t) } } }
                        if let k = dd.firstString("key_container_id", "keyContainerId") { certField("Key Container ID") { HStack(spacing: 6) { Text(k).appFont(.caption2, design: .monospaced); CopyButton(value: k) } } }
                        if let p = dd.firstString("key_provider", "keyProvider") { certField("Key Provider") { Text(p).appFont(.callout, weight: .medium).foregroundStyle(.yellow) } }
                        if let tpm = dd.first("tmp_protected", "tpmProtected").boolishIfPresent {
                            HStack(spacing: 10) { certLabel("TPM Protected"); Pill(tpm ? "Yes" : "No", tone: tpm ? .green : .yellow) }
                        }
                    }
                    Divider().padding(.vertical, 12)
                    VStack(spacing: 8) {
                        countRow("Configuration Profiles", m.profileCount)
                        if m.compliancePolicyCount > 0 { countRow("Compliance Policies", m.compliancePolicyCount) }
                        if m.managedAppCount > 0 { countRow("Managed Apps", m.managedAppCount) }
                    }
                } else {
                    Text("Management Resources").appFont(.title3, weight: .bold).padding(.bottom, 16)
                    VStack(alignment: .leading, spacing: 16) {
                        resource(m.profileCount, "Configuration Profiles", "MDM policy areas applied", tone: .blue)
                        resource(m.compliancePolicyCount, "Compliance Policies", "Security & health requirements", tone: .green)
                        resource(m.managedAppCount, "Managed Apps", "Apps deployed via MDM", tone: .orange)
                    }
                    Divider().padding(.vertical, 16)
                    HStack {
                        Text(m.compliancePolicyCount > 0 ? "Compliance Policies" : "Compliance").appFont(.callout, weight: .medium)
                        Spacer()
                        Pill(m.compliancePolicyCount > 0 ? "\(m.compliancePolicyCount) applied" : "No policies applied", tone: m.compliancePolicyCount > 0 ? .green : .yellow)
                    }
                }
            }
            .padding(20)
        }
    }

    private func certificateBox<Content: View>(subtitle: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "seal").foregroundStyle(.yellow).font(.system(size: 34, weight: .light))
                VStack(alignment: .leading, spacing: 2) {
                    Text("Certificate").appFont(.headline)
                    Text(subtitle).appFont(.caption).foregroundStyle(.secondary)
                }
            }
            content()
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(LinearGradient(colors: [Color.yellow.opacity(0.05), Color.yellow.opacity(0.12)], startPoint: .top, endPoint: .bottom), in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.yellow.opacity(0.3)))
    }

    private func certField<Content: View>(_ label: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 3) { certLabel(label); content() }
    }

    private func expiryColor(_ date: Date?) -> Color {
        switch ManagementDetail.expiryTone(date) {
        case .expired: return .red
        case .soon: return .yellow
        case .fine: return .green
        case .unknown: return .primary
        }
    }

    private func countRow(_ label: String, _ count: Int) -> some View {
        HStack {
            Text(label).appFont(.callout, weight: .medium).foregroundStyle(.secondary)
            Spacer()
            Text("\(count)").appFont(.title2, weight: .bold)
        }
    }

    private func resource(_ count: Int, _ label: String, _ hint: String, tone: Tone) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("\(count)").appFont(.title2, weight: .bold).foregroundStyle(tone.color)
            Text(label).appFont(.callout, weight: .medium).foregroundStyle(.secondary)
            Text(hint).appFont(.caption2).foregroundStyle(.tertiary)
        }
    }

    // MARK: Profiles

    private func profilesSection(_ m: ManagementDetail) -> some View {
        let q = profileSearch.trimmingCharacters(in: .whitespaces).lowercased()
        let filtered = q.isEmpty ? m.profiles : m.profiles.filter { $0.matches(q) }
        let userScoped = m.userScopedProfileCount
        var subtitle = "Management profiles applied to this device (\(filtered.count) of \(m.profiles.count) profiles"
        if userScoped > 0 { subtitle += ", \(m.profiles.count - userScoped) system level, \(userScoped) user level" }
        subtitle += ")"
        return Card {
            VStack(spacing: 0) {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Configuration Profiles").appFont(.title3, weight: .semibold)
                        Text(subtitle).appFont(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    TextField("Search profiles...", text: $profileSearch).textFieldStyle(.roundedBorder).frame(width: 240)
                }
                .padding(16)
                Divider()
                if filtered.isEmpty {
                    Text("No profiles match “\(profileSearch.trimmingCharacters(in: .whitespaces))”.").appFont(.callout).foregroundStyle(.secondary).padding(24)
                }
                ForEach(filtered) { p in
                    profileRow(p)
                    Divider()
                }
            }
        }
    }

    private func profileRow(_ p: ManagementDetail.Profile) -> some View {
        let open = expandedProfiles.contains(p.id)
        return VStack(spacing: 0) {
            Button {
                if open { expandedProfiles.remove(p.id) } else { expandedProfiles.insert(p.id) }
            } label: {
                HStack(spacing: 12) {
                    Image(systemName: "chevron.right").rotationEffect(.degrees(open ? 90 : 0)).foregroundStyle(.secondary).appFont(.caption)
                    ZStack {
                        RoundedRectangle(cornerRadius: 8).fill(Color.subtleBackground)
                        Image(systemName: "doc.text").foregroundStyle(.secondary)
                    }
                    .frame(width: 36, height: 36)
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            Text(p.name).appFont(.callout, weight: .medium).lineLimit(1)
                            if p.isRemovalDisallowed { Image(systemName: "lock.fill").foregroundStyle(.yellow).appFont(.caption2) }
                            if p.isVerified { Pill("Verified", tone: .green).help("Profile signature verified by the system") }
                        }
                        Text(p.organization ?? "Unknown Organization").appFont(.caption).foregroundStyle(.secondary).lineLimit(1)
                    }
                    Spacer()
                    HStack(spacing: 10) {
                        if p.payloadCount > 0 { Text("\(p.payloadCount) payload\(p.payloadCount == 1 ? "" : "s")").appFont(.caption).foregroundStyle(.secondary) }
                        Text(p.scope).appFont(.caption).foregroundStyle(.secondary)
                        if p.isLegacyMCX { Pill("Legacy MCX", tone: .orange).help("Emulated via MCX (Managed Client for X) - legacy method") }
                    }
                }
                .padding(.horizontal, 16).padding(.vertical, 10)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            if open {
                VStack(alignment: .leading, spacing: 12) {
                    HStack(alignment: .top, spacing: 24) {
                        VStack(alignment: .leading, spacing: 3) {
                            SectionLabel("Identifier")
                            HStack(spacing: 4) { Text(p.identifier).appFont(.caption2, design: .monospaced).textSelection(.enabled); CopyButton(value: p.identifier) }
                        }
                        if let uuid = p.uuid {
                            VStack(alignment: .leading, spacing: 3) {
                                SectionLabel("UUID")
                                HStack(spacing: 4) { Text(uuid).appFont(.caption2, design: .monospaced).textSelection(.enabled); CopyButton(value: uuid) }
                            }
                        }
                        if let d = p.installDateText {
                            VStack(alignment: .leading, spacing: 3) { SectionLabel("Installed"); Text(d).appFont(.caption2, design: .monospaced) }
                        }
                    }
                    if let desc = p.description {
                        VStack(alignment: .leading, spacing: 3) { SectionLabel("Description"); Text(desc).appFont(.callout) }
                            .padding(10).frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 8))
                    }
                    if !p.payloads.isEmpty {
                        SectionLabel("Payloads")
                        ForEach(p.payloads) { payload in payloadCard(payload) }
                    }
                }
                .padding(16)
                .background(Color.subtleBackground.opacity(0.6))
            }
        }
    }

    private func payloadCard(_ payload: ManagementDetail.Payload) -> some View {
        Card {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text(payload.displayName ?? payload.type ?? "Unknown Payload").appFont(.callout, weight: .medium)
                    Spacer()
                    if let t = payload.type { Text(t).appFont(.caption2, design: .monospaced).foregroundStyle(.secondary) }
                }
                if !payload.settings.isEmpty {
                    Divider()
                    ForEach(Array(payload.settings.enumerated()), id: \.offset) { _, entry in
                        HStack(alignment: .top, spacing: 12) {
                            Text(entry.key).appFont(.caption2, weight: .medium).foregroundStyle(.secondary).frame(width: 200, alignment: .leading).lineLimit(1).help(entry.key)
                            settingValue(entry.value)
                        }
                    }
                } else if let raw = payload.rawData {
                    DisclosureGroup("View Raw Data") {
                        Text(raw).appFont(.caption2, design: .monospaced).textSelection(.enabled)
                            .padding(8).frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 6))
                    }
                    .appFont(.caption)
                }
            }
            .padding(12)
        }
    }

    @ViewBuilder
    private func settingValue(_ v: JSONValue) -> some View {
        if let b = v.bool {
            Pill(b ? "Yes" : "No", tone: b ? .green : .gray)
        } else if v.object != nil || v.array != nil {
            Text(v.prettyPrinted).appFont(.caption2, design: .monospaced).textSelection(.enabled)
        } else {
            Text(v.string ?? "").appFont(.caption2).textSelection(.enabled)
        }
    }

    // MARK: Managed preferences

    private func policiesSection(_ m: ManagementDetail) -> some View {
        let q = policySearch.trimmingCharacters(in: .whitespaces).lowercased()
        let filtered = q.isEmpty ? m.managedPolicies : m.managedPolicies.filter { $0.matches(q) }
        return Card {
            VStack(spacing: 0) {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Managed Preferences").appFont(.title3, weight: .semibold)
                        Text("Managed settings from /Library/Managed Preferences/ (\(filtered.count) of \(m.managedPolicies.count) domains)").appFont(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    TextField("Search preferences...", text: $policySearch).textFieldStyle(.roundedBorder).frame(width: 240)
                }
                .padding(16)
                Divider()
                if filtered.isEmpty {
                    Text("No preferences match “\(policySearch.trimmingCharacters(in: .whitespaces))”.").appFont(.callout).foregroundStyle(.secondary).padding(24)
                }
                ForEach(filtered) { pol in
                    let open = expandedPolicies.contains(pol.id)
                    Button {
                        if open { expandedPolicies.remove(pol.id) } else { expandedPolicies.insert(pol.id) }
                    } label: {
                        HStack(spacing: 10) {
                            Image(systemName: "chevron.right").rotationEffect(.degrees(open ? 90 : 0)).foregroundStyle(.secondary).appFont(.caption2)
                            ZStack {
                                RoundedRectangle(cornerRadius: 6).fill(Color.subtleBackground)
                                Image(systemName: "gearshape").foregroundStyle(.secondary).appFont(.caption)
                            }
                            .frame(width: 28, height: 28)
                            Text(pol.domain).appFont(.callout, weight: .medium, design: .monospaced).lineLimit(1)
                            Spacer()
                            Text("\(pol.settingCount) setting\(pol.settingCount == 1 ? "" : "s")").appFont(.caption).foregroundStyle(.secondary)
                        }
                        .padding(.horizontal, 16).padding(.vertical, 8)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    if open, !pol.settings.isEmpty {
                        VStack(spacing: 0) {
                            HStack(spacing: 12) {
                                Text("KEY").frame(width: 260, alignment: .leading)
                                Text("VALUE").frame(maxWidth: .infinity, alignment: .leading)
                            }
                            .appFont(.caption2, weight: .semibold).foregroundStyle(.secondary).padding(.bottom, 4)
                            ForEach(Array(pol.settings.enumerated()), id: \.offset) { _, s in
                                HStack(alignment: .top, spacing: 12) {
                                    Text(s.name).appFont(.caption2, design: .monospaced).foregroundStyle(.secondary).frame(width: 260, alignment: .leading).lineLimit(1).help(s.name)
                                    Group {
                                        if s.value == "1" || s.value == "true" { Pill("Yes", tone: .green) }
                                        else if s.value == "0" || s.value == "false" { Pill("No", tone: .gray) }
                                        else { Text(s.value).appFont(.caption2, design: .monospaced).textSelection(.enabled) }
                                    }
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                }
                                .padding(.vertical, 3)
                                Divider()
                            }
                        }
                        .padding(.horizontal, 16).padding(.vertical, 10)
                        .background(Color.subtleBackground.opacity(0.6))
                    }
                    Divider()
                }
            }
        }
    }
}

// MARK: - Logs

/// Management-tool logs: one tab per root, a log picker and a viewer that
/// shows every text log as event rows (JSONL by record, structured lines by
/// their parsers), `.json` tails as a tree, with level filters and tag pills.
/// Port of `ManagementLogsSection.tsx`.
struct ManagementLogsSection: View {
    @Environment(AppState.self) private var appState
    let serialNumber: String
    let logs: LogsInfo
    /// The installs module: a root's version falls back to its tool's installed version here.
    var installs: JSONValue = .null

    enum TailState { case loading, loaded(LogsInfo.Root), error(String) }

    @State private var activeTool: String? = nil
    @State private var tails: [String: TailState] = [:]
    @State private var selectedFile: [String: String] = [:]
    @State private var filter = ""
    @State private var levelFilter = LogsInfo.LevelFilter()
    @State private var copied = false
    @State private var retryNonce = 0

    var body: some View {
        let roots = logs.roots
        Card {
            VStack(alignment: .leading, spacing: 0) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Management Tools Logs").appFont(.title3, weight: .semibold)
                    Text(summaryLine(roots)).appFont(.callout).foregroundStyle(.secondary)
                }
                .padding(.horizontal, 16).padding(.vertical, 12)
                Divider()
                if roots.count > 1 {
                    HStack(spacing: 8) {
                        ForEach(roots) { root in
                            let active = root.tool == activeTool
                            Button { selectTool(root.tool) } label: {
                                Text(root.productName(platform: logs.platform))
                                    .appFont(.callout, weight: .medium)
                                    .lineLimit(1)
                                    .frame(maxWidth: .infinity)
                                    .frame(height: 30)
                                    .background(active ? Color.primary : Color.clear, in: RoundedRectangle(cornerRadius: 6))
                                    .overlay(RoundedRectangle(cornerRadius: 6).stroke(active ? Color.clear : Color.cardBorder))
                                    .foregroundStyle(active ? Color(nsColor: .windowBackgroundColor) : Color.primary)
                                    .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    .padding(.horizontal, 16).padding(.top, 12)
                }
                if let root = roots.first(where: { $0.tool == activeTool }) { rootDetail(root) }
            }
        }
        .onAppear { if activeTool == nil { activeTool = roots.first?.tool } }
        .onChange(of: serialNumber) { tails = [:]; activeTool = roots.first?.tool }
        .task(id: "\(activeTool ?? "")-\(retryNonce)") { await loadIfNeeded() }
    }

    private func summaryLine(_ roots: [LogsInfo.Root]) -> String {
        var parts = ["\(roots.count) \(roots.count == 1 ? "tool" : "tools")", "\(logs.totalFiles) files"]
        if logs.totalBytes > 0 { parts.append(LogsInfo.formatBytes(logs.totalBytes)) }
        if let at = logs.collectedAt { parts.append("collected \(TimeFormatting.exact(at))") }
        return "Logs collected from the management tools on this device (\(parts.joined(separator: ", ")))"
    }

    private func selectTool(_ tool: String) {
        activeTool = tool
        filter = ""
        levelFilter = LogsInfo.LevelFilter()
        if case .error = tails[tool] { retryNonce += 1 }
    }

    private func loadIfNeeded() async {
        guard let tool = activeTool else { return }
        if let existing = tails[tool] {
            if case .error = existing {} else { return }
        }
        // The runner's own survey (This Mac, or a full module payload) already
        // carries the tails; only the API's slimmed device record needs a fetch.
        if let root = logs.roots.first(where: { $0.tool == tool }), !root.tails.isEmpty {
            tails[tool] = .loaded(root)
            return
        }
        let api = appState.api
        tails[tool] = .loading
        do {
            let json = try await api.deviceLogRoot(serialNumber, tool: tool)
            guard let root = LogsInfo.Root(json: json) else { throw LogLoadError() }
            tails[tool] = .loaded(root)
        } catch {
            tails[tool] = .error(error.localizedDescription)
        }
    }

    private func rootDetail(_ root: LogsInfo.Root) -> some View {
        let state = tails[root.tool]
        let loaded: LogsInfo.Root? = { if case .loaded(let r) = state { return r }; return nil }()
        let available = loaded?.tails.filter { $0.file != nil } ?? []
        let currentFile = selectedFile[root.tool].flatMap { f in available.contains { $0.file == f } ? f : nil } ?? available.first?.file
        let currentTail = available.first { $0.file == currentFile }
        let lines = LogsInfo.stitchCmTrace(currentTail?.lines ?? [])
        let needle = filter.trimmingCharacters(in: .whitespaces).lowercased()
        let isJson = (currentFile ?? "").lowercased().hasSuffix(".json")
        let classified = LogsInfo.classify(lines: lines, file: currentFile)
        let counts = LogsInfo.levelCounts(classified)
        let visible = classified.filter { levelFilter.passes($0.level) && (needle.isEmpty || $0.line.lowercased().contains(needle)) }
        let filtering = !needle.isEmpty || levelFilter.isActive
        let uniform = LogsInfo.uniformComponent(classified)
        let document: JSONValue? = isJson && !lines.isEmpty ? JSONValue.parse(lines.joined(separator: "\n")) : nil
        let withoutTails = root.files.filter { f in !available.contains { $0.file == f.path } }
        let version = root.version ?? LogsInfo.installedVersion(for: root.tool, platform: logs.platform, installs: installs)

        return VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .top, spacing: 28) {
                VStack(alignment: .leading, spacing: 3) {
                    SectionLabel("Path")
                    HStack(spacing: 6) {
                        Text(root.path).appFont(.caption2, design: .monospaced).padding(.horizontal, 6).padding(.vertical, 3).background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 4)).textSelection(.enabled)
                        CopyButton(value: root.path)
                    }
                }
                VStack(alignment: .leading, spacing: 3) {
                    SectionLabel("Files")
                    HStack(spacing: 4) {
                        Text("\(root.fileCount ?? root.files.count)").appFont(.callout)
                        if let b = root.totalBytes { Text("· \(LogsInfo.formatBytes(b))").appFont(.callout).foregroundStyle(.secondary) }
                    }
                }
                VStack(alignment: .leading, spacing: 3) {
                    SectionLabel("Last written")
                    Text(root.newestModified.map { TimeFormatting.exact($0) } ?? "Unknown").appFont(.callout)
                }
                if let session = root.latestSession {
                    VStack(alignment: .leading, spacing: 3) {
                        SectionLabel("Latest run")
                        HStack(spacing: 10) {
                            Pill(session.status ?? "unknown", tone: sessionTone(session.tone))
                            if let id = session.sessionId { Text(id).appFont(.caption, design: .monospaced) }
                            if let t = session.runType { Text(t).appFont(.caption).foregroundStyle(.secondary) }
                            if let d = session.durationSeconds { Text(LogsInfo.formatDuration(d)).appFont(.caption).foregroundStyle(.secondary) }
                            if let e = session.errors, e > 0 { Text("\(e) errors").appFont(.caption).foregroundStyle(.red) }
                            if let w = session.warnings, w > 0 { Text("\(w) warnings").appFont(.caption).foregroundStyle(.orange) }
                        }
                    }
                }
                Spacer()
                if let version {
                    VStack(alignment: .trailing, spacing: 3) {
                        SectionLabel("Version")
                        Text(version).appFont(.callout, design: .monospaced)
                    }
                }
            }
            HStack(alignment: .top, spacing: 12) {
                // Picker: fills the column and scrolls inside.
                VStack(alignment: .leading, spacing: 0) {
                    Text("LOGS").appFont(.caption2, weight: .semibold).foregroundStyle(.secondary).padding(.horizontal, 10).padding(.vertical, 6).frame(maxWidth: .infinity, alignment: .leading).background(Color.subtleBackground)
                    Divider()
                    ScrollView {
                        VStack(alignment: .leading, spacing: 0) {
                            if let loaded {
                                ForEach(loaded.tails) { tail in
                                    let entry = root.files.first { $0.path == tail.file }
                                    let current = tail.file == currentFile
                                    let flags = LogsInfo.fileFlags(tail)
                                    Button { if let f = tail.file { selectFile(root.tool, f) } } label: {
                                        VStack(alignment: .leading, spacing: 2) {
                                            HStack(alignment: .top, spacing: 6) {
                                                Text(tail.file ?? "").appFont(.caption2, design: .monospaced)
                                                if flags.errors { Circle().fill(Color.red).frame(width: 6, height: 6).padding(.top, 4).help("Errors in this log") }
                                                if flags.warnings { Circle().fill(Color.orange).frame(width: 6, height: 6).padding(.top, 4).help("Warnings in this log") }
                                            }
                                            Text([entry.map { LogsInfo.formatBytes($0.bytes) }, entry?.modified.map { TimeFormatting.exact($0) }].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " · ")).appFont(.caption2).foregroundStyle(.secondary)
                                        }
                                        .padding(.horizontal, 10).padding(.vertical, 6)
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                        .background(current ? Color.subtleBackground : Color.clear)
                                        .contentShape(Rectangle())
                                    }
                                    .buttonStyle(.plain)
                                    Divider()
                                }
                            } else if case .error(let msg) = state {
                                Text("Failed to load: \(msg)").appFont(.caption2).foregroundStyle(.secondary).padding(10)
                            } else {
                                Text("Loading...").appFont(.caption2).foregroundStyle(.secondary).padding(10)
                            }
                            if !withoutTails.isEmpty {
                                Text("NOT TAILED").appFont(.caption2, weight: .medium).foregroundStyle(.tertiary).padding(.horizontal, 10).padding(.vertical, 5).frame(maxWidth: .infinity, alignment: .leading).background(Color.subtleBackground.opacity(0.6))
                                ForEach(withoutTails) { f in
                                    VStack(alignment: .leading, spacing: 1) {
                                        Text(f.path).appFont(.caption2, design: .monospaced).foregroundStyle(.secondary)
                                        Text([LogsInfo.formatBytes(f.bytes), f.modified.map { TimeFormatting.exact($0) }].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " · ")).appFont(.caption2).foregroundStyle(.tertiary)
                                    }
                                    .padding(.horizontal, 10).padding(.vertical, 4)
                                    Divider()
                                }
                            }
                        }
                    }
                }
                .frame(width: 260)
                .frame(maxHeight: .infinity)
                .background(Color.cardBackground)
                .clipShape(RoundedRectangle(cornerRadius: 8))
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.cardBorder))

                VStack(alignment: .leading, spacing: 0) {
                    HStack(spacing: 10) {
                        Button {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(lines.joined(separator: "\n"), forType: .string)
                            copied = true
                            Task { try? await Task.sleep(for: .seconds(2)); copied = false }
                        } label: { Image(systemName: copied ? "checkmark" : "doc.on.doc").foregroundStyle(copied ? Color.green : Color.secondary) }
                            .buttonStyle(.bordered).disabled(lines.isEmpty).help(copied ? "Copied" : "Copy to clipboard")
                        Button { saveTail(root: root, file: currentFile, lines: lines) } label: { Image(systemName: "arrow.down.to.line") }
                            .buttonStyle(.bordered).disabled(lines.isEmpty).help("Save")
                        TextField("Filter lines", text: $filter).textFieldStyle(.roundedBorder).frame(width: 170)
                        if !isJson, !lines.isEmpty {
                            HStack(spacing: 6) {
                                levelToggle("Errors", count: counts.error, on: levelFilter.errors, tone: .red, title: levelFilter.errors ? "Showing errors" : "Show only errors") { levelFilter.errors.toggle() }
                                levelToggle("Warnings", count: counts.warning, on: levelFilter.warnings, tone: .orange, title: levelFilter.warnings ? "Showing warnings" : "Show only warnings") { levelFilter.warnings.toggle() }
                                levelToggle("Debug", count: counts.debug, on: levelFilter.debug, tone: .gray, title: levelFilter.debug ? "Hiding debug lines on next click" : "Show debug lines") { levelFilter.debug.toggle() }
                            }
                        }
                        HStack(spacing: 6) {
                            Text(currentFile ?? "").appFont(.caption2, design: .monospaced)
                            if !lines.isEmpty {
                                Text((filtering ? "\(visible.count) of \(lines.count) lines" : "last \(lines.count) lines") + ((currentTail?.truncated ?? false) ? ", truncated" : "")).appFont(.caption2)
                            }
                        }
                        .foregroundStyle(.secondary).lineLimit(1)
                        Spacer()
                    }
                    .padding(10)
                    .background(Color.subtleBackground)
                    Divider()
                    Group {
                        if state == nil || { if case .loading = state { return true }; return false }() {
                            Text("Loading log...").appFont(.callout).foregroundStyle(.secondary).padding(24).frame(maxWidth: .infinity)
                        } else if case .error(let msg) = state {
                            VStack(spacing: 10) {
                                Text("Failed to load log: \(msg)").appFont(.callout).foregroundStyle(.red)
                                Button("Retry") { retryNonce += 1 }.buttonStyle(.bordered)
                            }
                            .padding(24).frame(maxWidth: .infinity)
                        } else if lines.isEmpty {
                            Text("No log lines reported").appFont(.callout).foregroundStyle(.secondary).padding(24).frame(maxWidth: .infinity)
                        } else if let document, needle.isEmpty {
                            ScrollView {
                                LogJsonTree(value: document, name: nil, depth: 0)
                                    .appFont(.caption2, design: .monospaced)
                                    .padding(12)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                            .frame(maxHeight: 560)
                        } else if visible.isEmpty {
                            Text("No lines match the current filters").appFont(.callout).foregroundStyle(.secondary).padding(24).frame(maxWidth: .infinity)
                        } else if !isJson {
                            ScrollView {
                                LazyVStack(alignment: .leading, spacing: 0) {
                                    ForEach(visible) { entry in
                                        if let event = entry.event, event.parsed != nil {
                                            LogEventRow(event: event, hideComponent: uniform)
                                        } else {
                                            Text(entry.line.isEmpty ? " " : entry.line)
                                                .appFont(.caption2, design: .monospaced)
                                                .foregroundStyle(rawColor(entry.level))
                                                .textSelection(.enabled)
                                                .padding(.horizontal, 12).padding(.vertical, 6)
                                                .frame(maxWidth: .infinity, alignment: .leading)
                                        }
                                        Divider()
                                    }
                                }
                            }
                            .frame(maxHeight: 560)
                        } else {
                            LogPane {
                                LazyVStack(alignment: .leading, spacing: 0) {
                                    ForEach(visible) { entry in
                                        Text(entry.line.isEmpty ? " " : entry.line)
                                            .appFont(.caption2, design: .monospaced)
                                            .foregroundStyle(paneColor(entry.level))
                                            .textSelection(.enabled)
                                    }
                                }
                            }
                        }
                    }
                }
                .frame(maxWidth: .infinity)
                .background(Color.cardBackground)
                .clipShape(RoundedRectangle(cornerRadius: 8))
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.cardBorder))
            }
            .fixedSize(horizontal: false, vertical: true)
        }
        .padding(16)
    }

    private func selectFile(_ tool: String, _ file: String) {
        selectedFile[tool] = file
        filter = ""
        levelFilter = LogsInfo.LevelFilter()
    }

    private func levelToggle(_ label: String, count: Int, on: Bool, tone: Color, title: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 5) {
                Text(label).appFont(.caption2, weight: .medium)
                Text("\(count)").appFont(.caption2, design: .monospaced).foregroundStyle(on ? tone : Color.secondary)
            }
            .padding(.horizontal, 8).padding(.vertical, 5)
            .background(on ? tone.opacity(0.12) : Color.clear, in: RoundedRectangle(cornerRadius: 6))
            .overlay(RoundedRectangle(cornerRadius: 6).stroke(on ? tone.opacity(0.5) : Color.cardBorder))
            .foregroundStyle(on ? tone : Color.primary)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(count == 0)
        .opacity(count == 0 ? 0.4 : 1)
        .help(title)
    }

    private func sessionTone(_ t: LogsInfo.SessionSummary.Tone) -> Tone {
        switch t {
        case .success: return .green
        case .running: return .blue
        case .warning: return .orange
        case .failure: return .red
        case .neutral: return .gray
        }
    }

    /// Row colours for an unparsed line on the light surface.
    private func rawColor(_ level: LogsInfo.LineLevel) -> Color {
        switch level {
        case .error: return .red
        case .warning: return .orange
        case .debug: return .secondary
        case .plain: return .primary
        }
    }

    /// Line colours on the dark pane.
    private func paneColor(_ level: LogsInfo.LineLevel) -> Color {
        switch level {
        case .error: return Color(red: 1.0, green: 0.55, blue: 0.55)
        case .warning: return Color(red: 1.0, green: 0.8, blue: 0.4)
        case .debug: return Color(white: 0.55)
        case .plain: return Color(white: 0.9)
        }
    }

    private func saveTail(root: LogsInfo.Root, file: String?, lines: [String]) {
        guard let file, !lines.isEmpty else { return }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "\(serialNumber)-\(root.tool)-\(file.replacingOccurrences(of: "/", with: "_"))"
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            try? lines.joined(separator: "\n").write(to: url, atomically: true, encoding: .utf8)
        }
    }
}

/// Dark monospaced log surface.
struct LogPane<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        ScrollView([.vertical, .horizontal]) {
            content.padding(12).frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(maxHeight: 560)
        .background(Color(white: 0.12))
    }
}

/// One event row: time, level, tag pill, component, item, message; the whole
/// message and every field the line carried on expand.
struct LogEventRow: View {
    let event: LogsInfo.JsonlEvent
    var hideComponent = false
    @State private var open = false

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Button { open.toggle() } label: {
                HStack(alignment: .firstTextBaseline, spacing: 10) {
                    Text(eventTime).appFont(.caption2, design: .monospaced).foregroundStyle(.secondary).lineLimit(1)
                    if let level = event.level {
                        let tone = LogsInfo.levelTone(level)
                        Text(level.uppercased()).appFont(fixed: 10, weight: .semibold)
                            .padding(.horizontal, 5).padding(.vertical, 2)
                            .background(levelColor(tone).opacity(tone == .plain || tone == .debug ? 0.12 : 0.18), in: RoundedRectangle(cornerRadius: 4))
                            .foregroundStyle(tone == .plain ? Color.primary : levelColor(tone))
                    }
                    if let tag = event.tag {
                        let tone = tagColor(LogsInfo.tagTone(tag))
                        Text(tag).appFont(fixed: 10, weight: .medium).lineLimit(1)
                            .padding(.horizontal, 5).padding(.vertical, 2)
                            .background(tone.opacity(0.1), in: RoundedRectangle(cornerRadius: 4))
                            .overlay(RoundedRectangle(cornerRadius: 4).stroke(tone.opacity(0.4)))
                            .foregroundStyle(tone == Color.secondary ? Color.primary : tone)
                    }
                    if let t = event.eventType, !hideComponent { Text(t.replacingOccurrences(of: "_", with: " ")).appFont(.caption2).foregroundStyle(.secondary).lineLimit(1) }
                    if let item = event.item {
                        HStack(spacing: 3) {
                            Text(item).appFont(.caption2, weight: .medium)
                            if let v = event.version { Text(v).appFont(.caption2).foregroundStyle(.secondary) }
                        }
                        .lineLimit(1)
                    }
                    if let m = event.message { Text(m).appFont(.caption2).lineLimit(1).truncationMode(.tail) }
                    Spacer(minLength: 0)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            if open {
                if let m = event.message {
                    Text(m).appFont(.caption2).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                }
                if let parsed = event.parsed {
                    Text(parsed.prettyPrinted).appFont(.caption2, design: .monospaced).foregroundStyle(Color(white: 0.9)).textSelection(.enabled)
                        .padding(10).frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color(white: 0.12), in: RoundedRectangle(cornerRadius: 6))
                }
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 6)
    }

    private var eventTime: String {
        guard let ts = event.timestamp else { return "" }
        if let date = FlexibleDate.parse(ts) {
            return date.formatted(date: .omitted, time: .standard)
        }
        return ts
    }

    private func levelColor(_ tone: LogsInfo.LineLevel) -> Color {
        switch tone {
        case .error: return .red
        case .warning: return .orange
        case .debug: return .secondary
        case .plain: return .gray
        }
    }

    private func tagColor(_ tone: LogsInfo.TagTone) -> Color {
        switch tone {
        case .success: return .green
        case .retry: return .orange
        case .failure: return .red
        case .neutral: return .secondary
        }
    }
}

/// A .json tail (session.json, status.json) as a tree: objects and arrays
/// open by default with their size, scalars keyed and coloured by type.
/// Short lists of scalars are shown inline; long ones open in columns.
struct LogJsonTree: View {
    let value: JSONValue
    let name: String?
    let depth: Int
    @State private var open: Bool

    init(value: JSONValue, name: String?, depth: Int) {
        self.value = value
        self.name = name
        self.depth = depth
        _open = State(initialValue: depth < 2 || LogJsonTree.isScalarList(value))
    }

    static func isScalarList(_ v: JSONValue) -> Bool {
        guard let a = v.array else { return false }
        return a.allSatisfy { $0.object == nil && $0.array == nil }
    }

    var body: some View {
        switch value {
        case .null:
            row { Text("null").italic().foregroundStyle(.tertiary) }
        case .bool(let b):
            row { Text(b ? "true" : "false").foregroundStyle(b ? Color.green : Color.secondary) }
        case .number(let n):
            row { Text(n == n.rounded() && abs(n) < 1e15 ? String(Int(n)) : String(n)).foregroundStyle(Color.blue) }
        case .string(let s):
            row {
                if s.isEmpty { Text("empty").italic().foregroundStyle(.tertiary) } else { Text(s).textSelection(.enabled) }
            }
        case .array(let items):
            if items.isEmpty {
                row { Text("empty list").italic().foregroundStyle(.tertiary) }
            } else if LogJsonTree.isScalarList(value) {
                let inline = items.map { $0.string ?? $0.prettyPrinted }.joined(separator: ", ")
                if items.count <= 8, inline.count <= 120 {
                    row {
                        Text(inline).textSelection(.enabled)
                        Text("\(items.count)").foregroundStyle(.tertiary)
                    }
                } else {
                    branch(summary: "\(items.count) items") {
                        LazyVGrid(columns: [GridItem(.flexible(), alignment: .leading), GridItem(.flexible(), alignment: .leading), GridItem(.flexible(), alignment: .leading)], alignment: .leading, spacing: 2) {
                            ForEach(Array(items.enumerated()), id: \.offset) { _, item in
                                Text(item.string ?? item.prettyPrinted).textSelection(.enabled)
                            }
                        }
                    }
                }
            } else {
                branch(summary: "\(items.count) items") {
                    ForEach(Array(items.enumerated()), id: \.offset) { i, item in
                        LogJsonTree(value: item, name: String(i), depth: depth + 1)
                    }
                }
            }
        case .object(let obj):
            let entries = obj.sorted { $0.key < $1.key }
            if entries.isEmpty {
                row { Text("empty").italic().foregroundStyle(.tertiary) }
            } else if name == nil {
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(entries, id: \.key) { key, child in
                        LogJsonTree(value: child, name: key, depth: depth + 1)
                    }
                }
            } else {
                branch(summary: "\(entries.count) fields") {
                    ForEach(entries, id: \.key) { key, child in
                        LogJsonTree(value: child, name: key, depth: depth + 1)
                    }
                }
            }
        }
    }

    private func row<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            if let name { Text(name).foregroundStyle(.secondary).lineLimit(1) }
            content()
        }
        .padding(.vertical, 1)
    }

    private func branch<Content: View>(summary: String, @ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Button { open.toggle() } label: {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Image(systemName: "chevron.right").rotationEffect(.degrees(open ? 90 : 0)).foregroundStyle(.tertiary).appFont(fixed: 8)
                    if let name { Text(name).foregroundStyle(.secondary) }
                    Text(summary).foregroundStyle(.tertiary)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .padding(.vertical, 1)
            if open {
                VStack(alignment: .leading, spacing: 0) { content() }
                    .padding(.leading, 12)
                    .overlay(alignment: .leading) { Rectangle().fill(Color.cardBorder).frame(width: 1) }
                    .padding(.leading, 6)
            }
        }
    }
}

struct LogLoadError: LocalizedError {
    var errorDescription: String? { "No log data for this tool" }
}
