import SwiftUI
import ReportMateKit

/// Theme and text size (the web app's General settings).
struct AppearanceSettingsView: View {
    @AppStorage(AppFontScale.storageKey) private var fontScale: Double = AppFontScale.default
    @AppStorage(AppAppearance.storageKey) private var appearance: String = AppAppearance.system.rawValue

    var body: some View {
        Form {
            Section("Theme preference") {
                Picker("Theme", selection: $appearance) {
                    ForEach(AppAppearance.allCases) { Text($0.label).tag($0.rawValue) }
                }
                .pickerStyle(.segmented)
                Text("Light, dark, or follow system").appFont(.caption).foregroundStyle(.secondary)
            }
            Section("Text size") {
                HStack {
                    Slider(value: $fontScale, in: AppFontScale.range, step: AppFontScale.step)
                    Text(AppFontScale.label(fontScale)).monospacedDigit().frame(width: 48, alignment: .trailing)
                }
                Button("Reset to 100%") { fontScale = AppFontScale.default }.disabled(fontScale == AppFontScale.default)
                Text("The quick brown fox jumps over the lazy dog.").appFont(.body)
                Text("Serial SAMPLE-SERIAL · Asset SAMPLE-TAG · Last seen 3 hours ago").appFont(.caption).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
    }
}

enum AppAppearance: String, CaseIterable, Identifiable {
    case system, light, dark
    static let storageKey = "ui.appearance"
    var id: String { rawValue }
    var label: String {
        switch self {
        case .system: return "System"
        case .light: return "Light"
        case .dark: return "Dark"
        }
    }
    var colorScheme: ColorScheme? {
        switch self {
        case .system: return nil
        case .light: return .light
        case .dark: return .dark
        }
    }
}

/// Fleet-wide options stored on the API and shared with the web dashboard.
/// Port of `ClientSettingsPage.tsx` and its editors.
struct FleetSettingsView: View {
    enum Section: String, CaseIterable, Identifiable {
        case general = "General", inventory = "Inventory Mapping", rules = "Security Rules", kiosk = "Kiosk Displays", maintenance = "Maintenance"
        var id: String { rawValue }
    }

    @Environment(AppState.self) private var appState
    @State private var section: Section = .general
    @State private var settings: SettingsDocument = .defaults
    @State private var response: SettingsResponse?
    @State private var status: String?
    @State private var saving = false
    @State private var showWizard = false

    private var isFirstTime: Bool {
        guard let response else { return false }
        return !response.exists || settings.general.onboardingCompletedAt == nil
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Picker("Section", selection: $section) { ForEach(Section.allCases) { Text($0.rawValue).tag($0) } }
                    .pickerStyle(.segmented).labelsHidden()
                Spacer()
                Button("Reload") { Task { await load() } }
            }
            .padding(.horizontal, 16).padding(.vertical, 10)
            if isFirstTime {
                HStack {
                    Image(systemName: "sparkles").foregroundStyle(.blue)
                    Text("Run the one-time setup to auto-discover your inventory fields and seed security rules.").appFont(.callout)
                    Spacer()
                    Button("Run setup") { showWizard = true }.buttonStyle(.borderedProminent)
                }
                .padding(.horizontal, 16).padding(.vertical, 8)
                .background(Color.blue.opacity(0.08))
            }
            Group {
                switch section {
                case .general: GeneralSettingsSection(settings: $settings, save: save, status: status, saving: saving)
                case .inventory: InventoryMappingEditor(settings: $settings, save: save, status: status, saving: saving)
                case .rules: SecurityRulesEditor(settings: $settings, save: save, status: status, saving: saving)
                case .kiosk: KioskSettingsEditor(settings: $settings, save: save, status: status, saving: saving)
                case .maintenance: MaintenanceSection()
                }
            }
        }
        .task { await load() }
        .sheet(isPresented: $showWizard) {
            OnboardingWizardView(settings: settings) { doc in
                settings = doc
                await save()
            }
            .environment(appState)
        }
    }

    private func load() async {
        guard appState.isConfigured else { return }
        do {
            let r = try await appState.api.settings()
            response = r
            settings = r.value
            appState.settings = r.value
            appState.settingsLoaded = true
            status = r.exists ? "Loaded from API\(r.updatedAt.map { " · updated \(TimeFormatting.relative($0))" } ?? "")" : "Using defaults (nothing saved yet)"
        } catch {
            status = error.localizedDescription
        }
    }

    private func save() async {
        saving = true
        defer { saving = false }
        do {
            _ = try await appState.api.saveSettings(settings)
            appState.settings = settings
            status = "Saved"
            await load()
        } catch {
            status = error.localizedDescription
        }
    }
}

/// Save row shared by the editors.
private struct SaveBar: View {
    let title: String
    let status: String?
    let saving: Bool
    let save: () async -> Void
    var body: some View {
        HStack {
            if let status { Text(status).appFont(.caption).foregroundStyle(.secondary).lineLimit(1) }
            Spacer()
            Button(saving ? "Saving…" : title) { Task { await save() } }.buttonStyle(.borderedProminent).disabled(saving)
        }
    }
}

struct GeneralSettingsSection: View {
    @Environment(AppState.self) private var appState
    @Binding var settings: SettingsDocument
    let save: () async -> Void
    let status: String?
    let saving: Bool

    var body: some View {
        @Bindable var state = appState
        Form {
            Section("This Mac") {
                Toggle("Include archived devices", isOn: $state.includeArchived)
                Picker("Default platform filter", selection: $state.platformFilter) {
                    Text("All").tag(PlatformFilter.all)
                    Text("macOS").tag(PlatformFilter.macOS)
                    Text("Windows").tag(PlatformFilter.windows)
                }
            }
            Section {
                TextField("Fleet name", text: Binding(get: { settings.general.fleetName ?? "" }, set: { settings.general.fleetName = $0.isEmpty ? nil : $0 }))
                Picker("Default platform filter (web)", selection: Binding(get: { settings.general.defaultPlatformFilter ?? "all" }, set: { settings.general.defaultPlatformFilter = $0 == "all" ? nil : $0 })) {
                    Text("All").tag("all"); Text("macOS").tag("macOS"); Text("Windows").tag("Windows")
                }
                if let done = settings.general.onboardingCompletedAt {
                    LabeledContent("Setup completed", value: TimeFormatting.relative(done))
                }
            } header: {
                Text("Fleet (shared with the web dashboard)")
            }
            Section { SaveBar(title: "Save to API", status: status, saving: saving, save: save) }
        }
        .formStyle(.grouped)
    }
}

/// Labels, source keys, known values, order and visibility of the inventory fields.
struct InventoryMappingEditor: View {
    @Binding var settings: SettingsDocument
    let save: () async -> Void
    let status: String?
    let saving: Bool

    private var fields: [InventoryFieldMapping] { settings.inventory.fields.sorted { $0.order < $1.order } }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("ReportMate's fields. Adjust the label, source key, order, and visibility. Known values for usage feed the security rule editor.")
                .appFont(.caption).foregroundStyle(.secondary)
            Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 6) {
                GridRow {
                    Text("").frame(width: 44)
                    header("Field"); header("Source key"); header("Label"); header("Known values"); header("Visible")
                }
                ForEach(Array(fields.enumerated()), id: \.element.id) { index, field in
                    GridRow {
                        HStack(spacing: 2) {
                            Button { move(field.key, -1) } label: { Image(systemName: "chevron.up") }.buttonStyle(.borderless).disabled(index == 0)
                            Button { move(field.key, 1) } label: { Image(systemName: "chevron.down") }.buttonStyle(.borderless).disabled(index == fields.count - 1)
                        }
                        .frame(width: 44)
                        Text(field.key.rawValue).appFont(.callout, design: .monospaced)
                        TextField("source", text: binding(field.key, \.sourceKey)).textFieldStyle(.roundedBorder).frame(width: 120)
                        TextField("label", text: binding(field.key, \.label)).textFieldStyle(.roundedBorder).frame(width: 120)
                        TextField("e.g. Assigned, Shared, Lab", text: Binding(
                            get: { field.knownValues.joined(separator: ", ") },
                            set: { text in update(field.key) { $0.knownValues = text.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty } } }))
                            .textFieldStyle(.roundedBorder).frame(minWidth: 180)
                        Toggle("", isOn: binding(field.key, \.visible)).toggleStyle(.checkbox).labelsHidden()
                    }
                }
            }
            Spacer()
            SaveBar(title: "Save Mapping", status: status, saving: saving, save: save)
        }
        .padding(16)
    }

    private func header(_ t: String) -> some View { Text(t.uppercased()).appFont(.caption2, weight: .semibold).foregroundStyle(.secondary) }

    private func update(_ key: CanonicalInventoryKey, _ change: (inout InventoryFieldMapping) -> Void) {
        guard let i = settings.inventory.fields.firstIndex(where: { $0.key == key }) else { return }
        change(&settings.inventory.fields[i])
    }

    private func binding<V>(_ key: CanonicalInventoryKey, _ path: WritableKeyPath<InventoryFieldMapping, V>) -> Binding<V> {
        Binding(get: { settings.inventory.fields.first { $0.key == key }![keyPath: path] }, set: { v in update(key) { $0[keyPath: path] = v } })
    }

    private func move(_ key: CanonicalInventoryKey, _ dir: Int) {
        var sorted = fields
        guard let i = sorted.firstIndex(where: { $0.key == key }) else { return }
        let target = i + dir
        guard sorted.indices.contains(target) else { return }
        sorted.swapAt(i, target)
        for (n, var f) in sorted.enumerated() { f.order = n; sorted[n] = f }
        settings.inventory.fields = sorted
    }
}

/// Baseline severities per check, and the org rules that override them.
struct SecurityRulesEditor: View {
    @Binding var settings: SettingsDocument
    let save: () async -> Void
    let status: String?
    let saving: Bool

    static let checks = ["encryption", "firewall", "ssh", "rdp", "sip"]
    static let checkLabels: [String: String] = [
        "encryption": "Disk encryption (FileVault / BitLocker)", "firewall": "Firewall", "ssh": "Secure Shell (SSH / Remote Login)",
        "rdp": "Remote Desktop (RDP)", "sip": "System Integrity Protection",
    ]
    static let severities: [Severity] = [.ok, .warning, .danger, .neutral]

    private var knownUsage: [String] { settings.inventory.fields.first { $0.key == .usage }?.knownValues ?? [] }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Baseline").appFont(.headline)
                    Text("How each check is colored when no rule matches. These reproduce ReportMate's standard behavior.").appFont(.caption).foregroundStyle(.secondary)
                    Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 6) {
                        GridRow { header("Check"); header("When enabled"); header("When disabled") }
                        ForEach(Self.checks, id: \.self) { check in
                            GridRow {
                                Text(Self.checkLabels[check] ?? check).appFont(.callout)
                                severityPicker(Binding(get: { settings.security.defaults[check]?.enabledSeverity ?? .ok }, set: { setDefault(check, enabled: true, $0) }))
                                severityPicker(Binding(get: { settings.security.defaults[check]?.disabledSeverity ?? .danger }, set: { setDefault(check, enabled: false, $0) }))
                            }
                        }
                    }
                }
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text("Rules").appFont(.headline)
                        Spacer()
                        Button("+ Add rule") { addRule() }
                    }
                    Text("Override the baseline for devices matching a usage. Example: encryption disabled on Shared devices is neutral rather than red. When multiple rules match, the most specific wins (ties broken by the last rule).")
                        .appFont(.caption).foregroundStyle(.secondary)
                    if settings.security.rules.isEmpty {
                        Text("No rules yet. Devices use the baseline above.").appFont(.caption).foregroundStyle(.tertiary)
                        Button("Add starter rule (shared devices need not be encrypted)") { settings.security.rules = SettingsDocument.starterSecurityRules }
                    }
                    ForEach(settings.security.rules) { rule in ruleRow(rule) }
                }
                SaveBar(title: "Save Rules", status: status, saving: saving, save: save)
            }
            .padding(16)
        }
    }

    private func header(_ t: String) -> some View { Text(t.uppercased()).appFont(.caption2, weight: .semibold).foregroundStyle(.secondary) }

    private func severityPicker(_ binding: Binding<Severity>) -> some View {
        Picker("", selection: binding) { ForEach(Self.severities, id: \.self) { Text($0.rawValue).tag($0) } }.labelsHidden().frame(width: 110)
    }

    private func setDefault(_ check: String, enabled: Bool, _ v: Severity) {
        var d = settings.security.defaults[check] ?? SecurityCheckDefault(enabledSeverity: .ok, disabledSeverity: .danger)
        if enabled { d.enabledSeverity = v } else { d.disabledSeverity = v }
        settings.security.defaults[check] = d
    }

    private func update(_ id: String, _ change: (inout SecurityRule) -> Void) {
        guard let i = settings.security.rules.firstIndex(where: { $0.id == id }) else { return }
        change(&settings.security.rules[i])
    }

    private func addRule() {
        settings.security.rules.append(SecurityRule(id: "rule-\(Int(Date().timeIntervalSince1970))-\(settings.security.rules.count + 1)", module: "security", check: "encryption",
                                                    when: RuleCondition(inventory: ["usage": RuleOperator(in: ["Shared"])]), state: .disabled, severity: .neutral, enabled: true))
    }

    private func usageValues(_ rule: SecurityRule) -> [String] { rule.when?.inventory?["usage"]?.in ?? [] }

    private func ruleRow(_ rule: SecurityRule) -> some View {
        let usages = usageValues(rule)
        let unknown = !knownUsage.isEmpty && usages.contains { !knownUsage.contains($0) }
        return VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                Toggle("On", isOn: Binding(get: { rule.enabled ?? true }, set: { v in update(rule.id) { $0.enabled = v } })).toggleStyle(.checkbox)
                Picker("", selection: Binding(get: { rule.check }, set: { v in update(rule.id) { $0.check = v } })) {
                    ForEach(Self.checks, id: \.self) { Text($0).tag($0) }
                }
                .labelsHidden().frame(width: 110)
                Picker("", selection: Binding(get: { rule.state?.rawValue ?? "any" }, set: { v in update(rule.id) { $0.state = RuleState(rawValue: v) } })) {
                    Text("any").tag("any"); Text("enabled").tag("enabled"); Text("disabled").tag("disabled")
                }
                .labelsHidden().frame(width: 100)
                Text("usage in").appFont(.caption).foregroundStyle(.secondary)
                TextField("Shared, Lab", text: Binding(get: { usages.joined(separator: ", ") }, set: { text in
                    let values = text.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
                    update(rule.id) { $0.when = values.isEmpty ? nil : RuleCondition(inventory: ["usage": RuleOperator(in: values)]) }
                }))
                .textFieldStyle(.roundedBorder).frame(width: 160)
                Text("→").foregroundStyle(.secondary)
                severityPicker(Binding(get: { rule.severity }, set: { v in update(rule.id) { $0.severity = v } }))
                Spacer()
                Button(role: .destructive) { settings.security.rules.removeAll { $0.id == rule.id } } label: { Image(systemName: "trash") }.buttonStyle(.borderless)
            }
            if unknown {
                Text("Warning: references a usage value not seen in the fleet's known values (\(knownUsage.isEmpty ? "none discovered" : knownUsage.joined(separator: ", "))).")
                    .appFont(.caption).foregroundStyle(.orange)
            }
        }
        .padding(8)
        .background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 8))
    }
}

/// Settings for the read-only wall-display sessions.
struct KioskSettingsEditor: View {
    @Binding var settings: SettingsDocument
    let save: () async -> Void
    let status: String?
    let saving: Bool

    static let homePages: [(path: String, label: String)] = [
        ("/events", "Events"), ("/dashboard", "Dashboard"), ("/devices", "Devices"), ("/installs", "Installs"), ("/applications", "Applications"),
        ("/hardware", "Hardware"), ("/network", "Network"), ("/security", "Security"), ("/management", "Management"), ("/inventory", "Inventory"),
        ("/identity", "Identity"), ("/peripherals", "Peripherals"), ("/system", "System"),
    ]
    static let zoomSteps: [Double] = [1, 1.1, 1.25, 1.5, 1.75, 2]

    var body: some View {
        Form {
            Section {
                Picker("Home page", selection: $settings.kiosk.homePath) {
                    ForEach(Self.homePages, id: \.path) { Text($0.label).tag($0.path) }
                    if !Self.homePages.contains(where: { $0.path == settings.kiosk.homePath }) { Text(settings.kiosk.homePath).tag(settings.kiosk.homePath) }
                }
                Picker("Zoom", selection: $settings.kiosk.zoom) {
                    ForEach((Self.zoomSteps.contains(settings.kiosk.zoom) ? Self.zoomSteps : (Self.zoomSteps + [settings.kiosk.zoom]).sorted()), id: \.self) { z in
                        Text("\(Int((z * 100).rounded()))%").tag(z)
                    }
                }
                Stepper("Idle timeout: \(settings.kiosk.idleMinutes == 0 ? "never" : "\(settings.kiosk.idleMinutes) min")", value: $settings.kiosk.idleMinutes, in: 0...240)
                Picker("Theme", selection: $settings.kiosk.theme) {
                    Text("Dark").tag("dark"); Text("Light").tag("light"); Text("Follow system").tag("system")
                }
            } header: {
                Text("Kiosk displays")
            } footer: {
                Text("These apply only to kiosk sessions, the read-only sessions a wall display opens through its kiosk token. Signed-in people are not affected.")
                    .appFont(.caption).foregroundStyle(.secondary)
            }
            Section { SaveBar(title: "Save kiosk settings", status: status, saving: saving, save: save) }
        }
        .formStyle(.grouped)
    }
}

/// Manual cleanup: stale install errors, single and bulk device deletion.
struct MaintenanceSection: View {
    @Environment(AppState.self) private var appState
    @State private var clearDays = 10
    @State private var clearStatus: String?
    @State private var clearing = false
    @State private var deleteSerial = ""
    @State private var deleteStatus: String?
    @State private var deleting = false
    @State private var bulkSerials = ""
    @State private var bulkStatus: String?
    @State private var bulkFailures: [(serial: String, detail: String)] = []
    @State private var bulkRunning = false
    @State private var confirm: Confirmation?

    struct Confirmation: Identifiable {
        let id = UUID()
        let message: String
        let action: () -> Void
    }

    var body: some View {
        Form {
            Section {
                Text("Manual cleanup operations for stale data. These actions are not automated and must be triggered by an administrator.")
                    .appFont(.caption).foregroundStyle(.secondary)
            }
            Section("Clear stale installs errors and warnings") {
                Text("Clears error and warning fields from installs data for devices that have not reported within the specified number of days. This removes outdated error messages from decommissioned or offline devices that are no longer relevant.")
                    .appFont(.caption).foregroundStyle(.secondary)
                Stepper("Older than \(clearDays) days", value: $clearDays, in: 1...365)
                HStack {
                    Button(clearing ? "Clearing..." : "Clear Errors and Warnings") {
                        confirm = Confirmation(message: "This will clear all installs errors and warnings from devices that haven't reported in \(clearDays) or more days. Continue?") { Task { await clear() } }
                    }
                    .tint(.red).disabled(clearing)
                    if let clearStatus { Text(clearStatus).appFont(.caption).foregroundStyle(.secondary) }
                }
            }
            Section("Delete device by serial number") {
                Text("Permanently removes a single device along with all module data, events, and usage history. Prefer archiving for normal decommissioning. This action cannot be undone.")
                    .appFont(.caption).foregroundStyle(.secondary)
                HStack {
                    TextField("Serial number", text: $deleteSerial, prompt: Text("e.g. TESTSERIAL0001")).textFieldStyle(.roundedBorder)
                    Button(deleting ? "Deleting..." : "Delete Device") {
                        let serial = deleteSerial.trimmingCharacters(in: .whitespaces)
                        confirm = Confirmation(message: "Permanently delete device \"\(serial)\"? This removes all module data, events, and usage history. This cannot be undone.") { Task { await deleteOne(serial) } }
                    }
                    .tint(.red).disabled(deleting || deleteSerial.trimmingCharacters(in: .whitespaces).isEmpty)
                }
                if let deleteStatus { Text(deleteStatus).appFont(.caption).foregroundStyle(.secondary) }
            }
            Section("Bulk delete devices") {
                Text("Paste one serial number per line (or comma-separated). Each device is deleted independently; per-device results are reported below. Capped at 100 devices per request.")
                    .appFont(.caption).foregroundStyle(.secondary)
                TextEditor(text: $bulkSerials).appFont(.callout, design: .monospaced).frame(height: 110)
                    .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.cardBorder))
                HStack {
                    Button(bulkRunning ? "Deleting..." : "Delete All Listed Devices") {
                        let serials = bulkList
                        confirm = Confirmation(message: "Permanently delete \(serials.count) device\(serials.count == 1 ? "" : "s")? This cannot be undone.") { Task { await bulkDelete(serials) } }
                    }
                    .tint(.red).disabled(bulkRunning || bulkList.isEmpty)
                    if let bulkStatus { Text(bulkStatus).appFont(.caption).foregroundStyle(.secondary) }
                }
                ForEach(bulkFailures, id: \.serial) { f in
                    Text("\(f.serial): \(f.detail)").appFont(.caption).foregroundStyle(.red)
                }
            }
        }
        .formStyle(.grouped)
        .alert(item: $confirm) { c in
            Alert(title: Text("Are you sure?"), message: Text(c.message), primaryButton: .destructive(Text("Continue"), action: c.action), secondaryButton: .cancel())
        }
    }

    private var bulkList: [String] {
        Array(bulkSerials.split(whereSeparator: { $0 == "\n" || $0 == "," }).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }.prefix(100))
    }

    private func clear() async {
        clearing = true
        defer { clearing = false }
        do {
            let r = try await appState.api.clearInstallErrors(days: clearDays)
            let cleared = r["cleared"].int ?? 0, stale = r["totalStale"].int ?? 0
            clearStatus = "Cleared errors and warnings from \(cleared) device\(cleared == 1 ? "" : "s") (\(stale) stale device\(stale == 1 ? "" : "s") checked)"
        } catch {
            clearStatus = error.localizedDescription
        }
    }

    private func deleteOne(_ serial: String) async {
        deleting = true
        defer { deleting = false }
        do {
            try await appState.api.deleteDevice(serial)
            deleteStatus = "Deleted \(serial)."
            deleteSerial = ""
            await appState.loadDevices(force: true)
        } catch {
            deleteStatus = error.localizedDescription
        }
    }

    private func bulkDelete(_ serials: [String]) async {
        bulkRunning = true
        defer { bulkRunning = false }
        var ok = 0
        var failures: [(String, String)] = []
        for serial in serials {
            do { try await appState.api.deleteDevice(serial); ok += 1 } catch { failures.append((serial, error.localizedDescription)) }
        }
        bulkFailures = failures
        bulkStatus = "Deleted \(ok) of \(serials.count) devices (\(failures.count) failed)."
        if failures.isEmpty { bulkSerials = "" }
        await appState.loadDevices(force: true)
    }
}

/// One-time setup: discover inventory keys, map fields, seed starter rules.
struct OnboardingWizardView: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss
    let settings: SettingsDocument
    let finish: (SettingsDocument) async -> Void

    @State private var step = 0
    @State private var discovered: [DiscoveredInventoryKey]?
    @State private var discoverError: String?
    @State private var fields: [InventoryFieldMapping] = SettingsDocument.defaultInventoryFields
    @State private var seedStarter = true
    @State private var saving = false

    private static func norm(_ s: String) -> String { s.lowercased().filter { $0.isLetter || $0.isNumber } }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Set up ReportMate").appFont(.title3, weight: .semibold)
            Text("A one-time setup to map your inventory fields and seed sensible security rules.").appFont(.callout).foregroundStyle(.secondary)
            HStack(spacing: 12) {
                ForEach(Array(["Discover", "Map fields", "Security rules"].enumerated()), id: \.offset) { i, label in
                    HStack(spacing: 6) {
                        Text("\(i + 1)").appFont(.caption, weight: .bold).frame(width: 20, height: 20)
                            .background(i <= step ? Color.blue : Color.secondary.opacity(0.3), in: Circle()).foregroundStyle(.white)
                        Text(label).appFont(.callout, weight: i == step ? .semibold : .regular)
                    }
                }
            }
            Divider()
            Group {
                switch step {
                case 0: discoverStep
                case 1: mapStep
                default: rulesStep
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            Divider()
            HStack {
                Button("Cancel") { dismiss() }
                Spacer()
                if step > 0 { Button("Back") { step -= 1 } }
                if step < 2 {
                    Button("Continue") { step += 1 }.buttonStyle(.borderedProminent)
                } else {
                    Button(saving ? "Saving…" : "Finish setup") { Task { await finishSetup() } }.buttonStyle(.borderedProminent).disabled(saving)
                }
            }
        }
        .padding(20)
        .frame(width: 720, height: 520)
        .task { await discover() }
    }

    private var discoverStep: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let discoverError {
                Text("\(discoverError). You can still continue with the default mapping.").appFont(.callout).foregroundStyle(.orange)
            } else if let discovered {
                Text("Found \(discovered.count) inventory key\(discovered.count == 1 ? "" : "s") across your devices.").appFont(.callout)
                Table(discovered) {
                    TableColumn("Key") { Text($0.key).appFont(.callout, design: .monospaced) }
                    TableColumn("Devices") { Text("\($0.deviceCount)") }.width(80)
                    TableColumn("Distinct values") { Text("\($0.distinctCount)") }.width(110)
                    TableColumn("Samples") { Text($0.sampleValues.prefix(5).joined(separator: ", ")).appFont(.caption).foregroundStyle(.secondary).lineLimit(1) }
                }
            } else {
                ProgressView("Discovering inventory keys…")
            }
        }
    }

    private var mapStep: some View {
        Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 6) {
            GridRow {
                Text("FIELD").appFont(.caption2, weight: .semibold).foregroundStyle(.secondary)
                Text("SOURCE KEY").appFont(.caption2, weight: .semibold).foregroundStyle(.secondary)
                Text("VISIBLE").appFont(.caption2, weight: .semibold).foregroundStyle(.secondary)
            }
            ForEach(fields) { f in
                GridRow {
                    Text(f.label).appFont(.callout)
                    TextField("source", text: Binding(get: { f.sourceKey }, set: { v in update(f.key) { $0.sourceKey = v } })).textFieldStyle(.roundedBorder).frame(width: 200)
                    Toggle("", isOn: Binding(get: { f.visible }, set: { v in update(f.key) { $0.visible = v } })).toggleStyle(.checkbox).labelsHidden()
                }
            }
        }
    }

    private var rulesStep: some View {
        let usageValues = fields.first { $0.key == .usage }?.knownValues ?? []
        return VStack(alignment: .leading, spacing: 10) {
            Toggle(isOn: $seedStarter) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Seed the starter rule: shared and lab devices need not be encrypted").appFont(.callout)
                    if !usageValues.isEmpty { Text("Detected usage values: \(usageValues.joined(separator: ", "))").appFont(.caption).foregroundStyle(.secondary) }
                }
            }
            Text("You can refine the baseline severities and add rules later under Security Rules.").appFont(.caption).foregroundStyle(.secondary)
        }
    }

    private func update(_ key: CanonicalInventoryKey, _ change: (inout InventoryFieldMapping) -> Void) {
        guard let i = fields.firstIndex(where: { $0.key == key }) else { return }
        change(&fields[i])
    }

    private func discover() async {
        do {
            let keys = try await appState.api.discoverInventoryKeys()
            discovered = keys
            fields = SettingsDocument.defaultInventoryFields.map { f in
                guard let match = keys.first(where: { Self.norm($0.key) == Self.norm(f.sourceKey) || Self.norm($0.key) == Self.norm(f.key.rawValue) }) else { return f }
                var out = f
                out.sourceKey = match.key
                if f.key == .usage { out.knownValues = match.sampleValues }
                return out
            }
        } catch {
            discoverError = error.localizedDescription
        }
    }

    private func finishSetup() async {
        saving = true
        var doc = settings
        doc.schemaVersion = SettingsDocument.currentSchemaVersion
        doc.general.onboardingCompletedAt = ISO8601DateFormatter().string(from: Date())
        doc.inventory = .init(fields: fields.enumerated().map { i, f in var c = f; c.order = i; return c })
        doc.security.defaults = SettingsDocument.defaultSecurityConfig.defaults.merging(doc.security.defaults) { _, stored in stored }
        if seedStarter { doc.security.rules = SettingsDocument.starterSecurityRules }
        await finish(doc)
        saving = false
        dismiss()
    }
}
