import SwiftUI
import ReportMateKit

struct SettingsView: View {
    var body: some View {
        TabView {
            ConnectionSettingsView()
                .tabItem { Label("Connection", systemImage: "network") }
            AppearanceSettingsView()
                .tabItem { Label("Appearance", systemImage: "textformat.size") }
            FleetSettingsView()
                .tabItem { Label("Fleet", systemImage: "slider.horizontal.3") }
        }
        .frame(width: 560)
        .frame(minHeight: 420)
    }
}

struct ConnectionSettingsView: View {
    @Environment(AppState.self) private var appState
    @State private var draft = AppConfiguration()
    @State private var testing = false
    @State private var testResult: String?
    @State private var testFailed = false
    @State private var saveError: String?

    var body: some View {
        Form {
            Section {
                TextField("API URL", text: $draft.baseURL, prompt: Text("https://reportmate.example.com"))
                    .textContentType(.URL)
                    .autocorrectionDisabled()
                Picker("Authentication", selection: $draft.authMethod) {
                    ForEach(AuthMethod.allCases) { Text($0.displayName).tag($0) }
                }
                switch draft.authMethod {
                case .apiKey:
                    SecureField("API key", text: $draft.apiKey, prompt: Text("rm_…"))
                    Text("A per-client key from the API's admin key management, with the read scopes this app needs.")
                        .appFont(.caption).foregroundStyle(.secondary)
                case .passphrase:
                    SecureField("Passphrase", text: $draft.passphrase)
                    Text("The legacy shared client passphrase. Prefer an API key or Entra sign-in.")
                        .appFont(.caption).foregroundStyle(.secondary)
                case .entraBearer:
                    TextField("Entra audience (app id or api:// URI)", text: $draft.oidcAudience)
                        .autocorrectionDisabled()
                    Text("Tokens are minted from your local `az login` session; nothing is stored on this Mac.")
                        .appFont(.caption).foregroundStyle(.secondary)
                }
            } header: {
                Text("ReportMate API")
            }

            Section {
                HStack {
                    Button(testing ? "Testing…" : "Test Connection") { Task { await test() } }
                        .disabled(testing || !draft.isConfigured)
                    if let testResult {
                        Label(testResult, systemImage: testFailed ? "xmark.circle.fill" : "checkmark.circle.fill")
                            .foregroundStyle(testFailed ? .red : .green)
                            .appFont(.callout)
                            .lineLimit(3)
                    }
                    Spacer()
                    Button("Save") { save() }
                        .keyboardShortcut(.defaultAction)
                        .disabled(!draft.isConfigured || draft == appState.configuration)
                }
                if let saveError { Text(saveError).foregroundStyle(.red).appFont(.caption) }
            }

            Section {
                LabeledContent("Stored credential", value: appState.configuration.credentialSummary)
                LabeledContent("Environment overrides") {
                    Text("REPORTMATE_URL, REPORTMATE_API_KEY, REPORTMATE_PASSPHRASE, REPORTMATE_OIDC_AUDIENCE")
                        .appFont(.caption).foregroundStyle(.secondary).multilineTextAlignment(.trailing)
                }
                Button("Forget Credentials", role: .destructive) {
                    KeychainStore().clearAll()
                    draft = AppConfiguration()
                    try? appState.update(configuration: draft)
                }
            }
        }
        .formStyle(.grouped)
        .onAppear { draft = appState.configuration }
    }

    private func test() async {
        testing = true
        testResult = nil
        defer { testing = false }
        let api = appState.preview(configuration: draft)
        do {
            let total = try await api.testConnection()
            testFailed = false
            testResult = "Connected, \(total) devices"
        } catch {
            testFailed = true
            testResult = error.localizedDescription
        }
    }

    private func save() {
        do {
            try appState.update(configuration: draft)
            saveError = nil
        } catch {
            saveError = error.localizedDescription
        }
    }
}

struct AppearanceSettingsView: View {
    @AppStorage(AppFontScale.storageKey) private var fontScale: Double = AppFontScale.default

    var body: some View {
        Form {
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

/// Fleet-wide options that mirror the web app's server-side settings.
struct FleetSettingsView: View {
    @Environment(AppState.self) private var appState
    @State private var settings: SettingsDocument = .defaults
    @State private var status: String?
    @State private var saving = false

    var body: some View {
        @Bindable var state = appState
        Form {
            Section("Listing") {
                Toggle("Include archived devices", isOn: $state.includeArchived)
                Picker("Default platform filter", selection: $state.platformFilter) {
                    Text("All").tag(PlatformFilter.all)
                    Text("macOS").tag(PlatformFilter.macOS)
                    Text("Windows").tag(PlatformFilter.windows)
                }
            }
            Section {
                TextField("Fleet name", text: Binding(get: { settings.general.fleetName ?? "" }, set: { settings.general.fleetName = $0.isEmpty ? nil : $0 }))
                ForEach($settings.inventory.fields) { $field in
                    HStack {
                        Toggle(isOn: $field.visible) { Text(field.key.rawValue).appFont(.callout, design: .monospaced) }
                            .toggleStyle(.checkbox)
                        TextField("Label", text: $field.label).frame(width: 130)
                        TextField("Source key", text: $field.sourceKey).frame(width: 130)
                        Stepper(value: $field.order, in: 0...20) { Text("\(field.order)").monospacedDigit() }
                    }
                }
            } header: {
                Text("Inventory fields (shared with the web dashboard)")
            } footer: {
                Text("Labels, visibility and order of the assignment fields shown on device pages and used as filters. Saved to the API for every client.")
                    .appFont(.caption).foregroundStyle(.secondary)
            }
            Section("Security rules") {
                if settings.security.rules.isEmpty {
                    Text("No org rules. Defaults: encryption and SIP off are red, firewall off is amber, SSH and RDP on are amber.")
                        .appFont(.caption).foregroundStyle(.secondary)
                    Button("Add starter rule (shared devices need not be encrypted)") {
                        settings.security.rules = SettingsDocument.starterSecurityRules
                    }
                } else {
                    ForEach(settings.security.rules) { rule in
                        HStack {
                            VStack(alignment: .leading) {
                                Text(rule.id).appFont(.callout, weight: .medium)
                                Text("\(rule.check) \(rule.state?.rawValue ?? "any") → \(rule.severity.rawValue)")
                                    .appFont(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button(role: .destructive) { settings.security.rules.removeAll { $0.id == rule.id } } label: { Image(systemName: "trash") }
                                .buttonStyle(.borderless)
                        }
                    }
                }
            }
            Section {
                HStack {
                    Button("Reload") { Task { await load() } }
                    Spacer()
                    if let status { Text(status).appFont(.caption).foregroundStyle(.secondary) }
                    Button(saving ? "Saving…" : "Save to API") { Task { await save() } }.disabled(saving)
                }
            }
        }
        .formStyle(.grouped)
        .task { await load() }
    }

    private func load() async {
        guard appState.isConfigured else { return }
        do {
            let response = try await appState.api.settings()
            settings = response.value
            appState.settings = response.value
            appState.settingsLoaded = true
            status = response.exists ? "Loaded from API" : "Using defaults (nothing saved yet)"
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
        } catch {
            status = error.localizedDescription
        }
    }
}
