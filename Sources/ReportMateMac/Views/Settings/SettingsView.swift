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
        .frame(width: 820)
        .frame(minHeight: 520)
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

