import SwiftUI

struct SettingsView: View {

    @State private var viewModel = SettingsViewModel()

    var body: some View {
        Form {
            connectionSection
            collectionSection
            osquerySection
            enabledModulesSection
        }
        .formStyle(.grouped)
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                HStack(spacing: 12) {
                    if let message = viewModel.saveMessage {
                        Text(message)
                            .font(.caption)
                            .foregroundStyle(message.contains("success") ? .green : .red)
                    }
                    Button("Save") {
                        viewModel.save()
                    }
                    .disabled(!viewModel.hasChanges || viewModel.isSaving)
                }
            }
        }
        .overlay {
            if viewModel.isSaving {
                Color.black.opacity(0.1)
                ProgressView("Saving…")
                    .padding()
                    .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
            }
        }
    }

    // MARK: - Connection Section

    private var connectionSection: some View {
        Section("Connection") {
            settingTextField("API URL", text: $viewModel.apiUrl, key: "ApiUrl",
                             prompt: "https://reportmate.example.com")
            settingTextField("Device ID", text: $viewModel.deviceId, key: "DeviceId",
                             prompt: "Auto-detected if empty")
            settingSecureField("Passphrase", text: $viewModel.passphrase, key: "Passphrase")

            HStack {
                Toggle("Validate SSL", isOn: $viewModel.validateSSL)
                    .disabled(viewModel.isManaged("ValidateSSL"))
                managedBadge(for: "ValidateSSL")
            }
        }
    }

    // MARK: - Collection Section

    private var collectionSection: some View {
        Section("Collection") {
            settingTextField("Interval (seconds)", text: $viewModel.collectionInterval,
                             key: "CollectionInterval", prompt: "3600")

            HStack {
                Picker("Log Level", selection: $viewModel.logLevel) {
                    Text("debug").tag("debug")
                    Text("info").tag("info")
                    Text("warning").tag("warning")
                    Text("error").tag("error")
                }
                .disabled(viewModel.isManaged("LogLevel"))
                managedBadge(for: "LogLevel")
            }

            HStack {
                Picker("Storage Mode", selection: $viewModel.storageMode) {
                    Text("auto").tag("auto")
                    Text("quick").tag("quick")
                    Text("deep").tag("deep")
                }
                .disabled(viewModel.isManaged("StorageMode"))
                managedBadge(for: "StorageMode")
            }

            settingTextField("Timeout (seconds)", text: $viewModel.timeout,
                             key: "Timeout", prompt: "300")
        }
    }

    // MARK: - osquery Section

    private var osquerySection: some View {
        Section("osquery") {
            settingTextField("osquery Path", text: $viewModel.osqueryPath,
                             key: "OsqueryPath", prompt: "/usr/local/bin/osqueryi")
            settingTextField("Extension Path", text: $viewModel.osqueryExtensionPath,
                             key: "OsqueryExtensionPath",
                             prompt: "/usr/local/reportmate/macadmins_extension.ext")

            HStack {
                Toggle("Extension Enabled", isOn: $viewModel.extensionEnabled)
                    .disabled(viewModel.isManaged("ExtensionEnabled"))
                managedBadge(for: "ExtensionEnabled")
            }

            HStack {
                Toggle("Use Alt System Info", isOn: $viewModel.useAltSystemInfo)
                    .disabled(viewModel.isManaged("UseAltSystemInfo"))
                managedBadge(for: "UseAltSystemInfo")
            }
        }
    }

    // MARK: - Enabled Modules Section

    private var enabledModulesSection: some View {
        Section {
            let isManaged = viewModel.isManaged("EnabledModules")
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 150))], spacing: 8) {
                ForEach(ModuleDefinition.all) { module in
                    Toggle(isOn: moduleBinding(module.id)) {
                        Label(module.displayName, systemImage: module.systemImage)
                    }
                    .toggleStyle(.checkbox)
                    .disabled(isManaged)
                }
            }
            .padding(.vertical, 4)

            if isManaged {
                Label("Managed by configuration profile", systemImage: "lock.fill")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
        } header: {
            Text("Default Enabled Modules")
        } footer: {
            Text("Modules enabled for scheduled daemon runs. Manual runs from the Run tab can override these.")
        }
    }

    // MARK: - Helpers

    private func settingTextField(
        _ label: String, text: Binding<String>, key: String, prompt: String = ""
    ) -> some View {
        HStack {
            TextField(label, text: text, prompt: Text(prompt))
                .disabled(viewModel.isManaged(key))
            managedBadge(for: key)
        }
    }

    private func settingSecureField(
        _ label: String, text: Binding<String>, key: String
    ) -> some View {
        HStack {
            SecureField(label, text: text)
                .disabled(viewModel.isManaged(key))
            managedBadge(for: key)
        }
    }

    @ViewBuilder
    private func managedBadge(for key: String) -> some View {
        if viewModel.isManaged(key) {
            Label("MDM", systemImage: "lock.fill")
                .font(.caption)
                .foregroundStyle(.orange)
                .help("Set by MDM configuration profile — cannot be changed here")
        }
    }

    private func moduleBinding(_ id: String) -> Binding<Bool> {
        Binding(
            get: { viewModel.enabledModules.contains(id) },
            set: { isOn in
                if isOn { viewModel.enabledModules.insert(id) }
                else { viewModel.enabledModules.remove(id) }
            }
        )
    }
}
