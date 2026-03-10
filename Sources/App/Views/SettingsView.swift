//
//  SettingsView.swift
//  ReportMate
//
//  Main tab — centered app info header, then a 50/50 two-column layout.
//  Left column: Connection + osquery. Right column: Collection Schedules + Modules.
//  MDM-managed settings display a lock icon and are disabled.
//

import SwiftUI

struct SettingsView: View {
    @Bindable var viewModel: SettingsViewModel
    @Environment(XPCClient.self) private var xpcClient

    private var marketingVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "–"
    }

    private var buildNumber: String {
        Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "–"
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                appInfoHeader

                Divider()

                // Two-column layout — boxes stack within each column
                HStack(alignment: .top, spacing: 16) {
                    // Left column: Connection + osquery
                    VStack(spacing: 16) {
                        connectionSection
                        osquerySection
                    }
                    .frame(maxWidth: .infinity)

                    // Right column: Collection Schedules + Modules
                    VStack(spacing: 16) {
                        collectionSection
                        modulesSection
                    }
                    .frame(maxWidth: .infinity)
                }

                HStack {
                    saveStatusLabel
                    Spacer()
                }
                .padding(.top, 4)
            }
            .padding()
        }
        .onAppear {
            viewModel.configure(client: xpcClient)
            viewModel.load()
        }
    }

    // MARK: - App Info Header

    @ViewBuilder
    private var appInfoHeader: some View {
        VStack(spacing: 8) {
            Image(nsImage: NSApp.applicationIconImage)
                .resizable()
                .aspectRatio(contentMode: .fit)
                .frame(width: 72, height: 72)

            Text("ReportMate")
                .font(.largeTitle.bold())

            Text("Device telemetry collection and reporting for macOS endpoints.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            HStack(spacing: 12) {
                Text("v\(marketingVersion) (\(buildNumber))")
                    .font(.caption)
                    .foregroundStyle(.tertiary)

                Link("Documentation", destination: URL(string: "https://github.com/reportmate/reportmate-client-mac/wiki")!)
                    .font(.caption)
                Link("Report Issue", destination: URL(string: "https://github.com/reportmate/reportmate-client-mac/issues")!)
                    .font(.caption)
            }
        }
        .padding(.top, 8)
    }

    // MARK: - Auto-Save Status

    @ViewBuilder
    private var saveStatusLabel: some View {
        switch viewModel.saveStatus {
        case .idle:
            EmptyView()
        case .saving:
            ProgressView()
                .controlSize(.small)
        case .saved:
            Label("Saved", systemImage: "checkmark.circle.fill")
                .foregroundStyle(.green)
                .font(.callout)
                .transition(.opacity)
        case .failed(let msg):
            Label(msg, systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.red)
                .font(.callout)
        }
    }

    // MARK: - Connection Section

    @ViewBuilder
    private var connectionSection: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 12) {
                settingRow("ApiUrl", label: "API URL") {
                    TextField("https://reportmate.example.com", text: $viewModel.apiUrl)
                        .textFieldStyle(.roundedBorder)
                }

                settingRow("DeviceId", label: "Device ID") {
                    TextField("Auto-detected if empty", text: $viewModel.deviceId)
                        .textFieldStyle(.roundedBorder)
                }

                settingRow("Passphrase", label: "Passphrase") {
                    SecureField("Client passphrase", text: $viewModel.passphrase)
                        .textFieldStyle(.roundedBorder)
                }

                settingRow("ValidateSSL") {
                    Toggle("Validate SSL Certificates", isOn: $viewModel.validateSSL)
                }
            }
            .padding(.vertical, 8)
        } label: {
            Label("Connection", systemImage: "network")
                .font(.headline)
        }
    }

    // MARK: - Collection Schedules Section

    @ViewBuilder
    private var collectionSection: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 10) {
                scheduleRow(
                    label: "Hourly",
                    interval: "Every 60 min",
                    modules: "security, network, management"
                )
                Divider()
                scheduleRow(
                    label: "Fourhourly",
                    interval: "Every 4 hrs",
                    modules: "applications, inventory, system, identity"
                )
                Divider()
                scheduleRow(
                    label: "Daily",
                    interval: "9:00 AM",
                    modules: "hardware, peripherals"
                )
                Divider()
                scheduleRow(
                    label: "Full",
                    interval: "Every 12 hrs",
                    modules: "All modules"
                )
                Divider()

                settingRow("LogLevel", label: "Log Level") {
                    Picker("", selection: $viewModel.logLevel) {
                        Text("debug").tag("debug")
                        Text("info").tag("info")
                        Text("warning").tag("warning")
                        Text("error").tag("error")
                    }
                    .labelsHidden()
                    .frame(width: 120)
                }

                settingRow("Timeout", label: "Timeout (seconds)") {
                    HStack {
                        TextField("300", text: $viewModel.timeout)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 80)
                        Text("seconds")
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .padding(.vertical, 8)
        } label: {
            Label("Collection Schedules", systemImage: "clock.arrow.2.circlepath")
                .font(.headline)
        }
    }

    @ViewBuilder
    private func scheduleRow(label: String, interval: String, modules: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack {
                Text(label)
                    .font(.callout.bold())
                Spacer()
                Text(interval)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Text(modules)
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
    }

    // MARK: - osquery Section

    @ViewBuilder
    private var osquerySection: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 12) {
                settingRow("OsqueryPath", label: "osquery Path") {
                    TextField("/usr/local/bin/osqueryi", text: $viewModel.osqueryPath)
                        .textFieldStyle(.roundedBorder)
                }

                settingRow("OsqueryExtensionPath", label: "Extension Path") {
                    TextField("/usr/local/reportmate/macadmins_extension.ext", text: $viewModel.osqueryExtensionPath)
                        .textFieldStyle(.roundedBorder)
                }

                settingRow("ExtensionEnabled") {
                    Toggle("Extension Enabled", isOn: $viewModel.extensionEnabled)
                }

                settingRow("UseAltSystemInfo") {
                    Toggle("Use Alt System Info", isOn: $viewModel.useAltSystemInfo)
                }
            }
            .padding(.vertical, 8)
        } label: {
            Label("osquery", systemImage: "terminal")
                .font(.headline)
        }
    }

    // MARK: - Modules Section

    @ViewBuilder
    private var modulesSection: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                let managed = viewModel.isManaged("EnabledModules")
                ForEach(ModuleDefinition.all) { module in
                    Toggle(isOn: moduleBinding(module.id)) {
                        Label(module.displayName, systemImage: module.systemImage)
                    }
                    .toggleStyle(.checkbox)
                    .disabled(managed)
                }

                if managed {
                    Label("Managed by MDM", systemImage: "lock.fill")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }
            .padding(.vertical, 8)
        } label: {
            Label("Default Enabled Modules", systemImage: "square.grid.2x2")
                .font(.headline)
        }
    }

    // MARK: - Managed Setting Row

    @ViewBuilder
    private func settingRow<Content: View>(
        _ key: String,
        label: String? = nil,
        @ViewBuilder content: () -> Content
    ) -> some View {
        let managed = viewModel.isManaged(key)
        VStack(alignment: .leading, spacing: 2) {
            if let label {
                Text(label)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            content()
                .disabled(managed)
            if managed {
                Label("Managed by MDM", systemImage: "lock.fill")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
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
