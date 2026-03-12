//
//  SettingsView.swift
//  ReportMate
//
//  Main tab — centered app info header, then a 50/50 two-column layout.
//  Left column: Connection + osquery. Right column: Collection Schedules + Modules.
//  MDM-managed settings display a lock icon and are disabled.
//

import SwiftUI

struct ScheduleDefinition {
    let label: String
    let interval: String
    let modules: String
    let plistName: String

    var systemPlistPath: String {
        "/Library/LaunchDaemons/\(plistName)"
    }

    static let all: [ScheduleDefinition] = [
        .init(label: "Hourly", interval: "Every 60 min", modules: "security, network, management", plistName: "com.github.reportmate.hourly.plist"),
        .init(label: "Fourhourly", interval: "Every 4 hrs", modules: "applications, inventory, system, identity", plistName: "com.github.reportmate.fourhourly.plist"),
        .init(label: "Daily", interval: "9:00 AM", modules: "hardware, peripherals", plistName: "com.github.reportmate.daily.plist"),
        .init(label: "Full", interval: "Every 12 hrs", modules: "All modules", plistName: "com.github.reportmate.allmodules.plist"),
    ]
}

struct SettingsView: View {
    @Bindable var viewModel: SettingsViewModel
    @Environment(XPCClient.self) private var xpcClient

    @State private var plistPopoverSchedule: String?
    @State private var plistContent: String = ""

    private var marketingVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "–"
    }

    private var buildNumber: String {
        Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "–"
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                // App info header
                VStack(spacing: 6) {
                    Image(nsImage: NSApp.applicationIconImage)
                        .resizable()
                        .aspectRatio(contentMode: .fit)
                        .frame(width: 56, height: 56)
                    Text("ReportMate")
                        .font(.title2.bold())
                    Text("Device telemetry collection & reporting")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text("v\(marketingVersion) (\(buildNumber))")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                    HStack(spacing: 12) {
                        Link("Documentation", destination: URL(string: "https://github.com/reportmate/reportmate-client-mac/wiki")!)
                        Link("Report Issue", destination: URL(string: "https://github.com/reportmate/reportmate-client-mac/issues")!)
                    }
                    .font(.caption)
                }
                .padding(.top, 4)
                .padding(.bottom, 12)

                // Two-column layout — boxes stack within each column
                HStack(alignment: .top, spacing: 16) {
                    // Left column: Connection + osquery
                    VStack(spacing: 16) {
                        connectionSection
                        osquerySection
                    }
                    .frame(maxWidth: .infinity)

                    // Right column: Modules + Collection Schedules
                    VStack(spacing: 16) {
                        modulesSection
                        collectionSection
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
            HStack(alignment: .top, spacing: 16) {
                // Left: Daemon schedules
                VStack(alignment: .leading, spacing: 10) {
                    ForEach(Array(ScheduleDefinition.all.enumerated()), id: \.element.label) { index, schedule in
                        if index > 0 { Divider() }
                        scheduleRow(schedule: schedule)
                    }
                }
                .frame(maxWidth: .infinity)

                Divider()

                // Right: Log level + Timeout
                VStack(alignment: .leading, spacing: 12) {
                    settingRow("LogLevel", label: "Log Level") {
                        Picker("", selection: $viewModel.logLevel) {
                            Text("debug").tag("debug")
                            Text("info").tag("info")
                            Text("warning").tag("warning")
                            Text("error").tag("error")
                        }
                        .labelsHidden()
                        .frame(width: 120)
                        .frame(maxWidth: .infinity, alignment: .leading)
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
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding(.vertical, 8)
        } label: {
            Label("Collection Schedules", systemImage: "clock.arrow.2.circlepath")
                .font(.headline)
        }
    }

    @ViewBuilder
    private func scheduleRow(schedule: ScheduleDefinition) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack {
                Text(schedule.label)
                    .font(.callout.bold())
                Spacer()

                Text(schedule.interval)
                    .font(.caption)
                    .foregroundStyle(.secondary)

                Button {
                    loadPlist(for: schedule)
                } label: {
                    Image(systemName: "eye")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.borderless)
                .help("View LaunchDaemon plist")
                .popover(isPresented: Binding(
                    get: { plistPopoverSchedule == schedule.label },
                    set: { if !$0 { plistPopoverSchedule = nil } }
                )) {
                    plistPopoverContent(schedule: schedule)
                }
            }
            Text(schedule.modules)
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
    }

    @ViewBuilder
    private func plistPopoverContent(schedule: ScheduleDefinition) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Label(schedule.plistName, systemImage: "doc.text")
                    .font(.headline)
                Spacer()
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(plistContent, forType: .string)
                } label: {
                    Image(systemName: "doc.on.doc")
                }
                .buttonStyle(.borderless)
                .help("Copy to clipboard")
            }

            Divider()

            ScrollView {
                Text(plistContent)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(width: 480, height: 320)
        }
        .padding()
    }

    private func loadPlist(for schedule: ScheduleDefinition) {
        let path = schedule.systemPlistPath
        if let data = FileManager.default.contents(atPath: path),
           let content = String(data: data, encoding: .utf8) {
            plistContent = content
        } else {
            plistContent = "Plist not found at \(path)"
        }
        plistPopoverSchedule = schedule.label
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

    // MARK: - Modules Section (5x2 Grid)

    private let moduleColumns = Array(repeating: GridItem(.flexible(), spacing: 8), count: 5)

    @ViewBuilder
    private var modulesSection: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                let managed = viewModel.isManaged("EnabledModules")

                LazyVGrid(columns: moduleColumns, spacing: 8) {
                    ForEach(ModuleDefinition.all) { module in
                        moduleCard(module: module, managed: managed)
                    }
                }

                if managed {
                    Label("Managed by MDM", systemImage: "lock.fill")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }
            .padding(.vertical, 8)
        } label: {
            Label("Enabled Modules", systemImage: "square.grid.2x2")
                .font(.headline)
        }
    }

    @ViewBuilder
    private func moduleCard(module: ModuleDefinition, managed: Bool) -> some View {
        let isEnabled = viewModel.enabledModules.contains(module.id)
        VStack(spacing: 4) {
            Image(systemName: module.systemImage)
                .font(.title3)
                .frame(height: 20)
            Text(module.displayName)
                .font(.caption2)
                .lineLimit(1)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 8)
        .padding(.horizontal, 4)
        .background(
            RoundedRectangle(cornerRadius: 6)
                .fill(isEnabled ? Color.accentColor.opacity(0.12) : Color.clear)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 6)
                .stroke(isEnabled ? Color.accentColor : Color.secondary.opacity(0.2), lineWidth: 1)
        )
        .foregroundStyle(isEnabled ? .primary : .secondary)
        .contentShape(Rectangle())
        .onTapGesture {
            guard !managed else { return }
            if isEnabled { viewModel.enabledModules.remove(module.id) }
            else { viewModel.enabledModules.insert(module.id) }
        }
        .opacity(managed ? 0.5 : 1.0)
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
}
