//
//  SettingsViewModel.swift
//  ReportMate
//
//  Manages all configuration settings for the GUI.
//  Reads current values from the system plist and MDM status.
//  Writes changes via XPC helper for system-level persistence.
//

import Foundation

@Observable
@MainActor
final class SettingsViewModel {

    // MARK: - Auto-Save

    private var xpcClient: XPCClient?
    private var autoSaveTask: Task<Void, Never>?
    private var isLoading = false

    func configure(client: XPCClient) {
        xpcClient = client
    }

    private func scheduleAutoSave() {
        guard !isLoading, let client = xpcClient, !client.isRunning else { return }
        autoSaveTask?.cancel()
        autoSaveTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(0.75))
            guard !Task.isCancelled, let self else { return }
            self.save(using: client)
        }
    }

    // MARK: - Connection Settings

    var apiUrl = "" { didSet { scheduleAutoSave() } }
    var deviceId = "" { didSet { scheduleAutoSave() } }
    var passphrase = "" { didSet { scheduleAutoSave() } }
    var validateSSL = true { didSet { scheduleAutoSave() } }

    // MARK: - Collection Settings

    var collectionInterval = "3600" { didSet { scheduleAutoSave() } }
    var logLevel = "info" { didSet { scheduleAutoSave() } }
    var storageMode = "auto" { didSet { scheduleAutoSave() } }
    var timeout = "300" { didSet { scheduleAutoSave() } }

    // MARK: - osquery Settings

    var osqueryPath = "/usr/local/bin/osqueryi" { didSet { scheduleAutoSave() } }
    var osqueryExtensionPath = "" { didSet { scheduleAutoSave() } }
    var extensionEnabled = true { didSet { scheduleAutoSave() } }
    var useAltSystemInfo = true { didSet { scheduleAutoSave() } }

    // MARK: - Default Enabled Modules

    var enabledModules: Set<String> = [] { didSet { scheduleAutoSave() } }

    // MARK: - Save Status

    private(set) var saveStatus: SaveStatus = .idle

    enum SaveStatus {
        case idle, saving, saved, failed(String)
    }

    // MARK: - MDM Status

    private(set) var managedKeys: Set<String> = []

    private static let preferencesDomain = "com.github.reportmate"
    private static let systemPlistPath = "/Library/Preferences/com.github.reportmate.plist"

    func isManaged(_ key: String) -> Bool {
        managedKeys.contains(key)
    }

    // MARK: - Loading

    func load() {
        isLoading = true
        defer { isLoading = false }

        detectManagedKeys()

        var dict: [String: Any] = [:]
        if let data = try? Data(contentsOf: URL(fileURLWithPath: Self.systemPlistPath)),
           let parsed = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] {
            dict = parsed
        }

        apiUrl               = dict["ApiUrl"]             as? String ?? ""
        deviceId             = dict["DeviceId"]           as? String ?? ""
        passphrase           = dict["Passphrase"]         as? String ?? ""
        validateSSL          = dict["ValidateSSL"]        as? Bool   ?? true
        collectionInterval   = plistString(dict["CollectionInterval"]) ?? "3600"
        logLevel             = dict["LogLevel"]           as? String ?? "info"
        storageMode          = dict["StorageMode"]        as? String ?? "auto"
        timeout              = plistString(dict["Timeout"])            ?? "300"
        osqueryPath          = dict["OsqueryPath"]        as? String ?? "/usr/local/bin/osqueryi"
        osqueryExtensionPath = dict["OsqueryExtensionPath"] as? String ?? ""
        extensionEnabled     = dict["ExtensionEnabled"]   as? Bool   ?? true
        useAltSystemInfo     = dict["UseAltSystemInfo"]   as? Bool   ?? true

        let modules = dict["EnabledModules"] as? [String]
            ?? ["installs", "applications", "system", "management", "identity", "hardware", "peripherals", "security", "network", "inventory"]
        enabledModules = Set(modules)
    }

    // MARK: - Saving

    /// Saves all non-MDM-managed settings via the XPC helper.
    func save(using client: XPCClient) {
        saveStatus = .saving

        func saveString(_ key: String, _ value: String) {
            guard !isManaged(key) else { return }
            if value.isEmpty {
                client.removePreference(key: key)
            } else {
                client.setStringPreference(key: key, value: value)
            }
        }

        func saveBool(_ key: String, _ value: Bool) {
            guard !isManaged(key) else { return }
            client.setBoolPreference(key: key, value: value)
        }

        func saveInt(_ key: String, _ value: Int) {
            guard !isManaged(key) else { return }
            client.setIntPreference(key: key, value: value)
        }

        // Connection
        saveString("ApiUrl", apiUrl)
        saveString("DeviceId", deviceId)
        saveString("Passphrase", passphrase)
        saveBool("ValidateSSL", validateSSL)

        // Collection
        saveInt("CollectionInterval", Int(collectionInterval) ?? 3600)
        saveString("LogLevel", logLevel)
        saveString("StorageMode", storageMode)
        saveInt("Timeout", Int(timeout) ?? 300)

        // osquery
        saveString("OsqueryPath", osqueryPath)
        saveString("OsqueryExtensionPath", osqueryExtensionPath)
        saveBool("ExtensionEnabled", extensionEnabled)
        saveBool("UseAltSystemInfo", useAltSystemInfo)

        // Modules
        if !isManaged("EnabledModules") {
            client.setArrayPreference(key: "EnabledModules", value: enabledModules.sorted())
        }

        saveStatus = .saved
        Task {
            try? await Task.sleep(for: .seconds(2))
            if case .saved = saveStatus { saveStatus = .idle }
        }
    }

    // MARK: - Private Helpers

    private func plistString(_ val: Any?) -> String? {
        guard let val else { return nil }
        return "\(val)"
    }

    private func detectManagedKeys() {
        let domain = Self.preferencesDomain as CFString
        let allKeys = [
            "ApiUrl", "DeviceId", "Passphrase", "ValidateSSL",
            "CollectionInterval", "LogLevel", "StorageMode", "Timeout",
            "OsqueryPath", "OsqueryExtensionPath", "ExtensionEnabled",
            "UseAltSystemInfo", "EnabledModules",
        ]
        managedKeys = Set(allKeys.filter {
            CFPreferencesAppValueIsForced($0 as CFString, domain)
        })
    }
}
