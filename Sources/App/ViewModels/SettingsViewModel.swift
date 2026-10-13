//
//  SettingsViewModel.swift
//  ReportMate
//
//  Manages all configuration settings for the GUI.
//  Reads current values from the system plist and MDM status.
//  Writes changes via XPC helper for system-level persistence.
//

//
//  SettingsViewModel.swift
//  ReportMate
//
//  Manages all configuration settings for the GUI.
//  Reads current values from the system plist and MDM status. Edits stay in
//  the window until the user clicks Save, which asks for an administrator's
//  name and password and then writes the changed, unmanaged keys through the
//  privileged helper. Keys a configuration profile manages are never written.
//

import Foundation

/// The editable settings, as the window holds them.
struct SettingsSnapshot: Equatable {
    var apiUrl = ""
    var deviceId = ""
    var passphrase = ""
    var validateSSL = true
    var collectionInterval = "3600"
    var logLevel = "info"
    var storageMode = "auto"
    var timeout = "300"
    var osqueryPath = "/usr/local/bin/osqueryi"
    var osqueryExtensionPath = ""
    var extensionEnabled = true
    var useAltSystemInfo = true
    var enabledModules: Set<String> = []
}

/// One write the helper performs.
enum PreferenceWrite: Equatable {
    case string(String, String)
    case bool(String, Bool)
    case int(String, Int)
    case array(String, [String])
    case remove(String)

    var key: String {
        switch self {
        case .string(let key, _), .bool(let key, _), .int(let key, _), .array(let key, _), .remove(let key):
            return key
        }
    }
}

@Observable
@MainActor
final class SettingsViewModel {

    private var xpcClient: XPCClient?
    private var saved = SettingsSnapshot()

    func configure(client: XPCClient) {
        xpcClient = client
    }

    // MARK: - Connection Settings

    var apiUrl = ""
    var deviceId = ""
    var passphrase = ""
    var validateSSL = true

    // MARK: - Collection Settings

    var collectionInterval = "3600"
    var logLevel = "info"
    var storageMode = "auto"
    var timeout = "300"

    // MARK: - osquery Settings

    var osqueryPath = "/usr/local/bin/osqueryi"
    var osqueryExtensionPath = ""
    var extensionEnabled = true
    var useAltSystemInfo = true

    // MARK: - Default Enabled Modules

    var enabledModules: Set<String> = []

    // MARK: - Save Status

    private(set) var saveStatus: SaveStatus = .idle

    enum SaveStatus: Equatable {
        case idle, saving, saved, failed(String)
    }

    // MARK: - MDM Status

    private(set) var managedKeys: Set<String> = []

    private static let preferencesDomain = "com.github.reportmate"

    /// Every key the Prefs tab edits.
    static let editableKeys = [
        "ApiUrl", "DeviceId", "Passphrase", "ValidateSSL",
        "CollectionInterval", "LogLevel", "StorageMode", "Timeout",
        "OsqueryPath", "OsqueryExtensionPath", "ExtensionEnabled",
        "UseAltSystemInfo", "EnabledModules",
    ]
    private static let globalPrefsPath = "/Library/Preferences/com.github.reportmate.plist"

    /// True when a profile forces at least one of the app's keys.
    var hasManagedSettings: Bool { !managedKeys.isEmpty }

    /// True when a profile manages every key the tab edits, so the window is
    /// read-only and offers no Save.
    var isFullyManaged: Bool { Set(Self.editableKeys).isSubset(of: managedKeys) }

    func isManaged(_ key: String) -> Bool {
        managedKeys.contains(key)
    }

    /// True when an unmanaged field differs from what is saved.
    var hasUnsavedChanges: Bool {
        !Self.writes(from: saved, to: current, managed: managedKeys).isEmpty
    }

    // MARK: - Loading

    func load() {
        detectManagedKeys()

        // Read global preferences plist — written by Munki preinstall and XPC helper GUI writes.
        // Use direct file I/O: PlistBuddy (used by preinstall) writes directly without cfprefsd,
        // and we need to see the same values regardless of user context / daemon context.
        var dict: [String: Any] = [:]
        if let data = try? Data(contentsOf: URL(fileURLWithPath: Self.globalPrefsPath)),
           let parsed = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] {
            dict = parsed
        }

        // A field a configuration profile forces shows the forced value, which is
        // the one the runner uses, not whatever the local plist still holds.
        for key in managedKeys {
            if let value = CFPreferencesCopyAppValue(key as CFString, Self.preferencesDomain as CFString) {
                dict[key] = value
            }
        }

        load(from: dict, managed: managedKeys)
    }

    /// Shows `dict` as the saved settings, with `managed` the keys a profile
    /// forces. `load()` passes what is on disk; tests pass their own.
    func load(from dict: [String: Any], managed: Set<String>) {
        managedKeys = managed
        var snapshot = SettingsSnapshot()
        snapshot.apiUrl               = dict["ApiUrl"]             as? String ?? ""
        snapshot.deviceId             = dict["DeviceId"]           as? String ?? ""
        snapshot.passphrase           = dict["Passphrase"]         as? String ?? ""
        snapshot.validateSSL          = dict["ValidateSSL"]        as? Bool   ?? true
        snapshot.collectionInterval   = Self.plistString(dict["CollectionInterval"]) ?? "3600"
        snapshot.logLevel             = dict["LogLevel"]           as? String ?? "info"
        snapshot.storageMode          = dict["StorageMode"]        as? String ?? "auto"
        snapshot.timeout              = Self.plistString(dict["Timeout"])            ?? "300"
        snapshot.osqueryPath          = dict["OsqueryPath"]        as? String ?? "/usr/local/bin/osqueryi"
        snapshot.osqueryExtensionPath = dict["OsqueryExtensionPath"] as? String ?? ""
        snapshot.extensionEnabled     = dict["ExtensionEnabled"]   as? Bool   ?? true
        snapshot.useAltSystemInfo     = dict["UseAltSystemInfo"]   as? Bool   ?? true

        let modules = dict["EnabledModules"] as? [String]
            ?? ["installs", "applications", "system", "management", "identity", "hardware", "peripherals", "security", "network", "inventory"]
        snapshot.enabledModules = Set(modules)

        apply(snapshot)
        saved = snapshot
    }

    /// Discards unsaved edits, returning every field to its saved value.
    func revert() {
        apply(saved)
        saveStatus = .idle
    }

    private func apply(_ snapshot: SettingsSnapshot) {
        apiUrl = snapshot.apiUrl
        deviceId = snapshot.deviceId
        passphrase = snapshot.passphrase
        validateSSL = snapshot.validateSSL
        collectionInterval = snapshot.collectionInterval
        logLevel = snapshot.logLevel
        storageMode = snapshot.storageMode
        timeout = snapshot.timeout
        osqueryPath = snapshot.osqueryPath
        osqueryExtensionPath = snapshot.osqueryExtensionPath
        extensionEnabled = snapshot.extensionEnabled
        useAltSystemInfo = snapshot.useAltSystemInfo
        enabledModules = snapshot.enabledModules
    }

    private var current: SettingsSnapshot {
        SettingsSnapshot(
            apiUrl: apiUrl,
            deviceId: deviceId,
            passphrase: passphrase,
            validateSSL: validateSSL,
            collectionInterval: collectionInterval,
            logLevel: logLevel,
            storageMode: storageMode,
            timeout: timeout,
            osqueryPath: osqueryPath,
            osqueryExtensionPath: osqueryExtensionPath,
            extensionEnabled: extensionEnabled,
            useAltSystemInfo: useAltSystemInfo,
            enabledModules: enabledModules
        )
    }

    // MARK: - Saving

    /// The writes that take the stored settings from `old` to `new`, skipping
    /// keys a profile manages. An empty string removes the key, so the runner
    /// falls back to its default.
    static func writes(from old: SettingsSnapshot, to new: SettingsSnapshot, managed: Set<String>) -> [PreferenceWrite] {
        var writes: [PreferenceWrite] = []
        func allowed(_ key: String) -> Bool { !managed.contains(key) }
        func string(_ key: String, _ a: String, _ b: String) {
            guard a != b, allowed(key) else { return }
            writes.append(b.isEmpty ? .remove(key) : .string(key, b))
        }
        func bool(_ key: String, _ a: Bool, _ b: Bool) {
            if a != b, allowed(key) { writes.append(.bool(key, b)) }
        }
        func int(_ key: String, _ a: String, _ b: String, default fallback: Int) {
            if a != b, allowed(key) { writes.append(.int(key, Int(b) ?? fallback)) }
        }

        string("ApiUrl", old.apiUrl, new.apiUrl)
        string("DeviceId", old.deviceId, new.deviceId)
        string("Passphrase", old.passphrase, new.passphrase)
        bool("ValidateSSL", old.validateSSL, new.validateSSL)
        int("CollectionInterval", old.collectionInterval, new.collectionInterval, default: 3600)
        string("LogLevel", old.logLevel, new.logLevel)
        string("StorageMode", old.storageMode, new.storageMode)
        int("Timeout", old.timeout, new.timeout, default: 300)
        string("OsqueryPath", old.osqueryPath, new.osqueryPath)
        string("OsqueryExtensionPath", old.osqueryExtensionPath, new.osqueryExtensionPath)
        bool("ExtensionEnabled", old.extensionEnabled, new.extensionEnabled)
        bool("UseAltSystemInfo", old.useAltSystemInfo, new.useAltSystemInfo)
        if old.enabledModules != new.enabledModules, allowed("EnabledModules") {
            writes.append(.array("EnabledModules", new.enabledModules.sorted()))
        }
        return writes
    }

    /// Saves the changed, unmanaged settings. Asks for an administrator's name
    /// and password first; if the user cancels, the edits stay in the window
    /// unsaved. The authorization covers this one save and is then destroyed.
    func save() async {
        guard let client = xpcClient else { return }
        let target = current
        let pending = Self.writes(from: saved, to: target, managed: managedKeys)
        guard !pending.isEmpty else { return }

        guard let authorization = AdminAuthorization.authorize() else { return }
        defer { authorization.free() }
        let auth = authorization.externalForm

        saveStatus = .saving
        var failed: [String] = []
        var applied = saved
        for write in pending {
            let ok: Bool
            switch write {
            case .string(let key, let value): ok = await client.setStringPreference(key: key, value: value, authorization: auth)
            case .bool(let key, let value): ok = await client.setBoolPreference(key: key, value: value, authorization: auth)
            case .int(let key, let value): ok = await client.setIntPreference(key: key, value: value, authorization: auth)
            case .array(let key, let value): ok = await client.setArrayPreference(key: key, value: value, authorization: auth)
            case .remove(let key): ok = await client.removePreference(key: key, authorization: auth)
            }
            if ok { Self.record(write.key, from: target, into: &applied) } else { failed.append(write.key) }
        }
        saved = applied

        if !failed.isEmpty {
            saveStatus = .failed("Could not save \(failed.joined(separator: ", ")): the helper refused or is not available")
        } else {
            saveStatus = .saved
            try? await Task.sleep(for: .seconds(2))
            if saveStatus == .saved { saveStatus = .idle }
        }
    }

    /// Copies one key that saved from `target` into `snapshot`, so a failed
    /// key stays unsaved and is retried by the next Save.
    static func record(_ key: String, from target: SettingsSnapshot, into snapshot: inout SettingsSnapshot) {
        switch key {
        case "ApiUrl": snapshot.apiUrl = target.apiUrl
        case "DeviceId": snapshot.deviceId = target.deviceId
        case "Passphrase": snapshot.passphrase = target.passphrase
        case "ValidateSSL": snapshot.validateSSL = target.validateSSL
        case "CollectionInterval": snapshot.collectionInterval = target.collectionInterval
        case "LogLevel": snapshot.logLevel = target.logLevel
        case "StorageMode": snapshot.storageMode = target.storageMode
        case "Timeout": snapshot.timeout = target.timeout
        case "OsqueryPath": snapshot.osqueryPath = target.osqueryPath
        case "OsqueryExtensionPath": snapshot.osqueryExtensionPath = target.osqueryExtensionPath
        case "ExtensionEnabled": snapshot.extensionEnabled = target.extensionEnabled
        case "UseAltSystemInfo": snapshot.useAltSystemInfo = target.useAltSystemInfo
        case "EnabledModules": snapshot.enabledModules = target.enabledModules
        default: break
        }
    }

    // MARK: - Private Helpers

    private static func plistString(_ val: Any?) -> String? {
        guard let val else { return nil }
        return "\(val)"
    }

    private func detectManagedKeys() {
        let domain = Self.preferencesDomain as CFString
        managedKeys = Set(Self.editableKeys.filter {
            CFPreferencesAppValueIsForced($0 as CFString, domain)
        })
    }
}
