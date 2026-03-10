import Foundation

@MainActor
@Observable
final class SettingsViewModel {

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

    // MARK: - State

    var isSaving = false
    var saveMessage: String?
    var managedKeys: Set<String> = []

    // Snapshot of values at load time for change detection
    private var snapshot: [String: String] = [:]

    private static let preferencesDomain = "com.github.reportmate"
    private static let systemPlistPath = "/Library/Preferences/com.github.reportmate.plist"

    var hasChanges: Bool {
        !buildChanges().isEmpty
    }

    init() {
        loadSettings()
    }

    // MARK: - Public API

    func loadSettings() {
        let defaults = UserDefaults(suiteName: Self.preferencesDomain)

        apiUrl = readString(defaults, "ApiUrl") ?? ""
        deviceId = readString(defaults, "DeviceId") ?? ""
        passphrase = readString(defaults, "Passphrase") ?? ""
        validateSSL = readBool(defaults, "ValidateSSL") ?? true

        collectionInterval = readString(defaults, "CollectionInterval") ?? "3600"
        logLevel = readString(defaults, "LogLevel") ?? "info"
        storageMode = readString(defaults, "StorageMode") ?? "auto"
        timeout = readString(defaults, "Timeout") ?? "300"

        osqueryPath = readString(defaults, "OsqueryPath") ?? "/usr/local/bin/osqueryi"
        osqueryExtensionPath = readString(defaults, "OsqueryExtensionPath") ?? ""
        extensionEnabled = readBool(defaults, "ExtensionEnabled") ?? true
        useAltSystemInfo = readBool(defaults, "UseAltSystemInfo") ?? true

        let modules = defaults?.stringArray(forKey: "EnabledModules")
            ?? ["hardware", "system", "network", "security", "applications", "management", "inventory"]
        enabledModules = Set(modules)

        detectManagedKeys()
        storeSnapshot()
        saveMessage = nil
    }

    func isManaged(_ key: String) -> Bool {
        managedKeys.contains(key)
    }

    func save() {
        let changes = buildChanges()
        guard !changes.isEmpty else { return }

        isSaving = true
        saveMessage = nil

        let commands = changes.map { buildDefaultsWriteCommand($0.key, $0.value) }

        Task {
            let success = await performPrivilegedSave(commands)
            isSaving = false
            if success {
                loadSettings()
                saveMessage = "Settings saved successfully."
            } else {
                saveMessage = "Save failed. Authentication may have been cancelled."
            }
        }
    }

    // MARK: - Private Helpers

    private func readString(_ defaults: UserDefaults?, _ key: String) -> String? {
        if let val = defaults?.object(forKey: key) {
            return "\(val)"
        }
        return nil
    }

    private func readBool(_ defaults: UserDefaults?, _ key: String) -> Bool? {
        guard defaults?.object(forKey: key) != nil else { return nil }
        return defaults?.bool(forKey: key)
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

    private func storeSnapshot() {
        snapshot = [
            "ApiUrl": apiUrl,
            "DeviceId": deviceId,
            "Passphrase": passphrase,
            "ValidateSSL": validateSSL ? "1" : "0",
            "CollectionInterval": collectionInterval,
            "LogLevel": logLevel,
            "StorageMode": storageMode,
            "Timeout": timeout,
            "OsqueryPath": osqueryPath,
            "OsqueryExtensionPath": osqueryExtensionPath,
            "ExtensionEnabled": extensionEnabled ? "1" : "0",
            "UseAltSystemInfo": useAltSystemInfo ? "1" : "0",
            "EnabledModules": enabledModules.sorted().joined(separator: ","),
        ]
    }

    private func currentValues() -> [String: String] {
        [
            "ApiUrl": apiUrl,
            "DeviceId": deviceId,
            "Passphrase": passphrase,
            "ValidateSSL": validateSSL ? "1" : "0",
            "CollectionInterval": collectionInterval,
            "LogLevel": logLevel,
            "StorageMode": storageMode,
            "Timeout": timeout,
            "OsqueryPath": osqueryPath,
            "OsqueryExtensionPath": osqueryExtensionPath,
            "ExtensionEnabled": extensionEnabled ? "1" : "0",
            "UseAltSystemInfo": useAltSystemInfo ? "1" : "0",
            "EnabledModules": enabledModules.sorted().joined(separator: ","),
        ]
    }

    /// Returns dictionary of changed keys -> new values (only non-managed keys).
    private func buildChanges() -> [String: String] {
        let current = currentValues()
        var changes: [String: String] = [:]
        for (key, value) in current where !isManaged(key) {
            if snapshot[key] != value {
                changes[key] = value
            }
        }
        return changes
    }

    private func buildDefaultsWriteCommand(_ key: String, _ value: String) -> String {
        let domain = Self.systemPlistPath

        switch key {
        case "ValidateSSL", "ExtensionEnabled", "UseAltSystemInfo":
            let boolVal = value == "1" ? "TRUE" : "FALSE"
            return "/usr/bin/defaults write \(domain) \(key) -bool \(boolVal)"
        case "CollectionInterval", "Timeout":
            return "/usr/bin/defaults write \(domain) \(key) -integer \(value)"
        case "EnabledModules":
            let modules = value.components(separatedBy: ",").map { "'\($0)'" }.joined(separator: " ")
            return "/usr/bin/defaults write \(domain) EnabledModules -array \(modules)"
        default:
            // Shell-escape single quotes in value
            let escaped = value.replacingOccurrences(of: "'", with: "'\\''")
            return "/usr/bin/defaults write \(domain) \(key) -string '\(escaped)'"
        }
    }

    private func performPrivilegedSave(_ commands: [String]) async -> Bool {
        let scriptPath = NSTemporaryDirectory() + "reportmate-save-\(ProcessInfo.processInfo.processIdentifier).sh"
        let scriptContent = "#!/bin/sh\n" + commands.joined(separator: "\n") + "\n"

        do {
            try scriptContent.write(toFile: scriptPath, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes(
                [.posixPermissions: NSNumber(value: Int16(0o755))],
                ofItemAtPath: scriptPath
            )
        } catch {
            return false
        }

        return await withCheckedContinuation { continuation in
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            process.arguments = [
                "-e",
                "do shell script \"\(scriptPath)\" with administrator privileges",
            ]
            process.terminationHandler = { @Sendable proc in
                try? FileManager.default.removeItem(atPath: scriptPath)
                continuation.resume(returning: proc.terminationStatus == 0)
            }

            do {
                try process.run()
            } catch {
                try? FileManager.default.removeItem(atPath: scriptPath)
                continuation.resume(returning: false)
            }
        }
    }
}
