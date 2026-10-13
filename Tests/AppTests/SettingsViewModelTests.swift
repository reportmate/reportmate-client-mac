import XCTest
@testable import App

@MainActor
final class SettingsViewModelTests: XCTestCase {
    private let stored: [String: Any] = [
        "ApiUrl": "https://reports.example.com",
        "LogLevel": "info",
        "Timeout": 300,
        "EnabledModules": ["hardware", "system"],
    ]

    func testFreshLoadHasNoUnsavedChanges() {
        let model = SettingsViewModel()
        model.load(from: stored, managed: [])
        XCTAssertFalse(model.hasUnsavedChanges)
        XCTAssertEqual(model.apiUrl, "https://reports.example.com")
        XCTAssertEqual(model.timeout, "300")
    }

    func testEditMarksUnsavedAndRevertRestores() {
        let model = SettingsViewModel()
        model.load(from: stored, managed: [])
        model.logLevel = "debug"
        model.enabledModules.insert("network")
        XCTAssertTrue(model.hasUnsavedChanges)

        model.revert()
        XCTAssertFalse(model.hasUnsavedChanges)
        XCTAssertEqual(model.logLevel, "info")
        XCTAssertEqual(model.enabledModules, ["hardware", "system"])
    }

    func testEditToManagedKeyIsNotAnUnsavedChange() {
        let model = SettingsViewModel()
        model.load(from: stored, managed: ["LogLevel"])
        model.logLevel = "debug"
        XCTAssertFalse(model.hasUnsavedChanges)
    }

    func testFullyManagedOnlyWhenEveryKeyIsForced() {
        let model = SettingsViewModel()
        model.load(from: stored, managed: ["ApiUrl"])
        XCTAssertFalse(model.isFullyManaged)
        model.load(from: stored, managed: Set(SettingsViewModel.editableKeys))
        XCTAssertTrue(model.isFullyManaged)
    }

    func testWritesSkipManagedKeysAndRemoveEmptyStrings() {
        let old = SettingsSnapshot(apiUrl: "https://a.example.com", logLevel: "info", timeout: "300")
        var new = old
        new.apiUrl = ""
        new.logLevel = "debug"
        new.timeout = "600"
        new.enabledModules = ["system", "hardware"]

        let writes = SettingsViewModel.writes(from: old, to: new, managed: ["LogLevel"])
        XCTAssertEqual(writes, [
            .remove("ApiUrl"),
            .int("Timeout", 600),
            .array("EnabledModules", ["hardware", "system"]),
        ])
    }

    func testNoWritesWhenNothingChanged() {
        let snapshot = SettingsSnapshot(apiUrl: "https://a.example.com")
        XCTAssertTrue(SettingsViewModel.writes(from: snapshot, to: snapshot, managed: []).isEmpty)
    }

    func testPassphraseIsStatusOnly() {
        let model = SettingsViewModel()
        model.load(from: stored, managed: [])
        XCTAssertEqual(model.passphraseState, .notSet)

        var withPassphrase = stored
        withPassphrase["Passphrase"] = String(repeating: "x", count: 4)
        model.load(from: withPassphrase, managed: [])
        XCTAssertEqual(model.passphraseState, .set)
        XCTAssertFalse(model.hasUnsavedChanges)

        model.load(from: withPassphrase, managed: ["Passphrase"])
        XCTAssertEqual(model.passphraseState, .managed)
        XCTAssertFalse(model.isManaged("Passphrase"))
        XCTAssertFalse(SettingsViewModel.editableKeys.contains("Passphrase"))
    }
}
