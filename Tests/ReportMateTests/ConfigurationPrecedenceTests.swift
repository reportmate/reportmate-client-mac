import Foundation
import XCTest
@testable import ReportMate

/// A configuration profile beats every machine source, environment variables sit with
/// the machine settings, and only this run's explicit flags beat the profile.
final class ConfigurationPrecedenceTests: XCTestCase {
    func testProfileBeatsEnvironmentAndSystemPlist() {
        let config = ConfigurationManager.resolve(
            userPlist: ["ApiUrl": "https://user.example"],
            environment: ["ApiUrl": "https://env.example"],
            systemPlist: ["ApiUrl": "https://system.example"],
            policy: ["ApiUrl": "https://profile.example"],
            overrides: [:]
        )
        XCTAssertEqual(config.apiUrl, "https://profile.example")
    }

    func testSystemPlistBeatsEnvironment() {
        let config = ConfigurationManager.resolve(
            userPlist: nil,
            environment: ["LogLevel": "debug"],
            systemPlist: ["LogLevel": "warning"],
            policy: nil,
            overrides: [:]
        )
        XCTAssertEqual(config.logLevel, "warning")
    }

    func testEnvironmentBeatsUserPlist() {
        let config = ConfigurationManager.resolve(
            userPlist: ["LogLevel": "error"],
            environment: ["LogLevel": "debug"],
            systemPlist: nil,
            policy: nil,
            overrides: [:]
        )
        XCTAssertEqual(config.logLevel, "debug")
    }

    func testRunFlagBeatsProfile() {
        let config = ConfigurationManager.resolve(
            userPlist: nil,
            environment: [:],
            systemPlist: nil,
            policy: ["ApiUrl": "https://profile.example", "StorageMode": "quick"],
            overrides: ["ApiUrl": "https://flag.example"]
        )
        XCTAssertEqual(config.apiUrl, "https://flag.example")
        XCTAssertEqual(config.storageMode, .quick)
    }

    func testDefaultsApplyWhenNothingIsSet() {
        let config = ConfigurationManager.resolve(
            userPlist: nil, environment: [:], systemPlist: nil, policy: nil, overrides: [:]
        )
        XCTAssertNil(config.apiUrl)
        XCTAssertEqual(config.timeout, 300)
        XCTAssertTrue(config.validateSSL)
    }

    func testEveryMergedKeyCanComeFromAProfile() {
        let values: [String: Any] = [
            "ApiUrl": "https://p.example", "DeviceId": "D", "Passphrase": "P", "ApiKey": "K",
            "CollectionInterval": 60, "LogLevel": "debug", "EnabledModules": ["system"],
            "OsqueryPath": "/opt/osqueryi", "OsqueryExtensionPath": "/opt/ext",
            "ExtensionEnabled": false, "UseAltSystemInfo": false, "ValidateSSL": false,
            "Timeout": 42, "CompressPayload": false, "MaxRetryAttempts": 7,
            "QueryTimeoutSeconds": 11, "ExtensionQueryTimeoutSeconds": 12.5,
            "ModuleTimeoutSeconds": 13, "StorageMode": "deep",
        ]
        XCTAssertEqual(Set(values.keys), Set(ConfigurationManager.settingKeys))

        let policy = ConfigurationManager.policyValues(isForced: { _ in true }, read: { values[$0] })
        let config = ConfigurationManager.resolve(
            userPlist: nil, environment: [:], systemPlist: nil, policy: policy, overrides: [:]
        )
        XCTAssertEqual(config.apiUrl, "https://p.example")
        XCTAssertEqual(config.deviceId, "D")
        XCTAssertEqual(config.passphrase, "P")
        XCTAssertEqual(config.apiKey, "K")
        XCTAssertEqual(config.collectionInterval, 60)
        XCTAssertEqual(config.logLevel, "debug")
        XCTAssertEqual(config.enabledModules, ["system"])
        XCTAssertEqual(config.osqueryPath, "/opt/osqueryi")
        XCTAssertEqual(config.osqueryExtensionPath, "/opt/ext")
        XCTAssertFalse(config.extensionEnabled)
        XCTAssertFalse(config.useAltSystemInfo)
        XCTAssertFalse(config.validateSSL)
        XCTAssertEqual(config.timeout, 42)
        XCTAssertFalse(config.compressPayload)
        XCTAssertEqual(config.maxRetryAttempts, 7)
        XCTAssertEqual(config.queryTimeoutSeconds, 11)
        XCTAssertEqual(config.extensionQueryTimeoutSeconds, 12.5)
        XCTAssertEqual(config.moduleTimeoutSeconds, 13)
        XCTAssertEqual(config.storageMode, .deep)
    }

    func testOnlyForcedKeysCountAsPolicy() {
        let policy = ConfigurationManager.policyValues(
            isForced: { $0 == "Timeout" },
            read: { $0 == "Timeout" ? 99 : "unforced" }
        )
        XCTAssertEqual(policy?.count, 1)
        XCTAssertEqual(policy?["Timeout"] as? Int, 99)
        XCTAssertNil(ConfigurationManager.policyValues(isForced: { _ in false }, read: { _ in 1 }))
    }
}
