import Testing
import Foundation
@testable import ReportMateKit

@Suite struct JSONValueTests {
    @Test func decodesMixedTree() throws {
        let text = #"{"a": 1, "b": "two", "c": [true, null, 3.5], "d": {"e_f": "g"}}"#
        let v = try JSONValue.parse(Data(text.utf8))
        #expect(v["a"].int == 1)
        #expect(v["b"].string == "two")
        #expect(v["c"][0].bool == true)
        #expect(v["c"][1].isNull)
        #expect(v["c"][2].double == 3.5)
        #expect(v["d"]["e_f"].string == "g")
        #expect(v["d"].normalizedKeys()["eF"].string == "g")
        #expect(v[path: "d.e_f"].string == "g")
    }

    @Test func boolish() {
        #expect(JSONValue.string("true").boolish)
        #expect(JSONValue.string("1").boolish)
        #expect(JSONValue.number(1).boolish)
        #expect(!JSONValue.string("false").boolish)
        #expect(JSONValue.null.boolishIfPresent == nil)
        #expect(JSONValue.string("no").boolishIfPresent == false)
    }

    @Test func numberCoercesToString() {
        #expect(JSONValue.number(26200).string == "26200")
        #expect(JSONValue.number(2.5).string == "2.5")
    }
}

@Suite struct DateTests {
    @Test func parsesPythonIsoFormat() {
        #expect(FlexibleDate.parse("2026-09-09T12:34:56.123456+00:00") != nil)
        #expect(FlexibleDate.parse("2026-09-09T12:34:56.123456") != nil)
        #expect(FlexibleDate.parse("2026-09-09T12:34:56Z") != nil)
        #expect(FlexibleDate.parse("2026-09-09 12:34:56") != nil)
        #expect(FlexibleDate.parse("1765940509.72615") != nil)
        #expect(FlexibleDate.parse("null") == nil)
        #expect(FlexibleDate.parse("") == nil)
    }

    @Test func relativeTime() {
        let now = Date()
        #expect(TimeFormatting.relative(now.addingTimeInterval(-5), now: now) == "just now")
        #expect(TimeFormatting.relative(now.addingTimeInterval(-90), now: now) == "1 minute ago")
        #expect(TimeFormatting.relative(now.addingTimeInterval(-7200), now: now) == "2 hours ago")
        #expect(TimeFormatting.relative(now.addingTimeInterval(-3 * 86400), now: now) == "3 days ago")
        #expect(TimeFormatting.relative(nil as Date?) == "never")
    }
}

@Suite struct DeviceStatusTests {
    @Test func thresholds() {
        let now = Date()
        #expect(DeviceStatus.calculate(lastSeen: now.addingTimeInterval(-3600), now: now) == .active)
        #expect(DeviceStatus.calculate(lastSeen: now.addingTimeInterval(-2 * 86400), now: now) == .stale)
        #expect(DeviceStatus.calculate(lastSeen: now.addingTimeInterval(-10 * 86400), now: now) == .missing)
        #expect(DeviceStatus.calculate(lastSeen: nil as Date?, now: now) == .missing)
        #expect(DeviceStatus.calculate(lastSeen: now, archived: true, now: now) == .archived)
    }
}

@Suite struct PlatformTests {
    @Test func normalize() {
        #expect(Platform.normalize("macOS") == .macOS)
        #expect(Platform.normalize("Darwin") == .macOS)
        #expect(Platform.normalize("Windows 11 Pro") == .windows)
        #expect(Platform.normalize("win") == .windows)
        #expect(Platform.normalize(nil) == .unknown)
    }

    @Test func detectPrefersKernelName() {
        let device: JSONValue = ["platform": "Windows", "modules": ["system": ["operatingSystem": ["name": "macOS"]]]]
        #expect(Platform.detect(device: device) == .macOS)
    }
}

@Suite struct DeviceSummaryTests {
    @Test func buildsFromDevicesRow() throws {
        let row: JSONValue = [
            "serialNumber": "SAMPLE1", "deviceId": "uuid-1", "name": "Studio 12", "lastSeen": "2026-09-09T10:00:00+00:00",
            "createdAt": "2026-09-01T10:00:00+00:00", "platform": "macOS",
            "modules": ["inventory": ["deviceName": "Studio 12", "asset_tag": "ECU-1234", "usage": "Shared", "catalog": "Curriculum"],
                        "system": ["operatingSystem": ["name": "macOS", "version": "26.1.0"]]],
        ]
        let now = try #require(FlexibleDate.parse("2026-09-09T12:00:00+00:00"))
        let d = DeviceSummary(json: row, now: now)
        #expect(d.name == "Studio 12")
        #expect(d.inventory.assetTag == "ECU-1234")
        #expect(d.platform == .macOS)
        #expect(d.status == .active)
        #expect(d.identifierLine == "ECU-1234 | SAMPLE1")
        #expect(d.osVersion == "26.1.0")
    }
}

@Suite struct SearchTests {
    @Test func fuzzyRanking() {
        let a = DeviceSummary(json: ["serialNumber": "AAA111", "name": "Library Kiosk 3", "modules": ["inventory": ["assetTag": "LIB-3"]]])
        let b = DeviceSummary(json: ["serialNumber": "BBB222", "name": "Studio Mac 7", "modules": ["inventory": ["assetTag": "STU-7"]]])
        #expect(DeviceSearch.search([a, b], query: "kiosk").first?.serialNumber == "AAA111")
        #expect(DeviceSearch.search([a, b], query: "zzz").isEmpty)
        #expect(DeviceSearch.resolve("STU-7", in: [a, b])?.serialNumber == "BBB222")
    }
}

@Suite struct EventBundlingTests {
    @Test func bundlesRoutineInfoEvents() {
        let t = Date()
        let events = [
            FleetEvent(id: "1", device: "S1", kind: .info, message: "Hardware data reported", ts: t),
            FleetEvent(id: "2", device: "S1", kind: .info, message: "Network data reported", ts: t.addingTimeInterval(-30)),
            FleetEvent(id: "3", device: "S1", kind: .error, message: "Firefox has an error!", ts: t.addingTimeInterval(-40)),
        ]
        let bundled = EventBundling.bundle(events)
        #expect(bundled.count == 2)
        #expect(bundled.contains { $0.isBundle && $0.count == 2 })
        #expect(bundled.contains { $0.kind == .error && !$0.isBundle })
    }

    @Test func inlineDetails() {
        let payload: JSONValue = ["errors": "Could not process item Foo; Download failed for Bar", "warning_items": ["Baz"], "Managed Safari": "15.6.1"]
        let d = EventInlineDetails.extract(payload)
        #expect(d.errors.count == 2)
        #expect(d.warnings.first?.text == "Baz")
        #expect(d.successes == ["Managed Safari 15.6.1"])
    }

    @Test func eventLinks() {
        #expect(EventLinks.moduleId(kind: .warning, message: "2 Munki warnings", payload: nil) == "installs")
        #expect(EventLinks.moduleId(kind: .info, message: "Hardware data reported", payload: nil) == "hardware")
        #expect(EventLinks.moduleId(kind: .info, message: "hello", payload: nil) == nil)
    }
}

@Suite struct SecurityEvaluatorTests {
    @Test func starterRuleDowngradesSharedDevices() {
        var config = SettingsDocument.defaultSecurityConfig
        config.rules = SettingsDocument.starterSecurityRules
        #expect(SecurityEvaluator.evaluate(check: "encryption", enabled: false, context: ["usage": "Shared"], config: config) == .neutral)
        #expect(SecurityEvaluator.evaluate(check: "encryption", enabled: false, context: ["usage": "Assigned"], config: config) == .danger)
        #expect(SecurityEvaluator.evaluate(check: "encryption", enabled: true, context: [:], config: config) == .ok)
        #expect(SecurityEvaluator.evaluate(check: "ssh", enabled: nil, context: [:], config: config) == .unknown)
    }
}

@Suite struct FleetStatsTests {
    @Test func osVersionGrouping() {
        let devices = ["26.1.0", "26.1.1", "15.6.0"].enumerated().map { i, v in
            DeviceSummary(json: ["serialNumber": .string("S\(i)"), "platform": "macOS", "modules": ["system": ["operatingSystem": ["name": "macOS", "version": .string(v)]]]])
        }
        let nodes = FleetStats.osVersions(devices, platform: .macOS)
        #expect(nodes.map { $0.name } == ["26.1", "15.6"])
        #expect(nodes[0].count == 2)
        #expect(nodes[0].children.map { $0.name } == ["26.1.1", "26.1.0"])
    }
}

@Suite struct InstallsTests {
    @Test func standardizesStatuses() {
        #expect(InstallStatus.standardize("install_succeeded") == .installed)
        #expect(InstallStatus.standardize("Pending Update") == .pending)
        #expect(InstallStatus.standardize("needs attention") == .warning)
        #expect(InstallStatus.standardize("FAILED") == .error)
        #expect(InstallStatus.standardize("uninstalled") == .removed)
        #expect(InstallStatus.standardize(nil) == .pending)
    }

    @Test func cimianVersionComparison() {
        #expect(InstallsInfo.compareVersions("2.0.1", "2.0") == 1)
        #expect(InstallsInfo.compareVersions("1.9", "2.0") == -1)
        #expect(InstallsInfo.compareVersions("3.1", "3.1.0") == 0)
        #expect(InstallsInfo.isCimianSessionId("2026-08-28-1158"))
        #expect(!InstallsInfo.isCimianSessionId("2026-08-28T11:58:00Z"))
    }

    @Test func munkiItemsWithErrors() {
        let modules: JSONValue = ["installs": ["munki": [
            "version": "6.6.0", "manifestName": "site_default", "endTime": "2026-09-09T08:00:00Z",
            "items": [
                ["name": "Firefox", "displayName": "Firefox", "status": "installed", "version": "130.0", "installedVersion": "130.0"],
                ["name": "Zoom", "displayName": "Zoom", "status": "install_failed", "version": "6.1", "lastError": "Install of Zoom-6.1 failed with return code 1"],
            ],
        ]]]
        let info = InstallsInfo(modules: modules)
        #expect(info.isMunki)
        #expect(info.totalPackages == 2)
        #expect(info.installed == 1)
        #expect(info.packages.first { $0.name == "Zoom" }?.status == .error)
        #expect(info.packages.first { $0.name == "Zoom" }?.errors.count == 1)
        #expect(info.config?.manifest == "site_default")
    }

    @Test func itemPredicates() {
        #expect(InstallItems.isError(["currentStatus": "Failed"]))
        #expect(InstallItems.isWarning(["status": "Installed", "lastAttemptStatus": "warning"]))
        #expect(InstallItems.isPending(["currentStatus": "will-be-installed"]))
        #expect(InstallItems.isSuccess(["status": "install_succeeded"]))
        #expect(InstallItems.itemName(fromMessage: "Download of Excel failed: error -1005") == "Excel")
    }
}

@Suite struct ApplicationsTests {
    @Test func mergesUsageByNameAndPath() {
        let modules: JSONValue = ["applications": [
            "installedApplications": [["name": "Safari.app", "version": "18.0", "path": "/Applications/Safari.app", "publisher": "Apple"]],
            "dailyUsageHistory": [["date": "2026-09-08", "appName": "Safari", "launches": 3, "totalSeconds": 600, "users": ["rod"]]],
            "applicationUsage": ["activeSessions": [["name": "Safari", "path": "/Applications/Safari.app", "user": "rod", "isActive": 1, "startTime": "2026-09-09T08:00:00Z", "durationSeconds": 120]]],
        ]]
        let info = ApplicationsInfo(modules: modules)
        #expect(info.hasData)
        let safari = info.applications.first
        #expect(safari?.cleanName == "Safari")
        #expect(safari?.usage?.launchCount == 3)
        #expect(safari?.usage?.totalSeconds == 600)
        #expect(safari?.isRunning == true)
        #expect(info.runningApps.count == 1)
        #expect(ApplicationsInfo.formatDuration(3720) == "1h 2m")
    }
}
