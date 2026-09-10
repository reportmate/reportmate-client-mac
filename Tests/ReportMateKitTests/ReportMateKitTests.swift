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

@Suite struct ApplicationsReportTests {
    @Test func normalizesNames() {
        #expect(AppNameNormalizer.normalize("Microsoft Visual C++ 2015 Redistributable (x64)") == "Microsoft Visual C++ Redistributable")
        #expect(AppNameNormalizer.normalize("Google Chrome 120.0.6099") == "Google Chrome")
        #expect(AppNameNormalizer.normalize("Adobe Photoshop 2024") == "Adobe Photoshop")
        #expect(AppNameNormalizer.normalize("Blender 4.1.0") == "Blender")
        #expect(AppNameNormalizer.normalize("Slack (x64)") == "Slack")
        #expect(AppNameNormalizer.normalize("Zoom Desktop") == "Zoom")
        #expect(AppNameNormalizer.normalize("Microsoft.NET.Runtime.Mono.6.0") == "Microsoft .NET Runtime")
        #expect(AppNameNormalizer.normalize("Unknown") == "")
        #expect(AppNameNormalizer.normalize("${{ app }}") == "")
    }

    @Test func excludesJunk() {
        #expect(!AppNameNormalizer.shouldInclude("KB5031356"))
        #expect(!AppNameNormalizer.shouldInclude("Microsoft.NET.Sdk.Android"))
        #expect(!AppNameNormalizer.shouldInclude("Security Update for Microsoft Office"))
        #expect(!AppNameNormalizer.shouldInclude("  "))
        #expect(AppNameNormalizer.shouldInclude("Microsoft Visual Studio"))
        #expect(AppNameNormalizer.shouldInclude("Blender"))
    }

    @Test func sortsVersionsNewestFirst() {
        #expect(ApplicationsReport.sortVersionsDescending(["1.2", "1.10", "1.9"]) == ["1.10", "1.9", "1.2"])
    }

    @Test func versionAnalysisPrefersServerBuckets() throws {
        let rows = try JSONValue.parse(Data(#"[{"serialNumber":"SAMPLE1","deviceName":"A","name":"Blender 4.1","version":"4.1"},{"serialNumber":"SAMPLE2","deviceName":"B","name":"Blender 4.1","version":"4.0"}]"#.utf8))
            .elements.map(FleetApplicationRow.init(json:))
        let folded = ApplicationsReport.versionAnalysis(server: nil, apps: rows)
        #expect(folded["Blender"]?["4.1"] == 1)
        #expect(folded["Blender"]?["4.0"] == 1)
        let server = ApplicationsReport.parseServerDistribution(try JSONValue.parse(Data(#"{"Blender 4.1":{"totalDevices":5,"versions":{"4.1":3,"4.0":2}}}"#.utf8)))
        let fromServer = ApplicationsReport.versionAnalysis(server: server, apps: rows)
        #expect(fromServer["Blender"]?["4.1"] == 3)
        #expect(ApplicationsReport.parseServerDistribution(.object(["error": .string("nope")])) == nil)
    }

    @Test func aggregatesUsageByDimension() throws {
        let devices = try JSONValue.parse(Data(#"[{"serialNumber":"SAMPLE1","usage":"Shared","catalog":"Curriculum","location":"Room 1","fleet":"Lab","totalHours":12,"launchCount":40},{"serialNumber":"SAMPLE2","usage":"Assigned","catalog":"Curriculum","location":"Unknown","totalHours":60,"launchCount":5}]"#.utf8))
            .elements.map(DeviceAggregate.init(json:))
        let hours = UsageAggregates(devices: devices, metric: .hours)
        #expect(hours.grandTotal == 72)
        #expect(hours.byCatalog.first?.value == 72)
        #expect(hours.byLocation.map(\.label) == ["Room 1"])
        #expect(hours.bins.first { $0.label == "10–50h" }?.count == 1)
        #expect(hours.bins.first { $0.label == "50–100h" }?.count == 1)
        let launches = UsageAggregates(devices: devices, metric: .launches)
        #expect(launches.byUsage.first?.label == "Shared")
        #expect(launches.deviceCount == 2)
    }

    @Test func missingDevicesRespectSelections() throws {
        let all = try JSONValue.parse(Data(#"[{"serialNumber":"SAMPLE1","name":"A","usage":"Shared","room":"Lab 101"},{"serialNumber":"SAMPLE2","name":"B","usage":"Assigned","room":"Lab 102"},{"serialNumber":"SAMPLE3","name":"C","usage":"Shared","room":"Office"}]"#.utf8))
            .elements.map(ApplicationFilterDevice.init(json:))
        let missing = ApplicationsReport.missingDevices(all: all, devicesWithApp: ["SAMPLE1"], usages: ["shared"], catalogs: [], locations: [], rooms: [])
        #expect(missing.map(\.serialNumber) == ["SAMPLE3"])
        let byRoom = ApplicationsReport.missingDevices(all: all, devicesWithApp: [], usages: [], catalogs: [], locations: [], rooms: ["lab"])
        #expect(byRoom.map(\.serialNumber) == ["SAMPLE1", "SAMPLE2"])
    }

    @Test func formatsDurations() {
        #expect(ApplicationsReport.duration(seconds: 0) == "0m")
        #expect(ApplicationsReport.duration(seconds: 2700) == "45m")
        #expect(ApplicationsReport.duration(seconds: 7200) == "2h")
        #expect(ApplicationsReport.duration(seconds: 7500) == "2h 5m")
    }
}

@Suite struct LastRunSummaryTests {
    @Test func readsCountsAndFailedItems() throws {
        let payload = try JSONValue.parse(Data(#"{"run_type":"auto","success_count":2,"error_count":1,"failed_items":["Blender"],"full_installs_data":{"cimian":{"items":[{"itemName":"Blender","installedVersion":"4.1","currentStatus":"Error"},{"itemName":"Zoom","installedVersion":"6.0","currentStatus":"Installed"}]}}}"#.utf8))
        let s = try #require(LastRunSummary.parse(payload))
        #expect(s.runType == "auto")
        #expect(s.successCount == 2)
        #expect(s.items.map(\.name) == ["Blender"])
        #expect(s.items.first?.status == "Error")
        #expect(s.hasIssues)
        #expect(s.title == "Packages with Issues")
    }

    @Test func fallsBackToNonStableItemsAndText() throws {
        let unstable = try JSONValue.parse(Data(#"{"module_status":"ok","full_installs_data":{"munki":{"items":[{"name":"Slack","version":"4.3","status":"pending"},{"name":"Zoom","status":"installed"}]}}}"#.utf8))
        #expect(LastRunSummary.parse(unstable)?.items.map(\.name) == ["Slack"])
        let text = try JSONValue.parse(Data(#"{"module_status":"ok","full_installs_data":{"items":[{"name":"Zoom","status":"installed"}]},"warnings":"WARNING: Download of Excel failed for Excel; WARNING: Package com.foo.BarBaz references are: [\"BarBaz\", \"Bar Baz Long\"]"}"#.utf8))
        let items = try #require(LastRunSummary.parse(text)?.items)
        #expect(items.map(\.name).contains("Excel"))
        #expect(items.map(\.name).contains("BarBaz"))
        #expect(LastRunSummary.parse(.object(["kind": .string("info")])) == nil)
    }
}

@Suite struct InstallsReportTests {
    @Test func classifiesRecordStatuses() {
        #expect(InstallStatusClass.classify("Install Failed") == .error)
        #expect(InstallStatusClass.classify("will-be-installed") == .pending)
        #expect(InstallStatusClass.classify("Installed") == .installed)
        #expect(InstallStatusClass.bucket(recordStatus: "warning") == .warning)
        #expect(InstallStatusClass.removed.matches(recordStatus: "removal-requested"))
        #expect(!InstallStatusClass.installed.matches(recordStatus: "pending"))
    }

    @Test func buildsRecordsFromBulkRows() throws {
        let rows = try JSONValue.parse(Data(#"[{"id":"1","deviceId":"d1","deviceName":"Lab-01","serialNumber":"SAMPLE1","itemName":"Blender","currentStatus":"Installed","installedVersion":"4.1","usage":"Shared","catalog":"Curriculum","location":"Lab 101","platform":"Windows NT","source":"cimian"},{"id":"2","deviceId":"d1","deviceName":"Lab-01","serialNumber":"SAMPLE1","itemName":"managed_apps","currentStatus":"Installed","source":"cimian"},{"id":"3","deviceId":"d2","deviceName":"Studio","serialNumber":"SAMPLE2","itemName":"Blender","currentStatus":"pending","latestVersion":"4.2","usage":"Assigned","platform":"Darwin","source":"munki"}]"#.utf8))
            .elements.map(InstallRecord.init(json:))
        let all = InstallsReport.records(from: rows, selectedInstalls: ["blender"], usages: [], catalogs: [], rooms: [], fleets: [], areas: [], manifests: ["SAMPLE1": "lab-manifest"])
        #expect(all.count == 2)
        #expect(all.first?.manifest == "lab-manifest")
        #expect(all.first?.platform == "Windows")
        #expect(all.last?.platform == "Macintosh")
        #expect(all.last?.version == "4.2")
        let shared = InstallsReport.records(from: rows, selectedInstalls: [], usages: ["shared"], catalogs: [], rooms: [], fleets: [], areas: [], manifests: [:])
        #expect(shared.map(\.serialNumber) == ["SAMPLE1"])
    }

    @Test func configRowCountsFromItems() throws {
        let device = InstallsDevice(json: try JSONValue.parse(Data(#"{"serialNumber":"SAMPLE1","lastSeen":"2026-09-09T10:00:00Z","modules":{"inventory":{"deviceName":"Lab-01","usage":"Shared"},"installs":{"cimian":{"version":"25.9.1","config":{"ClientIdentifier":"lab","SoftwareRepoURL":"https://repo.example"},"items":[{"itemName":"A","currentStatus":"Installed"},{"itemName":"B","currentStatus":"Install Failed","lastError":"boom"},{"itemName":"C","currentStatus":"will-be-installed"}]}}}}"#.utf8)))
        let row = try #require(ConfigReportRow(device: device))
        #expect(row.configType == "Cimian")
        #expect(row.installedCount == 1 && row.errorCount == 1 && row.pendingCount == 1)
        #expect(row.clientIdentifier == "lab")
        #expect(device.platform == .windows)
        let cats = InstallsReport.categorize([device])
        #expect(cats.errors.count == 1 && cats.pending.count == 1)
        #expect(InstallsReport.itemCounts([device], .error).first?.name == "B")
        #expect(InstallsReport.aggregateMessages([device], errors: true).first?.message == "boom")
    }
}

@Suite struct LocalReportStoreTests {
    @Test func mergesNewestModulesAcrossRuns() throws {
        let cache = FileManager.default.temporaryDirectory.appendingPathComponent("rm-cache-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: cache) }
        func write(_ run: String, _ json: String) throws {
            let dir = cache.appendingPathComponent(run)
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            try Data(json.utf8).write(to: dir.appendingPathComponent("event.json"))
        }
        try write("2026-09-01-010000", #"{"metadata":{"serialNumber":"SAMPLE1","deviceId":"D1","platform":"macOS","clientVersion":"1.0","collectedAt":"2026-09-01T01:00:00Z"},"hardware":{"model":"Old"},"system":{"operatingSystem":{"name":"macOS","version":"15.0"}},"events":[{"eventType":"success","message":"first run","timestamp":"2026-09-01T01:00:00Z"}]}"#)
        try write("2026-09-02-020000", #"{"metadata":{"serialNumber":"SAMPLE1","deviceId":"D1","platform":"macOS","clientVersion":"1.1","collectedAt":"2026-09-02T02:00:00Z"},"hardware":{"model":"New"},"events":[{"eventType":"warning","message":"second run","timestamp":"2026-09-02T02:00:00Z","details":{"x":1}}]}"#)
        #expect(LocalReportStore.isAvailable(at: cache))
        let report = try #require(try LocalReportStore.load(from: cache))
        #expect(report.runCount == 2)
        #expect(report.device.serialNumber == "SAMPLE1")
        #expect(report.device[.hardware]["model"].string == "New")
        #expect(report.device[.system]["operatingSystem"]["version"].string == "15.0")
        #expect(report.device.clientVersion == "1.1")
        #expect(report.events.count == 2)
        #expect(report.events.first?.kind == .warning)
        #expect(report.events.first?.payload?["x"].int == 1)
        #expect(!LocalReportStore.isAvailable(at: cache.appendingPathComponent("missing")))
    }
}

@Suite struct DeepLinkTests {
    @Test func parsesAppLinks() throws {
        let device = try #require(DeepLink(url: URL(string: "reportmate://device/SAMPLE1?filter=errors#installs")!))
        #expect(device.target == .device(serial: "SAMPLE1", tab: "installs"))
        #expect(device.query["filter"] == "errors")
        #expect(device.url.absoluteString == "reportmate://device/SAMPLE1?tab=installs&filter=errors")
        let usage = try #require(DeepLink(url: URL(string: "reportmate://applications/usage/Adobe%20Photoshop?days=90")!))
        #expect(usage.target == .applicationUsage(app: "Adobe Photoshop"))
        #expect(usage.query["days"] == "90")
        #expect(DeepLink(url: URL(string: "reportmate://events/failures")!)?.target == .eventsFailures)
        #expect(DeepLink(url: URL(string: "reportmate://system?osVersion=15.4")!)?.target == .report("system"))
        #expect(DeepLink(url: URL(string: "reportmate://this-mac")!)?.target == .thisMac)
        #expect(DeepLink(url: URL(string: "reportmate://")!)?.target == .dashboard)
        #expect(DeepLink(url: URL(string: "reportmate://nonsense")!) == nil)
        #expect(DeepLink(url: URL(string: "reportmate://profiles")!)?.target == .report("management"))
        #expect(DeepLink(url: URL(string: "reportmate://this-device")!)?.target == .thisMac)
        #expect(DeepLink(url: URL(string: "reportmate://device/SAMPLE1?tab=security#installs")!)?.target == .device(serial: "SAMPLE1", tab: "security"))
    }

    @Test func acceptsWebURLsAndRoundTrips() throws {
        let fromWeb = try #require(DeepLink(url: URL(string: "https://reportmate.example.com/device/SAMPLE1?filter=last_run#installs")!))
        #expect(fromWeb.target == .device(serial: "SAMPLE1", tab: "installs"))
        let swapped = try #require(DeepLink(url: URL(string: "reportmate://reportmate.example.com/installs?filter=warnings&view=messages")!))
        #expect(swapped.target == .report("installs"))
        #expect(swapped.query["view"] == "messages")
        let web = try #require(fromWeb.webURL(base: URL(string: "https://reportmate.example.com")!))
        #expect(web.absoluteString == "https://reportmate.example.com/device/SAMPLE1?filter=last_run#installs")
        let apps = DeepLink(target: .report("applications"), query: ["type": "usage", "apps": "Blender,Zoom", "period": "30"])
        #expect(DeepLink(url: apps.url)?.query["apps"] == "Blender,Zoom")
    }
}
