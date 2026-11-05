import XCTest
@testable import ReportMate

final class ThreatDetectionsTests: XCTestCase {

    private func logLine(plugin: String, timestamp: String, message: [String: Any], directory: String? = nil) -> String {
        let messageData = try! JSONSerialization.data(withJSONObject: message)
        let event: [String: Any] = [
            "subsystem": "com.apple.XProtectFramework.PluginAPI",
            "category": "XPEvent.structured",
            "processImagePath": "\(directory ?? ThreatDetections.xprotectDirectory)/\(plugin)",
            "timestamp": timestamp,
            "eventMessage": String(data: messageData, encoding: .utf8)!
        ]
        return String(data: try! JSONSerialization.data(withJSONObject: event), encoding: .utf8)!
    }

    func testCleanScansAreNotDetections() {
        let output = [
            logLine(plugin: "XProtectRemediatorAdload", timestamp: "2026-01-02 03:04:05.000000-0700",
                    message: ["status_message": "NoThreatDetected", "status_code": 20, "caused_by": []]),
            logLine(plugin: "XProtectRemediatorPirrit", timestamp: "2026-01-02 03:04:05.000000-0700",
                    message: ["status_message": "Success", "status_code": 0, "caused_by": []]),
            logLine(plugin: "XProtectRemediatorPirrit", timestamp: "2026-01-02 03:04:05.000000-0700",
                    message: ["status_message": "PluginCanceled", "status_code": 30, "caused_by": []])
        ].joined(separator: "\n")
        XCTAssertTrue(ThreatDetections.parseXProtectRemediatorLog(output).isEmpty)
    }

    func testRemediatedThreatBecomesADetectionRow() {
        let output = logLine(
            plugin: "XProtectRemediatorAdload",
            timestamp: "2026-01-02 03:04:05.123456-0700",
            message: ["status_message": "ThreatRemediated", "caused_by": [["path": "/private/tmp/example.app"]]]
        )
        let rows = ThreatDetections.parseXProtectRemediatorLog(output)
        XCTAssertEqual(rows.count, 1)
        let row = rows[0]
        XCTAssertEqual(row["source"] as? String, "XProtectRemediator")
        XCTAssertEqual(row["threatName"] as? String, "Adload")
        XCTAssertEqual(row["threatId"] as? String, "XProtectRemediatorAdload")
        XCTAssertEqual(row["status"] as? String, "ThreatRemediated")
        XCTAssertEqual(row["actionTaken"] as? String, "Remediated")
        XCTAssertEqual(row["detectedAt"] as? String, "2026-01-02T10:04:05Z")
        XCTAssertEqual(row["filePath"] as? String, "/private/tmp/example.app")
        XCTAssertNil(row["severity"], "XProtect reports no severity, so none is invented")
    }

    func testFailedRemediationIsADetection() {
        XCTAssertTrue(ThreatDetections.isThreatStatus("FailedToRemediate"))
        XCTAssertTrue(ThreatDetections.isThreatStatus("ThreatDetected"))
        XCTAssertFalse(ThreatDetections.isThreatStatus("NoThreatDetected"))
        XCTAssertFalse(ThreatDetections.isThreatStatus("SomeOtherThreatWording"))
    }

    func testSpoofedImagePathsAreIgnored() {
        let message: [String: Any] = ["status_message": "ThreatRemediated", "caused_by": []]
        let stamp = "2026-01-02 03:04:05.000000-0700"
        let spoofed = [
            logLine(plugin: "XProtectRemediatorAdload", timestamp: stamp, message: message, directory: "/tmp/fake"),
            logLine(plugin: "XProtectRemediatorAdload", timestamp: stamp, message: message,
                    directory: ThreatDetections.xprotectDirectory + "/nested"),
            logLine(plugin: "XProtectRemediatorAdload", timestamp: stamp, message: message,
                    directory: ThreatDetections.xprotectDirectory + "/../../../../../../../../tmp"),
            logLine(plugin: "SomeTool", timestamp: stamp, message: message),
            logLine(plugin: "XProtectRemediator", timestamp: stamp, message: message)
        ].joined(separator: "\n")
        XCTAssertTrue(ThreatDetections.parseXProtectRemediatorLog(spoofed).isEmpty)
        XCTAssertTrue(ThreatDetections.xprotectPredicate.contains(
            "processImagePath BEGINSWITH \"/Library/Apple/System/Library/CoreServices/XProtect.app/\""))
    }

    func testRepeatsCollapseWithCountAndSpan() {
        let rows: [[String: Any]] = [
            ["source": "XProtectRemediator", "threatName": "Adload", "status": "ThreatRemediated", "detectedAt": "2026-01-01T00:00:00Z"],
            ["source": "XProtectRemediator", "threatName": "Adload", "status": "ThreatRemediated", "detectedAt": "2026-01-03T00:00:00Z"],
            ["source": "XProtectRemediator", "threatName": "Pirrit", "status": "ThreatRemediated", "detectedAt": "2026-01-02T00:00:00Z"]
        ]
        let collapsed = ThreatDetections.collapse(rows)
        XCTAssertEqual(collapsed.count, 2)
        XCTAssertEqual(collapsed[0]["threatName"] as? String, "Adload")
        XCTAssertEqual(collapsed[0]["count"] as? Int, 2)
        XCTAssertEqual(collapsed[0]["firstSeenAt"] as? String, "2026-01-01T00:00:00Z")
        XCTAssertEqual(collapsed[0]["lastSeenAt"] as? String, "2026-01-03T00:00:00Z")
        XCTAssertEqual(collapsed[1]["count"] as? Int, 1)
    }

    func testDefenderThreatList() {
        let output = """
        [{"id":"abc","name":"Virus:DOS/EICAR_Test_File","threatType":"virus","threatStatus":"quarantined",
          "detectionTime":1767225600000,"resources":[{"path":"/Users/example/eicar.txt"}]}]
        """
        let rows = ThreatDetections.parseDefenderThreatList(output)
        XCTAssertEqual(rows?.count, 1)
        XCTAssertEqual(rows?[0]["threatName"] as? String, "Virus:DOS/EICAR_Test_File")
        XCTAssertEqual(rows?[0]["status"] as? String, "quarantined")
        XCTAssertEqual(rows?[0]["detectedAt"] as? String, "2026-01-01T00:00:00Z")
        XCTAssertEqual(rows?[0]["filePath"] as? String, "/Users/example/eicar.txt")
    }

    func testUnreadableDefenderOutputIsNotAnEmptyList() {
        XCTAssertNil(ThreatDetections.parseDefenderThreatList("ERROR: daemon not running"))
        XCTAssertEqual(ThreatDetections.parseDefenderThreatList("[]")?.count, 0)
    }

    func testUnpatchedCVEListBound() {
        let entries = (0..<5).map { ["cve": "CVE-2026-000\($0)"] as [String: Any] }
        let small = UnpatchedCVEList.bounded(entries, limit: 10)
        XCTAssertEqual(small.entries.count, 5)
        XCTAssertEqual(small.total, 5)
        XCTAssertFalse(small.truncated)

        let cut = UnpatchedCVEList.bounded(entries, limit: 3)
        XCTAssertEqual(cut.entries.count, 3)
        XCTAssertEqual(cut.total, 5)
        XCTAssertTrue(cut.truncated)
    }
}

final class UpdateSearchTests: XCTestCase {
    private let success = Date(timeIntervalSince1970: 1_767_225_600)

    func testSuccessfulSession() {
        let result = UpdateSearch.status(
            preferences: ["LastSessionSuccessful": true, "LastResultCode": 2, "LastSuccessfulDate": success],
            listExitCode: 0, listError: ""
        )
        XCTAssertEqual(result?["status"] as? String, "succeeded")
        XCTAssertEqual(result?["checkedAt"] as? String, "2026-01-01T00:00:00Z")
        XCTAssertTrue(result?["error"] is NSNull)
    }

    func testFailedSession() {
        let result = UpdateSearch.status(
            preferences: ["LastSessionSuccessful": false, "LastResultCode": 100, "LastSuccessfulDate": success],
            listExitCode: 0, listError: ""
        )
        XCTAssertEqual(result?["status"] as? String, "failed")
        XCTAssertEqual(result?["error"] as? String, "The last software update scan failed (result code 100)")
        XCTAssertEqual(result?["lastSuccessfulAt"] as? String, "2026-01-01T00:00:00Z")
    }

    func testFailedListCommandWins() {
        let now = Date(timeIntervalSince1970: 1_767_312_000)
        let result = UpdateSearch.status(
            preferences: ["LastSessionSuccessful": true, "LastSuccessfulDate": success],
            listExitCode: 1, listError: "Cannot connect to the update server", now: now
        )
        XCTAssertEqual(result?["status"] as? String, "failed")
        XCTAssertEqual(result?["error"] as? String, "Cannot connect to the update server")
        XCTAssertEqual(result?["checkedAt"] as? String, "2026-01-02T00:00:00Z")
    }

    func testNoRecordIsNotReported() {
        XCTAssertNil(UpdateSearch.status(preferences: nil, listExitCode: 0, listError: nil))
        XCTAssertNil(UpdateSearch.status(preferences: [:], listExitCode: 0, listError: nil))
    }
}
