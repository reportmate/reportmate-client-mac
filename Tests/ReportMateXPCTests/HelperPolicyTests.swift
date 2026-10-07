import XCTest
@testable import ReportMateXPC

final class HelperPolicyTests: XCTestCase {

    func testRequirementPinsAppIdentifierAndTeam() {
        let requirement = HelperPolicy.clientRequirement(teamID: "ABCDE12345")
        XCTAssertTrue(requirement.contains("identifier \"com.github.reportmate\""))
        XCTAssertTrue(requirement.contains("certificate leaf[subject.OU] = \"ABCDE12345\""))
        XCTAssertTrue(requirement.hasPrefix("anchor apple generic"))
    }

    func testRunArgumentsAllowVerbosityAndModules() {
        XCTAssertTrue(HelperPolicy.isAllowedRun(arguments: []))
        XCTAssertTrue(HelperPolicy.isAllowedRun(arguments: ["-vvv"]))
        XCTAssertTrue(HelperPolicy.isAllowedRun(arguments: ["-vvv", "--run-modules", "hardware,network,system_info"]))
    }

    func testRunArgumentsRejectAnythingElse() {
        XCTAssertFalse(HelperPolicy.isAllowedRun(arguments: ["--api-url", "https://example.com"]))
        XCTAssertFalse(HelperPolicy.isAllowedRun(arguments: ["--run-modules"]))
        XCTAssertFalse(HelperPolicy.isAllowedRun(arguments: ["--run-modules", ""]))
        XCTAssertFalse(HelperPolicy.isAllowedRun(arguments: ["--run-modules", "hardware,,network"]))
        XCTAssertFalse(HelperPolicy.isAllowedRun(arguments: ["--run-modules", "hardware;rm -rf /"]))
        XCTAssertFalse(HelperPolicy.isAllowedRun(arguments: ["--run-modules", "../etc"]))
        XCTAssertFalse(HelperPolicy.isAllowedRun(arguments: ["-vvv", "extra"]))
    }

    func testPreferenceWritesLimitedToDomainAndKeys() {
        XCTAssertTrue(HelperPolicy.canWrite(key: "ApiUrl", domain: "com.github.reportmate"))
        XCTAssertTrue(HelperPolicy.canWrite(key: "EnabledModules", domain: "com.github.reportmate"))
        XCTAssertFalse(HelperPolicy.canWrite(key: "ApiUrl", domain: "com.apple.loginwindow"))
        XCTAssertFalse(HelperPolicy.canWrite(key: "SomethingElse", domain: "com.github.reportmate"))
    }

    func testPathTrustRules() {
        XCTAssertTrue(HelperPolicy.isTrusted(type: .typeRegular, owner: 0, group: 0, mode: 0o755))
        XCTAssertTrue(HelperPolicy.isTrusted(type: .typeDirectory, owner: 0, group: 80, mode: 0o775))
        XCTAssertFalse(HelperPolicy.isTrusted(type: .typeDirectory, owner: 0, group: 20, mode: 0o775))
        XCTAssertFalse(HelperPolicy.isTrusted(type: .typeRegular, owner: 501, group: 0, mode: 0o755))
        XCTAssertFalse(HelperPolicy.isTrusted(type: .typeRegular, owner: 0, group: 0, mode: 0o757))
        XCTAssertFalse(HelperPolicy.isTrusted(type: .typeSymbolicLink, owner: 0, group: 0, mode: 0o755))
    }

    func testUserOwnedFileIsNotTrusted() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("managedreportsrunner")
        try Data().write(to: file)
        XCTAssertFalse(HelperPolicy.isTrustedRootPath(file.path))
    }

    func testSystemBinaryIsTrusted() {
        XCTAssertTrue(HelperPolicy.isTrustedRootPath("/usr/bin/true"))
    }
}
