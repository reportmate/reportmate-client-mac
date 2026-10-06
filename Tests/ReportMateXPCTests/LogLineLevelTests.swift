import XCTest
@testable import ReportMateXPC

final class LogLineLevelTests: XCTestCase {

    func testLogFileLines() {
        XCTAssertEqual(LogLineLevel.classify("[2026-10-06 09:41:00] ERROR Upload failed"), .error)
        XCTAssertEqual(LogLineLevel.classify("[2026-10-06 09:41:00] WARN  osquery slow"), .warning)
        XCTAssertEqual(LogLineLevel.classify("[2026-10-06 09:41:00] DEBUG payload 12 KB"), .debug)
        XCTAssertEqual(LogLineLevel.classify("[2026-10-06 09:41:00] INFO  Collecting hardware"), .info)
    }

    func testSwiftLogStreamLines() {
        XCTAssertEqual(LogLineLevel.classify("2026-10-06T17:42:21+0000 error reportmate.client: [ReportMate] Execution failed"), .error)
        XCTAssertEqual(LogLineLevel.classify("2026-10-06T17:42:21+0000 warning reportmate.client: slow"), .warning)
        XCTAssertEqual(LogLineLevel.classify("2026-10-06T17:42:21+0000 info reportmate.client: [ReportMate] Data cached"), .info)
        XCTAssertEqual(LogLineLevel.classify("2026-10-06T17:42:21+0000 critical reportmate.client: boom"), .error)
    }

    func testConsoleTags() {
        XCTAssertEqual(LogLineLevel.classify("[ERROR] CLI binary not found"), .error)
        XCTAssertEqual(LogLineLevel.classify("[WARN] Retrying"), .warning)
        XCTAssertEqual(LogLineLevel.classify("[WARNING] Collection stopped by user."), .warning)
        XCTAssertEqual(LogLineLevel.classify("[OK] Transmitted"), .success)
        XCTAssertEqual(LogLineLevel.classify("[DEBUG] query took 3 ms"), .debug)
    }

    func testTagWinsOverMessageWord() {
        XCTAssertEqual(LogLineLevel.classify("[WARN] Error budget at 80%"), .warning)
    }

    func testOtherLines() {
        XCTAssertEqual(LogLineLevel.classify("ERROR: helper refused"), .error)
        XCTAssertEqual(LogLineLevel.classify("=== Hardware ==="), .header)
        XCTAssertEqual(LogLineLevel.classify("[01/55] [██░░] 5% system_info"), .info)
        XCTAssertEqual(LogLineLevel.classify("plain text"), .info)
    }
}
