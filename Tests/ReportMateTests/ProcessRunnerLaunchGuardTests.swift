import Foundation
import XCTest
@testable import ReportMate

/// Process aborts the whole runner with an uncatchable Objective-C exception when an argument
/// holds a NUL byte. These must surface as ordinary errors so a module's fallback fails alone.
final class ProcessRunnerLaunchGuardTests: XCTestCase {
    func testNulInScriptThrowsInsteadOfAborting() async {
        do {
            _ = try await ProcessRunner.bash("printf 'a\0b' | tr -d '\0'")
            XCTFail("expected a launch error")
        } catch {
            XCTAssertTrue("\(error)".contains("NUL"), "\(error)")
        }
    }

    func testEscapedNulForTrStillRuns() async throws {
        let result = try await ProcessRunner.bash("printf 'a\\0b' | tr -d '\\0'")
        XCTAssertEqual(result.standardOutput, "ab")
    }

    func testEmptyExecutableThrows() async {
        do {
            _ = try await ProcessRunner.run(executable: "", arguments: [])
            XCTFail("expected a launch error")
        } catch {
            XCTAssertTrue("\(error)".contains("empty executable"), "\(error)")
        }
    }
}
