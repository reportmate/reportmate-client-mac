import XCTest
@testable import App

final class RetryTests: XCTestCase {
    private struct Failure: Error {}

    func testStopsAtFirstSuccess() {
        var calls = 0
        var sleeps = 0
        let outcome = Retry.run(attempts: 5, delay: 1, sleep: { _ in sleeps += 1 }) {
            calls += 1
            return calls < 3 ? Failure() : nil
        }
        XCTAssertNil(outcome.error)
        XCTAssertEqual(outcome.tries, 3)
        XCTAssertEqual(sleeps, 2)
    }

    func testReportsTheLastErrorWhenEveryAttemptFails() {
        var sleeps = 0
        let outcome = Retry.run(attempts: 4, delay: 1, sleep: { _ in sleeps += 1 }) { Failure() }
        XCTAssertNotNil(outcome.error)
        XCTAssertEqual(outcome.tries, 4)
        XCTAssertEqual(sleeps, 3)
    }
}
