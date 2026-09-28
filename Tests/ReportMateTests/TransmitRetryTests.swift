import Foundation
import XCTest
@testable import ReportMate

/// A check-in is resent only when the failure could clear on its own; anything the
/// server would reject again is returned on the first attempt.
final class TransmitRetryTests: XCTestCase {
    func testDroppedConnectionIsRetried() {
        for code in [URLError.Code.networkConnectionLost, .timedOut, .notConnectedToInternet, .cannotConnectToHost] {
            XCTAssertTrue(APIClient.isTransient(.networkError(URLError(code))), "\(code)")
        }
    }

    func testTransientServerStatusIsRetried() {
        for status in [408, 429, 500, 502, 503, 504] {
            XCTAssertTrue(APIClient.isTransient(.httpError(status, "")), "\(status)")
        }
    }

    func testRepeatableRejectionIsNotRetried() {
        for status in [400, 401, 403, 404, 413, 422] {
            XCTAssertFalse(APIClient.isTransient(.httpError(status, "")), "\(status)")
        }
        XCTAssertFalse(APIClient.isTransient(.networkError(URLError(.serverCertificateUntrusted))))
        XCTAssertFalse(APIClient.isTransient(.invalidConfiguration("")))
    }

    func testBackoffMatchesWindowsClient() {
        XCTAssertEqual(APIClient.retryDelay(afterAttempt: 1), 1)
        XCTAssertEqual(APIClient.retryDelay(afterAttempt: 2), 2)
    }

    func testRetryAttemptsDefaultAndOverride() {
        var configuration = ReportMateConfiguration()
        XCTAssertEqual(configuration.maxRetryAttempts, 3)
        configuration.merge(with: ["MaxRetryAttempts": 5])
        XCTAssertEqual(configuration.maxRetryAttempts, 5)
    }
}
