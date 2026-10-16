import Foundation
import XCTest
@testable import ReportMate

final class ApplicationsEmptyInventoryTests: XCTestCase {
    /// Replaces the installed-application scan with a fixed result so the module's
    /// handling of that result can be tested without osquery or the filesystem.
    private final class StubbedApplicationsProcessor: ApplicationsModuleProcessor, @unchecked Sendable {
        let stubbedApps: [[String: Any]]

        init(apps: [[String: Any]]) {
            self.stubbedApps = apps
            super.init(configuration: ReportMateConfiguration())
        }

        override func collectInstalledApplications() async throws -> [[String: Any]] {
            stubbedApps
        }
    }

    func testEmptyScanThrowsSoTheModuleIsLeftOutOfThePayload() async {
        let processor = StubbedApplicationsProcessor(apps: [])

        do {
            _ = try await processor.collectData()
            XCTFail("an empty installed-application scan must not produce module data")
        } catch let error as ApplicationsModuleError {
            guard case .emptyInstalledApplications(let seconds) = error else {
                return XCTFail("unexpected error \(error)")
            }
            XCTAssertGreaterThanOrEqual(seconds, 0)
        } catch {
            XCTFail("unexpected error \(error)")
        }
    }

    func testEmptyScanErrorCarriesTheScanTiming() {
        let error = ApplicationsModuleError.emptyInstalledApplications(scanSeconds: 43.031)
        let message = error.localizedDescription
        XCTAssertTrue(message.contains("43.03s"), message)
        XCTAssertTrue(message.contains("no applications"), message)
    }
}
