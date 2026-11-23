import XCTest
@testable import ReportMate

final class PPDContentTests: XCTestCase {
    private var directory: URL!
    private let text = "*Manufacturer: \"HP\"\n*ModelName: \"HP LaserJet\"\n"

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try FileManager.default.removeItem(at: directory)
    }

    func testReadsPlainPPD() throws {
        let path = directory.appendingPathComponent("plain.ppd")
        try text.write(to: path, atomically: true, encoding: .utf8)
        XCTAssertEqual(try PeripheralsModuleProcessor.readPPDContent(atPath: path.path), text)
    }

    func testReadsGzippedPPD() throws {
        let plain = directory.appendingPathComponent("printer")
        try text.write(to: plain, atomically: true, encoding: .utf8)
        let gzip = Process()
        gzip.executableURL = URL(fileURLWithPath: "/usr/bin/gzip")
        gzip.arguments = [plain.path]
        try gzip.run()
        gzip.waitUntilExit()
        let path = directory.appendingPathComponent("printer.gz")
        XCTAssertEqual(try PeripheralsModuleProcessor.readPPDContent(atPath: path.path), text)
    }

    func testReadsLatin1PPD() throws {
        let path = directory.appendingPathComponent("latin.ppd")
        try Data([0x2A, 0x4E, 0xE9]).write(to: path)
        XCTAssertEqual(try PeripheralsModuleProcessor.readPPDContent(atPath: path.path), "*Né")
    }
}
