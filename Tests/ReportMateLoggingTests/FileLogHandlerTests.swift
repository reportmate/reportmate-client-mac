import Foundation
import Logging
import XCTest
@testable import ReportMateLogging

final class FileLogHandlerTests: XCTestCase {
    private var directory: String!
    private var logPath: String { "\(directory!)/reportmate.log" }
    private let timeZone = TimeZone(identifier: "America/Vancouver")!

    override func setUpWithError() throws {
        directory = NSTemporaryDirectory() + "reportmate-logging-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(atPath: directory)
    }

    private func date(_ string: String) -> Date {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = timeZone
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter.date(from: string)!
    }

    private func contents(_ path: String) throws -> String {
        try String(contentsOfFile: path, encoding: .utf8)
    }

    private func setModified(_ path: String, to date: Date) throws {
        try FileManager.default.setAttributes([.modificationDate: date], ofItemAtPath: path)
    }

    func testLineFormat() throws {
        let file = RollingLogFile(path: logPath, timeZone: timeZone)
        let at = date("2026-03-04 05:06:07")
        file.write(level: "INFO", message: "hello", at: at)
        file.write(level: "WARN", message: "careful", at: at)
        file.write(level: "DEBUG", message: "detail", at: at)
        file.write(level: "ERROR", message: "broken", at: at)

        XCTAssertEqual(try contents(logPath), """
            [2026-03-04 05:06:07] INFO  hello
            [2026-03-04 05:06:07] WARN  careful
            [2026-03-04 05:06:07] DEBUG detail
            [2026-03-04 05:06:07] ERROR broken

            """)
    }

    func testHandlerCollapsesLevels() {
        XCTAssertEqual(FileLogHandler.levelName(.trace), "DEBUG")
        XCTAssertEqual(FileLogHandler.levelName(.debug), "DEBUG")
        XCTAssertEqual(FileLogHandler.levelName(.info), "INFO")
        XCTAssertEqual(FileLogHandler.levelName(.notice), "INFO")
        XCTAssertEqual(FileLogHandler.levelName(.warning), "WARN")
        XCTAssertEqual(FileLogHandler.levelName(.error), "ERROR")
        XCTAssertEqual(FileLogHandler.levelName(.critical), "ERROR")
    }

    func testHandlerWritesThroughLogger() throws {
        let file = RollingLogFile(path: logPath, timeZone: timeZone)
        let handler = FileLogHandler(file: file, level: .info)
        var logger = Logger(label: "test", factory: { _ in handler })
        logger.logLevel = .info
        logger.debug("hidden")
        logger.info("shown")

        let lines = try contents(logPath).split(separator: "\n")
        XCTAssertEqual(lines.count, 1)
        XCTAssertTrue(lines[0].hasSuffix("] INFO  shown"))
    }

    func testRollsOnFirstWriteOfNewDay() throws {
        let file = RollingLogFile(path: logPath, timeZone: timeZone)
        file.write(level: "INFO", message: "yesterday", at: date("2026-03-04 23:59:59"))
        try setModified(logPath, to: date("2026-03-04 23:59:59"))

        file.write(level: "INFO", message: "today", at: date("2026-03-05 00:00:01"))

        XCTAssertEqual(try contents("\(directory!)/reportmate-2026-03-04.log"),
                       "[2026-03-04 23:59:59] INFO  yesterday\n")
        XCTAssertEqual(try contents(logPath), "[2026-03-05 00:00:01] INFO  today\n")
    }

    func testDoesNotRollWithinTheSameDay() throws {
        let file = RollingLogFile(path: logPath, timeZone: timeZone)
        file.write(level: "INFO", message: "one", at: date("2026-03-04 01:00:00"))
        try setModified(logPath, to: date("2026-03-04 01:00:00"))
        file.write(level: "INFO", message: "two", at: date("2026-03-04 22:00:00"))

        XCTAssertEqual(try contents(logPath).split(separator: "\n").count, 2)
        XCTAssertFalse(FileManager.default.fileExists(atPath: "\(directory!)/reportmate-2026-03-04.log"))
    }

    func testRollUsesLastWriteDayNotYesterday() throws {
        let file = RollingLogFile(path: logPath, timeZone: timeZone)
        file.write(level: "INFO", message: "old", at: date("2026-03-01 12:00:00"))
        try setModified(logPath, to: date("2026-03-01 12:00:00"))
        file.write(level: "INFO", message: "new", at: date("2026-03-05 12:00:00"))

        XCTAssertTrue(FileManager.default.fileExists(atPath: "\(directory!)/reportmate-2026-03-01.log"))
    }

    func testKeepsOnlyNewestRolledFiles() throws {
        let fm = FileManager.default
        for day in 1...35 {
            let name = String(format: "reportmate-2026-01-%02d.log", day)
            fm.createFile(atPath: "\(directory!)/\(name)", contents: Data("x\n".utf8))
        }
        fm.createFile(atPath: "\(directory!)/reportmate-appusage-2026-01-01.log", contents: Data("x\n".utf8))

        let file = RollingLogFile(path: logPath, keep: 30, timeZone: timeZone)
        file.write(level: "INFO", message: "old", at: date("2026-02-27 12:00:00"))
        try setModified(logPath, to: date("2026-02-27 12:00:00"))
        file.write(level: "INFO", message: "new", at: date("2026-02-28 12:00:00"))

        let rolled = try fm.contentsOfDirectory(atPath: directory)
            .filter { $0.hasPrefix("reportmate-2026") }
            .sorted()
        XCTAssertEqual(rolled.count, 30)
        XCTAssertEqual(rolled.first, "reportmate-2026-01-07.log")
        XCTAssertEqual(rolled.last, "reportmate-2026-02-27.log")
        XCTAssertTrue(fm.fileExists(atPath: "\(directory!)/reportmate-appusage-2026-01-01.log"),
                      "another stem's rolled files are left alone")
    }

    func testFallsBackWhenPrimaryIsNotWritable() throws {
        let primary = "\(directory!)/locked/reportmate.log"
        try FileManager.default.createDirectory(atPath: "\(directory!)/locked", withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o500])
        defer { try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: "\(directory!)/locked") }
        try XCTSkipIf(geteuid() == 0, "root ignores directory permissions")

        let fallback = "\(directory!)/fallback/reportmate.log"
        let file = RollingLogFile(path: primary, fallbackPath: fallback, timeZone: timeZone)
        file.write(level: "INFO", message: "hello", at: date("2026-03-04 05:06:07"))

        XCTAssertEqual(file.path, fallback)
        XCTAssertEqual(try contents(fallback), "[2026-03-04 05:06:07] INFO  hello\n")
    }

    func testLaunchdTrimmerTruncatesOnlyLargeCaptureFiles() throws {
        let fm = FileManager.default
        let big = "\(directory!)/launchd-com.example.hourly.log"
        let small = "\(directory!)/launchd-com.example.daily.log"
        let other = "\(directory!)/reportmate.log"
        fm.createFile(atPath: big, contents: Data(repeating: 0x61, count: 2_048))
        fm.createFile(atPath: small, contents: Data(repeating: 0x61, count: 512))
        fm.createFile(atPath: other, contents: Data(repeating: 0x61, count: 2_048))

        let trimmed = LaunchdLogTrimmer.trim(directory: directory, limit: 1_024)

        XCTAssertEqual(trimmed, ["launchd-com.example.hourly.log"])
        XCTAssertEqual((try fm.attributesOfItem(atPath: big))[.size] as? Int, 0)
        XCTAssertEqual((try fm.attributesOfItem(atPath: small))[.size] as? Int, 512)
        XCTAssertEqual((try fm.attributesOfItem(atPath: other))[.size] as? Int, 2_048)
    }
}
