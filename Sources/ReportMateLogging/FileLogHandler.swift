import Foundation
import Logging

/// swift-log handler that appends one line per record to a daily-rolled file.
///
/// Line format: `[yyyy-MM-dd HH:mm:ss] LEVEL message`, local time, level
/// left-aligned in a five-character column so `INFO`/`WARN` lines carry two
/// spaces and `DEBUG`/`ERROR` lines carry one. Every handler created for the
/// same `RollingLogFile` shares the file and its lock, so a process with many
/// loggers still writes one ordered stream.
public struct FileLogHandler: LogHandler, Sendable {
    public var logLevel: Logger.Level
    public var metadata: Logger.Metadata = [:]

    private let file: RollingLogFile

    public init(file: RollingLogFile, level: Logger.Level = .info) {
        self.file = file
        self.logLevel = level
    }

    public subscript(metadataKey key: String) -> Logger.Metadata.Value? {
        get { metadata[key] }
        set { metadata[key] = newValue }
    }

    public func log(
        level: Logger.Level,
        message: Logger.Message,
        metadata: Logger.Metadata?,
        source: String,
        file: String,
        function: String,
        line: UInt
    ) {
        self.file.write(level: Self.levelName(level), message: message.description)
    }

    /// Collapses swift-log's eight levels onto the four the estate convention uses.
    public static func levelName(_ level: Logger.Level) -> String {
        switch level {
        case .trace, .debug: return "DEBUG"
        case .info, .notice: return "INFO"
        case .warning: return "WARN"
        case .error, .critical: return "ERROR"
        }
    }
}

/// An append-only log file that rolls on the first write of a new local day.
///
/// The current file lives at `path`. When a write finds the file was last
/// written on an earlier day it is renamed to `<stem>-yyyy-MM-dd.log` (the
/// date of that last write) and a fresh file is started; only the newest
/// `keep` rolled files are retained. Several processes may share the file:
/// appends use `O_APPEND`, and the roll re-checks the file on disk before
/// renaming so a sibling that already rolled it is not undone.
///
/// If the directory cannot be created or the file cannot be opened for
/// writing (for example when running unprivileged) the file falls back to
/// `fallbackPath` with the same rules. `path` reports where lines end up.
public final class RollingLogFile: @unchecked Sendable {
    public let path: String
    public let keep: Int

    private let lock = NSLock()
    private let calendar: Calendar
    private var descriptor: Int32 = -1
    private var openedDay: DateComponents?
    private let lineFormatter: DateFormatter
    private let dayFormatter: DateFormatter

    /// - Parameters:
    ///   - path: Preferred location of the live log file.
    ///   - fallbackPath: Used when `path` is not writable. Pass `nil` to
    ///     disable the fallback; writes are then dropped silently.
    ///   - keep: Number of rolled daily files to retain.
    ///   - timeZone: Time zone that defines "the day"; local by default.
    public init(
        path: String,
        fallbackPath: String? = nil,
        keep: Int = 30,
        timeZone: TimeZone = .current
    ) {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = timeZone
        self.calendar = calendar
        self.keep = keep

        lineFormatter = DateFormatter()
        lineFormatter.locale = Locale(identifier: "en_US_POSIX")
        lineFormatter.timeZone = timeZone
        lineFormatter.dateFormat = "yyyy-MM-dd HH:mm:ss"

        dayFormatter = DateFormatter()
        dayFormatter.locale = Locale(identifier: "en_US_POSIX")
        dayFormatter.timeZone = timeZone
        dayFormatter.dateFormat = "yyyy-MM-dd"

        if Self.prepare(path: path) {
            self.path = path
        } else if let fallbackPath, Self.prepare(path: fallbackPath) {
            self.path = fallbackPath
        } else {
            self.path = path
        }
    }

    deinit {
        if descriptor >= 0 { close(descriptor) }
    }

    /// Default fallback for a file that would normally live under `/Library`.
    public static func userFallbackPath(for path: String) -> String {
        let name = (path as NSString).lastPathComponent
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return "\(home)/Library/Logs/ReportMate/\(name)"
    }

    /// Appends one formatted line, rolling the file first if the day changed.
    public func write(level: String, message: String, at date: Date = Date()) {
        let stamp = lock.withLock { lineFormatter.string(from: date) }
        let paddedLevel = level.padding(toLength: max(5, level.count), withPad: " ", startingAt: 0)
        append("[\(stamp)] \(paddedLevel) \(message)\n", at: date)
    }

    /// Appends raw text, rolling the file first if the day changed.
    public func append(_ text: String, at date: Date = Date()) {
        lock.lock()
        defer { lock.unlock() }

        let today = calendar.dateComponents([.year, .month, .day], from: date)
        if descriptor < 0 || openedDay != today {
            reopen(for: date, today: today)
        }
        guard descriptor >= 0 else { return }

        let bytes = Array(text.utf8)
        var offset = 0
        while offset < bytes.count {
            let written = bytes.withUnsafeBufferPointer {
                Darwin.write(descriptor, $0.baseAddress! + offset, $0.count - offset)
            }
            if written <= 0 {
                if errno == EINTR { continue }
                return
            }
            offset += written
        }
    }

    // MARK: - Rolling

    private func reopen(for date: Date, today: DateComponents) {
        if descriptor >= 0 {
            close(descriptor)
            descriptor = -1
        }
        rollIfStale(now: date, today: today)
        descriptor = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0o644)
        openedDay = today
    }

    /// Renames the live file if its last write was on an earlier day than `today`.
    private func rollIfStale(now: Date, today: DateComponents) {
        let fm = FileManager.default
        guard let attrs = try? fm.attributesOfItem(atPath: path),
              let modified = attrs[.modificationDate] as? Date,
              (attrs[.size] as? NSNumber)?.intValue ?? 0 > 0 else { return }

        let lastDay = calendar.dateComponents([.year, .month, .day], from: modified)
        guard let lastDate = calendar.date(from: lastDay),
              let todayDate = calendar.date(from: today),
              lastDate < todayDate else { return }

        let rolled = rolledPath(for: modified)
        if fm.fileExists(atPath: rolled) {
            // A sibling process rolled the same day already; merge rather than clobber.
            if let handle = FileHandle(forWritingAtPath: rolled),
               let data = fm.contents(atPath: path) {
                handle.seekToEndOfFile()
                handle.write(data)
                try? handle.close()
                try? fm.removeItem(atPath: path)
            }
        } else {
            try? fm.moveItem(atPath: path, toPath: rolled)
        }
        prune()
    }

    private var stem: String {
        ((path as NSString).lastPathComponent as NSString).deletingPathExtension
    }

    private var directory: String {
        (path as NSString).deletingLastPathComponent
    }

    private func rolledPath(for date: Date) -> String {
        "\(directory)/\(stem)-\(dayFormatter.string(from: date)).log"
    }

    /// Deletes rolled files beyond the newest `keep`, judged by the date in the name.
    private func prune() {
        let fm = FileManager.default
        guard let names = try? fm.contentsOfDirectory(atPath: directory) else { return }
        let rolled = names.filter { Self.isRolledName($0, stem: stem) }.sorted(by: >)
        for name in rolled.dropFirst(keep) {
            try? fm.removeItem(atPath: "\(directory)/\(name)")
        }
    }

    static func isRolledName(_ name: String, stem: String) -> Bool {
        let prefix = "\(stem)-"
        guard name.hasPrefix(prefix), name.hasSuffix(".log") else { return false }
        let datePart = name.dropFirst(prefix.count).dropLast(4)
        guard datePart.count == 10 else { return false }
        for (index, character) in datePart.enumerated() {
            if index == 4 || index == 7 {
                if character != "-" { return false }
            } else if !character.isNumber {
                return false
            }
        }
        return true
    }

    /// Creates the parent directory (0755) and checks the file can be appended to.
    private static func prepare(path: String) -> Bool {
        let directory = (path as NSString).deletingLastPathComponent
        var isDirectory: ObjCBool = false
        if !FileManager.default.fileExists(atPath: directory, isDirectory: &isDirectory) {
            do {
                try FileManager.default.createDirectory(
                    atPath: directory,
                    withIntermediateDirectories: true,
                    attributes: [.posixPermissions: 0o755]
                )
            } catch {
                return false
            }
        } else if !isDirectory.boolValue {
            return false
        }
        let fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0o644)
        guard fd >= 0 else { return false }
        close(fd)
        return true
    }
}
