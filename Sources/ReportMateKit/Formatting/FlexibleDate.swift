import Foundation

/// Parses the many timestamp shapes ReportMate data carries.
///
/// The API serialises Python `datetime.isoformat()`, which may or may not
/// have a timezone and may carry six fractional digits; the clients send
/// ISO 8601 with `Z`, plain `yyyy-MM-dd HH:mm:ss`, Unix seconds, and Unix
/// seconds with a fraction (`"1765940509.72615"`).
public enum FlexibleDate {
    nonisolated(unsafe) private static let isoFractional: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    nonisolated(unsafe) private static let iso: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()

    private static let formats: [String] = [
        "yyyy-MM-dd'T'HH:mm:ss.SSSSSSXXXXX",
        "yyyy-MM-dd'T'HH:mm:ss.SSSSSS",
        "yyyy-MM-dd'T'HH:mm:ssXXXXX",
        "yyyy-MM-dd'T'HH:mm:ss",
        "yyyy-MM-dd HH:mm:ss.SSSSSSXXXXX",
        "yyyy-MM-dd HH:mm:ss.SSSSSS",
        "yyyy-MM-dd HH:mm:ssXXXXX",
        "yyyy-MM-dd HH:mm:ss",
        "yyyy-MM-dd",
        "MM/dd/yyyy HH:mm:ss",
        "MM/dd/yyyy",
    ]

    nonisolated(unsafe) private static let formatters: [DateFormatter] = formats.map { format in
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(secondsFromGMT: 0)
        f.dateFormat = format
        return f
    }

    private static let lock = NSLock()

    /// Parse any supported timestamp representation. Returns nil for empty,
    /// `"null"`, `"undefined"` and anything unrecognised.
    public static func parse(_ value: String?) -> Date? {
        guard let raw = value?.trimmingCharacters(in: .whitespacesAndNewlines), !raw.isEmpty else { return nil }
        let lower = raw.lowercased()
        if lower == "null" || lower == "undefined" || lower == "none" || lower == "unknown" { return nil }

        // Unix seconds or milliseconds, possibly with a fraction.
        if let n = Double(raw), n > 0 {
            return fromUnix(n)
        }

        lock.lock(); defer { lock.unlock() }
        if let d = isoFractional.date(from: raw) { return d }
        if let d = iso.date(from: raw) { return d }
        for f in formatters {
            if let d = f.date(from: raw) { return d }
        }
        return nil
    }

    public static func parse(_ value: JSONValue) -> Date? {
        switch value {
        case .number(let n): return n > 0 ? fromUnix(n) : nil
        case .string(let s): return parse(s)
        default: return nil
        }
    }

    private static func fromUnix(_ n: Double) -> Date? {
        // 13-digit values are milliseconds; anything before the year 2000 is junk.
        let seconds = n > 10_000_000_000 ? n / 1000 : n
        let date = Date(timeIntervalSince1970: seconds)
        guard date.timeIntervalSince1970 > 946_684_800 else { return nil }
        return date
    }
}
