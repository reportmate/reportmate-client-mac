import Foundation

/// Time formatting that matches the web dashboard's `time.ts` word for word,
/// so "3 hours ago" reads the same in both apps.
public enum TimeFormatting {
    /// `formatRelativeTime`: "just now", "5 minutes ago", "2 days ago", "never".
    public static func relative(_ date: Date?, now: Date = Date()) -> String {
        guard let date else { return "never" }
        let diff = now.timeIntervalSince(date)
        if diff < 0 { return "just now" }
        let seconds = Int(diff)
        let minutes = seconds / 60
        let hours = minutes / 60
        let days = hours / 24
        if seconds < 10 { return "just now" }
        if seconds < 60 { return "\(seconds) seconds ago" }
        if minutes < 60 { return minutes == 1 ? "1 minute ago" : "\(minutes) minutes ago" }
        if hours < 24 { return hours == 1 ? "1 hour ago" : "\(hours) hours ago" }
        return days == 1 ? "1 day ago" : "\(days) days ago"
    }

    public static func relative(_ text: String?, now: Date = Date()) -> String {
        guard let text, !text.isEmpty else { return "never" }
        guard let date = FlexibleDate.parse(text) else { return "unknown" }
        return relative(date, now: now)
    }

    /// `formatExactTime`: `2026.09.09 14:05:33` in local time.
    public static func exact(_ date: Date?) -> String {
        guard let date else { return "Unknown" }
        return exactFormatter.string(from: date)
    }

    public static func exact(_ text: String?) -> String {
        exact(FlexibleDate.parse(text))
    }

    /// `formatBootTime`: `Jan 14, 2026 11:32 PM`.
    public static func medium(_ date: Date?) -> String {
        guard let date else { return "Unknown" }
        return mediumFormatter.string(from: date)
    }

    public static func medium(_ text: String?) -> String {
        medium(FlexibleDate.parse(text))
    }

    /// `Sep 9, 2026` (the web's `toLocaleDateString` with short month).
    public static func shortDate(_ date: Date?) -> String {
        guard let date else { return "Unknown" }
        return shortDateFormatter.string(from: date)
    }

    public static func shortDate(_ text: String?) -> String {
        guard let text, !text.isEmpty else { return "Unknown" }
        guard let d = FlexibleDate.parse(text) else { return text }
        return shortDate(d)
    }

    /// Duration in seconds rendered as `1h 05m`, `12m 30s` or `45s`.
    public static func duration(seconds: Double) -> String {
        guard seconds.isFinite, seconds >= 0 else { return "—" }
        let total = Int(seconds.rounded())
        let h = total / 3600
        let m = (total % 3600) / 60
        let s = total % 60
        if h > 0 { return String(format: "%dh %02dm", h, m) }
        if m > 0 { return String(format: "%dm %02ds", m, s) }
        return "\(s)s"
    }

    /// Hours rendered as `12.5h` or `45m`.
    public static func hours(_ hours: Double) -> String {
        guard hours.isFinite, hours >= 0 else { return "—" }
        if hours < 1 { return "\(Int((hours * 60).rounded()))m" }
        if hours < 10 { return String(format: "%.1fh", hours) }
        return "\(Int(hours.rounded()))h"
    }

    private static let exactFormatter: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy.MM.dd HH:mm:ss"
        return f
    }()

    private static let mediumFormatter: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US")
        f.dateFormat = "MMM d, yyyy h:mm a"
        return f
    }()

    private static let shortDateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US")
        f.dateFormat = "MMM d, yyyy"
        return f
    }()
}

/// Byte and count formatting shared by hardware and storage views.
public enum ByteFormatting {
    /// `formatBytes`: `512 GB`, `16 GB`, `1.5 TB`.
    public static func bytes(_ value: Double) -> String {
        guard value > 0, value.isFinite else { return "0 Bytes" }
        let units = ["Bytes", "KB", "MB", "GB", "TB", "PB"]
        let i = min(Int(log(value) / log(1024)), units.count - 1)
        let scaled = value / pow(1024, Double(i))
        let rounded = (scaled * 100).rounded() / 100
        if rounded == rounded.rounded() { return "\(Int(rounded)) \(units[i])" }
        return String(format: "%g %@", rounded, units[i])
    }

    public static func gigabytes(_ bytes: Double) -> String {
        guard bytes > 0 else { return "Unknown" }
        return "\(Int((bytes / 1_073_741_824).rounded())) GB"
    }

    public static func count(_ n: Int) -> String {
        countFormatter.string(from: NSNumber(value: n)) ?? String(n)
    }

    private static let countFormatter: NumberFormatter = {
        let f = NumberFormatter()
        f.numberStyle = .decimal
        return f
    }()
}
