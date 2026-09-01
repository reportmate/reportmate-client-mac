import Foundation

/// Keeps the per-daemon launchd capture files small.
///
/// launchd appends a daemon's stdout and stderr to
/// `launchd-<label>.log` beside the client's own log. Those files exist so a
/// crash leaves a trace, not as a log, so any that has grown past `limit`
/// bytes is emptied at the next client start. Nothing rotates them.
public enum LaunchdLogTrimmer {
    public static let defaultLimit = 1_048_576

    /// Truncates every `launchd-*.log` in `directory` larger than `limit` bytes.
    /// Returns the names that were truncated.
    @discardableResult
    public static func trim(directory: String, limit: Int = defaultLimit) -> [String] {
        let fm = FileManager.default
        guard let names = try? fm.contentsOfDirectory(atPath: directory) else { return [] }
        var trimmed: [String] = []
        for name in names where name.hasPrefix("launchd-") && name.hasSuffix(".log") {
            let path = "\(directory)/\(name)"
            guard let attrs = try? fm.attributesOfItem(atPath: path),
                  let size = (attrs[.size] as? NSNumber)?.intValue, size > limit else { continue }
            if truncate(path, 0) == 0 {
                trimmed.append(name)
            }
        }
        return trimmed
    }
}
