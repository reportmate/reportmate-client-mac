import Foundation

/// Whether the last search for Apple software updates succeeded, reported as the system
/// module's `updateSearch` beside the pending updates.
///
/// The runner lists pending updates from the cached scan (`softwareupdate --list --no-scan`), so
/// the search itself is the scan macOS runs on its own schedule. Its outcome is recorded in
/// `/Library/Preferences/com.apple.SoftwareUpdate.plist`: `LastSessionSuccessful`,
/// `LastResultCode` and `LastSuccessfulDate`. When the runner's own `softwareupdate` call fails,
/// that failure is reported instead, because the pending list sent with it cannot be trusted.
enum UpdateSearch {

    static let preferencesPath = "/Library/Preferences/com.apple.SoftwareUpdate.plist"

    /// Builds `updateSearch` from the SoftwareUpdate preferences and the runner's own
    /// `softwareupdate --list --no-scan` result. Returns nil when neither says anything, so a
    /// device with no record is reported as not reported rather than as succeeded.
    static func status(
        preferences: [String: Any]?,
        listExitCode: Int32?,
        listError: String?,
        now: Date = Date()
    ) -> [String: Any]? {
        let lastSuccess = (preferences?["LastSuccessfulDate"] as? Date)
            ?? (preferences?["LastFullSuccessfulDate"] as? Date)

        if let code = listExitCode, code != 0 {
            let detail = (listError ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            var result: [String: Any] = [
                "status": "failed",
                "error": detail.isEmpty
                    ? "softwareupdate --list exited with status \(code)"
                    : String(detail.prefix(500)),
                "checkedAt": ThreatDetections.iso8601(now),
                "source": "softwareupdate"
            ]
            if let lastSuccess { result["lastSuccessfulAt"] = ThreatDetections.iso8601(lastSuccess) }
            return result
        }

        guard let preferences, let successful = boolValue(preferences["LastSessionSuccessful"]) else {
            return nil
        }

        var result: [String: Any] = ["source": "SoftwareUpdate"]
        let resultCode = (preferences["LastResultCode"] as? NSNumber)?.intValue
        if let resultCode { result["resultCode"] = resultCode }
        if let lastSuccess { result["lastSuccessfulAt"] = ThreatDetections.iso8601(lastSuccess) }

        if successful {
            result["status"] = "succeeded"
            result["error"] = NSNull()
            result["checkedAt"] = lastSuccess.map(ThreatDetections.iso8601) ?? NSNull()
        } else {
            result["status"] = "failed"
            result["error"] = resultCode.map { "The last software update scan failed (result code \($0))" }
                ?? "The last software update scan failed"
            // macOS records when a scan last succeeded, not when the failed one ran.
            result["checkedAt"] = NSNull()
        }
        return result
    }

    private static func boolValue(_ value: Any?) -> Bool? {
        if let bool = value as? Bool { return bool }
        if let number = value as? NSNumber { return number.intValue != 0 }
        return nil
    }

    /// Reads the SoftwareUpdate preferences, or nil when the file is missing or unreadable.
    static func readPreferences(path: String = preferencesPath) -> [String: Any]? {
        guard let data = FileManager.default.contents(atPath: path) else { return nil }
        return (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any]
    }
}
