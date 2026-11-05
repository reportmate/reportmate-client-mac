import Foundation

/// Turns the raw output of the macOS detection sources into rows shaped like the Windows
/// client's `detections` entries, so the API reads both platforms the same way.
///
/// Row keys follow the Windows `DetectionAlert` model: threatId, threatName, severity,
/// category, status, actionTaken, source, filePath, processName, user, description,
/// detectedAt, count, firstSeenAt, lastSeenAt. A field the source does not report is left out
/// rather than filled with a guess; in particular neither XProtect nor `mdatp threat list`
/// reports a severity, so Mac rows carry none.
enum ThreatDetections {

    /// Detections older than this are not read from the unified log.
    static let logWindowDays = 30

    /// Upper bound on detection rows sent per device, newest first.
    static let maxRows = 200

    /// Upper bound on the raw text kept in `description`.
    static let maxDescriptionLength = 2000

    static let xprotectDirectory = "/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS"
    static let xprotectPluginPrefix = "XProtectRemediator"

    // MARK: - XProtect Remediator

    /// Unified log predicate for the structured result each XProtect Remediator plugin logs
    /// after a scan. Clean scans are filtered out in the predicate so they never cross the pipe.
    static let xprotectPredicate = """
        subsystem == "com.apple.XProtectFramework.PluginAPI" AND category == "XPEvent.structured" \
        AND NOT eventMessage CONTAINS "NoThreatDetected"
        """

    /// XProtect Remediator status messages that mean a threat was found. Everything else the
    /// plugins log (Success, NoThreatDetected, PluginCanceled, ...) is a scan outcome, not a
    /// detection.
    static func isThreatStatus(_ status: String) -> Bool {
        let lower = status.lowercased()
        if lower == "failedtoremediate" { return true }
        return lower.contains("threat") && lower != "nothreatdetected"
    }

    static func xprotectAction(_ status: String) -> String? {
        switch status {
        case "ThreatRemediated": return "Remediated"
        case "ThreatPartiallyRemediated": return "PartiallyRemediated"
        case "ThreatDetectedRemediatorDispatched": return "RemediatorDispatched"
        case "FailedToRemediate": return "RemediationFailed"
        case "ThreatDetected": return "NoAction"
        default: return nil
        }
    }

    /// Parses `log show --style ndjson` output for the XProtect Remediator structured events.
    static func parseXProtectRemediatorLog(_ ndjson: String) -> [[String: Any]] {
        var rows: [[String: Any]] = []
        for line in ndjson.split(whereSeparator: \.isNewline) {
            guard let data = line.data(using: .utf8),
                  let event = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let message = event["eventMessage"] as? String,
                  let messageData = message.data(using: .utf8),
                  let payload = try? JSONSerialization.jsonObject(with: messageData) as? [String: Any],
                  let status = payload["status_message"] as? String,
                  isThreatStatus(status) else {
                continue
            }

            let imagePath = event["processImagePath"] as? String ?? ""
            let plugin = (imagePath as NSString).lastPathComponent
            var family = plugin.hasPrefix(xprotectPluginPrefix)
                ? String(plugin.dropFirst(xprotectPluginPrefix.count))
                : plugin
            if family.isEmpty { family = plugin }

            var row: [String: Any] = [
                "source": "XProtectRemediator",
                "category": "Malware",
                "status": status,
                "description": String(message.prefix(maxDescriptionLength))
            ]
            if !plugin.isEmpty { row["threatId"] = plugin }
            if !family.isEmpty { row["threatName"] = family }
            if let action = xprotectAction(status) { row["actionTaken"] = action }
            if let stamp = event["timestamp"] as? String, let iso = isoFromLogTimestamp(stamp) {
                row["detectedAt"] = iso
            }
            if let path = firstPath(in: payload["caused_by"]) { row["filePath"] = path }
            rows.append(row)
        }
        return rows
    }

    /// `log show` timestamps look like `2026-11-04 20:17:55.870946-0700`.
    static func isoFromLogTimestamp(_ stamp: String) -> String? {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        for format in ["yyyy-MM-dd HH:mm:ss.SSSSSSZ", "yyyy-MM-dd HH:mm:ssZ"] {
            formatter.dateFormat = format
            if let date = formatter.date(from: stamp) {
                return iso8601(date)
            }
        }
        return nil
    }

    /// The first file path named in an XProtect `caused_by` list, whose entries are either
    /// path strings or objects carrying one.
    static func firstPath(in value: Any?) -> String? {
        guard let list = value as? [Any] else { return nil }
        for item in list {
            if let text = item as? String, text.hasPrefix("/") { return text }
            if let dict = item as? [String: Any] {
                for key in ["path", "file_path", "filePath", "file", "url"] {
                    if let text = dict[key] as? String, !text.isEmpty {
                        return text.hasPrefix("file://") ? (URL(string: text)?.path ?? text) : text
                    }
                }
            }
        }
        return nil
    }

    // MARK: - Microsoft Defender

    /// Parses `mdatp threat list --output json`. Returns nil when the output is not a JSON list,
    /// so an unreadable answer is never mistaken for "no threats".
    static func parseDefenderThreatList(_ output: String) -> [[String: Any]]? {
        let trimmed = output.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let data = trimmed.data(using: .utf8),
              let parsed = try? JSONSerialization.jsonObject(with: data) else {
            return nil
        }
        let list: [Any]
        if let array = parsed as? [Any] {
            list = array
        } else if let dict = parsed as? [String: Any], let array = (dict["threats"] ?? dict["value"]) as? [Any] {
            list = array
        } else {
            return nil
        }

        var rows: [[String: Any]] = []
        for case let threat as [String: Any] in list {
            guard let name = string(threat, ["name", "threatName"]) else { continue }
            var row: [String: Any] = ["source": "MicrosoftDefender", "threatName": name]
            if let id = string(threat, ["id", "threatId"]) { row["threatId"] = id }
            if let type = string(threat, ["threatType", "type", "category"]) { row["category"] = type }
            if let status = string(threat, ["threatStatus", "status", "state"]) {
                row["status"] = status
                row["actionTaken"] = status
            }
            if let severity = string(threat, ["severity"]) { row["severity"] = severity }
            if let detected = date(threat["detectionTime"] ?? threat["detectedAt"] ?? threat["detectionTimestamp"]) {
                row["detectedAt"] = detected
            }
            if let path = string(threat, ["path", "filePath"]) ?? firstPath(in: threat["resources"]) {
                row["filePath"] = path
            }
            rows.append(row)
        }
        return rows
    }

    private static func string(_ dict: [String: Any], _ keys: [String]) -> String? {
        for key in keys {
            if let text = dict[key] as? String {
                let value = text.trimmingCharacters(in: .whitespacesAndNewlines)
                if !value.isEmpty { return value }
            }
        }
        return nil
    }

    /// Epoch seconds or milliseconds, as a number or a numeric string, or an ISO 8601 string.
    static func date(_ value: Any?) -> String? {
        var seconds: Double?
        if let number = value as? NSNumber, !(value is Bool) {
            seconds = number.doubleValue
        } else if let text = value as? String {
            if let number = Double(text) {
                seconds = number
            } else if let parsed = ISO8601DateFormatter().date(from: text) {
                return iso8601(parsed)
            }
        }
        guard var epoch = seconds, epoch > 0 else { return nil }
        if epoch > 100_000_000_000 { epoch /= 1000 }
        return iso8601(Date(timeIntervalSince1970: epoch))
    }

    static func iso8601(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.timeZone = TimeZone(identifier: "UTC")
        return formatter.string(from: date)
    }

    // MARK: - Collapse

    /// Folds repeats of the same threat, status and path into one row with a count and the
    /// first and last time it was seen, newest first, bounded at `maxRows`.
    static func collapse(_ rows: [[String: Any]]) -> [[String: Any]] {
        var order: [String] = []
        var merged: [String: [String: Any]] = [:]
        for row in rows {
            let key = ["source", "threatId", "threatName", "status", "filePath"]
                .map { row[$0] as? String ?? "" }
                .joined(separator: "\u{1F}")
            let seen = row["detectedAt"] as? String
            if var existing = merged[key] {
                existing["count"] = (existing["count"] as? Int ?? 1) + 1
                if let seen {
                    if (existing["firstSeenAt"] as? String).map({ seen < $0 }) ?? true { existing["firstSeenAt"] = seen }
                    if (existing["lastSeenAt"] as? String).map({ seen > $0 }) ?? true {
                        existing["lastSeenAt"] = seen
                        existing["detectedAt"] = seen
                        if let description = row["description"] { existing["description"] = description }
                    }
                }
                merged[key] = existing
            } else {
                var first = row
                first["count"] = 1
                if let seen {
                    first["firstSeenAt"] = seen
                    first["lastSeenAt"] = seen
                }
                merged[key] = first
                order.append(key)
            }
        }
        let collapsed = order.compactMap { merged[$0] }
        let sorted = collapsed.sorted {
            ($0["lastSeenAt"] as? String ?? "") > ($1["lastSeenAt"] as? String ?? "")
        }
        return Array(sorted.prefix(maxRows))
    }
}

/// Bounds the SOFA unpatched CVE list sent per device.
enum UnpatchedCVEList {

    /// Enough for any supported macOS release, while keeping the check-in payload bounded.
    static let limit = 1000

    /// Returns the entries to send, the full count collected and whether the list was cut.
    static func bounded(_ entries: [[String: Any]], limit: Int = limit) -> (entries: [[String: Any]], total: Int, truncated: Bool) {
        (Array(entries.prefix(limit)), entries.count, entries.count > limit)
    }
}
