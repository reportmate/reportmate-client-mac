import Foundation

/// What an installs event's payload says happened in the run: the packages
/// that changed state, with counts. Port of `parseInstallsEventPayload`.
public struct LastRunSummary: Sendable, Hashable {
    public struct Item: Sendable, Hashable, Identifiable {
        public let name: String
        public let version: String
        public let status: String
        public var id: String { "\(name)|\(version)|\(status)" }
        public init(name: String, version: String, status: String) { self.name = name; self.version = version; self.status = status }
    }

    public let runType: String?
    public let successCount: Int?
    public let errorCount: Int?
    public let items: [Item]

    public var hasItems: Bool { !items.isEmpty }
    public var hasCounts: Bool { successCount != nil || errorCount != nil }
    public var isEmpty: Bool { !hasItems && !hasCounts }

    /// Any package in a warning, error, pending or removed state.
    public var hasIssues: Bool {
        items.contains { ["warning", "error", "failed", "pending", "removed"].contains($0.status.lowercased()) }
    }

    public var title: String { hasIssues ? "Packages with Issues" : "Last Run Summary" }

    /// `nil` when the payload is not an installs run.
    public static func parse(_ payload: JSONValue) -> LastRunSummary? {
        guard payload.object != nil, let p = installsPayload(in: payload) else { return nil }
        let runType = p.firstString("run_type", "runType")
        let successCount = p.first("success_count", "successCount").int
        let errorCount = p.first("error_count", "errorCount").int
        let installsData = p["full_installs_data"]
        guard installsData.object != nil else {
            if successCount != nil || errorCount != nil { return LastRunSummary(runType: runType, successCount: successCount, errorCount: errorCount, items: []) }
            return nil
        }

        var rawItems = installsData["cimian"]["items"].elements + installsData["munki"]["items"].elements
        if rawItems.isEmpty { rawItems = installsData["items"].elements }
        func summary(_ items: [Item]) -> LastRunSummary { LastRunSummary(runType: runType, successCount: successCount, errorCount: errorCount, items: items) }
        if rawItems.isEmpty { return summary(directPackageRefs(p)) }

        func names(_ value: JSONValue) -> [String] {
            value.elements.compactMap { $0.string ?? $0["name"].nonEmptyString }.filter { !$0.isEmpty }
        }
        let failed = names(p["failed_items"])
        let specific = failed + names(p["packages"]) + names(p["items"])
        if !specific.isEmpty {
            let wanted = Set(specific.map { $0.lowercased() })
            let matched = rawItems.compactMap { item -> Item? in
                let name = (item.firstString("itemName", "name", "displayName") ?? "").lowercased()
                guard wanted.contains(name) else { return nil }
                return Item(name: item.firstString("displayName", "name", "itemName") ?? "Unknown",
                            version: item.firstString("version", "installedVersion", "latestVersion") ?? "",
                            status: item.firstString("status", "currentStatus") ?? (failed.isEmpty ? "Installed" : "Error"))
            }
            if !matched.isEmpty { return summary(matched) }
        }

        var items: [Item] = []
        let session = installsData["cimian"]["sessions"].elements.first ?? installsData["recentSessions"].elements.first
        let sessionStart = session.flatMap { $0.firstString("start_time", "startTime") }.flatMap(FlexibleDate.parse)
        let sessionId = session.flatMap { $0.firstString("session_id", "sessionId") }
        if sessionStart != nil || sessionId != nil {
            for item in rawItems {
                guard let marker = item.firstString("lastSeenInSession", "last_seen_in_session") else { continue }
                if InstallsInfo.isCimianSessionId(marker) {
                    guard let sessionId, marker.trimmingCharacters(in: .whitespaces) == sessionId.trimmingCharacters(in: .whitespaces) else { continue }
                } else {
                    guard let sessionStart, let itemTime = FlexibleDate.parse(marker), itemTime >= sessionStart.addingTimeInterval(-60) else { continue }
                }
                items.append(Item(name: item.firstString("displayName", "name") ?? "Unknown",
                                  version: item.firstString("version", "installedVersion") ?? "",
                                  status: item.firstString("status", "currentStatus") ?? "Unknown"))
            }
        }
        if items.isEmpty {
            for item in rawItems {
                let status = (item.firstString("status", "currentStatus") ?? "").lowercased()
                let hasWarning = item.firstString("lastWarning", "last_warning") != nil
                let hasError = item.firstString("lastError", "last_error") != nil
                let nonStable = ["warning", "error", "pending", "removed", "pending update", "pending install", "failed"].contains(status)
                if hasWarning || hasError || nonStable {
                    items.append(Item(name: item.firstString("displayName", "name") ?? "Unknown",
                                      version: item.firstString("version", "installedVersion") ?? "",
                                      status: hasError ? "Error" : hasWarning ? "Warning" : (item.firstString("status", "currentStatus") ?? "Unknown")))
                }
            }
        }
        if items.isEmpty { items = directPackageRefs(p) }
        if items.isEmpty {
            var seen = Set<String>()
            for item in textItems(p["warnings"].string ?? "", status: "Warning") + textItems(p.firstString("errors", "error") ?? "", status: "Error") {
                if seen.insert(item.name.lowercased()).inserted { items.append(item) }
            }
        }
        return summary(items)
    }

    static func installsPayload(in payload: JSONValue) -> JSONValue? {
        if !payload["full_installs_data"].isNull || !payload["module_status"].isNull { return payload }
        if payload["isBundle"].boolish {
            for sub in payload["payloads"].elements {
                let p = sub["payload"]
                if !p["full_installs_data"].isNull || !p["module_status"].isNull { return p }
            }
        }
        return nil
    }

    /// Top-level `name: "1.2.3"` pairs, the shape some clients send.
    static func directPackageRefs(_ payload: JSONValue) -> [Item] {
        let skip: Set<String> = ["full_installs_data", "warnings", "errors", "run_type", "runType", "session_id", "module_status", "success_count", "error_count",
                                 "module_id", "collected_at", "client_version", "platform"]
        return (payload.object ?? [:]).sorted { $0.key < $1.key }.compactMap { key, value in
            guard !skip.contains(key), let s = value.string, s.range(of: #"^[\d.]+"#, options: .regularExpression) != nil else { return nil }
            return Item(name: key, version: s, status: "Installed")
        }
    }

    /// Package names pulled out of a run's warning or error text.
    static func textItems(_ text: String, status: String) -> [Item] {
        guard !text.trimmingCharacters(in: .whitespaces).isEmpty else { return [] }
        let segments = text.components(separatedBy: try! NSRegularExpression(pattern: #";\s*(?:WARNING|ERROR):\s*"#, options: .caseInsensitive))
            .map { $0.replacingOccurrences(of: #"^(?:WARNING|ERROR):\s*"#, with: "", options: [.regularExpression, .caseInsensitive]).trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && $0.range(of: #"^(?:warning|error)$"#, options: [.regularExpression, .caseInsensitive]) == nil }
        return segments.map { segment in
            if let m = capture(segment, #"\bfor\s+([A-Za-z0-9][\w.-]*)[\s;,.]*$"#) { return Item(name: m, version: "", status: status) }
            if let refs = capture(segment, #"^Package\s+[\w.]+\s+references are:\s*\[([^\]]+)\]"#) {
                let names = refs.components(separatedBy: "\"").enumerated().filter { $0.offset % 2 == 1 }.map(\.element)
                if let best = names.sorted(by: { $0.count < $1.count }).first { return Item(name: best, version: "", status: status) }
            }
            if let pkg = capture(segment, #"^Package\s+([\w.]+)"#) {
                let last = pkg.split(separator: ".").last.map(String.init) ?? pkg
                let readable = last.replacingOccurrences(of: #"([a-z])([A-Z])"#, with: "$1 $2", options: .regularExpression)
                return Item(name: readable, version: "", status: status)
            }
            return Item(name: segment.count > 70 ? String(segment.prefix(67)) + "..." : segment, version: "", status: status)
        }
    }

    private static func capture(_ s: String, _ pattern: String) -> String? {
        guard let re = try? NSRegularExpression(pattern: pattern, options: .caseInsensitive),
              let m = re.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)), m.numberOfRanges > 1,
              let r = Range(m.range(at: 1), in: s) else { return nil }
        return String(s[r])
    }
}

private extension String {
    func components(separatedBy re: NSRegularExpression) -> [String] {
        var parts: [String] = []
        var last = startIndex
        for m in re.matches(in: self, range: NSRange(startIndex..., in: self)) {
            guard let r = Range(m.range, in: self) else { continue }
            parts.append(String(self[last..<r.lowerBound]))
            last = r.upperBound
        }
        parts.append(String(self[last...]))
        return parts
    }
}
