import Foundation

/// This Mac's own report, assembled from the runner's cache without the API.
public struct LocalReport: Sendable {
    public let device: DeviceDetail
    public let events: [FleetEvent]
    public let collectedAt: Date?
    public let runCount: Int
    public let cacheDirectory: URL
}

/// Reads `/Library/Managed Reports/cache/<run>/event.json`, the payload the
/// runner sent (or would have sent) on each run. Every run carries only the
/// modules it collected, so the newest copy of each module is taken across
/// runs and the run events are gathered into one feed.
public enum LocalReportStore {
    public static let defaultCache = URL(fileURLWithPath: "/Library/Managed Reports/cache")
    /// Runs read newest first; older runs only add modules the newer ones lack.
    public static let maxRuns = 120

    /// Whether the cache exists and holds at least one readable run.
    public static func isAvailable(at cache: URL = defaultCache) -> Bool {
        !runDirectories(in: cache).isEmpty
    }

    static func runDirectories(in cache: URL) -> [URL] {
        guard let entries = try? FileManager.default.contentsOfDirectory(at: cache, includingPropertiesForKeys: [.isDirectoryKey], options: [.skipsHiddenFiles]) else { return [] }
        return entries.filter { url in
            (try? url.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true
                && FileManager.default.isReadableFile(atPath: url.appendingPathComponent("event.json").path)
        }
        .sorted { $0.lastPathComponent > $1.lastPathComponent }
    }

    /// `nil` when there is no cache; throws when a run cannot be parsed.
    public static func load(from cache: URL = defaultCache, now: Date = Date()) throws -> LocalReport? {
        let runs = Array(runDirectories(in: cache).prefix(maxRuns))
        guard !runs.isEmpty else { return nil }
        var modules: [String: JSONValue] = [:]
        var events: [FleetEvent] = []
        var serial = "", deviceId = "", platform = "macOS", clientVersion: String?
        var newest: Date?
        for run in runs {
            let json = try JSONValue.parse(try Data(contentsOf: run.appendingPathComponent("event.json")))
            let meta = json["metadata"]
            if serial.isEmpty { serial = meta["serialNumber"].nonEmptyString ?? "" }
            if deviceId.isEmpty { deviceId = meta["deviceId"].nonEmptyString ?? "" }
            if let p = meta["platform"].nonEmptyString { platform = p }
            if clientVersion == nil { clientVersion = meta["clientVersion"].nonEmptyString }
            let collected = FlexibleDate.parse(meta["collectedAt"])
            if newest == nil { newest = collected }
            for (key, value) in json.object ?? [:] where key != "metadata" && key != "events" {
                if modules[key] == nil, !value.isNull { modules[key] = value }
            }
            for (i, e) in json["events"].elements.enumerated() {
                let stamp = e.firstString("timestamp", "ts") ?? meta["collectedAt"].string
                var fields: [String: JSONValue] = [
                    "id": .string("\(run.lastPathComponent)-\(i)"),
                    "device": .string(serial.isEmpty ? deviceId : serial),
                    "platform": .string(platform),
                    "kind": .string(e.firstString("eventType", "kind") ?? "info"),
                    "message": e["message"],
                ]
                if let stamp { fields["ts"] = .string(stamp) }
                let details = e.first("details", "payload")
                if !details.isNull { fields["payload"] = details }
                events.append(FleetEvent(json: .object(fields)))
            }
        }
        var record: [String: JSONValue] = [
            "serialNumber": .string(serial),
            "deviceId": .string(deviceId.isEmpty ? serial : deviceId),
            "platform": .string(platform),
            "modules": .object(modules),
        ]
        if let clientVersion { record["clientVersion"] = .string(clientVersion) }
        if let newest { record["lastSeen"] = .string(ISO8601DateFormatter().string(from: newest)) }
        let device = DeviceDetail(json: .object(record), now: now)
        return LocalReport(device: device, events: events.sorted { ($0.ts ?? .distantPast) > ($1.ts ?? .distantPast) }, collectedAt: newest, runCount: runs.count, cacheDirectory: cache)
    }
}
