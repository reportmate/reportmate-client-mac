import Foundation

/// Records whether osquery actually worked during a collection run.
///
/// Every module reaches osquery through `executeWithFallback`, which drops to a
/// bash equivalent when a query fails and returns an empty dictionary when that
/// fails too. Both paths were silent: an osquery that no longer ran on the host
/// OS left the device checking in on schedule while reporting almost nothing,
/// and nothing in the payload said why. This type makes that state explicit so
/// it can travel to the API as an event instead of being inferred from missing
/// cards in the UI.
public actor OSQueryHealth {
    public static let shared = OSQueryHealth()

    private var probed = false
    private var healthy = false
    private var version: String?
    private var failureReason: String?
    private var degradedModules: Set<String> = []
    private var starvedModules: Set<String> = []

    private init() {}

    /// Record the outcome of the once-per-run probe.
    func recordProbe(healthy: Bool, version: String?, failureReason: String?) {
        self.probed = true
        self.healthy = healthy
        self.version = version
        self.failureReason = failureReason
    }

    func hasProbed() -> Bool { probed }

    /// A module fell back to bash because osquery could not answer.
    func recordDegraded(module: String) { degradedModules.insert(module) }

    /// A module got nothing from osquery *or* bash — it reports no data at all.
    func recordStarved(module: String) { starvedModules.insert(module) }

    public func snapshot() -> Snapshot {
        Snapshot(
            probed: probed,
            healthy: healthy,
            version: version,
            failureReason: failureReason,
            degradedModules: degradedModules.sorted(),
            starvedModules: starvedModules.sorted()
        )
    }

    public struct Snapshot: Sendable {
        public let probed: Bool
        public let healthy: Bool
        public let version: String?
        public let failureReason: String?
        public let degradedModules: [String]
        public let starvedModules: [String]

        /// True when this run collected less than it should have.
        public var isDegraded: Bool {
            !healthy || !starvedModules.isEmpty || !degradedModules.isEmpty
        }

        /// True when the run is materially broken rather than merely partial.
        public var isCritical: Bool {
            !healthy || !starvedModules.isEmpty
        }

        public var summary: String {
            if !healthy {
                return "osquery unavailable: \(failureReason ?? "unknown failure")"
            }
            if !starvedModules.isEmpty {
                return "osquery healthy but \(starvedModules.count) module(s) collected no data: \(starvedModules.joined(separator: ", "))"
            }
            return "osquery degraded: \(degradedModules.count) module(s) used bash fallback"
        }

        public var details: [String: String] {
            [
                "osqueryHealthy": String(healthy),
                "osqueryVersion": version ?? "unknown",
                "failureReason": failureReason ?? "",
                "degradedModules": degradedModules.joined(separator: ", "),
                "starvedModules": starvedModules.joined(separator: ", ")
            ]
        }
    }
}
