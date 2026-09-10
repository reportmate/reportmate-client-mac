import Foundation

/// Usage attached to an installed application: Windows attaches it to the
/// app, macOS keys watcher sessions by bundle path, and both send a per-day
/// history keyed by name. The three are merged, longest view wins.
public struct ApplicationUsage: Sendable, Hashable {
    public var launchCount = 0
    public var totalSeconds: Double = 0
    public var lastUsed: String?
    public var firstSeen: String?
    public var users: [String] = []
    public var activeNow = false
    public var daysSeen = 0

    public var uniqueUserCount: Int { users.count }
    public var averageSessionSeconds: Double? { launchCount > 0 ? totalSeconds / Double(launchCount) : nil }
    public var hasUsage: Bool { launchCount > 0 || totalSeconds > 0 }
}

/// One installed application row (port of the web `ApplicationInfo`).
public struct ApplicationItem: Sendable, Hashable, Identifiable {
    public var id: String
    public var name: String
    public var displayName: String
    public var version: String
    public var publisher: String
    public var category: String
    public var installDate: String?
    public var size: String?
    public var path: String?
    public var bundleId: String?
    public var source: String?
    public var architecture: String?
    public var nested: Bool
    public var signedBy: String?
    public var obtainedFrom: String?
    public var usage: ApplicationUsage?
    public var raw: JSONValue

    /// Name without the `.app` suffix.
    public var cleanName: String {
        (displayName.isEmpty ? name : displayName).replacingOccurrences(of: #"\.app$"#, with: "", options: .regularExpression)
    }

    public var hasUsage: Bool { usage?.hasUsage ?? false }
    public var usageSeconds: Double { usage?.totalSeconds ?? 0 }
    public var isRunning: Bool { usage?.activeNow ?? false }

    /// Publisher, or the bundle id or path when the publisher is unknown.
    public var secondaryLine: String {
        if publisher != "Unknown Publisher", !publisher.isEmpty {
            return bundleId.map { "\(publisher) · \($0)" } ?? publisher
        }
        return bundleId ?? path ?? ""
    }
}

public enum ApplicationUsageFilter: String, Sendable, CaseIterable, Identifiable {
    case all, used, active, unused
    public var id: String { rawValue }
    public var label: String {
        switch self {
        case .all: return "All"
        case .used: return "Used"
        case .active: return "Running"
        case .unused: return "No usage"
        }
    }
}

/// Port of the Applications tab's data assembly.
public struct ApplicationsInfo: Sendable, Hashable {
    public var applications: [ApplicationItem]
    public var activeSessionCount: Int
    public var historyDays: Int
    public var hasData: Bool
    public var raw: JSONValue

    /// Non-helper apps, most used first.
    public var baseApps: [ApplicationItem] { applications.filter { !$0.nested } }
    public var nestedCount: Int { applications.filter(\.nested).count }
    public var usedApps: [ApplicationItem] { baseApps.filter(\.hasUsage) }
    public var runningApps: [ApplicationItem] { baseApps.filter(\.isRunning) }
    public var unusedApps: [ApplicationItem] { baseApps.filter { !$0.hasUsage } }
    public var totalUsageSeconds: Double { usedApps.reduce(0) { $0 + $1.usageSeconds } }
    public var distinctUsers: Int { Set(applications.flatMap { $0.usage?.users ?? [] }).count }
    public var topApps: [ApplicationItem] { Array(usedApps.filter { $0.usageSeconds > 0 }.prefix(8)) }

    public func filtered(_ filter: ApplicationUsageFilter, hideNested: Bool) -> [ApplicationItem] {
        let base = hideNested ? baseApps : applications
        switch filter {
        case .all: return base
        case .used: return base.filter(\.hasUsage)
        case .active: return base.filter(\.isRunning)
        case .unused: return base.filter { !$0.hasUsage }
        }
    }

    static func usageKey(_ name: String?) -> String {
        guard let name else { return "" }
        var base = name
        if let r = name.range(of: #"\(([^)]+)\)\s*$"#, options: .regularExpression) {
            base = String(name[r]).trimmingCharacters(in: CharacterSet(charactersIn: "() "))
        }
        return base.replacingOccurrences(of: #"\.app$"#, with: "", options: [.regularExpression, .caseInsensitive]).trimmingCharacters(in: .whitespaces).lowercased()
    }

    public init(modules: JSONValue) {
        let rawModule = modules["applications"].unwrappingSingleton()
        raw = rawModule
        let module = rawModule.normalizedKeys()
        let source = module["installedApplications"].array ?? module["applications"].array ?? []
        hasData = !source.isEmpty

        let usageData = module["applicationUsage"].isNull ? module["usage"] : module["applicationUsage"]
        let sessions = usageData["activeSessions"].elements
        activeSessionCount = sessions.count
        let history = module["dailyUsageHistory"].elements
        historyDays = Set(history.compactMap { $0["date"].string }).count

        var byName: [String: Agg] = [:]
        for row in history {
            let key = ApplicationsInfo.usageKey(row["appName"].string)
            guard !key.isEmpty else { continue }
            var e = byName[key] ?? Agg()
            e.launches += row["launches"].int ?? 0
            e.seconds += row["totalSeconds"].double ?? 0
            if let date = row["date"].string {
                e.days.insert(date)
                if e.last.isEmpty || date > String(e.last.prefix(10)) { e.last = "\(date)T00:00:00Z" }
                if e.first.isEmpty || date < String(e.first.prefix(10)) { e.first = "\(date)T00:00:00Z" }
            }
            for u in row["users"].elements.compactMap(\.string) { e.users.insert(u) }
            byName[key] = e
        }
        var byPath: [String: Agg] = [:]
        for s in sessions {
            guard let path = s["path"].nonEmptyString else { continue }
            var e = byPath[path] ?? Agg()
            e.launches += 1
            e.seconds += s["durationSeconds"].double ?? 0
            if let start = s["startTime"].string {
                if start > e.last { e.last = start }
                if e.first.isEmpty || start < e.first { e.first = start }
                e.days.insert(String(start.prefix(10)))
            }
            if let u = s["user"].nonEmptyString { e.users.insert(u) }
            if s["isActive"].boolish { e.active = true }
            byPath[path] = e
        }

        var apps: [ApplicationItem] = []
        for (index, app) in source.enumerated() {
            if let s = app.string, app.object == nil {
                let name = s.replacingOccurrences(of: #"\.app$"#, with: "", options: [.regularExpression, .caseInsensitive])
                var merged = Agg()
                if let n = byName[ApplicationsInfo.usageKey(name)] { merged = n }
                apps.append(ApplicationItem(id: "app-\(index)-\(name)", name: name, displayName: name, version: "Unknown", publisher: "Unknown Publisher", category: "Application",
                                            installDate: nil, size: nil, path: nil, bundleId: nil, source: nil, architecture: nil, nested: false, signedBy: nil, obtainedFrom: nil,
                                            usage: ApplicationsInfo.usage(from: merged), raw: app))
                continue
            }
            let path = app.firstString("path", "installLocation")
            let name = app.firstString("name", "displayName") ?? "Unknown Application"
            var merged = Agg()
            let existing = app["usage"].isNull ? app["Usage"] : app["usage"]
            if !existing.isNull {
                merged.launches = existing["launchCount"].int ?? 0
                merged.seconds = existing.firstDouble("totalSeconds", "totalUsageSeconds") ?? 0
                merged.last = existing.firstString("lastUsed", "lastLaunchTime") ?? ""
                merged.first = existing["firstSeen"].string ?? ""
                for u in existing["users"].elements.compactMap(\.string) { merged.users.insert(u) }
            }
            let sources = [byName[ApplicationsInfo.usageKey(name)], path.flatMap { byPath[$0] }]
            for src in sources.compactMap({ $0 }) {
                merged.launches = max(merged.launches, src.launches)
                merged.seconds = max(merged.seconds, src.seconds)
                if src.last > merged.last { merged.last = src.last }
                if !src.first.isEmpty, merged.first.isEmpty || src.first < merged.first { merged.first = src.first }
                merged.users.formUnion(src.users)
                merged.days.formUnion(src.days)
                if src.active { merged.active = true }
            }
            if merged.launches == 0, let p = path, let bp = byPath[p] { merged.launches = bp.launches }
            let nested = path.map { $0.range(of: #"\.app/.*\.app$"#, options: [.regularExpression, .caseInsensitive]) != nil } ?? false
            apps.append(ApplicationItem(
                id: app["id"].nonEmptyString ?? "\(name)-\(index)", name: name, displayName: app["displayName"].nonEmptyString ?? name,
                version: app.firstString("version", "bundleVersion") ?? "Unknown",
                publisher: app.firstString("publisher", "signedBy", "vendor") ?? "Unknown Publisher",
                category: app["category"].nonEmptyString ?? "Uncategorized",
                installDate: app.firstString("installDate", "lastModified"), size: app["size"].string,
                path: path, bundleId: app.firstString("bundleId", "bundleIdentifier"), source: app["source"].nonEmptyString,
                architecture: app["architecture"].nonEmptyString, nested: nested, signedBy: app["signedBy"].nonEmptyString,
                obtainedFrom: app["obtainedFrom"].nonEmptyString, usage: ApplicationsInfo.usage(from: merged), raw: app))
        }
        apps.sort { a, b in
            if a.usageSeconds != b.usageSeconds { return a.usageSeconds > b.usageSeconds }
            let la = a.usage?.launchCount ?? 0, lb = b.usage?.launchCount ?? 0
            if la != lb { return la > lb }
            return a.cleanName.localizedCaseInsensitiveCompare(b.cleanName) == .orderedAscending
        }
        applications = apps
    }

    private static func usage(from agg: Agg) -> ApplicationUsage? {
        guard agg.launches > 0 || agg.seconds > 0 || agg.active else { return nil }
        return ApplicationUsage(launchCount: agg.launches, totalSeconds: agg.seconds, lastUsed: agg.last.isEmpty ? nil : agg.last,
                                firstSeen: agg.first.isEmpty ? nil : agg.first, users: Array(agg.users).sorted(), activeNow: agg.active, daysSeen: agg.days.count)
    }

    private struct Agg { var launches = 0; var seconds = 0.0; var last = ""; var first = ""; var users = Set<String>(); var days = Set<String>(); var active = false }

    /// Table dedupe: the same name and publisher at the same path collapses to the newest version.
    public static func deduplicate(_ apps: [ApplicationItem]) -> [ApplicationItem] {
        var map: [String: (ApplicationItem, Int)] = [:]
        var order: [String] = []
        for (index, app) in apps.enumerated() {
            let key = "\(app.name)-\(app.publisher)-\(app.path ?? "")"
            if let (existing, i) = map[key] {
                if app.version > existing.version || index > i { map[key] = (app, index) }
            } else {
                map[key] = (app, index)
                order.append(key)
            }
        }
        return order.compactMap { map[$0]?.0 }
    }

    /// Relevance-ranked search across name, publisher, bundle id, version, path and users.
    public static func search(_ apps: [ApplicationItem], query: String) -> [ApplicationItem] {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        guard !q.isEmpty else { return apps }
        var scored: [(item: ApplicationItem, score: Int)] = []
        for app in apps {
            let score = ApplicationsInfo.relevance(app, q)
            if score > 0 { scored.append((app, score)) }
        }
        scored.sort { a, b in
            if a.score != b.score { return a.score > b.score }
            return a.item.cleanName.localizedCaseInsensitiveCompare(b.item.cleanName) == .orderedAscending
        }
        return scored.map(\.item)
    }

    /// `formatDuration`: `45s`, `12m`, `3h 05m`, `4d 6h`.
    public static func formatDuration(_ seconds: Double) -> String {
        guard seconds > 0 else { return "-" }
        if seconds < 60 { return "\(Int(seconds.rounded()))s" }
        if seconds < 3600 { return "\(Int((seconds / 60).rounded()))m" }
        let hours = Int(seconds / 3600)
        if hours >= 48 { return "\(Int((Double(hours) / 24).rounded()))d \(hours % 24)h" }
        let mins = Int(((seconds.truncatingRemainder(dividingBy: 3600)) / 60).rounded())
        return mins > 0 ? "\(hours)h \(mins)m" : "\(hours)h"
    }

    public static func shortUser(_ user: String) -> String {
        user.split(separator: "\\").last.map(String.init) ?? user
    }
}

extension ApplicationsInfo {
    static func relevance(_ app: ApplicationItem, _ q: String) -> Int {
        var score = 0
        let name = app.name.lowercased()
        let display = app.displayName.lowercased()
        if name == q || display == q {
            score += 100
        } else if name.hasPrefix(q) || display.hasPrefix(q) {
            score += 50
        } else if name.contains(q) || display.contains(q) {
            score += 25
        }
        if app.publisher.lowercased().contains(q) { score += 10 }
        if (app.signedBy ?? "").lowercased().contains(q) { score += 8 }
        if (app.bundleId ?? "").lowercased().contains(q) { score += 6 }
        if app.version.lowercased().contains(q) { score += 5 }
        if (app.path ?? "").lowercased().contains(q) { score += 3 }
        if let users = app.usage?.users, users.contains(where: { $0.lowercased().contains(q) }) { score += 4 }
        return score
    }
}
