import Foundation

/// A row in an events feed: one event, or several routine collection events
/// from the same device inside a two-minute window folded together.
public struct BundledEvent: Sendable, Hashable, Identifiable {
    public var id: String
    public var device: String
    public var deviceName: String?
    public var assetTag: String?
    public var platform: Platform
    public var kind: EventKind
    public var ts: Date?
    public var message: String
    public var payload: JSONValue?
    public var count: Int
    public var eventIds: [String]
    public var isBundle: Bool
    public var bundledKinds: [EventKind]

    public var displayDeviceName: String {
        if let n = deviceName, n != device, n.lowercased() != "unknown" { return n }
        return device.isEmpty ? "Unknown Device" : device
    }

    /// Success events whose message ends in "removed" are shown in the Removed colour.
    public var isRemoval: Bool {
        kind == .success && message.trimmingCharacters(in: .whitespaces).range(of: #"\bremoved$"#, options: [.regularExpression, .caseInsensitive]) != nil
    }
}

/// Port of the web app's `eventBundling.ts`.
public enum EventBundling {
    public static let bundleWindow: TimeInterval = 120

    public static func bundle(_ events: [FleetEvent]) -> [BundledEvent] {
        guard !events.isEmpty else { return [] }
        var seen = Set<String>()
        let unique = events.filter { seen.insert($0.id).inserted }
        let sorted = unique.sorted { ($0.ts ?? .distantPast) > ($1.ts ?? .distantPast) }

        var bundled: [BundledEvent] = []
        var processed = Set<String>()
        for event in sorted {
            if processed.contains(event.id) { continue }
            let eventTime = event.ts ?? .distantPast
            let related = sorted.filter { other in
                !processed.contains(other.id) &&
                other.device == event.device &&
                abs((other.ts ?? .distantPast).timeIntervalSince(eventTime)) <= bundleWindow &&
                shouldBundle(event, other)
            }
            if related.count > 1 {
                let kinds = Array(Set(related.map(\.kind)))
                related.forEach { processed.insert($0.id) }
                let idHash = related.map(\.id).sorted().joined(separator: "-").prefix(20)
                bundled.append(BundledEvent(
                    id: "bundle-\(event.device)-\(Int(eventTime.timeIntervalSince1970))-\(idHash)",
                    device: event.device, deviceName: event.deviceName, assetTag: event.assetTag, platform: event.platform,
                    kind: primaryKind(kinds), ts: event.ts, message: bundleMessage(related, kinds: kinds), payload: nil,
                    count: related.count, eventIds: related.map(\.id), isBundle: true, bundledKinds: kinds))
            } else {
                processed.insert(event.id)
                bundled.append(BundledEvent(
                    id: event.id, device: event.device, deviceName: event.deviceName, assetTag: event.assetTag, platform: event.platform,
                    kind: event.kind, ts: event.ts, message: event.message.isEmpty ? payloadPreview(event.payload ?? .null) : event.message,
                    payload: event.payload, count: 1, eventIds: [event.id], isBundle: false, bundledKinds: [event.kind]))
            }
        }
        return bundled
    }

    private static func shouldBundle(_ a: FleetEvent, _ b: FleetEvent) -> Bool {
        let meaningful: Set<EventKind> = [.error, .warning, .success]
        if meaningful.contains(a.kind) || meaningful.contains(b.kind) { return false }
        return true
    }

    private static func primaryKind(_ kinds: [EventKind]) -> EventKind {
        if kinds.contains(.error) { return .error }
        if kinds.contains(.warning) { return .warning }
        if kinds.contains(.success) { return .success }
        if kinds.contains(.system) { return .system }
        return kinds.first ?? .info
    }

    private static func bundleMessage(_ events: [FleetEvent], kinds: [EventKind]) -> String {
        let unique = Array(Set(events.map(\.message).filter { !$0.isEmpty }))
        if unique.count == 1 { return unique[0] }
        if kinds.contains(.system), kinds.contains(.info), let sys = events.first(where: { $0.kind == .system && !$0.message.isEmpty }) {
            return sys.message
        }
        var modules: [String] = []
        for e in events {
            for m in moduleNames(in: e.payload ?? .null) where !modules.contains(m) { modules.append(m) }
        }
        if !modules.isEmpty {
            let capitalized = modules.map { $0.prefix(1).uppercased() + $0.dropFirst() }
            if capitalized.count <= 3 { return "\(capitalized.joined(separator: ", ")) data reported" }
            return "\(capitalized.count) modules data reported"
        }
        return "\(events.count) data collection events"
    }

    /// `formatPayloadPreview`: a fallback message when the event has none.
    public static func payloadPreview(_ payload: JSONValue) -> String {
        switch payload {
        case .null: return "No details"
        case .string(let s): return s.count > 120 ? String(s.prefix(120)) + "..." : s
        case .object:
            if let m = payload["message"].nonEmptyString { return m.count > 120 ? String(m.prefix(120)) + "..." : m }
            if let s = payload["summary"].nonEmptyString { return s }
            let names = moduleNames(in: payload)
            if !names.isEmpty {
                let capitalized = names.map { $0.prefix(1).uppercased() + $0.dropFirst() }
                if capitalized.count <= 3 { return "\(capitalized.joined(separator: ", ")) data reported" }
                return "\(capitalized.count) modules data reported"
            }
            return (payload.object?.isEmpty ?? true) ? "Event recorded" : "Data reported"
        default: return String(describing: payload.string ?? "").prefix(80).description
        }
    }

    public static func moduleNames(in payload: JSONValue) -> [String] {
        if let arr = payload["modules_processed"].array, !arr.isEmpty { return arr.compactMap(\.string) }
        if payload["modules_processed"].double != nil, let enabled = payload["enabled_modules"].array { return enabled.compactMap(\.string) }
        if let arr = payload["metadata"]["enabledModules"].array { return arr.compactMap(\.string) }
        if let arr = payload["modules"].array { return arr.compactMap(\.string) }
        if let obj = payload["modules"].object { return obj.keys.sorted() }
        return []
    }
}

/// One line of inline detail under an event: a run message (rendered as a
/// mono chip) or an item name with version.
public struct InlineLine: Sendable, Hashable {
    public var text: String
    public var isMessage: Bool
    public var name: String?
    public var version: String?
    public var message: String?
}

public struct InlineDetails: Sendable, Hashable {
    public var errors: [InlineLine] = []
    public var warnings: [InlineLine] = []
    public var successes: [String] = []
    public var isRemoval = false

    public var isEmpty: Bool { errors.isEmpty && warnings.isEmpty && successes.isEmpty }
}

/// Port of `eventInlineDetails.ts`.
public enum EventInlineDetails {
    static let reservedKeys: Set<String> = [
        "count", "errors", "warnings", "error_items", "warning_items", "failed_items",
        "error_messages", "warning_messages", "module_status", "warning_count", "error_count",
        "run_type", "session_id", "modules", "modules_processed", "message", "summary",
        "items", "action", "duration_seconds", "item_warning_count", "operational_warning_count",
        "operational_warnings", "operational_errors", "session_installs", "session_updates", "session_removals",
        "recommendation", "collection_type", "collectionType", "operating_system", "display_version",
        "version", "uptime", "previous_boot_time", "current_boot_time",
    ]

    public static func extract(_ payload: JSONValue?) -> InlineDetails {
        var out = InlineDetails()
        guard let p = payload, p.object != nil else { return out }
        out.isRemoval = (p["action"].string ?? "").lowercased() == "remove" || p["removed_items"].array != nil

        func pushString(_ target: inout [InlineLine], _ v: JSONValue) {
            guard let s = v.string, !s.trimmingCharacters(in: .whitespaces).isEmpty else { return }
            for part in LogText.clean(s).split(separator: ";") {
                let t = part.trimmingCharacters(in: .whitespaces)
                if !t.isEmpty { target.append(InlineLine(text: t, isMessage: true)) }
            }
        }
        func pushItems(_ target: inout [InlineLine], _ v: JSONValue) {
            guard let items = v.array else { return }
            for item in items {
                if let s = item.string, item.object == nil {
                    let t = s.trimmingCharacters(in: .whitespaces)
                    if !t.isEmpty { target.append(InlineLine(text: t, isMessage: false)) }
                } else if item.object != nil {
                    let name = (item.firstString("displayName", "name") ?? "").trimmingCharacters(in: .whitespaces)
                    let version = (item["version"].string ?? "").trimmingCharacters(in: .whitespaces)
                    let detail = LogText.clean(item.firstString("error", "warning", "message") ?? "")
                    let nameVersion = name + (version.isEmpty ? "" : " \(version)")
                    let line = detail.isEmpty ? nameVersion : (name.isEmpty ? detail : "\(nameVersion): \(detail)")
                    if !line.isEmpty {
                        target.append(InlineLine(text: line, isMessage: !detail.isEmpty, name: name.isEmpty ? nil : name,
                                                 version: version.isEmpty ? nil : version, message: detail.isEmpty ? nil : detail))
                    }
                }
            }
        }

        if let items = p["items"].array {
            for item in items {
                if let s = item.string, item.object == nil {
                    let t = s.trimmingCharacters(in: .whitespaces)
                    if !t.isEmpty { out.successes.append(t) }
                } else if item.object != nil {
                    let name = (item.firstString("displayName", "name") ?? "").trimmingCharacters(in: .whitespaces)
                    let version = (item["version"].string ?? "").trimmingCharacters(in: .whitespaces)
                    if !name.isEmpty { out.successes.append(version.isEmpty ? name : "\(name) \(version)") }
                }
            }
        }

        pushString(&out.errors, p["errors"])
        pushString(&out.warnings, p["warnings"])
        pushItems(&out.errors, p["error_messages"])
        pushItems(&out.warnings, p["warning_messages"])
        pushItems(&out.errors, p["error_items"])
        pushItems(&out.warnings, p["warning_items"])
        pushItems(&out.errors, p["failed_items"])
        pushItems(&out.errors, p["operational_errors"])
        pushItems(&out.warnings, p["operational_warnings"])

        if let rec = p["recommendation"].nonEmptyString {
            out.warnings.append(InlineLine(text: rec, isMessage: true))
        }

        if let obj = p.object {
            for (key, value) in obj.sorted(by: { $0.key < $1.key }) {
                if reservedKeys.contains(key) || key.lowercased().hasSuffix("count") { continue }
                if case .string(let s) = value, let first = s.trimmingCharacters(in: .whitespaces).first, first.isNumber {
                    out.successes.append("\(key) \(s.trimmingCharacters(in: .whitespaces))")
                }
            }
        }

        func dedupe(_ lines: [InlineLine]) -> [InlineLine] {
            var seen = Set<String>()
            return lines.filter { seen.insert($0.text).inserted }
        }
        out.errors = dedupe(out.errors)
        out.warnings = dedupe(out.warnings)
        var seenS = Set<String>()
        out.successes = out.successes.filter { seenS.insert($0).inserted }
        return out
    }

    /// Items-only view: run messages that name a package collapse to the name.
    public static func itemsOnly(_ lines: [InlineLine]) -> [InlineLine] {
        var out: [InlineLine] = []
        for line in lines {
            if !line.isMessage { out.append(line); continue }
            let name = line.name ?? InstallItems.itemName(fromMessage: line.text)
            guard let name else { continue }
            let text = line.version.map { "\(name) \($0)" } ?? name
            if !out.contains(where: { $0.text == text }) { out.append(InlineLine(text: text, isMessage: false)) }
        }
        return out
    }
}

/// Where an event row's device link should land (port of `eventLinks.ts`).
public enum EventLinks {
    static let installsMessage = try! NSRegularExpression(pattern: #"\b(munki|cimian|managed software|package|packages|install|installs|installed|installing|uninstall|removal|removed|update|updated|pkginfo|manifest|catalog)\b"#, options: [.caseInsensitive])

    static let modulePatterns: [(String, NSRegularExpression)] = [
        ("hardware", #"\b(hardware|cpu|processor|memory|ram|disk|storage|battery)\b"#),
        ("network", #"\b(network|wifi|wi-fi|ethernet|dns|dhcp|ip address)\b"#),
        ("security", #"\b(security|antivirus|defender|firewall|tpm|encryption|filevault|bitlocker)\b"#),
        ("management", #"\b(profile|policy|configuration|management|mdm|enrollment|intune)\b"#),
        ("applications", #"\b(application|applications|app)\b"#),
        ("inventory", #"\b(inventory|asset tag|serial)\b"#),
        ("peripherals", #"\b(peripheral|printer|display|monitor|keyboard|mouse)\b"#),
        ("identity", #"\b(identity|account|user|logon)\b"#),
        ("system", #"\b(system|operating system|os|uptime|boot)\b"#),
    ].map { ($0.0, try! NSRegularExpression(pattern: $0.1, options: [.caseInsensitive])) }

    public static func moduleId(kind: EventKind, message: String, payload: JSONValue?) -> String? {
        if let m = payload?["module_id"].nonEmptyString { return m }
        guard !message.isEmpty else { return nil }
        let range = NSRange(message.startIndex..., in: message)
        if installsMessage.firstMatch(in: message, range: range) != nil { return "installs" }
        for (id, re) in modulePatterns where re.firstMatch(in: message, range: range) != nil { return id }
        if [.success, .warning, .error].contains(kind) { return "installs" }
        return nil
    }

    /// The installs-tab filter that shows what this event reports.
    public static func installsFilter(for kind: EventKind) -> String {
        switch kind {
        case .error: return "error"
        case .warning: return "warning"
        default: return "last_run"
        }
    }
}

/// Text cleanup for log lines (port of `logText.ts`'s `cleanLogText`).
public enum LogText {
    public static func clean(_ text: String) -> String {
        var s = text
        // Strip ANSI escapes and control characters.
        s = s.replacingOccurrences(of: #"\u{1B}\[[0-9;]*[A-Za-z]"#, with: "", options: .regularExpression)
        s = s.replacingOccurrences(of: #"[\u{0000}-\u{0008}\u{000B}\u{000C}\u{000E}-\u{001F}]"#, with: "", options: .regularExpression)
        return s.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
