import Foundation

/// A `reportmate://` link: the web app's routes with the scheme swapped, so a
/// web URL becomes an app link by replacing `https://<host>` with
/// `reportmate://`, and an app link becomes a web URL by the reverse.
///
/// Forms accepted by `init(url:)`:
///
///     reportmate://dashboard
///     reportmate://devices?status=active&search=lab
///     reportmate://device/<serial>?tab=installs&filter=errors     (or #installs)
///     reportmate://events?filter=errors&view=messages
///     reportmate://events/failures
///     reportmate://installs?filter=warnings&view=messages
///     reportmate://applications?type=usage&apps=Blender,Zoom&period=30
///     reportmate://applications/usage/<app>?days=30
///     reportmate://applications/coverage
///     reportmate://system?osVersion=15.4  (and the other reports)
///     reportmate://settings
///     reportmate://this-mac                                    (this-device, this-pc and local are aliases)
///     reportmate://<web host>/device/<serial>#installs   (a pasted web URL, scheme swapped)
///     https://<web host>/device/<serial>#installs        (a web URL as-is)
public struct DeepLink: Sendable, Hashable {
    public enum Target: Sendable, Hashable {
        case dashboard
        case devices
        case device(serial: String, tab: String?)
        case events
        case eventsFailures
        /// installs, applications, system, management, identity, hardware, peripherals, security, network
        case report(String)
        case applicationUsage(app: String)
        case applicationCoverage
        case settings
        case thisMac
    }

    public static let scheme = "reportmate"
    public static let reportNames: [String] = ["installs", "applications", "system", "management", "identity", "hardware", "peripherals", "security", "network"]
    public static let deviceTabs: [String] = ["info", "installs", "applications", "system", "management", "identity", "hardware", "peripherals", "security", "network", "events"]

    public let target: Target
    /// Filters and selections, exactly as the web page's query string carries them.
    public var query: [String: String]

    public init(target: Target, query: [String: String] = [:]) {
        self.target = target
        self.query = query
    }

    public init?(url: URL) {
        guard let comps = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return nil }
        let scheme = (comps.scheme ?? "").lowercased()
        guard scheme == DeepLink.scheme || scheme == "https" || scheme == "http" else { return nil }
        var segments: [String] = []
        if scheme == DeepLink.scheme, let host = comps.host, !host.isEmpty, !host.contains(".") {
            segments.append(host)
        }
        segments += comps.path.split(separator: "/").map { String($0).removingPercentEncoding ?? String($0) }.filter { !$0.isEmpty }
        // The web handoff route wraps the real path: /open/device/X -> /device/X.
        if segments.first?.lowercased() == "open" { segments.removeFirst() }
        var query: [String: String] = [:]
        for item in comps.queryItems ?? [] { if let v = item.value, !v.isEmpty { query[item.name] = v } }
        let fragment = comps.fragment?.trimmingCharacters(in: .whitespaces)
        let head = segments.first?.lowercased()
        switch head {
        case nil, "dashboard", "":
            target = .dashboard
        case "devices":
            target = .devices
        case "device":
            guard segments.count >= 2 else { return nil }
            let tab = query["tab"]?.lowercased() ?? fragment?.lowercased()
            query["tab"] = nil
            target = .device(serial: segments[1], tab: tab.flatMap { DeepLink.deviceTabs.contains($0) ? $0 : nil })
        case "events":
            target = segments.count >= 2 && segments[1].lowercased() == "failures" ? .eventsFailures : .events
        case "applications":
            if segments.count >= 3, segments[1].lowercased() == "usage" {
                target = .applicationUsage(app: segments[2])
            } else if segments.count >= 2, segments[1].lowercased() == "coverage" {
                target = .applicationCoverage
            } else {
                target = .report("applications")
            }
        case "settings":
            target = .settings
        case "this-mac", "this-device", "this-pc", "local":
            target = .thisMac
        case "profiles":
            // The web nav still links /profiles; the module lives inside management.
            target = .report("management")
        case "inventory":
            target = .devices
        default:
            guard let head, DeepLink.reportNames.contains(head) else { return nil }
            target = .report(head)
        }
        self.query = query
    }

    /// The path the web app uses for this target, without query or fragment.
    public var webPath: String {
        switch target {
        case .dashboard: return "/dashboard"
        case .devices: return "/devices"
        case .device(let serial, _): return "/device/\(DeepLink.encode(serial))"
        case .events: return "/events"
        case .eventsFailures: return "/events/failures"
        case .report(let name): return "/\(name)"
        case .applicationUsage(let app): return "/applications/usage/\(DeepLink.encode(app))"
        case .applicationCoverage: return "/applications/coverage"
        case .settings: return "/settings"
        case .thisMac: return "/this-mac"
        }
    }

    private var queryItems: [URLQueryItem] {
        var items = query.sorted { $0.key < $1.key }.map { URLQueryItem(name: $0.key, value: $0.value) }
        if case .device(_, let tab?) = target { items.insert(URLQueryItem(name: "tab", value: tab), at: 0) }
        return items
    }

    /// The canonical `reportmate://…` form.
    public var url: URL {
        var comps = URLComponents()
        comps.scheme = DeepLink.scheme
        let path = webPath
        let parts = path.split(separator: "/", maxSplits: 1).map(String.init)
        comps.host = parts.first
        comps.percentEncodedPath = parts.count > 1 ? "/" + parts[1] : ""
        let items = queryItems
        if !items.isEmpty { comps.queryItems = items }
        return comps.url ?? URL(string: "\(DeepLink.scheme)://dashboard")!
    }

    /// The same link on the web dashboard, for people without the app.
    public func webURL(base: URL) -> URL? {
        var comps = URLComponents(url: base, resolvingAgainstBaseURL: false)
        comps?.path = webPath
        var items = query.sorted { $0.key < $1.key }.map { URLQueryItem(name: $0.key, value: $0.value) }
        var fragment: String?
        if case .device(_, let tab?) = target {
            fragment = tab
            items.removeAll { $0.name == "tab" }
        }
        comps?.queryItems = items.isEmpty ? nil : items
        comps?.fragment = fragment
        return comps?.url
    }

    /// The web dashboard's `/open` handoff: opens the app when it is installed and
    /// falls back to the web page otherwise, so it is the link to share.
    public func handoffURL(webBase: URL) -> URL? {
        guard let web = webURL(base: webBase), var comps = URLComponents(url: web, resolvingAgainstBaseURL: false) else { return nil }
        comps.path = "/open" + comps.path
        return comps.url
    }

    static func encode(_ s: String) -> String {
        s.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed.subtracting(CharacterSet(charactersIn: "/"))) ?? s
    }
}
