import Foundation

/// Typed rows for the System tab's tables, built from the normalised system
/// module lists that `SystemInfo` keeps raw.
public enum SystemItems {
    /// A launchd daemon or agent, or a Windows service.
    public struct Service: Sendable, Hashable, Identifiable {
        public var id: String { (label ?? name) + path }
        public var name: String
        public var label: String?
        public var displayName: String
        public var description: String
        public var status: String
        public var startType: String?
        public var pid: Int?
        public var runAtLoad: Bool
        public var keepAlive: Bool
        public var disabled: Bool
        public var path: String
        public var program: String?
        public var type: String
        public var source: String
        public var managedByProfile: Bool
        public var profileIdentifier: String?
        public var plistContent: String?
        public var username: String?

        public init(json s: JSONValue, isMac: Bool) {
            let hasLabel = s["label"].nonEmptyString != nil
            if isMac || hasLabel {
                name = s.firstString("label", "name") ?? ""
                label = s["label"].nonEmptyString
                displayName = s.firstString("label", "name") ?? ""
                description = ""
                pid = s["pid"].int
                status = s["status"].nonEmptyString ?? (pid != nil ? "Running" : "Stopped")
                startType = nil
            } else {
                name = s.firstString("name", "serviceName") ?? ""
                label = nil
                displayName = s.firstString("displayName", "display_name") ?? ""
                description = s["description"].string ?? ""
                status = s.firstString("status", "state") ?? "Unknown"
                startType = s.firstString("startType", "start_type")
                pid = s["pid"].int
            }
            runAtLoad = s["runAtLoad"].boolish
            keepAlive = s["keepAlive"].boolish
            disabled = s["disabled"].boolish
            path = s.firstString("path", "binaryPath") ?? ""
            program = s["program"].nonEmptyString
            type = s["type"].string ?? ""
            source = s["source"].string ?? ""
            managedByProfile = s["managedByProfile"].boolish
            profileIdentifier = s["profileIdentifier"].nonEmptyString
            plistContent = s["plistContent"].nonEmptyString
            username = s["username"].nonEmptyString
        }

        public var isRunning: Bool {
            let s = status.lowercased()
            return s.contains("running") || s.contains("started") || pid != nil
        }
    }

    /// A launchd item as the Background Activity table classifies it.
    public enum LaunchdScope: String, Sendable, CaseIterable { case all, system, user, apple
        public var label: String {
            switch self {
            case .all: return "All Sources"
            case .system: return "Third-Party (System)"
            case .user: return "User Level"
            case .apple: return "Apple"
            }
        }
    }
    public enum LaunchdKind: String, Sendable { case daemon, agent }
    public enum LaunchdStatus: String, Sendable { case running, stopped, disabled }

    public static func scope(of item: Service) -> LaunchdScope {
        let source = item.source.lowercased()
        let name = (item.label ?? item.name).lowercased()
        let path = item.path.lowercased()
        if source == "apple" || name.hasPrefix("com.apple.") || path.contains("/system/") { return .apple }
        if source == "user" || path.contains("/users/") { return .user }
        return .system
    }

    public static func kind(of item: Service) -> LaunchdKind {
        let type = item.type.lowercased()
        let path = item.path.lowercased()
        return (type.contains("agent") || path.contains("launchagents")) ? .agent : .daemon
    }

    public static func launchdStatus(of item: Service) -> LaunchdStatus {
        let status = item.status.lowercased()
        let isDisabled = item.disabled || status == "disabled" || status == "unloaded"
        let isRunning = item.pid != nil || status == "running" || status == "loaded" || status == "enabled"
        if isDisabled { return .disabled }
        if isRunning { return .running }
        return .stopped
    }

    /// A Windows scheduled task (or a launchd item viewed as a task).
    public struct ScheduledTask: Sendable, Hashable, Identifiable {
        public var id: String { path + name }
        public var name: String
        public var path: String
        public var enabled: Bool
        public var action: String
        public var hidden: Bool
        public var state: String
        public var lastRunTime: String?
        public var nextRunTime: String?
        public var lastRunCode: String
        public var lastRunMessage: String
        public var status: String

        public init(json t: JSONValue) {
            name = t.firstString("name", "label") ?? ""
            path = t["path"].string ?? ""
            if let e = t["enabled"].boolishIfPresent { enabled = e } else if let r = t["runAtLoad"].boolishIfPresent { enabled = r } else { enabled = !t["disabled"].boolish }
            action = t.firstString("action", "program", "path") ?? ""
            hidden = t["hidden"].boolish
            state = t.firstString("state", "status") ?? ""
            lastRunTime = t.firstString("lastRunTime", "last_run_time")
            nextRunTime = t.firstString("nextRunTime", "next_run_time")
            lastRunCode = t.firstString("lastRunCode", "last_run_code") ?? ""
            lastRunMessage = t.firstString("lastRunMessage", "last_run_message") ?? ""
            status = t.firstString("status", "state") ?? "Unknown"
        }
    }

    public struct LoginItem: Sendable, Hashable, Identifiable {
        public var id: String { name + (path ?? "") }
        public var name: String
        public var path: String?
        public var type: String
        public var enabled: Bool
        public init(json i: JSONValue) {
            name = i["name"].string ?? ""
            path = i["path"].nonEmptyString
            type = i["type"].nonEmptyString ?? "LoginItem"
            enabled = i["enabled"].boolishIfPresent ?? true
        }
    }

    public struct Extension: Sendable, Hashable, Identifiable {
        public var id: String { identifier + (bundlePath ?? "") }
        public var identifier: String
        public var version: String?
        public var state: String
        public var teamId: String?
        public var bundlePath: String?
        public var category: String?
        public var type: String?
        public var extensionCategory: String?
        public var appName: String?
        public var managedByProfile: Bool
        public var profileIdentifier: String?

        public init(json e: JSONValue) {
            identifier = e["identifier"].string ?? ""
            version = e["version"].nonEmptyString
            state = e["state"].string ?? "unknown"
            teamId = e.firstString("teamId", "team")
            bundlePath = e["bundlePath"].nonEmptyString
            category = e["category"].nonEmptyString
            type = e["type"].nonEmptyString
            extensionCategory = e["extensionCategory"].nonEmptyString
            appName = e["appName"].nonEmptyString
            managedByProfile = e["managedByProfile"].boolish
            profileIdentifier = e["profileIdentifier"].nonEmptyString
        }

        public enum Status: String, Sendable { case all, enabled, waiting, disabled }

        /// `normalizeState`: activated and enabled read as Enabled.
        public var normalizedState: (label: String, status: Status) {
            let s = state.lowercased()
            if s.contains("waiting") { return ("Waiting", .waiting) }
            if s.contains("activated") || s.contains("enabled") || s == "active" { return ("Enabled", .enabled) }
            if s == "disabled" || s == "inactive" { return ("Disabled", .disabled) }
            return (state.isEmpty ? "Unknown" : state, .all)
        }

        public static let categories = ["Actions", "Camera Extensions", "Dock Tiles", "Driver Extensions", "Endpoint Security Extensions", "File Providers",
                                        "File System Extensions", "Finder", "Media Extensions", "Network Extensions", "Photos Editing", "Quick Look", "Sharing", "Spotlight", "Xcode Source Editor"]

        /// `getExtensionCategory`
        public var resolvedCategory: String {
            let c = (extensionCategory ?? category ?? type ?? "").lowercased()
            let idl = identifier.lowercased()
            let bp = (bundlePath ?? "").lowercased()
            if c.contains("network") { return "Network Extensions" }
            if c.contains("endpoint") || c.contains("security") { return "Endpoint Security Extensions" }
            if c.contains("driver") { return "Driver Extensions" }
            if c.contains("file provider") { return "File Providers" }
            if c.contains("file system") { return "File System Extensions" }
            if c.contains("finder") { return "Finder" }
            if c.contains("quicklook") || c.contains("quick look") { return "Quick Look" }
            if c.contains("sharing") || c.contains("share") { return "Sharing" }
            if c.contains("spotlight") { return "Spotlight" }
            if c.contains("photos") { return "Photos Editing" }
            if c.contains("action") { return "Actions" }
            if c.contains("camera") { return "Camera Extensions" }
            if c.contains("media") { return "Media Extensions" }
            if c.contains("dock") { return "Dock Tiles" }
            if c.contains("xcode") || c.contains("source editor") { return "Xcode Source Editor" }
            if idl.contains("quicklook") || idl.contains("qlgenerator") { return "Quick Look" }
            if idl.contains("share") || idl.contains("sharingservice") { return "Sharing" }
            if idl.contains("fileprovider") { return "File Providers" }
            if idl.contains("network") { return "Network Extensions" }
            if idl.contains("endpoint") || idl.contains("edr") || idl.contains("security") { return "Endpoint Security Extensions" }
            if idl.contains("finder") { return "Finder" }
            if idl.contains("spotlight") || idl.contains("mdimporter") { return "Spotlight" }
            if idl.contains("action") { return "Actions" }
            if idl.contains("camera") { return "Camera Extensions" }
            if idl.contains("photos") || idl.contains("photoedit") { return "Photos Editing" }
            if idl.contains("docktile") { return "Dock Tiles" }
            if bp.contains("quicklook") { return "Quick Look" }
            if bp.contains("share") { return "Sharing" }
            if bp.contains("finder") { return "Finder" }
            if bp.contains("spotlight") || bp.contains("mdimporter") { return "Spotlight" }
            if bp.contains("fileprovider") { return "File Providers" }
            if bp.contains("photoedit") { return "Photos Editing" }
            return extensionCategory ?? "Actions"
        }

        static let knownApps: [String: String] = [
            "findmy": "Find My", "1password": "1Password", "icloud": "iCloud", "iwork": "iWork", "keynote": "Keynote", "pages": "Pages", "numbers": "Numbers",
            "safari": "Safari", "mail": "Mail", "notes": "Notes", "photos": "Photos", "preview": "Preview", "textedit": "TextEdit", "xcode": "Xcode",
            "automator": "Automator", "finder": "Finder", "zoom": "Zoom", "slack": "Slack", "dropbox": "Dropbox", "onedrive": "OneDrive", "googledrive": "Google Drive",
            "chrome": "Google Chrome", "firefox": "Firefox", "vscode": "VS Code", "visualstudiocode": "VS Code", "iterm": "iTerm", "iterm2": "iTerm2", "terminal": "Terminal",
            "bartender": "Bartender", "cleanmymac": "CleanMyMac", "raycast": "Raycast", "alfred": "Alfred", "bettertouchtool": "BetterTouchTool",
            "keyboard-maestro": "Keyboard Maestro", "screenflow": "ScreenFlow", "vlc": "VLC", "spotify": "Spotify", "microsoft": "Microsoft", "office": "Microsoft Office",
            "word": "Microsoft Word", "excel": "Microsoft Excel", "powerpoint": "Microsoft PowerPoint", "outlook": "Microsoft Outlook", "teams": "Microsoft Teams",
        ]
        static let extensionTypes = ["extension", "widget", "intent", "intents", "share", "sharing", "action", "quicklook", "spotlight", "finder", "provider", "network", "endpoint", "security", "helper", "service", "daemon", "agent"]

        /// `getAppName`
        public var resolvedAppName: String {
            if let a = appName { return a }
            if let bp = bundlePath, let r = bp.range(of: #"/([^/]+)\.app"#, options: .regularExpression) {
                let seg = String(bp[r]).dropFirst()
                return String(seg.dropLast(4))
            }
            let parts = identifier.split(separator: ".").map(String.init)
            guard parts.count >= 3 else { return "System" }
            for p in parts.dropFirst(2) { if let k = Extension.knownApps[p.lowercased()] { return k } }
            var appPart = ""
            for p in parts.dropFirst(2) {
                let l = p.lowercased()
                if !Extension.extensionTypes.contains(where: { l.contains($0) }), l.count > 2 { appPart = p; break }
            }
            if appPart.isEmpty { appPart = parts[2] }
            var spaced = appPart.replacingOccurrences(of: #"([a-z])([A-Z])"#, with: "$1 $2", options: .regularExpression)
            spaced = spaced.replacingOccurrences(of: #"([A-Z]+)([A-Z][a-z])"#, with: "$1 $2", options: .regularExpression)
            spaced = spaced.replacingOccurrences(of: "-", with: " ").replacingOccurrences(of: "_", with: " ")
            return spaced.split(separator: " ").map { $0.prefix(1).uppercased() + $0.dropFirst() }.joined(separator: " ").trimmingCharacters(in: .whitespaces)
        }
    }

    public struct KernelExtension: Sendable, Hashable, Identifiable {
        public var id: String { name + (path ?? "") }
        public var name: String
        public var version: String?
        public var path: String?
        public var size: Double
        public var loaded: Bool
        public init(json k: JSONValue) {
            name = k["name"].string ?? ""
            version = k["version"].nonEmptyString
            path = k["path"].nonEmptyString
            size = k["size"].double ?? 0
            loaded = k["loaded"].boolishIfPresent ?? true
        }
    }

    public struct HelperTool: Sendable, Hashable, Identifiable {
        public var id: String { name + (path ?? "") }
        public var name: String
        public var path: String?
        public var bundleIdentifier: String?
        public var teamId: String?
        public var signed: Bool
        public var modifiedDate: String?
        public init(json h: JSONValue) {
            name = h["name"].string ?? ""
            path = h["path"].nonEmptyString
            bundleIdentifier = h.firstString("bundleIdentifier", "bundle_identifier")
            teamId = h.firstString("teamId", "team_id")
            signed = h["signed"].boolish
            modifiedDate = h.firstString("modifiedDate", "modified_date")
        }
    }

    public struct InstalledUpdate: Sendable, Hashable, Identifiable {
        public var id: String { updateId + (title ?? "") }
        public var updateId: String
        public var title: String?
        public var category: String?
        public var installDate: String?
        public var requiresRestart: Bool
        public init(json u: JSONValue) {
            updateId = u.firstString("id", "updateId") ?? ""
            title = u.firstString("title", "name")
            category = u["category"].nonEmptyString
            installDate = u.firstString("installDate", "installed_date")
            requiresRestart = u["requiresRestart"].boolish || u["requires_restart"].boolish
        }
    }

    public struct InstallHistoryItem: Sendable, Hashable, Identifiable {
        public var id: String { packageId + (installTime ?? "") }
        public var packageId: String
        public var packageFilename: String?
        public var version: String?
        public var installTime: String?
        public var installDate: Date? { FlexibleDate.parse(installTime) }
        public init(json i: JSONValue) {
            packageId = i.firstString("packageId", "package_id") ?? ""
            packageFilename = i.firstString("packageFilename", "package_filename")
            version = i["version"].nonEmptyString
            installTime = i.firstString("installTime", "install_time")
        }

        /// Apple system updates among the receipts.
        public var isSystemUpdate: Bool {
            let p = packageId.lowercased()
            return p.contains("com.apple") || p.contains("macos") || p.contains("securityupdate") || p.contains("safari") || p.contains("xprotect")
        }
    }

    /// Windows built-in vs third-party classification by install path.
    public enum WindowsSource: String, Sendable { case windows, thirdParty = "third-party"
        public var label: String { self == .windows ? "Windows" : "Third-party" }
    }

    static let osPathPrefixes = ["\\systemroot\\", "%systemroot%", "%windir%", "system32\\", "\\system32\\"]

    public static func classifyServicePath(_ path: String?) -> WindowsSource {
        var p = (path ?? "").trimmingCharacters(in: .whitespaces).lowercased()
        if p.hasPrefix("\"") { p.removeFirst() }
        if p.isEmpty { return .windows }
        if p.contains("\\driverstore\\filerepository\\") { return .thirdParty }
        if p.range(of: #"^[a-z]:\\windows\\"#, options: .regularExpression) != nil { return .windows }
        if osPathPrefixes.contains(where: { p.hasPrefix($0) }) { return .windows }
        return .thirdParty
    }

    public static func classifyTaskPath(_ path: String?) -> WindowsSource {
        (path ?? "").trimmingCharacters(in: .whitespaces).lowercased().hasPrefix("\\microsoft\\") ? .windows : .thirdParty
    }
}

extension SystemInfo {
    public var serviceItems: [SystemItems.Service] { services.map { SystemItems.Service(json: $0, isMac: isMac) } }
    public var taskItems: [SystemItems.ScheduledTask] { scheduledTasks.map(SystemItems.ScheduledTask.init(json:)) }
    /// Mac: launchd services and scheduled tasks in one Background Activity list.
    public var launchdItems: [SystemItems.Service] { (scheduledTasks + services).map { SystemItems.Service(json: $0, isMac: true) } }
    public var loginItemRows: [SystemItems.LoginItem] { loginItems.map(SystemItems.LoginItem.init(json:)) }
    public var extensionRows: [SystemItems.Extension] { systemExtensions.map(SystemItems.Extension.init(json:)) }
    public var kextRows: [SystemItems.KernelExtension] { kernelExtensions.map(SystemItems.KernelExtension.init(json:)) }
    public var helperRows: [SystemItems.HelperTool] { privilegedHelperTools.map(SystemItems.HelperTool.init(json:)) }
    public var installedUpdateRows: [SystemItems.InstalledUpdate] { installedUpdates.map(SystemItems.InstalledUpdate.init(json:)) }
    public var installHistoryRows: [SystemItems.InstallHistoryItem] { installHistory.map(SystemItems.InstallHistoryItem.init(json:)) }
    public var runningServiceCount: Int { serviceItems.filter(\.isRunning).count }
}
