import Foundation

/// Standardised install status, the five states the web app renders.
public enum InstallStatus: String, Sendable, Hashable, CaseIterable, Codable {
    case installed = "Installed"
    case pending = "Pending"
    case warning = "Warning"
    case error = "Error"
    case removed = "Removed"

    /// `standardizeInstallStatus`: any client spelling to the standard five.
    public static func standardize(_ raw: String?) -> InstallStatus {
        guard let raw, !raw.isEmpty else { return .pending }
        let trimmed = raw.trimmingCharacters(in: .whitespaces)
        if let exact = InstallStatus(rawValue: trimmed) { return exact }
        switch trimmed.lowercased() {
        case "installed", "install", "success", "successful", "completed", "complete", "up to date", "uptodate", "current", "ok", "install_succeeded":
            return .installed
        case "pending", "pending install", "pending_install", "pending update", "pending_update", "pendingupdate", "available",
             "update available", "update_available", "downloading", "installing", "queued", "waiting", "scheduled",
             "not available", "not_available", "notavailable":
            return .pending
        case "warning", "warnings", "warn", "caution", "needs attention", "needs_attention", "partial", "partially installed", "outdated":
            return .warning
        case "error", "errors", "failed", "failure", "fail", "broken", "corrupt", "corrupted", "missing", "not found", "not_found",
             "invalid", "timeout", "cancelled", "canceled":
            return .error
        case "removed", "uninstalled", "deleted", "absent", "not installed", "not_installed":
            return .removed
        default:
            return .pending
        }
    }

    public var displayName: String { rawValue }
}

/// A run message attached to a package (or to the run itself).
public struct InstallMessage: Sendable, Hashable, Identifiable {
    public var id: String
    public var code: String?
    public var message: String
    public var details: String?
    public var timestamp: String?
    public var package: String?
}

/// One managed item as the Installs tab lists it.
public struct InstallPackage: Sendable, Hashable, Identifiable {
    public var id: String
    public var name: String
    public var displayName: String
    public var version: String
    public var installedVersion: String
    public var status: InstallStatus
    public var type: String
    /// Non-empty only when the item was acted on in the latest run.
    public var lastUpdate: String
    public var itemSize: String?
    public var category: String
    public var developer: String
    public var pendingReason: String
    public var failureCount: Int
    public var lastAttemptStatus: String?
    public var errors: [InstallMessage] = []
    public var warnings: [InstallMessage] = []
    public var raw: JSONValue

    public var hasExpandableContent: Bool {
        !errors.isEmpty || !warnings.isEmpty || (status == .pending && !pendingReason.trimmingCharacters(in: .whitespaces).isEmpty)
    }

    /// Item size in bytes rendered as `1.2 GB`.
    public var formattedItemSize: String {
        guard let s = itemSize, let bytes = Double(s), bytes > 0 else { return "" }
        let units = ["B", "KB", "MB", "GB", "TB"]
        var size = bytes
        var i = 0
        while size >= 1024, i < units.count - 1 { size /= 1024; i += 1 }
        return i == 0 ? "\(Int(size)) \(units[i])" : String(format: "%.1f %@", size, units[i])
    }
}

public struct InstallsConfig: Sendable, Hashable {
    public var type: String
    public var version: String
    public var softwareRepoURL: String
    public var manifest: String
    public var runType: String
    public var lastRun: String
    public var duration: String
    public var durationSeconds: Double?
    public var catalogs: String
}

/// System-level problem no item can carry (manifest, catalog, preflight).
public struct SystemProblem: Sendable, Hashable {
    public var isError: Bool
    public var message: String
}

public struct SystemProblemsSummary: Sendable, Hashable {
    public var problems: [SystemProblem] = []
    public var sessionId: String?
    public var time: String?
    public var failedWithoutItems = false
    public var isEmpty: Bool { problems.isEmpty && !failedWithoutItems }
}

/// Port of `data-processing/modules/installs.ts` (`extractInstalls`).
public struct InstallsInfo: Sendable, Hashable {
    public var totalPackages: Int
    public var installed: Int
    public var pending: Int
    public var failed: Int
    public var lastUpdate: String
    public var packages: [InstallPackage]
    public var systemName: String
    public var cacheSizeMb: Double?
    public var config: InstallsConfig?
    public var runErrors: [InstallMessage]
    public var runWarnings: [InstallMessage]
    public var hasData: Bool
    public var isMunki: Bool
    public var raw: JSONValue

    public var hasManagementSystem: Bool { config != nil || !systemName.isEmpty }

    public var lastRunCount: Int { packages.filter { !$0.lastUpdate.isEmpty }.count }

    public func count(_ status: InstallStatus, lastRunOnly: Bool = false) -> Int {
        packages.filter { (!lastRunOnly || !$0.lastUpdate.isEmpty) && $0.status == status }.count
    }

    /// Timestamp of the last run, from config or the raw module.
    public var lastRunTimestamp: String? {
        if let r = config?.lastRun, !r.isEmpty { return r }
        return raw["munki"]["endTime"].nonEmptyString ?? raw["cimian"]["sessions"][0].firstString("startTime", "start_time")
    }

    public init(modules: JSONValue) {
        let installs = modules["installs"].unwrappingSingleton().normalizedKeys()
        raw = installs
        packages = []
        runErrors = []
        runWarnings = []
        totalPackages = 0; installed = 0; pending = 0; failed = 0
        lastUpdate = ""
        systemName = ""
        cacheSizeMb = nil
        config = nil
        hasData = !installs.isNull && !installs.isEmptyContainer
        isMunki = false
        guard hasData else { return }

        let cimian = installs["cimian"]
        let munki = installs["munki"]
        let hasMunkiSessions = !munki["sessions"].elements.isEmpty
        let hasCimianItems = !cimian["items"].elements.isEmpty
        let hasMunkiItems = !munki["items"].elements.isEmpty
        let hasMunkiSystem = !munki.isNull
        isMunki = hasMunkiItems || hasMunkiSystem

        // Latest session markers
        var latestSessionStart = "", latestSessionEnd = "", latestSessionId = ""
        if let s = cimian["sessions"].array?.first {
            latestSessionStart = s.firstString("startTime", "start_time") ?? ""
            latestSessionEnd = s.firstString("endTime", "end_time") ?? ""
            latestSessionId = s.firstString("sessionId", "session_id") ?? ""
        } else if let s = installs["recentSessions"].array?.first {
            latestSessionStart = s.firstString("startTime", "start_time") ?? ""
            latestSessionEnd = s.firstString("endTime", "end_time") ?? ""
            latestSessionId = s.firstString("sessionId", "session_id") ?? ""
        } else if hasMunkiSessions, let s = munki["sessions"].array?.first {
            latestSessionStart = s.firstString("startTime", "start_time") ?? ""
            latestSessionEnd = s.firstString("endTime", "end_time") ?? ""
            latestSessionId = s.firstString("sessionId", "session_id") ?? ""
        } else if let t = munki["startTime"].nonEmptyString ?? munki["endTime"].nonEmptyString {
            latestSessionStart = t
            latestSessionEnd = munki["endTime"].nonEmptyString ?? ""
        }

        // Items to process
        struct RawItem {
            var raw: JSONValue
            var name: String
            var displayName: String
            var status: String?
            var version: String
            var installedVersion: String
            var id: String
            var type: String
            var lastSeenInSession: String
            var lastUpdate: String
            var lastAttemptTime: String
            var lastAttemptStatus: String
            var failureCount: Int
            var installCount: Int
            var updateCount: Int
            var itemSize: String
            var category: String
            var developer: String
            var recentAttempts: [JSONValue]
        }
        var items: [RawItem] = []
        if hasCimianItems {
            for item in cimian["items"].elements {
                let name = item.firstString("itemName", "displayName", "name") ?? "Unknown"
                let type = item.firstString("type", "itemType", "group") ?? ""
                if name == "managed_apps" || name == "managed_profiles" || type == "managed_apps" || type == "managed_profiles" { continue }
                items.append(RawItem(
                    raw: item, name: name,
                    displayName: item.firstString("displayName", "itemName", "name") ?? "Unknown",
                    status: item.firstString("currentStatus", "mappedStatus", "status"),
                    version: item.firstString("installedVersion", "version", "latestVersion") ?? "Unknown",
                    installedVersion: item["installedVersion"].string ?? "",
                    id: item["id"].nonEmptyString ?? (item["itemName"].string ?? "").lowercased(),
                    type: "cimian",
                    lastSeenInSession: item["lastSeenInSession"].string ?? "",
                    lastUpdate: item["lastUpdate"].string ?? "",
                    lastAttemptTime: item["lastAttemptTime"].string ?? "",
                    lastAttemptStatus: item["lastAttemptStatus"].string ?? "",
                    failureCount: item["failureCount"].int ?? 0, installCount: item["installCount"].int ?? 0, updateCount: item["updateCount"].int ?? 0,
                    itemSize: item["itemSize"].string ?? "", category: item.firstString("category", "Category") ?? "",
                    developer: item.firstString("developer", "Developer") ?? "", recentAttempts: item["recentAttempts"].elements))
            }
        } else if hasMunkiItems {
            let processed: Set<String> = ["install_succeeded", "install_failed", "removed"]
            for item in munki["items"].elements {
                let name = item.firstString("name", "displayName") ?? "Unknown"
                let status = item["status"].string ?? ""
                let session = item["lastSeenInSession"].nonEmptyString ?? (processed.contains(status) ? (item["endTime"].string ?? "") : "")
                items.append(RawItem(
                    raw: item, name: name, displayName: item.firstString("displayName", "name") ?? "Unknown",
                    status: item.firstString("currentStatus", "status"),
                    version: item.firstString("version", "installedVersion") ?? "Unknown",
                    installedVersion: item["installedVersion"].string ?? "",
                    id: item["id"].nonEmptyString ?? name.lowercased().replacingOccurrences(of: " ", with: "-"),
                    type: "munki", lastSeenInSession: session, lastUpdate: "",
                    lastAttemptTime: item["lastAttemptTime"].string ?? "", lastAttemptStatus: item["lastAttemptStatus"].string ?? "",
                    failureCount: item["failureCount"].int ?? 0, installCount: item["installCount"].int ?? 0, updateCount: item["updateCount"].int ?? 0,
                    itemSize: item["itemSize"].string ?? "", category: item.firstString("category") ?? "", developer: item.firstString("developer") ?? "",
                    recentAttempts: item["recentAttempts"].elements))
            }
        } else if let recent = installs["recentInstalls"].array, !recent.isEmpty {
            for item in recent {
                let name = item.firstString("name", "displayName") ?? "Unknown"
                items.append(RawItem(raw: item, name: name, displayName: item.firstString("displayName", "name") ?? name,
                                     status: item["status"].string, version: item.firstString("version", "installedVersion") ?? "",
                                     installedVersion: item["installedVersion"].string ?? "", id: item["id"].nonEmptyString ?? name.lowercased(),
                                     type: item["type"].string ?? "Package", lastSeenInSession: item["lastSeenInSession"].string ?? "",
                                     lastUpdate: item["lastUpdate"].string ?? "", lastAttemptTime: "", lastAttemptStatus: "",
                                     failureCount: 0, installCount: 0, updateCount: 0, itemSize: "", category: "", developer: "", recentAttempts: []))
            }
        } else if let pendingNames = cimian["pendingPackages"].array, !pendingNames.isEmpty {
            for p in pendingNames.compactMap(\.string) {
                items.append(RawItem(raw: .string(p), name: p, displayName: p, status: "Pending", version: "Unknown", installedVersion: "", id: p, type: "cimian",
                                     lastSeenInSession: installs.firstString("lastCheckIn", "collectedAt") ?? "", lastUpdate: "", lastAttemptTime: "", lastAttemptStatus: "",
                                     failureCount: 0, installCount: 0, updateCount: 0, itemSize: "", category: "", developer: "", recentAttempts: []))
            }
        } else if let pendingNames = munki["pendingPackages"].array, !pendingNames.isEmpty {
            for p in pendingNames.compactMap(\.string) {
                items.append(RawItem(raw: .string(p), name: p, displayName: p, status: "Pending", version: "Unknown", installedVersion: "",
                                     id: p.lowercased().replacingOccurrences(of: " ", with: "-"), type: "munki",
                                     lastSeenInSession: munki["endTime"].string ?? "", lastUpdate: "", lastAttemptTime: "", lastAttemptStatus: "",
                                     failureCount: 0, installCount: 0, updateCount: 0, itemSize: "", category: "", developer: "", recentAttempts: []))
            }
        }

        var packages: [InstallPackage] = []
        for item in items {
            var finalStatus: InstallStatus
            if item.type == "cimian" {
                let standardized = InstallStatus.standardize(item.status)
                if standardized == .error || standardized == .warning || standardized == .removed {
                    finalStatus = standardized
                } else if !item.version.isEmpty, item.version != "Unknown", !item.installedVersion.isEmpty {
                    finalStatus = InstallsInfo.compareVersions(item.installedVersion, item.version) >= 0 ? .installed : .pending
                } else {
                    finalStatus = standardized
                }
            } else {
                finalStatus = InstallStatus.standardize(item.status)
            }

            // Date processed: only for items acted on in the latest run.
            var dateProcessed = ""
            let marker = item.lastSeenInSession
            if !marker.isEmpty {
                if InstallsInfo.isCimianSessionId(marker) {
                    if !latestSessionId.isEmpty, marker.trimmingCharacters(in: .whitespaces) == latestSessionId.trimmingCharacters(in: .whitespaces) {
                        let display = [item.lastAttemptTime, item.lastUpdate, latestSessionEnd, latestSessionStart].first { !$0.isEmpty } ?? ""
                        dateProcessed = display.isEmpty ? "" : InstallsInfo.normalizeCimianTimestamp(display)
                    }
                } else if !latestSessionStart.isEmpty,
                          let itemTime = FlexibleDate.parse(InstallsInfo.normalizeCimianTimestamp(marker)),
                          let sessionTime = FlexibleDate.parse(latestSessionStart),
                          itemTime >= sessionTime.addingTimeInterval(-60) {
                    dateProcessed = InstallsInfo.normalizeCimianTimestamp(marker)
                }
            }

            var pkg = InstallPackage(
                id: item.id.isEmpty ? item.name : item.id, name: item.name, displayName: item.displayName,
                version: item.version.isEmpty ? item.installedVersion : item.version, installedVersion: item.installedVersion,
                status: finalStatus, type: item.type, lastUpdate: dateProcessed, itemSize: item.itemSize.isEmpty ? nil : item.itemSize,
                category: item.category, developer: item.developer, pendingReason: item.raw.firstString("pendingReason", "pending_reason") ?? "",
                failureCount: item.failureCount, lastAttemptStatus: item.lastAttemptStatus.isEmpty ? nil : item.lastAttemptStatus, raw: item.raw)

            let hasLoop = item.raw["hasInstallLoop"].boolish
            if let lastError = item.raw["lastError"].nonEmptyString {
                var stamp = [item.lastAttemptTime, item.lastUpdate].first { !$0.isEmpty } ?? ISO8601DateFormatter().string(from: Date())
                let failed = item.recentAttempts.filter { ["failed", "error"].contains(($0["status"].string ?? "").lowercased()) }
                if let latest = failed.max(by: { (FlexibleDate.parse($0["timestamp"]) ?? .distantPast) < (FlexibleDate.parse($1["timestamp"]) ?? .distantPast) }),
                   let t = latest["timestamp"].nonEmptyString { stamp = t }
                let split = LogText.split(lastError)
                pkg.errors.append(InstallMessage(id: "\(pkg.id)-last-error", code: hasLoop ? "INSTALL_LOOP" : "ERROR", message: split.message, details: split.details, timestamp: stamp, package: item.name))
            }
            if let lastWarning = item.raw["lastWarning"].nonEmptyString {
                var stamp = [item.lastAttemptTime, item.lastUpdate].first { !$0.isEmpty } ?? ISO8601DateFormatter().string(from: Date())
                let warned = item.recentAttempts.filter { ($0["status"].string ?? "").lowercased() == "warning" }
                if let latest = warned.max(by: { (FlexibleDate.parse($0["timestamp"]) ?? .distantPast) < (FlexibleDate.parse($1["timestamp"]) ?? .distantPast) }),
                   let t = latest["timestamp"].nonEmptyString { stamp = t }
                let split = LogText.split(lastWarning)
                pkg.warnings.append(InstallMessage(id: "\(pkg.id)-last-warning", code: hasLoop ? "INSTALL_LOOP" : "WARNING", message: split.message, details: split.details, timestamp: stamp, package: item.name))
            }
            packages.append(pkg)
        }

        for i in packages.indices where packages[i].name == "DotNetRuntime" && packages[i].failureCount > 0 {
            packages[i].warnings.append(InstallMessage(id: "\(packages[i].id)-architecture-warning", code: "ARCHITECTURE_MISMATCH",
                                                       message: "DotNetRuntime has \(packages[i].failureCount) failure(s) - likely ARM64 vs x64 architecture mismatch",
                                                       details: nil, timestamp: ISO8601DateFormatter().string(from: Date()), package: packages[i].name))
        }
        for i in packages.indices {
            if !packages[i].errors.isEmpty { packages[i].status = .error } else if !packages[i].warnings.isEmpty { packages[i].status = .warning }
        }

        // Run type and duration
        var runType = "Manual"
        var duration = "Unknown"
        var durationSeconds: Double?
        func pick(_ sessions: [JSONValue]) {
            let active = sessions.first { s in
                let st = s["status"].string ?? ""
                let activity = (s["totalActions"].int ?? 0) > 0 || (s["packagesFailed"].int ?? 0) > 0 || (s["packagesInstalled"].int ?? 0) > 0
                    || (s["failures"].int ?? 0) > 0 || (s["installs"].int ?? 0) > 0 || (s["updates"].int ?? 0) > 0
                return (st == "completed" || st == "partial_failure") && activity
            }
            let completed = sessions.first { ($0["status"].string ?? "") == "completed" && (($0["durationSeconds"].double ?? 0) > 0 || (($0["duration"].string ?? "") != "" && $0["duration"].string != "00:00:00")) }
            let chosen = active ?? completed ?? sessions.first
            guard let chosen else { return }
            runType = chosen.firstString("runType", "run_type") ?? "Manual"
            duration = chosen["duration"].nonEmptyString ?? "Unknown"
            durationSeconds = chosen["durationSeconds"].double
        }
        if let recent = installs["recentSessions"].array, !recent.isEmpty {
            pick(recent)
        } else if hasMunkiSessions {
            let sessions = munki["sessions"].elements
            let withActivity = sessions.first { s in
                let st = s["status"].string ?? ""
                return (st == "completed" || st == "partial_failure") && ((s["summary"]["totalActions"].int ?? 0) > 0 || (s["summary"]["failures"].int ?? 0) > 0) && (s["durationSeconds"].double ?? 0) > 0
            }
            let chosen = withActivity ?? sessions.first { $0["status"].string != "running" } ?? sessions[0]
            runType = chosen.firstString("runType", "run_type") ?? "Manual"
            durationSeconds = chosen["durationSeconds"].double
            duration = durationSeconds.map { "\(Int($0))s" } ?? "Unknown"
        } else if let sessions = cimian["sessions"].array, !sessions.isEmpty {
            pick(sessions)
        }

        if let mb = installs["cacheStatus"]["cacheSizeMb"].double {
            cacheSizeMb = mb
        } else if let mb = installs["recentSessions"][0]["cacheSizeMb"].double {
            cacheSizeMb = mb
        }

        // Config
        let catalogsText: String = {
            let list = cimian["catalogs"].elements.compactMap(\.string) + munki["catalogs"].elements.compactMap(\.string)
            if !list.isEmpty { return list.joined(separator: ", ") }
            let cfg = cimian["config"]
            if let d = cfg.firstString("DefaultCatalog", "defaultCatalog") { return d }
            if let s = cfg.firstString("Catalogs", "catalogs"), s != "[]", let parsed = JSONValue.parse(s)?.array, !parsed.isEmpty {
                return parsed.compactMap(\.string).joined(separator: ", ")
            }
            return "Not configured"
        }()
        if isMunki {
            systemName = "Munki"
            config = InstallsConfig(type: "Munki", version: munki["version"].string ?? "",
                                    softwareRepoURL: munki.firstString("softwareRepoURL", "softwareRepoUrl") ?? "",
                                    manifest: munki.firstString("manifestName", "clientIdentifier") ?? "",
                                    runType: hasMunkiSessions ? runType : "Auto",
                                    lastRun: munki.firstString("endTime", "lastRun") ?? "",
                                    duration: hasMunkiSessions ? duration : "Unknown",
                                    durationSeconds: hasMunkiSessions ? durationSeconds : nil, catalogs: catalogsText)
        } else {
            systemName = cimian["config"]["systemName"].nonEmptyString ?? "Cimian"
            let session0 = cimian["sessions"][0]["config"]
            config = InstallsConfig(type: "Cimian", version: cimian["version"].nonEmptyString ?? installs["version"].string ?? "",
                                    softwareRepoURL: cimian["config"].firstString("SoftwareRepoURL", "softwareRepoUrl") ?? session0.firstString("softwareRepoUrl", "software_repo_url") ?? "",
                                    manifest: cimian["config"].firstString("ClientIdentifier", "clientIdentifier") ?? session0.firstString("clientIdentifier", "client_identifier") ?? "",
                                    runType: runType, lastRun: installs["lastCheckIn"].string ?? "",
                                    duration: durationSeconds.map { "\(Int($0))s" } ?? duration, durationSeconds: durationSeconds, catalogs: catalogsText)
        }
        lastUpdate = installs.firstString("lastCheckIn", "collectedAt") ?? ""

        // Munki run-level messages and legacy string parsing
        if isMunki {
            let stamp = munki["endTime"].nonEmptyString ?? ISO8601DateFormatter().string(from: Date())
            for i in packages.indices {
                if let e = packages[i].raw["lastError"].nonEmptyString, packages[i].errors.isEmpty {
                    let split = LogText.split(e)
                    packages[i].errors.append(InstallMessage(id: "munki-item-error-\(packages[i].id)", code: packages[i].raw["hasInstallLoop"].boolish ? "INSTALL_LOOP" : "MUNKI_ERROR", message: split.message, details: split.details, timestamp: stamp, package: packages[i].name))
                    packages[i].status = .error
                } else if let w = packages[i].raw["lastWarning"].nonEmptyString, packages[i].warnings.isEmpty, packages[i].errors.isEmpty {
                    let split = LogText.split(w)
                    packages[i].warnings.append(InstallMessage(id: "munki-item-warning-\(packages[i].id)", code: packages[i].raw["hasInstallLoop"].boolish ? "INSTALL_LOOP" : "MUNKI_WARNING", message: split.message, details: split.details, timestamp: stamp, package: packages[i].name))
                    if packages[i].status != .error { packages[i].status = .warning }
                }
            }
            if hasMunkiSessions {
                for problem in munki["errorItems"].elements where problem["name"].nonEmptyString == nil {
                    if let m = problem["message"].nonEmptyString { runErrors.append(InstallMessage(id: "munki-run-error-system", code: "MUNKI_ERROR", message: m, details: nil, timestamp: stamp, package: "Munki")) }
                }
                for problem in munki["warningItems"].elements where problem["name"].nonEmptyString == nil {
                    if let m = problem["message"].nonEmptyString { runWarnings.append(InstallMessage(id: "munki-run-warning-system", code: "MUNKI_WARNING", message: m, details: nil, timestamp: stamp, package: "Munki")) }
                }
            } else {
                if let errors = munki["errors"].nonEmptyString {
                    for (msg, details) in InstallsInfo.parseInstallerBlocks(errors) {
                        InstallsInfo.attach(message: msg, details: details, isError: true, stamp: stamp, packages: &packages, runErrors: &runErrors, runWarnings: &runWarnings)
                    }
                }
                if let warnings = munki["warnings"].nonEmptyString {
                    for msg in warnings.split(separator: ";").map({ $0.trimmingCharacters(in: .whitespaces) }).filter({ !$0.isEmpty }) {
                        InstallsInfo.attach(message: msg, details: nil, isError: false, stamp: stamp, packages: &packages, runErrors: &runErrors, runWarnings: &runWarnings)
                    }
                }
            }
            let problemArray = munki["problemInstallsArray"].array?.compactMap(\.string)
            let problemItems: [String] = problemArray?.map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
                ?? (munki["problemInstalls"].nonEmptyString?.components(separatedBy: CharacterSet(charactersIn: ";,")).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty } ?? [])
            for name in problemItems {
                let needle = name.lowercased()
                var idx = packages.firstIndex { $0.name.lowercased() == needle || $0.displayName.lowercased() == needle }
                if idx == nil {
                    packages.append(InstallPackage(id: name.lowercased().replacingOccurrences(of: " ", with: "-"), name: name, displayName: name, version: "", installedVersion: "",
                                                   status: .warning, type: "munki", lastUpdate: munki["endTime"].string ?? "", itemSize: nil, category: "", developer: "",
                                                   pendingReason: "", failureCount: 0, lastAttemptStatus: nil, raw: .null))
                    idx = packages.count - 1
                }
                if let i = idx, !packages[i].warnings.contains(where: { $0.code == "MUNKI_PROBLEM_INSTALL" }) {
                    packages[i].warnings.append(InstallMessage(id: "munki-problem-\(packages[i].id)", code: "MUNKI_PROBLEM_INSTALL", message: "Reported as a problem install by Munki", details: nil, timestamp: stamp, package: name))
                    if packages[i].status != .error { packages[i].status = .warning }
                }
            }
        }

        self.packages = packages
        totalPackages = packages.count
        installed = packages.filter { $0.status == .installed }.count
        pending = packages.filter { $0.status == .pending }.count
        let errors = packages.filter { $0.status == .error }.count
        let warnings = packages.filter { $0.status == .warning }.count
        failed = errors + warnings + (isMunki ? runErrors.count + runWarnings.count : 0)
    }

    /// Attach a legacy Munki run message to the package it names, a synthetic
    /// package for an item missing from the list, or the run itself.
    private static func attach(message: String, details: String?, isError: Bool, stamp: String, packages: inout [InstallPackage], runErrors: inout [InstallMessage], runWarnings: inout [InstallMessage]) {
        let lower = message.lowercased()
        let sorted = packages.indices.sorted { packages[$0].name.count > packages[$1].name.count }
        var matched = sorted.first { i in
            let p = packages[i]
            return (!p.name.isEmpty && lower.contains(p.name.lowercased())) || (!p.displayName.isEmpty && p.displayName != p.name && lower.contains(p.displayName.lowercased()))
        }
        if matched == nil, let itemName = itemName(fromMunkiMessage: message) {
            matched = packages.firstIndex { $0.name.lowercased() == itemName.lowercased() }
            if matched == nil {
                packages.append(InstallPackage(id: itemName.lowercased().replacingOccurrences(of: " ", with: "-"), name: itemName, displayName: itemName, version: "", installedVersion: "",
                                               status: isError ? .error : .warning, type: "munki", lastUpdate: stamp, itemSize: nil, category: "", developer: "", pendingReason: "",
                                               failureCount: 0, lastAttemptStatus: nil, raw: .null))
                matched = packages.count - 1
            }
        }
        if let i = matched {
            if isError {
                if packages[i].errors.contains(where: { $0.message == message }) { return }
                packages[i].errors.append(InstallMessage(id: "munki-run-error-\(packages[i].id)", code: "MUNKI_ERROR", message: message, details: details, timestamp: stamp, package: packages[i].name))
                packages[i].status = .error
            } else {
                if packages[i].warnings.contains(where: { $0.message == message }) { return }
                packages[i].warnings.append(InstallMessage(id: "munki-run-warning-\(packages[i].id)", code: "MUNKI_WARNING", message: message, details: nil, timestamp: stamp, package: packages[i].name))
                if packages[i].status != .error { packages[i].status = .warning }
            }
        } else if isError {
            runErrors.append(InstallMessage(id: "munki-run-error-system", code: "MUNKI_ERROR", message: message, details: details, timestamp: stamp, package: "Munki"))
        } else {
            runWarnings.append(InstallMessage(id: "munki-run-warning-system", code: "MUNKI_WARNING", message: message, details: nil, timestamp: stamp, package: "Munki"))
        }
    }

    /// Group installer log blocks (between `---` lines) into single messages.
    static func parseInstallerBlocks(_ raw: String) -> [(String, String?)] {
        var out: [(String, String?)] = []
        var block: [String] = []
        var inBlock = false
        func summary(_ lines: [String]) -> String {
            lines.first { l in
                !l.lowercased().hasPrefix("installer:phase:") && !l.lowercased().hasPrefix("installer:status:") && !l.lowercased().hasPrefix("installer:%")
                    && l.range(of: #"^installer:\s*Package name is\s*$"#, options: [.regularExpression, .caseInsensitive]) == nil
                    && l.range(of: #"^installer:\s*Upgrading at base path"#, options: [.regularExpression, .caseInsensitive]) == nil
                    && l.trimmingCharacters(in: .whitespaces).count > 10
            } ?? lines.last ?? ""
        }
        for part in raw.split(separator: ";").map({ $0.trimmingCharacters(in: .whitespaces) }) where !part.isEmpty {
            if part.range(of: #"^-{10,}$"#, options: .regularExpression) != nil {
                if inBlock, !block.isEmpty {
                    out.append((summary(block), block.joined(separator: "\n")))
                    block = []
                }
                inBlock.toggle()
                continue
            }
            if inBlock { block.append(part) } else { out.append((part, nil)) }
        }
        if !block.isEmpty { out.append((summary(block), block.joined(separator: "\n"))) }
        return out
    }

    /// `extractItemNameFromMessage`
    static func itemName(fromMunkiMessage message: String) -> String? {
        let patterns = [#"Could not process item (.+?) for"#, #"Install of (.+?)(?:\s+failed|-\d)"#, #"Download of (.+?) failed"#,
                        #"Could not install (.+?)(?:\.|;|$)"#, #"Problem (?:with|installing) (.+?)(?:\.|;|$)"#]
        for p in patterns {
            if let re = try? NSRegularExpression(pattern: p, options: .caseInsensitive),
               let m = re.firstMatch(in: message, range: NSRange(message.startIndex..., in: message)), m.numberOfRanges > 1,
               let r = Range(m.range(at: 1), in: message) {
                return String(message[r]).trimmingCharacters(in: .whitespaces)
            }
        }
        return nil
    }

    /// `compareSemanticVersions`
    public static func compareVersions(_ a: String, _ b: String) -> Int {
        if a.isEmpty, b.isEmpty { return 0 }
        if a.isEmpty { return -1 }
        if b.isEmpty { return 1 }
        if a == b { return 0 }
        func parse(_ v: String) -> [Int]? {
            let t = v.trimmingCharacters(in: .whitespaces)
            guard let r = t.range(of: #"^\d+(?:\.\d+)*"#, options: .regularExpression) else { return nil }
            let parts = t[r].split(separator: ".").compactMap { Int($0) }
            return parts.isEmpty ? nil : parts
        }
        guard let pa = parse(a), let pb = parse(b) else {
            return a.localizedCaseInsensitiveCompare(b) == .orderedAscending ? -1 : (a.localizedCaseInsensitiveCompare(b) == .orderedDescending ? 1 : 0)
        }
        for i in 0..<max(pa.count, pb.count) {
            let x = i < pa.count ? pa[i] : 0
            let y = i < pb.count ? pb[i] : 0
            if x > y { return 1 }
            if x < y { return -1 }
        }
        return 0
    }

    /// Cimian session ids look like `2026-08-28-1158`.
    public static func isCimianSessionId(_ value: String?) -> Bool {
        guard let v = value?.trimmingCharacters(in: .whitespaces) else { return false }
        return v.range(of: #"^\d{4}-\d{2}-\d{2}-\d{4}$"#, options: .regularExpression) != nil
    }

    /// `normalizeCimianTimestamp`: Cimian writes Pacific local time with a `Z`
    /// suffix; shift those eight hours so they read as UTC like the web app.
    public static func normalizeCimianTimestamp(_ timestamp: String) -> String {
        guard !timestamp.isEmpty else { return "" }
        let iso = ISO8601DateFormatter()
        iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if timestamp.contains("-08:00") || timestamp.contains("-07:00") || timestamp.contains("+") {
            if let d = FlexibleDate.parse(timestamp) { return iso.string(from: d) }
        }
        if timestamp.hasSuffix("Z"), !timestamp.contains("+"), !timestamp.contains("-08"), !timestamp.contains("-07"), let d = FlexibleDate.parse(timestamp) {
            return iso.string(from: d.addingTimeInterval(8 * 3600))
        }
        return timestamp
    }
}

extension LogText {
    /// `splitLogText`: the first line is the message, the rest are details.
    public static func split(_ raw: String) -> (message: String, details: String?) {
        let text = cleanMultiline(raw)
        guard let nl = text.firstIndex(of: "\n") else { return (text, nil) }
        let details = text[text.index(after: nl)...].trimmingCharacters(in: .whitespacesAndNewlines)
        return (String(text[..<nl]).trimmingCharacters(in: .whitespaces), details.isEmpty ? nil : details)
    }

    /// `cleanLogText`: strip ANSI, normalise line endings, collapse blank runs.
    public static func cleanMultiline(_ raw: String) -> String {
        var s = raw.replacingOccurrences(of: #"\u{1B}\[[0-9;]*[A-Za-z]|\u{1B}"#, with: "", options: .regularExpression)
        s = s.replacingOccurrences(of: "\r\n", with: "\n").replacingOccurrences(of: "\r", with: "\n")
        s = s.split(separator: "\n", omittingEmptySubsequences: false).map { $0.replacingOccurrences(of: #"\s+$"#, with: "", options: .regularExpression) }.joined(separator: "\n")
        s = s.replacingOccurrences(of: #"\n{3,}"#, with: "\n\n", options: .regularExpression)
        return s.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

/// Port of `installs/systemProblems.ts`.
public enum SystemProblems {
    static func systemLines(_ raw: JSONValue) -> [String] {
        guard let s = raw.string else { return [] }
        return LogText.cleanMultiline(s).components(separatedBy: CharacterSet(charactersIn: ";\n"))
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && $0.range(of: #"^-{3,}$"#, options: .regularExpression) == nil && !$0.lowercased().hasPrefix("installer:") && InstallItems.itemName(fromMessage: $0) == nil }
    }

    /// `installs` is the normalised installs module.
    public static func collect(installs: JSONValue, now: Date = Date()) -> SystemProblemsSummary {
        let munki = installs["munki"], cimian = installs["cimian"]
        var empty = SystemProblemsSummary()
        if !munki.isNull {
            let sessions = munki["sessions"].elements
            if !sessions.isEmpty {
                // Only the latest session is read: a run's problems describe the
                // state that run found, and the next clean run supersedes them.
                let session = sessions[0]
                let itemless = munki["items"].elements.isEmpty
                let failedWithoutItems = (session["status"].string ?? "").lowercased() == "failed" && itemless
                var problems: [SystemProblem] = []
                for (keys, isError) in [(["errorItems", "error_items"], true), (["warningItems", "warning_items"], false)] {
                    let list = keys.map { session[$0] }.first { !$0.isNull }?.elements ?? []
                    for problem in list where problem["name"].nonEmptyString == nil {
                        let message = LogText.cleanMultiline(problem["message"].string ?? "")
                        if !message.isEmpty, !problems.contains(where: { $0.message == message }) { problems.append(SystemProblem(isError: isError, message: message)) }
                    }
                }
                if problems.isEmpty {
                    empty.failedWithoutItems = failedWithoutItems
                    return empty
                }
                return SystemProblemsSummary(problems: problems, sessionId: session.firstString("sessionId", "session_id"),
                                             time: session.firstString("endTime", "end_time", "startTime", "start_time") ?? "", failedWithoutItems: failedWithoutItems)
            }
            let errors = systemLines(munki["errors"])
            let warnings = systemLines(munki["warnings"])
            let status = (munki["status"].string ?? "").lowercased()
            let failed = munki["lastRunSuccess"].boolishIfPresent == false || status == "error" || munki["errors"].nonEmptyString != nil
            return SystemProblemsSummary(problems: errors.map { SystemProblem(isError: true, message: $0) } + warnings.map { SystemProblem(isError: false, message: $0) },
                                         sessionId: nil, time: nil, failedWithoutItems: failed && munki["items"].elements.isEmpty)
        }
        if !cimian.isNull {
            let sessions = cimian["sessions"].elements
            guard !sessions.isEmpty else { return empty }
            let latestFailed = ["failed", "error"].contains((sessions[0]["status"].string ?? "").lowercased())
            empty.failedWithoutItems = latestFailed && cimian["items"].elements.isEmpty
            return empty
        }
        return empty
    }
}

/// Item-level predicates shared by the installs report and the events feed
/// (port of `installs/status.ts`).
public enum InstallItems {
    public enum Category: String, Sendable { case error, warning, pending, success }

    static let runWarningPatterns: [NSRegularExpression] = [
        #"^(?:Download|Install|Installation|Removal|Update) of (.+?) failed"#,
        #"Could not process item (\S+)"#,
        #"Will not attempt to remove (\S+)"#,
        #"^(\S+) (?:requires|is not|was not|could not)"#,
    ].map { try! NSRegularExpression(pattern: $0, options: [.caseInsensitive]) }

    /// The package a Munki run message is about, or nil.
    public static func itemName(fromMessage message: String) -> String? {
        for re in runWarningPatterns {
            if let m = re.firstMatch(in: message, range: NSRange(message.startIndex..., in: message)), m.numberOfRanges > 1, let r = Range(m.range(at: 1), in: message) {
                return String(message[r]).replacingOccurrences(of: #"[.,:]+$"#, with: "", options: .regularExpression)
            }
        }
        return nil
    }

    /// Cimian items first, then Munki.
    public static func items(of device: JSONValue) -> [JSONValue] {
        let installs = device["modules"]["installs"]
        let cimian = installs["cimian"]["items"].elements
        if !cimian.isEmpty { return cimian }
        return installs["munki"]["items"].elements
    }

    /// The state the API computed at ingest (`reportmateStatus`), when present.
    static func storedCategory(_ item: JSONValue) -> Category? {
        switch item.firstString("reportmateStatus", "reportmate_status")?.lowercased() {
        case "error": return .error
        case "warning": return .warning
        case "pending": return .pending
        case "installed": return .success
        default: return nil
        }
    }

    /// One state is spelled three ways across live payloads ("Update Available",
    /// "update-available", "update_available"), so normalise before matching.
    static func normalizedStatus(_ raw: String?) -> String {
        (raw ?? "").lowercased().replacingOccurrences(of: " ", with: "-").replacingOccurrences(of: "_", with: "-")
    }

    static func statusCategory(_ raw: String?) -> Category? {
        let status = normalizedStatus(raw)
        if status.isEmpty { return nil }
        if status.contains("error") || status.contains("failed") || status.contains("problem") || status == "needs-reinstall" { return .error }
        // "not-installed" contains "installed" and means the opposite: managed, expected, absent.
        if status.contains("warning") || status.contains("install-loop") || status == "needs-attention" || status == "not-installed" { return .warning }
        if status.contains("pending") || status.contains("will-be-installed") || status.contains("update-available") || status.contains("will-be-removed")
            || status.contains("scheduled") || status.contains("available") || status.contains("downloading") || status.contains("installing")
            || status == "skipped" || status == "unknown" { return .pending }
        // An install that ran and completed in the most recent run, not merely present.
        if status == "install-succeeded" || status == "completed" || status == "success" { return .success }
        return nil
    }

    /// Whether the tool's verdict says the item is fine: Installed and Removed are
    /// judgements written after the run.
    static func verdictIsGood(_ item: JSONValue) -> Bool {
        let status = normalizedStatus(item.firstString("currentStatus", "current_status", "mappedStatus", "mapped_status"))
        if status.isEmpty || status == "not-installed" { return false }
        return ["installed", "removed", "uninstalled", "install-succeeded", "completed", "success"].contains(status)
    }

    static func attemptCategory(_ item: JSONValue) -> Category? {
        let attempt = (item.firstString("lastAttemptStatus", "last_attempt_status") ?? "").lowercased()
        if attempt.isEmpty { return nil }
        if attempt.contains("warn") { return .warning }
        if attempt.contains("fail") || attempt.contains("error") { return .error }
        return nil
    }

    /// A package that reinstalls every run is not healthy, however it reports.
    static func hasInstallLoop(_ item: JSONValue) -> Bool {
        item.first("hasInstallLoop", "has_install_loop").boolish || item.first("installLoopDetected", "install_loop_detected").boolish
    }

    /// Whether the run itself attributed a message (stamped `lastSeenInSession`),
    /// rather than the client scraping it from the run log.
    static func runReported(_ item: JSONValue, hasSessions: Bool) -> Bool {
        !hasSessions || item.firstString("lastSeenInSession", "last_seen_in_session") != nil
    }

    /// The item's state, by the same ladder the API applies at ingest
    /// (`itemCategory` in `installs/status.ts`).
    public static func category(of item: JSONValue, hasSessions: Bool = false) -> Category? {
        if let stored = storedCategory(item) { return stored }
        let verdict = statusCategory(item.firstString("currentStatus", "current_status", "mappedStatus", "mapped_status"))
        if verdict == .error || verdict == .warning { return verdict }
        if verdictIsGood(item) { return hasInstallLoop(item) ? .warning : verdict }
        let presence = statusCategory(item["status"].string)
        if presence == .error || presence == .warning { return presence }
        let attempt = attemptCategory(item)
        if attempt == .error || attempt == .warning { return attempt }
        if runReported(item, hasSessions: hasSessions) {
            if item.firstString("lastError", "last_error") != nil { return .error }
            if item.firstString("lastWarning", "last_warning") != nil { return .warning }
        }
        if hasInstallLoop(item) { return .warning }
        return verdict ?? presence
    }

    public static func isError(_ item: JSONValue) -> Bool { category(of: item) == .error }
    public static func isWarning(_ item: JSONValue) -> Bool { category(of: item) == .warning }
    public static func isPending(_ item: JSONValue) -> Bool { category(of: item) == .pending }
    public static func isSuccess(_ item: JSONValue) -> Bool { category(of: item) == .success }

    public static func matches(_ item: JSONValue, _ category: Category?) -> Bool {
        guard let category else { return true }
        switch category {
        case .error: return isError(item)
        case .warning: return isWarning(item)
        case .pending: return isPending(item)
        case .success: return isSuccess(item)
        }
    }

    public static func name(of item: JSONValue) -> String {
        item.firstString("itemName", "item_name", "name", "displayName", "display_name") ?? "Unknown"
    }

    /// `getItemMessage`
    public static func message(of item: JSONValue, _ category: Category) -> String {
        switch category {
        case .error: return item.firstString("lastError", "last_error") ?? ""
        case .warning: return item.firstString("lastWarning", "last_warning") ?? ""
        case .success:
            if let v = item.firstString("installedVersion", "installed_version", "version", "latestVersion", "latest_version") { return "Installed \(v)" }
            return ""
        case .pending:
            if let r = item.firstString("pendingReason", "pending_reason") { return r }
            if let t = item.firstString("version", "latestVersion", "latest_version") { return "Waiting to install \(t)" }
            return ""
        }
    }

    public static func timestamp(of item: JSONValue) -> String? {
        item.firstString("endTime", "end_time", "lastAttemptTime", "last_attempt_time", "lastUpdate", "last_update")
    }

    /// Munki's run-level warnings, attributed to items by name where possible.
    public static func runLevelWarnings(of device: JSONValue) -> [(message: String, itemName: String?)] {
        guard let raw = device["modules"]["installs"]["munki"]["warnings"].nonEmptyString else { return [] }
        return raw.replacingOccurrences(of: "WARNING:", with: "\n").components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
            .map { ($0, itemName(fromMessage: $0)) }
    }
}
