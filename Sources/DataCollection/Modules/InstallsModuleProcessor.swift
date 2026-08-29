import Foundation

/// Installs module processor - uses osquery first with bash fallback
/// Supports both Munki (macOS) and Cimian (cross-platform) managed installs
/// Reference: https://github.com/macadmins/osquery-extension for Munki tables
/// Tables: munki_info, munki_installs (macadmins extension)
/// NO PYTHON - uses osquery for: package_install_history, homebrew_packages, munki_info, munki_installs
/// Bash/plutil/awk fallback for: Munki manifests, install history plist
public class InstallsModuleProcessor: BaseModuleProcessor, @unchecked Sendable {
    
    public init(configuration: ReportMateConfiguration) {
        super.init(moduleId: "installs", configuration: configuration)
    }
    
    public override func collectData() async throws -> ModuleData {
        // Total collection steps for progress tracking
        let totalSteps = 8
        
        // Collect install data sequentially with progress tracking
        ConsoleFormatter.writeQueryProgress(queryName: "install_history", current: 1, total: totalSteps)
        let history = try await collectInstallHistory()
        
        ConsoleFormatter.writeQueryProgress(queryName: "homebrew_packages", current: 2, total: totalSteps)
        let homebrew = try await collectHomebrewPackages()
        
        ConsoleFormatter.writeQueryProgress(queryName: "munki_log", current: 3, total: totalSteps)
        // Newer Munki builds write structured session reports; when present they replace the
        // log slicing and the regex attribution below, and the legacy plist path is untouched.
        let sessionReports = MunkiSessionReportReader.read()
        let runLog: String
        if let reports = sessionReports, !reports.runLog.isEmpty {
            runLog = reports.runLog
        } else {
            runLog = try await collectMunkiRunLog()
        }

        ConsoleFormatter.writeQueryProgress(queryName: "munki_info", current: 4, total: totalSteps)
        let info = try await collectMunkiInfo(runLog: runLog)

        ConsoleFormatter.writeQueryProgress(queryName: "munki_installs", current: 5, total: totalSteps)
        var installs = try await collectMunkiManagedInstalls()

        ConsoleFormatter.writeQueryProgress(queryName: "pending_updates", current: 6, total: totalSteps)
        let pending = try await collectPendingUpdates()
        
        ConsoleFormatter.writeQueryProgress(queryName: "catalog_metadata", current: 7, total: totalSteps)
        let catalogData = try await collectCatalogMetadata()
        
        ConsoleFormatter.writeQueryProgress(queryName: "manifest_catalogs", current: 8, total: totalSteps)
        let manifestCatalogs = try await collectManifestCatalogs(manifestName: info["manifestName"] as? String)
        
        // Enrich installs with category/developer from catalog
        installs = enrichInstallsWithCatalogData(installs: installs, catalogData: catalogData)
        
        // Build MunkiInfo object if Munki is detected
        var munkiInfoObject: MunkiInfo? = nil
        if info["isInstalled"] as? Bool == true || !installs.isEmpty {
            var munki = MunkiInfo()
            munki.isInstalled = info["isInstalled"] as? Bool ?? !installs.isEmpty
            munki.version = info["version"] as? String ?? ""
            munki.clientIdentifier = info["clientIdentifier"] as? String
            munki.manifestName = info["manifestName"] as? String
            munki.softwareRepoURL = info["softwareRepoURL"] as? String
            munki.consoleUser = info["consoleUser"] as? String
            munki.startTime = info["startTime"] as? String
            munki.endTime = info["endTime"] as? String
            munki.lastRunSuccess = (info["success"] as? String) == "true"
            munki.errors = info["errors"] as? String
            munki.warnings = info["warnings"] as? String
            munki.problemInstalls = info["problemInstalls"] as? String
            
            // Set catalogs from manifest
            munki.catalogs = manifestCatalogs
            
            // Parse endTime to lastRun date
            if let endTimeStr = info["endTime"] as? String, !endTimeStr.isEmpty {
                let formatter = ISO8601DateFormatter()
                formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
                munki.lastRun = formatter.date(from: endTimeStr)
            }
            
            // Determine overall status
            if let errors = munki.errors, !errors.isEmpty {
                munki.status = "Error"
            } else if let warnings = munki.warnings, !warnings.isEmpty {
                munki.status = "Warning"
            } else if munki.lastRunSuccess {
                munki.status = "Active"
            } else if munki.isInstalled {
                munki.status = "Inactive"
            }
            
            // Add collected items
            munki.items = installs
            
            // Attach per-item warnings/errors using precise regex extraction from raw arrays
            // Each Munki warning/error message has a known pattern containing the exact item name
            let warningArray = info["warningsArray"] as? [String] ?? []
            let errorArray = info["errorsArray"] as? [String] ?? []
            munki.items = Self.attachMessagesToItems(
                items: munki.items,
                warningMessages: warningArray,
                errorMessages: errorArray
            )
            
            munkiInfoObject = munki
        }
        
        // Build installs data - runLog at top level like Cimian does
        var installsData: [String: Any] = [
            "installHistory": history,
            "homebrewPackages": homebrew,
            "managedInstalls": installs.map { item -> [String: Any] in
                [
                    "name": item.name,
                    "displayName": item.displayName,
                    "version": item.version,
                    "installedVersion": item.installedVersion,
                    "status": item.status,
                    "type": item.type,
                    "installedSize": item.installedSize
                ]
            },
            "pendingUpdates": pending,
            "munki": munkiInfoObject.map { munki -> [String: Any] in
                var dict: [String: Any] = [
                    "isInstalled": munki.isInstalled,
                    "version": munki.version,
                    "status": munki.status,
                    "lastRunSuccess": munki.lastRunSuccess,
                    "items": munki.items.map { item -> [String: Any] in
                        let d: [String: Any] = [
                            "id": item.id,
                            "name": item.name,
                            "displayName": item.displayName,
                            "version": item.version,
                            "installedVersion": item.installedVersion,
                            "status": item.status,
                            "type": item.type,
                            "installedSize": item.installedSize,
                            "endTime": item.endTime,
                            "lastError": item.lastError,
                            "lastWarning": item.lastWarning,
                            "pendingReason": item.pendingReason,
                            "category": item.category,
                            "developer": item.developer
                        ]
                        return d
                    }
                ]
                if let clientId = munki.clientIdentifier { dict["clientIdentifier"] = clientId }
                if let manifest = munki.manifestName { dict["manifestName"] = manifest }
                if let repoURL = munki.softwareRepoURL { dict["softwareRepoURL"] = repoURL }
                if let console = munki.consoleUser { dict["consoleUser"] = console }
                if let start = munki.startTime { dict["startTime"] = start }
                if let end = munki.endTime { dict["endTime"] = end }
                if let errors = munki.errors { dict["errors"] = errors }
                if let warnings = munki.warnings { dict["warnings"] = warnings }
                if let problems = munki.problemInstalls { dict["problemInstalls"] = problems }
                if let lastRun = munki.lastRun { dict["lastRun"] = ISO8601DateFormatter().string(from: lastRun) }
                if !munki.catalogs.isEmpty { dict["catalogs"] = munki.catalogs }
                return dict
            } ?? [:]
        ]
        
        // Inject newly installed/removed items info for event message generation
        if var munkiDict = installsData["munki"] as? [String: Any] {
            munkiDict["newlyInstalledCount"] = info["newlyInstalledCount"] as? Int ?? 0
            munkiDict["newlyInstalledItems"] = info["newlyInstalledItems"] as? [[String: String]] ?? []
            munkiDict["newlyRemovedCount"] = info["newlyRemovedCount"] as? Int ?? 0
            munkiDict["newlyRemovedItems"] = info["newlyRemovedItems"] as? [[String: String]] ?? []
            if let reports = sessionReports {
                munkiDict = Self.applySessionReports(reports, to: munkiDict)
            }
            installsData["munki"] = munkiDict
        }
        
        // Add runLog at top level (same key as Cimian for API compatibility)
        if !runLog.isEmpty {
            installsData["runLog"] = runLog
        }
        
        return BaseModuleData(moduleId: moduleId, data: installsData)
    }
    
    // MARK: - Structured session reports (newer Munki builds)

    /// Merges Munki's session reports into the `munki` payload using the field names the
    /// Windows client sends for Cimian, so the dashboard reads both platforms the same way.
    /// Sessions stay snake_case as written; events and items are camelCase.
    static func applySessionReports(_ reports: MunkiSessionReports, to munki: [String: Any]) -> [String: Any] {
        var dict = munki
        dict["sessions"] = Array(reports.sessions.prefix(20))
        dict["events"] = reports.events.map { event -> [String: Any] in
            var e = MunkiSessionReportReader.camelCased(event)
            // Windows names these `package` and `version` on the wire.
            if let name = event["package_name"] { e["package"] = name }
            if let version = event["package_version"] { e["version"] = version }
            return e
        }
        dict["totalSessions"] = reports.totalSessions
        if let id = reports.sessionId { dict["sessionId"] = id }
        if let runType = reports.runType { dict["runType"] = runType }
        if let duration = reports.durationSeconds { dict["durationSeconds"] = duration }
        if let status = reports.status { dict["lastSessionStatus"] = status }
        dict["warningItems"] = reports.warningItems
        dict["errorItems"] = reports.errorItems
        if let version = reports.environment["munki_version"] as? String, !version.isEmpty,
           (dict["version"] as? String ?? "").isEmpty
        {
            dict["version"] = version
        }
        if let clientId = reports.environment["client_identifier"] as? String, !clientId.isEmpty, dict["clientIdentifier"] == nil {
            dict["clientIdentifier"] = clientId
        }

        // Per-item fields from items.json, keyed by exact name. lastError / lastWarning
        // from the report replace the regex attribution when present.
        var byName: [String: [String: Any]] = [:]
        for record in reports.items {
            if let name = record["item_name"] as? String { byName[name] = record }
        }
        var errorByName: [String: String] = [:]
        for problem in reports.errorItems {
            if let name = problem["name"] as? String, let message = problem["message"] as? String, errorByName[name] == nil {
                errorByName[name] = message
            }
        }
        var warningByName: [String: String] = [:]
        for problem in reports.warningItems {
            if let name = problem["name"] as? String, let message = problem["message"] as? String, warningByName[name] == nil {
                warningByName[name] = message
            }
        }
        if let items = dict["items"] as? [[String: Any]] {
            dict["items"] = items.map { item -> [String: Any] in
                var i = item
                let name = item["name"] as? String ?? ""
                if let record = byName[name] {
                    i["itemName"] = record["item_name"]
                    i["itemType"] = record["item_type"]
                    i["currentStatus"] = record["current_status"]
                    i["mappedStatus"] = record["current_status"]
                    i["latestVersion"] = record["latest_version"]
                    i["lastSeenInSession"] = record["last_seen_in_session"] ?? ""
                    i["lastAttemptTime"] = record["last_attempt_time"] ?? ""
                    i["lastAttemptStatus"] = record["last_attempt_status"] ?? ""
                    i["lastUpdate"] = record["last_update"] ?? ""
                    i["failureCount"] = record["failure_count"] ?? 0
                    i["warningCount"] = record["warning_count"] ?? 0
                    i["installCount"] = 0
                    if let action = record["action_performed"] { i["actionPerformed"] = action }
                    if let installed = record["installed_version"] as? String, !installed.isEmpty { i["installedVersion"] = installed }
                    if let lastError = record["last_error"] as? String, !lastError.isEmpty { i["lastError"] = lastError }
                    if let lastWarning = record["last_warning"] as? String, !lastWarning.isEmpty { i["lastWarning"] = lastWarning }
                }
                if let message = errorByName[name] { i["lastError"] = message }
                if let message = warningByName[name], (i["lastError"] as? String ?? "").isEmpty { i["lastWarning"] = message }
                return i
            }
        }
        return dict
    }

    // MARK: - Per-item message consolidation (precise regex extraction)
    
    /// Known Munki warning/error message patterns with a capture group for the exact item name.
    /// These patterns come from Munki's source code (installer.py, updatecheck.py, etc.)
    private static let munkiItemPatterns: [NSRegularExpression] = {
        let patterns = [
            // "Could not process item ITEMNAME for install."
            #"could not process item (.+?) for (?:install|removal)"#,
            // "Could not resolve all dependencies for ITEMNAME,"
            #"could not resolve all dependencies for (.+?),"#,
            // "ITEMNAME is not available on this machine"
            #"^(.+?) is not available on this machine"#,
            // "Skipping ITEMNAME because it's not for this machine"
            #"skipping (.+?) because"#,
            // "Problem installing ITEMNAME"
            #"problem installing (.+?)[\.\s]"#,
            // "Install of ITEMNAME failed"
            #"install of (.+?) failed"#,
            // "Error installing ITEMNAME"
            #"error installing (.+?)[\.\s:]"#,
            // "Download of ITEMNAME failed"
            #"download of (.+?) failed"#,
            // "Could not install ITEMNAME"
            #"could not install (.+?)[\.\s]"#,
            // "Removal of ITEMNAME failed"
            #"removal of (.+?) failed"#,
            // "Package ITEMNAME requires a restart"
            #"package (.+?) requires a restart"#,
            // "WARNING about ITEMNAME:" (generic with colon)
            #"(?:warning|error):?\s+(.+?):\s"#,
        ]
        return patterns.compactMap { try? NSRegularExpression(pattern: $0, options: .caseInsensitive) }
    }()
    
    /// Extract the exact item name from a Munki warning/error message using known patterns.
    /// Returns nil if no pattern matches (message is system-level, not per-item).
    private static func extractItemName(from message: String) -> String? {
        let nsMessage = message as NSString
        let range = NSRange(location: 0, length: nsMessage.length)
        
        for regex in munkiItemPatterns {
            if let match = regex.firstMatch(in: message, range: range),
               match.numberOfRanges >= 2 {
                let capturedRange = match.range(at: 1)
                if capturedRange.location != NSNotFound {
                    return nsMessage.substring(with: capturedRange)
                }
            }
        }
        return nil
    }
    
    /// Transient network conditions hit while downloading an installer.
    ///
    /// Munki records these in ProblemInstalls because the item could not be installed
    /// on this run, but they are not install failures: nothing is wrong with the package
    /// or the device, and Munki retries on the next run. They are routine on laptops that
    /// sleep, roam between networks, or leave the campus network mid-download.
    ///
    /// Text-based fallback, used alongside Munki's `download_error_is_transient`.
    /// That key is the better signal — Munki derives it from the NSURLError code
    /// rather than the localized description — and a `true` there is enough on its
    /// own. This still runs when the key is absent (older Munki) or `false`, since
    /// Munki loses the original code on its catch-all path and rethrows as
    /// `.download(errorCode: -1, ...)`, which can carry a genuinely transient
    /// description. Either signal saying "transient" is treated as transient.
    ///
    /// This is deliberately an allowlist of known-transient conditions rather than a
    /// `"Download failed:"` prefix match. Munki raises insufficient disk space through the
    /// same `FetchError.download` case, so it carries the identical prefix while being a
    /// real, actionable failure that must keep surfacing as an error. Anything not matched
    /// here stays an error.
    static func isTransientDownloadFailure(_ note: String) -> Bool {
        guard note.hasPrefix("Download failed:") else { return false }
        let lower = note.lowercased()
        // NSURLError descriptions, as surfaced by Munki's FetchError description.
        let transientConditions = [
            "the network connection was lost",               // NSURLErrorNetworkConnectionLost (-1005)
            "the request timed out",                         // NSURLErrorTimedOut (-1001)
            "the internet connection appears to be offline",  // NSURLErrorNotConnectedToInternet (-1009)
            "could not connect to the server",               // NSURLErrorCannotConnectToHost (-1004)
            "a server with the specified hostname could not be found", // NSURLErrorCannotFindHost (-1003)
            "network connection was interrupted",
        ]
        return transientConditions.contains { lower.contains($0) }
    }

    /// Attach warnings and errors to their respective items using precise name extraction.
    /// Each raw message from Munki's Warnings[] / Errors[] plist arrays is matched to an item
    /// by extracting the exact item name from the message using known Munki patterns.
    /// Messages that don't match any item are left as system-level (in munki.warnings/errors).
    /// NOTE: Status is NOT overridden — factual status (installed, install_failed, etc.) is preserved.
    /// Error/warning text goes into lastError/lastWarning fields for display purposes.
    static func attachMessagesToItems(
        items: [MunkiItem],
        warningMessages: [String],
        errorMessages: [String]
    ) -> [MunkiItem] {
        var result = items
        
        // Build a lookup of lowercased item names → index for exact matching
        var nameToIndex: [String: Int] = [:]
        for (i, item) in result.enumerated() {
            nameToIndex[item.name.lowercased()] = i
            let displayLower = item.displayName.lowercased()
            if displayLower != item.name.lowercased() {
                nameToIndex[displayLower] = i
            }
        }
        
        /// Find the item index for a message by extracting the item name via regex
        func findItem(for message: String) -> Int? {
            guard let extractedName = extractItemName(from: message) else { return nil }
            return nameToIndex[extractedName.lowercased()]
        }
        
        // Process errors — populate lastError field, mark install_failed if not already failed/removed
        for rawMessage in errorMessages {
            let message = rawMessage.hasPrefix("ERROR: ") ? String(rawMessage.dropFirst(7)) : rawMessage
            guard !message.isEmpty else { continue }
            if let idx = findItem(for: message) {
                // A transient download failure is not an install failure — the item is
                // still pending and Munki retries next run. Record it as a warning so it
                // stays visible without counting against the device.
                if isTransientDownloadFailure(message) {
                    if result[idx].lastWarning.isEmpty {
                        result[idx].lastWarning = message
                    }
                    if result[idx].pendingReason.isEmpty {
                        result[idx].pendingReason = message
                    }
                    continue
                }
                if result[idx].lastError.isEmpty {
                    result[idx].lastError = message
                }
                // Only escalate status to install_failed if item isn't already in a terminal state
                let terminalStatuses: Set<String> = ["install_failed", "removed", "uninstalled"]
                if !terminalStatuses.contains(result[idx].status) {
                    result[idx].status = "install_failed"
                    if result[idx].pendingReason.isEmpty {
                        result[idx].pendingReason = message
                    }
                }
            }
        }
        
        // Process warnings — populate lastWarning field, don't change status
        for rawMessage in warningMessages {
            let message = rawMessage.hasPrefix("WARNING: ") ? String(rawMessage.dropFirst(9)) : rawMessage
            guard !message.isEmpty else { continue }
            if let idx = findItem(for: message) {
                if result[idx].lastWarning.isEmpty {
                    result[idx].lastWarning = message
                }
                if result[idx].pendingReason.isEmpty {
                    result[idx].pendingReason = message
                }
            }
        }
        
        return result
    }
    
    // MARK: - Munki Run Log (extract last complete run from ManagedSoftwareUpdate.log)
    
    /// Collects the last complete run from Munki's ManagedSoftwareUpdate.log
    /// Munki logs are cumulative with runs delimited by:
    /// - "### Starting managedsoftwareupdate run: <type> ###"
    /// - "### Ending managedsoftwareupdate run ###"
    /// We extract only the last complete run (not all historical runs)
    private func collectMunkiRunLog() async throws -> String {
        let logPath = "/Library/Managed Installs/Logs/ManagedSoftwareUpdate.log"
        
        // Check if log exists
        guard FileManager.default.fileExists(atPath: logPath) else {
            return ""
        }
        
        // Use tac to read file in reverse, find markers, then restore order
        // This is efficient as it doesn't need to load the entire log file
        let bashScript = """
            logfile="/Library/Managed Installs/Logs/ManagedSoftwareUpdate.log"
            
            if [ ! -f "$logfile" ]; then
                exit 0
            fi
            
            # Use awk to find the last run by reading from the end
            # Get line numbers of all "### Starting" and "### Ending" markers
            ending_lines=$(grep -n "### Ending managedsoftwareupdate run ###" "$logfile" | tail -1 | cut -d: -f1)
            starting_lines=$(grep -n "### Starting managedsoftwareupdate run:" "$logfile" | tail -1 | cut -d: -f1)
            
            # If we have both markers and ending is after starting (complete run)
            if [ -n "$starting_lines" ] && [ -n "$ending_lines" ] && [ "$ending_lines" -ge "$starting_lines" ]; then
                # Extract lines from starting to ending (inclusive)
                sed -n "${starting_lines},${ending_lines}p" "$logfile"
            elif [ -n "$starting_lines" ]; then
                # Incomplete run - extract from starting to end of file
                sed -n "${starting_lines},\\$p" "$logfile"
            fi
            """
        
        // Execute bash script through ProcessRunner. This reads a Munki log and truncates at
        // 100KB below, so it deliberately expects output well past the 64KB pipe buffer — and
        // the previous `waitUntilExit()` before reading deadlocked at exactly that point. The
        // machines with the most log data were the ones that hung.
        do {
            let result = try await ProcessRunner.bash(bashScript)
            if result.timedOut {
                ConsoleFormatter.writeDebug("Munki log read exceeded its time budget")
                return ""
            }

            let output = result.standardOutput.trimmingCharacters(in: .whitespacesAndNewlines)
            if !output.isEmpty {
                // Limit to reasonable size (100KB max to avoid bloating the payload)
                let maxSize = 100_000
                if output.count > maxSize {
                    let truncated = String(output.suffix(maxSize))
                    return "... (truncated, showing last \(maxSize) characters) ...\n\n" + truncated
                }
                return output
            }
        } catch {
            // Log error but don't fail - run log is optional
            print("Warning: Failed to collect Munki run log: \(error)")
        }
        
        return ""
    }
    
    // MARK: - Run Log Parsing

    private static let runLogTimestampRegex: NSRegularExpression = {
        // ISO-ish timestamp prefix Munki writes, e.g. "2026-04-14 16:29:43.081-07:00 "
        let pattern = #"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+\-]\d{2}:?\d{2})?\s+"#
        return try! NSRegularExpression(pattern: pattern, options: [])
    }()

    /// Extracts `ERROR:` and `WARNING:` lines from a collected Munki run log and returns them
    /// with timestamp and level prefix stripped — matching the shape of plist-stripped values.
    private func parseRunLogMessages(_ runLog: String) -> (errors: [String], warnings: [String]) {
        guard !runLog.isEmpty else { return ([], []) }
        var errors: [String] = []
        var warnings: [String] = []
        for rawLine in runLog.split(whereSeparator: { $0 == "\n" || $0 == "\r" }) {
            let line = String(rawLine)
            let range = NSRange(line.startIndex..., in: line)
            let stripped = Self.runLogTimestampRegex.stringByReplacingMatches(
                in: line, options: [], range: range, withTemplate: ""
            ).trimmingCharacters(in: .whitespaces)
            if stripped.hasPrefix("ERROR: ") {
                errors.append(String(stripped.dropFirst(7)))
            } else if stripped.hasPrefix("WARNING: ") {
                warnings.append(String(stripped.dropFirst(9)))
            }
        }
        return (errors, warnings)
    }

    // MARK: - Munki Info (native Swift plist reading — no osquery extension delay)

    /// Reads Munki metadata directly from ManagedInstallReport.plist and ManagedInstalls.plist
    /// using native PropertyListSerialization — zero shell spawning, instant.
    /// `runLog` (if non-empty) is scanned for `ERROR:`/`WARNING:` lines and merged into
    /// `errors`/`warnings` to surface catalog-retrieval failures that Munki doesn't always
    /// persist to ManagedInstallReport.plist's Errors key.
    private func collectMunkiInfo(runLog: String = "") async throws -> [String: Any] {
        var info: [String: Any] = [:]
        
        let munkiDir = "/Library/Managed Installs"
        guard FileManager.default.fileExists(atPath: munkiDir) else {
            info["isInstalled"] = false
            return info
        }
        
        info["isInstalled"] = true
        
        // Get Munki version from the binary
        if FileManager.default.fileExists(atPath: "/usr/local/munki/managedsoftwareupdate") {
            let result = try? await ProcessRunner.run(
                executable: "/usr/local/munki/managedsoftwareupdate",
                arguments: ["--version"],
                timeout: 30
            )
            let version = (result?.standardOutput ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            if result?.timedOut != true, !version.isEmpty {
                info["version"] = version
            }
        }
        
        // Read preferences plist for config
        let prefsPath = "/Library/Preferences/ManagedInstalls.plist"
        if let prefsData = try? Data(contentsOf: URL(fileURLWithPath: prefsPath)),
           let prefsPlist = try? PropertyListSerialization.propertyList(from: prefsData, options: [], format: nil) as? [String: Any] {
            info["softwareRepoURL"] = prefsPlist["SoftwareRepoURL"] as? String
            info["clientIdentifier"] = prefsPlist["ClientIdentifier"] as? String
        }
        
        // Read ManagedInstallReport.plist for last run info
        let reportPath = "\(munkiDir)/ManagedInstallReport.plist"
        guard let reportData = try? Data(contentsOf: URL(fileURLWithPath: reportPath)),
              let report = try? PropertyListSerialization.propertyList(from: reportData, options: [], format: nil) as? [String: Any] else {
            return info
        }
        
        info["manifestName"] = report["ManifestName"] as? String
        info["consoleUser"] = report["ConsoleUser"] as? String
        
        // Version from report (overrides binary version if present)
        if let munkiVersion = report["ManagedInstallVersion"] as? String, !munkiVersion.isEmpty {
            info["version"] = munkiVersion
        }
        
        // Timestamps — convert Date to ISO8601 string
        let isoFormatter = ISO8601DateFormatter()
        isoFormatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        
        if let startTime = report["StartTime"] as? Date {
            info["startTime"] = isoFormatter.string(from: startTime)
        }
        if let endTime = report["EndTime"] as? Date {
            info["endTime"] = isoFormatter.string(from: endTime)
        }
        
        // Errors / Warnings — merge plist Errors/Warnings with ERROR:/WARNING: lines from the
        // run log. Munki doesn't always persist early failures (e.g. catalog 404) to the plist
        // Errors key; those lines live only in ManagedSoftwareUpdate.log. Dedupe by exact
        // stripped-string equality so we never double-report.
        let plistErrorsRaw = (report["Errors"] as? [String]) ?? []
        let plistWarningsRaw = (report["Warnings"] as? [String]) ?? []
        let plistErrorsStripped = plistErrorsRaw.map {
            $0.hasPrefix("ERROR: ") ? String($0.dropFirst(7)) : $0
        }
        let plistWarningsStripped = plistWarningsRaw.map {
            $0.hasPrefix("WARNING: ") ? String($0.dropFirst(9)) : $0
        }

        let (logErrors, logWarnings) = parseRunLogMessages(runLog)

        func mergeOrderPreserving(_ plist: [String], _ log: [String]) -> [String] {
            var seen = Set<String>()
            var merged: [String] = []
            for item in plist + log {
                let key = item.trimmingCharacters(in: .whitespacesAndNewlines)
                if key.isEmpty { continue }
                if seen.insert(key).inserted {
                    merged.append(item)
                }
            }
            return merged
        }

        let mergedErrors = mergeOrderPreserving(plistErrorsStripped, logErrors)
        let mergedWarnings = mergeOrderPreserving(plistWarningsStripped, logWarnings)

        if !mergedErrors.isEmpty {
            info["errors"] = mergedErrors.joined(separator: "; ")
            // Re-prefix for attachMessagesToItems, which expects raw "ERROR: ..." lines
            info["errorsArray"] = mergedErrors.map { "ERROR: \($0)" }
            info["success"] = "false"
        } else {
            info["success"] = "true"
        }

        if !mergedWarnings.isEmpty {
            info["warnings"] = mergedWarnings.joined(separator: "; ")
            info["warningsArray"] = mergedWarnings.map { "WARNING: \($0)" }
        }
        
        // Problem installs — ProblemInstalls is [[String: Any]] (array of dicts), not [String]
        if let problems = report["ProblemInstalls"] as? [[String: Any]], !problems.isEmpty {
            let names = problems.compactMap { $0["display_name"] as? String ?? $0["name"] as? String }
            info["problemInstalls"] = names.joined(separator: "; ")
            info["problemInstallsArray"] = names
        }
        
        // InstallResults - items installed during the most recent Munki run (name + version for event messages)
        if let installResults = report["InstallResults"] as? [[String: Any]], !installResults.isEmpty {
            info["newlyInstalledCount"] = installResults.count
            let installedDetails = installResults.map { item -> [String: String] in
                let name = item["display_name"] as? String ?? item["name"] as? String ?? "Unknown"
                let version = item["version"] as? String ?? item["installed_version"] as? String ?? ""
                return ["name": name, "version": version]
            }
            info["newlyInstalledItems"] = installedDetails
        } else {
            info["newlyInstalledCount"] = 0
            info["newlyInstalledItems"] = [] as [[String: String]]
        }
        
        // RemovalResults - items removed during the most recent Munki run
        if let removalResults = report["RemovalResults"] as? [[String: Any]], !removalResults.isEmpty {
            info["newlyRemovedCount"] = removalResults.count
            let removedDetails = removalResults.map { item -> [String: String] in
                let name = item["display_name"] as? String ?? item["name"] as? String ?? "Unknown"
                let version = item["version"] as? String ?? ""
                return ["name": name, "version": version]
            }
            info["newlyRemovedItems"] = removedDetails
        } else {
            info["newlyRemovedCount"] = 0
            info["newlyRemovedItems"] = [] as [[String: String]]
        }
        
        return info
    }
    
    // MARK: - Install History (osquery: package_install_history)
    
    private func collectInstallHistory() async throws -> [[String: Any]] {
        // osquery package_install_history table for macOS installer history
        let osqueryScript = """
            SELECT 
                package_id,
                name,
                version,
                source,
                time
            FROM package_install_history
            ORDER BY time DESC
            LIMIT 100;
            """
        
        // Pure bash + plutil + awk approach - NO Python
        let bashScript = """
            history_file="/Library/Receipts/InstallHistory.plist"
            
            if [ -f "$history_file" ]; then
                # Convert plist to JSON
                json_output=$(plutil -convert json -o - "$history_file" 2>/dev/null)
                
                if [ -n "$json_output" ]; then
                    # Parse JSON using awk (no Python/JavaScript needed for basic extraction)
                    # Output last 100 entries as JSON array
                    echo "$json_output" | awk '
                    BEGIN { RS="},"; FS="\\n"; count=0; print "[" }
                    {
                        if (count >= 100) exit
                        name=""; version=""; pkgId=""; date=""; process=""
                        for (i=1; i<=NF; i++) {
                            if ($i ~ /"displayName"/) {
                                gsub(/.*"displayName"[[:space:]]*:[[:space:]]*"/, "", $i)
                                gsub(/".*/, "", $i)
                                name = $i
                            }
                            if ($i ~ /"displayVersion"/) {
                                gsub(/.*"displayVersion"[[:space:]]*:[[:space:]]*"/, "", $i)
                                gsub(/".*/, "", $i)
                                version = $i
                            }
                            if ($i ~ /"processName"/) {
                                gsub(/.*"processName"[[:space:]]*:[[:space:]]*"/, "", $i)
                                gsub(/".*/, "", $i)
                                process = $i
                            }
                            if ($i ~ /"date"/) {
                                gsub(/.*"date"[[:space:]]*:[[:space:]]*"/, "", $i)
                                gsub(/".*/, "", $i)
                                date = $i
                            }
                        }
                        if (name != "") {
                            if (count > 0) printf ","
                            printf "{\\"name\\": \\"%s\\", \\"version\\": \\"%s\\", \\"time\\": \\"%s\\", \\"source\\": \\"%s\\"}", name, version, date, process
                            count++
                        }
                    }
                    END { print "]" }
                    ' 2>/dev/null || echo '[]'
                else
                    echo '[]'
                fi
            else
                echo '[]'
            fi
            """
        
        let result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript
        )
        
        var history: [[String: Any]] = []
        
        if let items = result["items"] as? [[String: Any]] {
            history = items
        }
        
        return history.map { item in
            [
                "name": item["name"] as? String ?? "",
                "version": item["version"] as? String ?? "",
                "packageId": item["package_id"] as? String ?? "",
                "installedDate": item["time"] as? String ?? "",
                "source": item["source"] as? String ?? ""
            ]
        }
    }
    
    // MARK: - Homebrew Packages (osquery: homebrew_packages)
    
    private func collectHomebrewPackages() async throws -> [[String: Any]] {
        // osquery homebrew_packages table
        let osqueryScript = """
            SELECT 
                name,
                version,
                path,
                prefix
            FROM homebrew_packages;
            """
        
        let bashScript = """
            # Get Homebrew packages if installed - pure bash with awk
            if command -v brew >/dev/null 2>&1; then
                brew list --versions 2>/dev/null | awk '
                BEGIN { print "["; first = 1 }
                {
                    name = $1
                    $1 = ""
                    version = $0
                    gsub(/^[[:space:]]+/, "", version)
                    if (!first) print ","
                    printf "{\\"name\\": \\"%s\\", \\"version\\": \\"%s\\"}", name, version
                    first = 0
                }
                END { print "]" }
                '
            else
                echo '[]'
            fi
            """
        
        let result = try await executeWithFallback(
            osquery: osqueryScript,
            bash: bashScript
        )
        
        var packages: [[String: Any]] = []
        
        if let items = result["items"] as? [[String: Any]] {
            packages = items
        }
        
        return packages.map { pkg in
            [
                "name": pkg["name"] as? String ?? "",
                "version": pkg["version"] as? String ?? "",
                "installPath": pkg["path"] as? String ?? pkg["prefix"] as? String ?? ""
            ]
        }
    }
    
    // MARK: - Munki Managed Installs (native Swift plist reading — no osquery extension delay)
    
    /// Reads all Munki-managed items from ManagedInstallReport.plist and cross-references
    /// InstallResults, RemovalResults, ProblemInstalls, ItemsToInstall, ItemsToRemove
    /// to derive rich status values matching MunkiReport's 7-status model:
    ///   installed, install_succeeded, install_failed, pending_install, pending_removal, removed, uninstalled
    private func collectMunkiManagedInstalls() async throws -> [MunkiItem] {
        let reportPath = "/Library/Managed Installs/ManagedInstallReport.plist"
        
        guard let reportData = try? Data(contentsOf: URL(fileURLWithPath: reportPath)),
              let report = try? PropertyListSerialization.propertyList(from: reportData, options: [], format: nil) as? [String: Any] else {
            return []
        }
        
        let managedInstalls = report["ManagedInstalls"] as? [[String: Any]] ?? []
        
        // Get the end time from the report (same for all items in this run)
        let isoFormatter = ISO8601DateFormatter()
        isoFormatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        var endTimeStr = ""
        if let endTime = report["EndTime"] as? Date {
            endTimeStr = isoFormatter.string(from: endTime)
        }
        
        // Read all cross-reference arrays from the plist (matching MunkiReport's logic)
        let installResults = report["InstallResults"] as? [[String: Any]] ?? []
        let removalResults = report["RemovalResults"] as? [[String: Any]] ?? []
        let problemInstalls = report["ProblemInstalls"] as? [[String: Any]] ?? []
        let itemsToInstall = report["ItemsToInstall"] as? [[String: Any]] ?? []
        let itemsToRemove = report["ItemsToRemove"] as? [[String: Any]] ?? []
        
        // Build lookup: InstallResults name → (status, time, version)
        var installResultsMap: [String: (status: Int, time: String, version: String)] = [:]
        for result in installResults {
            guard let name = result["name"] as? String else { continue }
            let status = result["status"] as? Int ?? -1
            var timeStr = ""
            if let time = result["time"] as? Date {
                timeStr = isoFormatter.string(from: time)
            }
            let version = result["version"] as? String ?? ""
            installResultsMap[name] = (status: status, time: timeStr, version: version)
        }
        
        // Build lookup: RemovalResults name → (status, time)
        var removalResultsMap: [String: (status: Int, time: String)] = [:]
        for result in removalResults {
            guard let name = result["name"] as? String else { continue }
            let status = result["status"] as? Int ?? -1
            var timeStr = ""
            if let time = result["time"] as? Date {
                timeStr = isoFormatter.string(from: time)
            }
            removalResultsMap[name] = (status: status, time: timeStr)
        }
        
        // Build lookup: ProblemInstalls name → note (error detail), plus the set of
        // items Munki itself flagged as a transient network failure. Munki records
        // download_error_is_transient from the NSURLError code, which is a far more
        // reliable signal than reading the localized description; older clients
        // don't emit it, so the text heuristic remains as a fallback.
        var problemInstallsMap: [String: String] = [:]
        var munkiTransientNames = Set<String>()
        for item in problemInstalls {
            guard let name = item["name"] as? String else { continue }
            problemInstallsMap[name] = item["note"] as? String ?? ""
            if item["download_error_is_transient"] as? Bool == true {
                munkiTransientNames.insert(name)
            }
        }
        
        // Build sets for pending items
        let itemsToInstallNames = Set(itemsToInstall.compactMap { $0["name"] as? String })
        let itemsToRemoveNames = Set(itemsToRemove.compactMap { $0["name"] as? String })
        
        // Version info from ItemsToInstall (richer for pending items)
        var itemsToInstallVersions: [String: String] = [:]
        for item in itemsToInstall {
            guard let name = item["name"] as? String else { continue }
            if let version = item["version_to_install"] as? String, !version.isEmpty {
                itemsToInstallVersions[name] = version
            }
        }
        
        var items: [MunkiItem] = []
        var processedNames = Set<String>()
        
        // Process ManagedInstalls (items from managed_installs manifest key)
        for itemData in managedInstalls {
            let name = itemData["name"] as? String ?? ""
            guard !name.isEmpty else { continue }
            processedNames.insert(name)
            
            var item = MunkiItem()
            item.name = name
            item.displayName = itemData["display_name"] as? String ?? name
            item.id = name.lowercased().replacingOccurrences(of: " ", with: "-")
            item.version = itemData["version_to_install"] as? String ?? ""
            item.installedVersion = itemData["installed_version"] as? String ?? ""
            item.endTime = endTimeStr
            item.type = "munki"
            
            if let sizeInt = itemData["installed_size"] as? Int {
                item.installedSize = sizeInt
            }
            
            let installed = itemData["installed"] as? Bool ?? false
            
            // Rich status determination matching MunkiReport's priority:
            // InstallResults > RemovalResults > ProblemInstalls > ItemsToRemove > installed bool > ItemsToInstall
            if let result = installResultsMap[name] {
                if result.status == 0 {
                    item.status = "install_succeeded"
                    if !result.time.isEmpty { item.endTime = result.time }
                    if !result.version.isEmpty && item.installedVersion.isEmpty {
                        item.installedVersion = result.version
                    }
                } else {
                    item.status = "install_failed"
                    if !result.time.isEmpty { item.endTime = result.time }
                }
            } else if let result = removalResultsMap[name] {
                item.status = result.status == 0 ? "removed" : "install_failed"
                if !result.time.isEmpty { item.endTime = result.time }
            } else if let note = problemInstallsMap[name] {
                if munkiTransientNames.contains(name) || Self.isTransientDownloadFailure(note) {
                    // Still wanted, just not downloaded yet — Munki retries next run.
                    item.status = "pending_install"
                    item.lastWarning = note
                } else {
                    item.status = "install_failed"
                    if !note.isEmpty { item.lastError = note }
                }
            } else if itemsToRemoveNames.contains(name) {
                item.status = "pending_removal"
            } else if installed {
                item.status = "installed"
            } else if itemsToInstallNames.contains(name) {
                item.status = "pending_install"
                if item.version.isEmpty, let v = itemsToInstallVersions[name] {
                    item.version = v
                }
            } else {
                item.status = "pending_install"
            }
            
            // Derive pending reason for non-installed items
            if item.status != "installed" && item.status != "install_succeeded" {
                item.pendingReason = derivePendingReason(item: item)
            }
            
            items.append(item)
        }
        
        // Add items from RemovalResults that aren't in ManagedInstalls (removed/uninstalled items)
        for result in removalResults {
            guard let name = result["name"] as? String, !name.isEmpty,
                  !processedNames.contains(name) else { continue }
            processedNames.insert(name)
            
            var item = MunkiItem()
            item.name = name
            item.displayName = result["display_name"] as? String ?? name
            item.id = name.lowercased().replacingOccurrences(of: " ", with: "-")
            item.version = ""
            item.installedVersion = ""
            item.type = "munki"
            
            let status = result["status"] as? Int ?? -1
            item.status = status == 0 ? "removed" : "install_failed"
            
            if let time = result["time"] as? Date {
                item.endTime = isoFormatter.string(from: time)
            }
            
            items.append(item)
        }
        
        // Add items from ItemsToRemove that aren't already processed (pending_removal)
        for itemData in itemsToRemove {
            guard let name = itemData["name"] as? String, !name.isEmpty,
                  !processedNames.contains(name) else { continue }
            processedNames.insert(name)
            
            var item = MunkiItem()
            item.name = name
            item.displayName = itemData["display_name"] as? String ?? name
            item.id = name.lowercased().replacingOccurrences(of: " ", with: "-")
            item.version = ""
            item.installedVersion = itemData["installed_version"] as? String ?? ""
            item.type = "munki"
            item.status = "pending_removal"
            item.pendingReason = "Scheduled for removal"
            
            if let sizeInt = itemData["installed_size"] as? Int {
                item.installedSize = sizeInt
            }
            
            items.append(item)
        }
        
        return items
    }
    
    // MARK: - Pending Updates (local plist only — no network calls)
    
    /// Reads cached Apple software update recommendations from the local plist.
    /// NEVER calls `softwareupdate -l` which contacts Apple's servers (20-30s).
    /// Munki pending installs are already captured in munki_installs (step 4).
    private func collectPendingUpdates() async throws -> [[String: Any]] {
        var updates: [[String: Any]] = []
        
        // Read cached macOS software update recommendations (instant, no network)
        let suPlistPath = "/Library/Preferences/com.apple.SoftwareUpdate.plist"
        let url = URL(fileURLWithPath: suPlistPath)
        
        guard FileManager.default.fileExists(atPath: suPlistPath),
              let data = try? Data(contentsOf: url),
              let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
              let dict = plist as? [String: Any],
              let recommended = dict["RecommendedUpdates"] as? [[String: Any]] else {
            return updates
        }
        
        for update in recommended {
            updates.append([
                "name": update["Display Name"] as? String ?? "",
                "version": update["Display Version"] as? String ?? "",
                "size": "",
                "source": "softwareupdate"
            ])
        }
        
        return updates
    }
    
    // MARK: - Derive Pending Reason
    
    /// Derives a human-readable pending reason for a MunkiItem based on its status
    /// Works with MunkiReport-matching statuses: install_failed, pending_install, pending_removal, removed, uninstalled
    private func derivePendingReason(item: MunkiItem) -> String {
        let version = item.version
        let installedVersion = item.installedVersion
        
        switch item.status {
        case "install_failed":
            if !item.lastError.isEmpty { return item.lastError }
            return "Installation failed"
            
        case "pending_removal":
            return "Scheduled for removal"
            
        case "removed":
            return "Removed"
            
        case "uninstalled":
            return "Uninstalled"
            
        case "pending_install":
            // A transient download failure explains the pending state better than
            // "Not yet installed" — surface it rather than the generic reason.
            if !item.lastWarning.isEmpty { return item.lastWarning }
            if installedVersion.isEmpty {
                return "Not yet installed"
            }
            if !version.isEmpty && version != installedVersion {
                return "Update available: \(installedVersion) → \(version)"
            }
            return "Installation pending"
            
        default:
            if installedVersion.isEmpty {
                return "Not yet installed"
            }
            if !version.isEmpty && version != installedVersion {
                return "Update available: \(installedVersion) → \(version)"
            }
            return "Installation pending"
        }
    }
    
    // MARK: - Catalog Metadata Collection
    
    /// Collects category and developer metadata from Munki catalogs using Swift
    /// native plist reading — no shell spawning, works with binary and XML plists.
    /// Munki catalogs are root-level arrays of pkgsinfo dicts and can be 10-50 MB;
    /// shell-based approaches (PlistBuddy loops, plutil | JSON pipe) are too slow.
    private func collectCatalogMetadata() async throws -> [String: (category: String, developer: String)] {
        let catalogsPath = "/Library/Managed Installs/catalogs"
        var metadata: [String: (category: String, developer: String)] = [:]
        
        guard FileManager.default.fileExists(atPath: catalogsPath),
              let catalogFiles = try? FileManager.default.contentsOfDirectory(atPath: catalogsPath) else {
            return metadata
        }
        
        for catalogFile in catalogFiles {
            if catalogFile.hasPrefix(".") { continue }
            
            let catalogPath = "\(catalogsPath)/\(catalogFile)"
            let url = URL(fileURLWithPath: catalogPath)
            
            guard let data = try? Data(contentsOf: url),
                  let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
                  let items = plist as? [[String: Any]] else {
                continue
            }
            
            for item in items {
                guard let name = item["name"] as? String, !name.isEmpty else { continue }
                let category = item["category"] as? String ?? ""
                let developer = item["developer"] as? String ?? ""
                if !category.isEmpty || !developer.isEmpty {
                    metadata[name] = (category: category, developer: developer)
                }
            }
        }
        
        return metadata
    }
    
    /// Enriches MunkiItem array with category/developer from catalog metadata
    private func enrichInstallsWithCatalogData(
        installs: [MunkiItem],
        catalogData: [String: (category: String, developer: String)]
    ) -> [MunkiItem] {
        return installs.map { item in
            var enriched = item
            if let metadata = catalogData[item.name] {
                enriched.category = metadata.category
                enriched.developer = metadata.developer
            }
            return enriched
        }
    }
    
    // MARK: - Manifest Catalogs Collection
    
    /// Returns the catalog names that Munki has cached locally.
    /// The filenames in /Library/Managed Installs/catalogs/ are exactly the catalog names in use.
    private func collectManifestCatalogs(manifestName: String?) async throws -> [String] {
        let catalogsDir = "/Library/Managed Installs/catalogs"
        
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: catalogsDir) else {
            return []
        }
        
        return entries.filter { !$0.hasPrefix(".") }.sorted()
    }
}
