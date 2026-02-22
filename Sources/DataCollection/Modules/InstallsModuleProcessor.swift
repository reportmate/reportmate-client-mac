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
        
        ConsoleFormatter.writeQueryProgress(queryName: "munki_info", current: 3, total: totalSteps)
        let info = try await collectMunkiInfo()
        
        ConsoleFormatter.writeQueryProgress(queryName: "munki_installs", current: 4, total: totalSteps)
        var installs = try await collectMunkiManagedInstalls()
        
        ConsoleFormatter.writeQueryProgress(queryName: "pending_updates", current: 5, total: totalSteps)
        let pending = try await collectPendingUpdates()
        
        ConsoleFormatter.writeQueryProgress(queryName: "munki_log", current: 6, total: totalSteps)
        let runLog = try await collectMunkiRunLog()
        
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
            
            // Consolidate warnings/errors into per-item messages (one message max per item)
            // Parse semicolon-separated warning/error strings, match to items by name,
            // and attach a single consolidated message to each matched item
            munki.items = Self.attachMessagesToItems(
                items: munki.items,
                warnings: munki.warnings,
                errors: munki.errors
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
                        var d: [String: Any] = [
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
                        if let msg = item.message { d["message"] = msg }
                        if let reason = item.pendingReason { d["pendingReason"] = reason }
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
        
        // Inject newly installed count - items actually installed during this run (from ItemsInstalled plist key)
        if var munkiDict = installsData["munki"] as? [String: Any] {
            munkiDict["newlyInstalledCount"] = info["newlyInstalledCount"] as? Int ?? 0
            installsData["munki"] = munkiDict
        }
        
        // Add runLog at top level (same key as Cimian for API compatibility)
        if !runLog.isEmpty {
            installsData["runLog"] = runLog
        }
        
        return BaseModuleData(moduleId: moduleId, data: installsData)
    }
    
    // MARK: - Per-item message consolidation
    
    /// Parse semicolon-separated warnings/errors, match each to an item by name,
    /// and consolidate into a single `message` per item. Also updates item status
    /// to "Warning" or "Error" accordingly. Messages that don't match any item are
    /// left in the top-level munki.warnings/errors string (unchanged).
    static func attachMessagesToItems(
        items: [MunkiItem],
        warnings: String?,
        errors: String?
    ) -> [MunkiItem] {
        var result = items
        
        // Build a lookup: lowercased item name → index in result array
        // Include both name and displayName for matching
        var nameToIndex: [(String, Int)] = []
        for (i, item) in result.enumerated() {
            nameToIndex.append((item.name.lowercased(), i))
            if item.displayName.lowercased() != item.name.lowercased() {
                nameToIndex.append((item.displayName.lowercased(), i))
            }
        }
        // Sort longest names first to avoid partial matches (e.g., "ReportMateConfig" before "ReportMate")
        nameToIndex.sort { $0.0.count > $1.0.count }
        
        /// Find which item index a message belongs to
        func matchItem(for message: String) -> Int? {
            let lower = message.lowercased()
            for (name, idx) in nameToIndex {
                if lower.contains(name) { return idx }
            }
            return nil
        }
        
        // Collect all messages per item index: (index, [messages])
        var messagesPerItem: [Int: [String]] = [:]
        var statusPerItem: [Int: String] = [:]  // Track highest severity per item
        
        // Process errors first (higher severity)
        if let errorStr = errors, !errorStr.isEmpty {
            let lines = errorStr.components(separatedBy: ";").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
            for line in lines {
                if let idx = matchItem(for: line) {
                    messagesPerItem[idx, default: []].append(line)
                    statusPerItem[idx] = "Error"
                }
            }
        }
        
        // Process warnings (lower severity — won't override Error)
        if let warnStr = warnings, !warnStr.isEmpty {
            let lines = warnStr.components(separatedBy: ";").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
            for line in lines {
                if let idx = matchItem(for: line) {
                    messagesPerItem[idx, default: []].append(line)
                    if statusPerItem[idx] == nil {
                        statusPerItem[idx] = "Warning"
                    }
                }
            }
        }
        
        // Apply consolidated messages to items (one message per item)
        for (idx, messages) in messagesPerItem {
            // Join multiple messages into a single consolidated message
            result[idx].message = messages.joined(separator: " | ")
            // Update status to highest severity found
            if let newStatus = statusPerItem[idx] {
                result[idx].status = newStatus
            }
            // If item was Pending and now has a warning about why, add pending reason
            if result[idx].status == "Warning" && result[idx].pendingReason == nil {
                result[idx].pendingReason = messages.first
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
        
        // Execute bash script
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/bash")
        process.arguments = ["-c", bashScript]
        
        let outputPipe = Pipe()
        let errorPipe = Pipe()
        process.standardOutput = outputPipe
        process.standardError = errorPipe
        
        do {
            try process.run()
            process.waitUntilExit()
            
            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
               !output.isEmpty {
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
    
    // MARK: - Munki Info (native Swift plist reading — no osquery extension delay)
    
    /// Reads Munki metadata directly from ManagedInstallReport.plist and ManagedInstalls.plist
    /// using native PropertyListSerialization — zero shell spawning, instant.
    private func collectMunkiInfo() async throws -> [String: Any] {
        var info: [String: Any] = [:]
        
        let munkiDir = "/Library/Managed Installs"
        guard FileManager.default.fileExists(atPath: munkiDir) else {
            info["isInstalled"] = false
            return info
        }
        
        info["isInstalled"] = true
        
        // Get Munki version from the binary
        if FileManager.default.fileExists(atPath: "/usr/local/munki/managedsoftwareupdate") {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/local/munki/managedsoftwareupdate")
            process.arguments = ["--version"]
            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = Pipe()
            try? process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            if let version = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines), !version.isEmpty {
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
        
        // Errors array
        if let errors = report["Errors"] as? [String], !errors.isEmpty {
            info["errors"] = errors.joined(separator: "; ")
            info["success"] = "false"
        } else {
            info["success"] = "true"
        }
        
        // Warnings array
        if let warnings = report["Warnings"] as? [String], !warnings.isEmpty {
            info["warnings"] = warnings.joined(separator: "; ")
        }
        
        // Problem installs
        if let problems = report["ProblemInstalls"] as? [String], !problems.isEmpty {
            info["problemInstalls"] = problems.joined(separator: "; ")
        }
        
        // ItemsInstalled count (items newly installed during this run)
        if let itemsInstalled = report["ItemsInstalled"] as? [[String: Any]] {
            info["newlyInstalledCount"] = itemsInstalled.count
        } else {
            info["newlyInstalledCount"] = 0
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
    
    /// Reads the ManagedInstalls array from ManagedInstallReport.plist using
    /// native PropertyListSerialization — zero shell spawning, instant.
    private func collectMunkiManagedInstalls() async throws -> [MunkiItem] {
        let reportPath = "/Library/Managed Installs/ManagedInstallReport.plist"
        
        guard let reportData = try? Data(contentsOf: URL(fileURLWithPath: reportPath)),
              let report = try? PropertyListSerialization.propertyList(from: reportData, options: [], format: nil) as? [String: Any],
              let managedInstalls = report["ManagedInstalls"] as? [[String: Any]] else {
            return []
        }
        
        // Get the end time from the report (same for all items in this run)
        let isoFormatter = ISO8601DateFormatter()
        isoFormatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        var endTimeStr = ""
        if let endTime = report["EndTime"] as? Date {
            endTimeStr = isoFormatter.string(from: endTime)
        }
        
        var items: [MunkiItem] = []
        
        for itemData in managedInstalls {
            var item = MunkiItem()
            
            let name = itemData["name"] as? String ?? ""
            item.name = name
            item.displayName = itemData["display_name"] as? String ?? name
            item.id = name.lowercased().replacingOccurrences(of: " ", with: "-")
            item.version = ""
            item.installedVersion = itemData["installed_version"] as? String ?? ""
            item.endTime = endTimeStr
            item.type = "munki"
            
            // Handle installed_size
            if let sizeInt = itemData["installed_size"] as? Int {
                item.installedSize = sizeInt
            }
            
            // Map 'installed' to status
            let installed = itemData["installed"] as? Bool ?? false
            if installed {
                item.status = "Installed"
            } else {
                item.status = "Pending"
                item.pendingReason = derivePendingReason(item: item)
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
    
    /// Derives a human-readable pending reason for a MunkiItem based on its state
    /// Mirrors the Windows CimianItem.DerivePendingReason() logic
    private func derivePendingReason(item: MunkiItem) -> String {
        let version = item.version.isEmpty ? "Unknown" : item.version
        let installedVersion = item.installedVersion.isEmpty ? "Unknown" : item.installedVersion
        
        // Not yet installed (no installed version)
        if installedVersion == "Unknown" || installedVersion.isEmpty {
            return "Not yet installed"
        }
        
        // Version mismatch = update available
        if version != installedVersion && version != "Unknown" {
            return "Update available: \(installedVersion) → \(version)"
        }
        
        // Versions match but still pending (possible re-install or metadata sync)
        if version == installedVersion {
            return "Reinstallation pending"
        }
        
        // Generic pending
        return "Installation pending"
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
