import Foundation

/// Errors surfaced from the fleet API.
public enum APIError: LocalizedError, Sendable {
    case notConfigured
    case invalidURL(String)
    case http(status: Int, message: String, path: String)
    case unauthorized(path: String)
    case forbidden(path: String)
    case notFound(path: String)
    case decoding(String)
    case transport(String)

    public var errorDescription: String? {
        switch self {
        case .notConfigured: return "The ReportMate API is not configured. Open Settings and enter the API URL and a credential."
        case .invalidURL(let s): return "Invalid API URL: \(s)"
        case .http(let status, let message, let path): return "HTTP \(status) from \(path): \(message)"
        case .unauthorized(let path): return "The API rejected the credential (401) for \(path)."
        case .forbidden(let path): return "The credential lacks the scope for \(path) (403)."
        case .notFound(let path): return "Not found: \(path)"
        case .decoding(let s): return "Could not decode the API response: \(s)"
        case .transport(let s): return s
        }
    }

    public var isAuthFailure: Bool {
        switch self {
        case .unauthorized, .forbidden: return true
        default: return false
        }
    }
}

/// Client for the ReportMate FastAPI service (`/api/v1`).
///
/// Every method returns the parsed JSON tree or a typed model built from it.
/// The client is immutable after construction; `AppState` rebuilds it when
/// the configuration changes.
public final class ReportMateAPI: Sendable {
    public let configuration: AppConfiguration
    private let session: URLSession
    private let tokenSource: AzTokenSource
    private let base: URL?

    public init(configuration: AppConfiguration, tokenSource: AzTokenSource = .shared, session: URLSession? = nil) {
        self.configuration = configuration
        self.tokenSource = tokenSource
        self.base = URL(string: configuration.normalizedBaseURL)
        if let session {
            self.session = session
        } else {
            let cfg = URLSessionConfiguration.default
            cfg.timeoutIntervalForRequest = 120
            cfg.timeoutIntervalForResource = 300
            cfg.httpAdditionalHeaders = ["User-Agent": "ReportMateMac/\(ReportMateAPI.clientVersion)"]
            cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
            self.session = URLSession(configuration: cfg)
        }
    }

    public static let clientVersion: String = {
        (Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String) ?? "dev"
    }()

    public var isConfigured: Bool { configuration.isConfigured && base != nil }

    // MARK: - Request plumbing

    private func url(_ path: String, query: [String: String?] = [:]) throws -> URL {
        guard let base else { throw APIError.notConfigured }
        var comps = URLComponents(url: base.appendingPathComponent("api/v1" + path), resolvingAgainstBaseURL: false)
        let items = query.compactMap { k, v -> URLQueryItem? in
            guard let v else { return nil }
            return URLQueryItem(name: k, value: v)
        }
        if !items.isEmpty { comps?.queryItems = items }
        guard let u = comps?.url else { throw APIError.invalidURL(path) }
        return u
    }

    private func authorizedRequest(_ url: URL, method: String = "GET", body: Data? = nil) async throws -> URLRequest {
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        switch configuration.authMethod {
        case .apiKey:
            req.setValue(configuration.apiKey, forHTTPHeaderField: "X-API-Key")
        case .passphrase:
            req.setValue(configuration.passphrase, forHTTPHeaderField: "X-Client-Passphrase")
        case .entraBearer:
            let token = try await tokenSource.token(forResource: configuration.oidcAudience)
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        if let body {
            req.httpBody = body
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        return req
    }

    /// Perform a request and return the raw body. 404 becomes `nil`.
    private func perform(_ path: String, query: [String: String?] = [:], method: String = "GET", body: Data? = nil) async throws -> Data? {
        guard isConfigured else { throw APIError.notConfigured }
        let u = try url(path, query: query)
        let req = try await authorizedRequest(u, method: method, body: body)
        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await session.data(for: req)
        } catch {
            throw APIError.transport(error.localizedDescription)
        }
        guard let http = response as? HTTPURLResponse else { throw APIError.transport("No HTTP response") }
        switch http.statusCode {
        case 200..<300: return data
        case 401: throw APIError.unauthorized(path: path)
        case 403: throw APIError.forbidden(path: path)
        case 404: return nil
        default:
            let detail = (try? JSONValue.parse(data))?["detail"].string ?? String(data: data.prefix(300), encoding: .utf8) ?? ""
            throw APIError.http(status: http.statusCode, message: detail, path: path)
        }
    }

    /// GET a JSON tree. Missing resources are `.null`.
    public func getJSON(_ path: String, query: [String: String?] = [:]) async throws -> JSONValue {
        guard let data = try await perform(path, query: query) else { return .null }
        do {
            return try JSONValue.parse(data)
        } catch {
            throw APIError.decoding("\(path): \(error.localizedDescription)")
        }
    }

    private func sendJSON(_ path: String, method: String, body: JSONValue? = nil, query: [String: String?] = [:]) async throws -> JSONValue {
        let data = try body.map { try JSONEncoder().encode($0) }
        guard let out = try await perform(path, query: query, method: method, body: data) else { return .null }
        if out.isEmpty { return .null }
        return (try? JSONValue.parse(out)) ?? .null
    }

    // MARK: - Health

    public func health() async throws -> JSONValue {
        try await getJSON("/health")
    }

    /// A cheap authenticated call used by Settings to validate a credential.
    public func testConnection() async throws -> Int {
        let json = try await getJSON("/devices", query: ["limit": "1"])
        return json["total"].int ?? json["devices"].elements.count
    }

    // MARK: - Dashboard and devices

    public func dashboard(eventsLimit: Int = 200, includeArchived: Bool = false) async throws -> DashboardData {
        let json = try await getJSON("/dashboard", query: ["eventsLimit": String(eventsLimit), "includeArchived": includeArchived ? "true" : nil])
        return DashboardData(json: json)
    }

    public func devices(includeArchived: Bool = false, limit: Int? = nil, offset: Int = 0) async throws -> DevicesPage {
        let json = try await getJSON("/devices", query: [
            "includeArchived": includeArchived ? "true" : nil,
            "limit": limit.map(String.init),
            "offset": offset > 0 ? String(offset) : nil,
        ])
        return DevicesPage(json: json)
    }

    /// Every device, following pagination when the server caps a page.
    public func allDevices(includeArchived: Bool = false) async throws -> [DeviceSummary] {
        let first = try await devices(includeArchived: includeArchived)
        var all = first.devices
        var page = first
        var offset = first.devices.count
        while page.hasMore, !page.devices.isEmpty {
            page = try await devices(includeArchived: includeArchived, limit: page.pageSize, offset: offset)
            all.append(contentsOf: page.devices)
            offset += page.devices.count
        }
        var seen = Set<String>()
        return all.filter { seen.insert($0.serialNumber).inserted }
    }

    public func device(_ serial: String) async throws -> DeviceDetail? {
        let json = try await getJSON("/device/\(encode(serial))")
        guard !json.isNull else { return nil }
        return DeviceDetail(json: json)
    }

    /// The fast Info-tab payload (inventory, system, hardware, management, security, network).
    public func deviceInfo(_ serial: String) async throws -> DeviceDetail? {
        let json = try await getJSON("/device/\(encode(serial))/info")
        guard !json.isNull else { return nil }
        return DeviceDetail(json: json)
    }

    public func deviceModule(_ serial: String, _ module: ModuleName) async throws -> JSONValue {
        let json = try await getJSON("/device/\(encode(serial))/modules/\(module.rawValue)")
        return json["data"]
    }

    public func deviceEvents(_ serial: String, limit: Int = 100, kind: EventKind? = nil) async throws -> [FleetEvent] {
        let json = try await getJSON("/device/\(encode(serial))/events", query: ["limit": String(limit), "type": kind?.rawValue])
        return json["events"].elements.map { entry in
            var e = FleetEvent(json: entry)
            if e.device.isEmpty { e.device = serial }
            return e
        }
    }

    public func deviceInstallsLog(_ serial: String) async throws -> String? {
        let json = try await getJSON("/device/\(encode(serial))/installs/log")
        return json["runLog"].nonEmptyString
    }

    public func deviceLogRoot(_ serial: String, tool: String) async throws -> JSONValue {
        let json = try await getJSON("/device/\(encode(serial))/logs/\(encode(tool))")
        return json["root"]
    }

    public func deviceUsageHistory(_ serial: String, days: Int = 90, appName: String? = nil) async throws -> [UsageHistoryEntry] {
        let json = try await getJSON("/device/\(encode(serial))/applications/usage/history", query: ["days": String(days), "appName": appName])
        return json["data"].elements.map(UsageHistoryEntry.init(json:))
    }

    // MARK: - Events

    public func events(limit: Int = 100, offset: Int = 0, kinds: [EventKind]? = nil, startDate: Date? = nil, endDate: Date? = nil) async throws -> EventsPage {
        let iso = ISO8601DateFormatter()
        let json = try await getJSON("/events", query: [
            "limit": String(limit),
            "offset": offset > 0 ? String(offset) : nil,
            "type": kinds.flatMap { $0.isEmpty ? nil : $0.map(\.rawValue).joined(separator: ",") },
            "startDate": startDate.map(iso.string),
            "endDate": endDate.map(iso.string),
        ])
        return EventsPage(json: json)
    }

    public func eventPayload(_ id: String) async throws -> JSONValue {
        let json = try await getJSON("/events/\(encode(id))/payload")
        let payload = json["payload"]
        return payload.isNull ? json : payload
    }

    public func ingestFailures(limit: Int = 100, offset: Int = 0, serial: String? = nil, reason: String? = nil, hours: Int = 168, outcome: String = "rejected") async throws -> IngestFailuresPage {
        let json = try await getJSON("/events/failures", query: [
            "limit": String(limit), "offset": offset > 0 ? String(offset) : nil,
            "serial": serial, "reason": reason, "hours": String(hours), "outcome": outcome,
        ])
        return IngestFailuresPage(json: json)
    }

    public func installStats() async throws -> JSONValue {
        try await getJSON("/stats/installs")
    }

    // MARK: - Fleet reports

    /// A bulk module report such as `/api/v1/hardware`. Raw because each
    /// report has its own envelope; the report views decode what they need.
    public func fleetReport(_ path: String, query: [String: String?] = [:]) async throws -> JSONValue {
        try await getJSON(path, query: query)
    }

    // MARK: - Applications

    /// Chip-cloud options and the device list for the Applications report.
    public func applicationFilters() async throws -> ApplicationFilterOptions {
        let json = try await getJSON("/applications/filters")
        guard json.object != nil else { throw APIError.decoding("Invalid response format from filters API") }
        return ApplicationFilterOptions(json: json)
    }

    /// Installed-application rows, filtered server-side by `applicationNames`,
    /// inventory dimensions and platform.
    public func applications(query: [String: String?]) async throws -> [FleetApplicationRow] {
        let json = try await getJSON("/applications", query: query)
        guard let rows = json.array else { throw APIError.decoding(json["error"].string ?? "Invalid data format") }
        return rows.map(FleetApplicationRow.init(json:))
    }

    public func applicationUsage(query: [String: String?]) async throws -> UtilizationData {
        UtilizationData(json: try await getJSON("/applications/usage", query: query))
    }

    /// Per-(app, version) counts aggregated in SQL; `nil` when the endpoint
    /// cannot serve the request, so callers fold the rows themselves.
    public func applicationDistribution(query: [String: String?]) async throws -> [String: ServerDistributionBucket]? {
        ApplicationsReport.parseServerDistribution(try await getJSON("/applications/distribution", query: query))
    }

    public func applicationUsageByDevice(app: String, days: Int, usages: [String] = [], catalogs: [String] = [], locations: [String] = []) async throws -> UsageByDeviceReport {
        var query: [String: String?] = ["app": app, "days": String(days)]
        if !usages.isEmpty { query["usages"] = usages.joined(separator: ",") }
        if !catalogs.isEmpty { query["catalogs"] = catalogs.joined(separator: ",") }
        if !locations.isEmpty { query["locations"] = locations.joined(separator: ",") }
        return UsageByDeviceReport(json: try await getJSON("/applications/usage/by-device", query: query))
    }

    public func applicationCollectionHealth(freshDays: Int = 7, staleDays: Int = 30) async throws -> CollectionHealth {
        CollectionHealth(json: try await getJSON("/applications/collection-health", query: ["freshDays": String(freshDays), "staleDays": String(staleDays)]))
    }

    // MARK: - Installs

    /// Item names, inventory dimensions and the slimmed device list for the Installs report.
    public func installsFilters(includeArchived: Bool = false) async throws -> InstallsFilterOptions {
        let json = try await getJSON("/installs/filters", query: ["includeArchived": includeArchived ? "true" : nil])
        guard json.object != nil else { throw APIError.decoding("Invalid response format from filters API") }
        return InstallsFilterOptions(json: json)
    }

    /// (device, package) rows for the fleet, one page at a time (the API caps a
    /// page at 5000; the whole list is well over 100k rows). Filtering happens client-side.
    public func installRecords(includeArchived: Bool = false, limit: Int = 5000, offset: Int = 0) async throws -> [InstallRecord] {
        let json = try await getJSON("/installs", query: ["includeArchived": includeArchived ? "true" : nil, "limit": String(limit), "offset": offset > 0 ? String(offset) : nil])
        let rows = json.array ?? json["devices"].array ?? json["data"].array
        guard let rows else { throw APIError.decoding(json["error"].string ?? json["message"].string ?? "Received invalid data format from API") }
        return rows.map(InstallRecord.init(json:))
    }

    // MARK: - Settings

    public func settings() async throws -> SettingsResponse {
        SettingsResponse(json: try await getJSON("/settings"))
    }

    public func saveSettings(_ document: SettingsDocument) async throws -> JSONValue {
        let data = try JSONEncoder().encode(document)
        let value = try JSONValue.parse(data)
        return try await sendJSON("/settings", method: "PUT", body: value)
    }

    public func discoverInventoryKeys() async throws -> [DiscoveredInventoryKey] {
        let json = try await getJSON("/settings/inventory/discover")
        let list = json["keys"].isNull ? json.elements : json["keys"].elements
        return list.map(DiscoveredInventoryKey.init(json:))
    }

    // MARK: - Admin

    public func archiveDevice(_ serial: String) async throws {
        _ = try await sendJSON("/device/\(encode(serial))/archive", method: "PATCH")
    }

    public func unarchiveDevice(_ serial: String) async throws {
        _ = try await sendJSON("/device/\(encode(serial))/unarchive", method: "PATCH")
    }

    public func deleteDevice(_ serial: String) async throws {
        _ = try await sendJSON("/device/\(encode(serial))", method: "DELETE")
    }

    /// Clears install errors and warnings from devices silent for `days` or more (0 = every device).
    public func clearInstallErrors(days: Int = 10) async throws -> JSONValue {
        try await sendJSON("/admin/installs/clear-errors", method: "DELETE", query: ["days": String(days)])
    }

    public func apiKeys() async throws -> JSONValue {
        try await getJSON("/admin/api-keys")
    }

    // MARK: - Helpers

    private func encode(_ s: String) -> String {
        s.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed.subtracting(CharacterSet(charactersIn: "/"))) ?? s
    }
}
