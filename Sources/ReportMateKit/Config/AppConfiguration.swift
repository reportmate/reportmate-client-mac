import Foundation

/// How the app authenticates to the API. The API accepts all three; see
/// `verify_authentication` in the API's `dependencies.py`.
public enum AuthMethod: String, Sendable, Codable, CaseIterable, Identifiable {
    /// `X-API-Key`, a per-client scoped key minted from the API's admin endpoints.
    case apiKey
    /// `X-Client-Passphrase`, the legacy shared passphrase (full access).
    case passphrase
    /// `Authorization: Bearer <jwt>` minted by `az account get-access-token`.
    case entraBearer

    public var id: String { rawValue }

    public var displayName: String {
        switch self {
        case .apiKey: return "API key"
        case .passphrase: return "Passphrase"
        case .entraBearer: return "Entra sign-in (az)"
        }
    }
}

/// Connection settings for the fleet API.
///
/// Resolution order: environment (`REPORTMATE_URL`, `REPORTMATE_API_KEY`,
/// `REPORTMATE_PASSPHRASE`, `REPORTMATE_OIDC_AUDIENCE`) wins over the
/// Keychain, which wins over nothing. Secrets never touch UserDefaults.
public struct AppConfiguration: Sendable, Equatable {
    public var baseURL: String
    public var authMethod: AuthMethod
    public var apiKey: String
    public var passphrase: String
    public var oidcAudience: String
    /// The web dashboard, used to build links that fall back to the browser.
    public var webBaseURL: String

    public static let webBaseURLDefaultsKey = "webBaseURL"

    public init(baseURL: String = "", authMethod: AuthMethod = .apiKey, apiKey: String = "", passphrase: String = "", oidcAudience: String = "", webBaseURL: String = "") {
        self.baseURL = baseURL
        self.authMethod = authMethod
        self.apiKey = apiKey
        self.passphrase = passphrase
        self.oidcAudience = oidcAudience
        self.webBaseURL = webBaseURL
    }

    public var normalizedWebURL: URL? {
        var s = webBaseURL.trimmingCharacters(in: .whitespacesAndNewlines)
        while s.hasSuffix("/") { s.removeLast() }
        guard !s.isEmpty, let url = URL(string: s), url.host != nil else { return nil }
        return url
    }

    public var normalizedBaseURL: String {
        var s = baseURL.trimmingCharacters(in: .whitespacesAndNewlines)
        while s.hasSuffix("/") { s.removeLast() }
        // Accept a URL that already ends in /api/v1 or /api.
        if s.hasSuffix("/api/v1") { s.removeLast("/api/v1".count) }
        if s.hasSuffix("/api") { s.removeLast("/api".count) }
        return s
    }

    public var isConfigured: Bool {
        guard !normalizedBaseURL.isEmpty, URL(string: normalizedBaseURL) != nil else { return false }
        switch authMethod {
        case .apiKey: return !apiKey.isEmpty
        case .passphrase: return !passphrase.isEmpty
        case .entraBearer: return !oidcAudience.isEmpty
        }
    }

    public var credentialSummary: String {
        switch authMethod {
        case .apiKey: return apiKey.isEmpty ? "No API key" : "API key ending …\(apiKey.suffix(4))"
        case .passphrase: return passphrase.isEmpty ? "No passphrase" : "Passphrase set"
        case .entraBearer: return oidcAudience.isEmpty ? "No audience" : "Entra bearer for \(oidcAudience)"
        }
    }

    // MARK: - Persistence

    public static func load(keychain: KeychainStore = KeychainStore(), environment: [String: String] = ProcessInfo.processInfo.environment) -> AppConfiguration {
        var config = AppConfiguration()
        config.baseURL = keychain.get(.apiBaseURL) ?? ""
        config.apiKey = keychain.get(.apiKey) ?? ""
        config.passphrase = keychain.get(.passphrase) ?? ""
        config.oidcAudience = keychain.get(.oidcAudience) ?? ""
        config.webBaseURL = UserDefaults.standard.string(forKey: AppConfiguration.webBaseURLDefaultsKey) ?? ""
        if let m = keychain.get(.authMethod), let method = AuthMethod(rawValue: m) {
            config.authMethod = method
        } else if !config.apiKey.isEmpty {
            config.authMethod = .apiKey
        } else if !config.passphrase.isEmpty {
            config.authMethod = .passphrase
        } else if !config.oidcAudience.isEmpty {
            config.authMethod = .entraBearer
        }

        if let v = environment["REPORTMATE_URL"], !v.isEmpty { config.baseURL = v }
        if let v = environment["REPORTMATE_WEB_URL"], !v.isEmpty { config.webBaseURL = v }
        if let v = environment["REPORTMATE_API_KEY"], !v.isEmpty { config.apiKey = v; config.authMethod = .apiKey }
        if let v = environment["REPORTMATE_PASSPHRASE"], !v.isEmpty, config.apiKey.isEmpty { config.passphrase = v; config.authMethod = .passphrase }
        if let v = environment["REPORTMATE_OIDC_AUDIENCE"], !v.isEmpty {
            config.oidcAudience = v
            if config.apiKey.isEmpty, config.passphrase.isEmpty { config.authMethod = .entraBearer }
        }
        return config
    }

    public func save(keychain: KeychainStore = KeychainStore()) throws {
        try keychain.set(normalizedBaseURL, for: .apiBaseURL)
        try keychain.set(apiKey, for: .apiKey)
        try keychain.set(passphrase, for: .passphrase)
        try keychain.set(oidcAudience, for: .oidcAudience)
        try keychain.set(authMethod.rawValue, for: .authMethod)
        UserDefaults.standard.set(webBaseURL.trimmingCharacters(in: .whitespacesAndNewlines), forKey: AppConfiguration.webBaseURLDefaultsKey)
    }
}
