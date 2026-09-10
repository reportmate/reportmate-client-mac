import Foundation

/// Server-side settings shared with the web app (`src/lib/settings/types.ts`).
/// The API stores this as one JSONB document; both apps read the same shape.
public enum Severity: String, Sendable, Codable, Hashable {
    case ok, warning, danger, neutral, unknown
}

public enum CanonicalInventoryKey: String, Sendable, Codable, Hashable, CaseIterable {
    case usage, catalog, department, area, location, fleet, assetTag, owner
}

public struct InventoryFieldMapping: Sendable, Codable, Hashable, Identifiable {
    public var id: String { key.rawValue }
    public var key: CanonicalInventoryKey
    public var sourceKey: String
    public var label: String
    public var order: Int
    public var visible: Bool
    public var knownValues: [String]

    public init(key: CanonicalInventoryKey, sourceKey: String, label: String, order: Int, visible: Bool, knownValues: [String] = []) {
        self.key = key
        self.sourceKey = sourceKey
        self.label = label
        self.order = order
        self.visible = visible
        self.knownValues = knownValues
    }

    enum CodingKeys: String, CodingKey { case key, sourceKey, label, order, visible, knownValues }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        key = try c.decode(CanonicalInventoryKey.self, forKey: .key)
        sourceKey = try c.decodeIfPresent(String.self, forKey: .sourceKey) ?? key.rawValue
        label = try c.decodeIfPresent(String.self, forKey: .label) ?? key.rawValue
        order = try c.decodeIfPresent(Int.self, forKey: .order) ?? 0
        visible = try c.decodeIfPresent(Bool.self, forKey: .visible) ?? true
        knownValues = try c.decodeIfPresent([String].self, forKey: .knownValues) ?? []
    }
}

public struct SecurityCheckDefault: Sendable, Codable, Hashable {
    public var enabledSeverity: Severity
    public var disabledSeverity: Severity
    public init(enabledSeverity: Severity, disabledSeverity: Severity) {
        self.enabledSeverity = enabledSeverity
        self.disabledSeverity = disabledSeverity
    }
}

public struct RuleOperator: Sendable, Codable, Hashable {
    public var `in`: [String]?
    public var eq: String?
    public var ne: String?
    public init(in: [String]? = nil, eq: String? = nil, ne: String? = nil) {
        self.in = `in`; self.eq = eq; self.ne = ne
    }
}

public struct RuleCondition: Sendable, Codable, Hashable {
    public var inventory: [String: RuleOperator]?
    public init(inventory: [String: RuleOperator]? = nil) { self.inventory = inventory }
}

public enum RuleState: String, Sendable, Codable, Hashable {
    case enabled, disabled, any
}

public struct SecurityRule: Sendable, Codable, Hashable, Identifiable {
    public var id: String
    public var module: String?
    public var check: String
    public var fieldPath: String?
    public var when: RuleCondition?
    public var state: RuleState?
    public var severity: Severity
    public var enabled: Bool?

    public init(id: String, module: String? = nil, check: String, fieldPath: String? = nil, when: RuleCondition? = nil,
                state: RuleState? = nil, severity: Severity, enabled: Bool? = true) {
        self.id = id; self.module = module; self.check = check; self.fieldPath = fieldPath
        self.when = when; self.state = state; self.severity = severity; self.enabled = enabled
    }
}

public struct SecurityConfig: Sendable, Codable, Hashable {
    public var defaults: [String: SecurityCheckDefault]
    public var rules: [SecurityRule]
    public init(defaults: [String: SecurityCheckDefault], rules: [SecurityRule]) {
        self.defaults = defaults
        self.rules = rules
    }

    enum CodingKeys: String, CodingKey { case defaults, rules }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        defaults = try c.decodeIfPresent([String: SecurityCheckDefault].self, forKey: .defaults) ?? [:]
        rules = try c.decodeIfPresent([SecurityRule].self, forKey: .rules) ?? []
    }
}

public struct GeneralSettings: Sendable, Codable, Hashable {
    public var fleetName: String?
    public var defaultPlatformFilter: String?
    public var onboardingCompletedAt: String?
    public init(fleetName: String? = nil, defaultPlatformFilter: String? = nil, onboardingCompletedAt: String? = nil) {
        self.fleetName = fleetName
        self.defaultPlatformFilter = defaultPlatformFilter
        self.onboardingCompletedAt = onboardingCompletedAt
    }
}

public struct KioskSettings: Sendable, Codable, Hashable {
    public var homePath: String
    public var zoom: Double
    public var idleMinutes: Int
    public var theme: String
    public init(homePath: String = "/events", zoom: Double = 1.25, idleMinutes: Int = 5, theme: String = "dark") {
        self.homePath = homePath; self.zoom = zoom; self.idleMinutes = idleMinutes; self.theme = theme
    }

    enum CodingKeys: String, CodingKey { case homePath, zoom, idleMinutes, theme }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        homePath = try c.decodeIfPresent(String.self, forKey: .homePath) ?? "/events"
        zoom = try c.decodeIfPresent(Double.self, forKey: .zoom) ?? 1.25
        idleMinutes = try c.decodeIfPresent(Int.self, forKey: .idleMinutes) ?? 5
        theme = try c.decodeIfPresent(String.self, forKey: .theme) ?? "dark"
    }
}

public struct SettingsDocument: Sendable, Codable, Hashable {
    public var schemaVersion: Int
    public var general: GeneralSettings
    public var inventory: InventorySettings
    public var security: SecurityConfig
    public var kiosk: KioskSettings

    public struct InventorySettings: Sendable, Codable, Hashable {
        public var fields: [InventoryFieldMapping]
        public init(fields: [InventoryFieldMapping]) { self.fields = fields }
    }

    public static let currentSchemaVersion = 1

    public static let defaultInventoryFields: [InventoryFieldMapping] = [
        .init(key: .usage, sourceKey: "usage", label: "Usage", order: 0, visible: true),
        .init(key: .catalog, sourceKey: "catalog", label: "Catalog", order: 1, visible: true),
        .init(key: .department, sourceKey: "department", label: "Department", order: 2, visible: true),
        .init(key: .area, sourceKey: "area", label: "Area", order: 3, visible: false),
        .init(key: .location, sourceKey: "location", label: "Location", order: 4, visible: true),
        .init(key: .fleet, sourceKey: "fleet", label: "Fleet", order: 5, visible: false),
        .init(key: .assetTag, sourceKey: "assetTag", label: "Asset Tag", order: 6, visible: true),
        .init(key: .owner, sourceKey: "owner", label: "Owner", order: 7, visible: true),
    ]

    public static let defaultSecurityConfig = SecurityConfig(
        defaults: [
            "encryption": .init(enabledSeverity: .ok, disabledSeverity: .danger),
            "firewall": .init(enabledSeverity: .ok, disabledSeverity: .warning),
            "ssh": .init(enabledSeverity: .warning, disabledSeverity: .ok),
            "rdp": .init(enabledSeverity: .warning, disabledSeverity: .ok),
            "sip": .init(enabledSeverity: .ok, disabledSeverity: .danger),
        ],
        rules: []
    )

    public static let starterSecurityRules: [SecurityRule] = [
        SecurityRule(id: "encryption-shared-neutral", module: "security", check: "encryption",
                     when: RuleCondition(inventory: ["usage": RuleOperator(in: ["Shared", "Lab"])]),
                     state: .disabled, severity: .neutral, enabled: true)
    ]

    public static let defaults = SettingsDocument(
        schemaVersion: currentSchemaVersion,
        general: GeneralSettings(),
        inventory: InventorySettings(fields: defaultInventoryFields),
        security: defaultSecurityConfig,
        kiosk: KioskSettings()
    )

    public init(schemaVersion: Int, general: GeneralSettings, inventory: InventorySettings, security: SecurityConfig, kiosk: KioskSettings) {
        self.schemaVersion = schemaVersion
        self.general = general
        self.inventory = inventory
        self.security = security
        self.kiosk = kiosk
    }

    enum CodingKeys: String, CodingKey { case schemaVersion, general, inventory, security, kiosk }

    /// `withDefaults`: a stored document may be partial; fill every gap.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try c.decodeIfPresent(Int.self, forKey: .schemaVersion) ?? SettingsDocument.currentSchemaVersion
        general = try c.decodeIfPresent(GeneralSettings.self, forKey: .general) ?? GeneralSettings()
        let inv = try c.decodeIfPresent(InventorySettings.self, forKey: .inventory)
        inventory = (inv?.fields.isEmpty == false) ? inv! : InventorySettings(fields: SettingsDocument.defaultInventoryFields)
        var sec = try c.decodeIfPresent(SecurityConfig.self, forKey: .security) ?? SettingsDocument.defaultSecurityConfig
        sec.defaults = SettingsDocument.defaultSecurityConfig.defaults.merging(sec.defaults) { _, stored in stored }
        security = sec
        kiosk = try c.decodeIfPresent(KioskSettings.self, forKey: .kiosk) ?? KioskSettings()
    }

    /// Visible inventory fields in display order.
    public var visibleInventoryFields: [InventoryFieldMapping] {
        inventory.fields.filter(\.visible).sorted { $0.order < $1.order }
    }
}

/// Envelope of `GET /api/v1/settings`.
public struct SettingsResponse: Sendable {
    public var exists: Bool
    public var value: SettingsDocument
    public var schemaVersion: Int
    public var updatedAt: Date?
    public var updatedBy: String?

    public init(json: JSONValue) {
        exists = json["exists"].boolish
        schemaVersion = json["schemaVersion"].int ?? SettingsDocument.currentSchemaVersion
        updatedAt = FlexibleDate.parse(json["updatedAt"])
        updatedBy = json["updatedBy"].nonEmptyString
        if let data = try? JSONEncoder().encode(json["value"]), !json["value"].isNull,
           let doc = try? JSONDecoder().decode(SettingsDocument.self, from: data) {
            value = doc
        } else {
            value = SettingsDocument.defaults
        }
    }
}

/// One row of `GET /api/v1/settings/inventory/discover`.
public struct DiscoveredInventoryKey: Sendable, Hashable, Identifiable {
    public var id: String { key }
    public var key: String
    public var deviceCount: Int
    public var distinctCount: Int
    public var sampleValues: [String]

    public init(json: JSONValue) {
        key = json["key"].string ?? ""
        deviceCount = json["deviceCount"].int ?? 0
        distinctCount = json["distinctCount"].int ?? 0
        sampleValues = json["sampleValues"].elements.compactMap(\.string)
    }
}
