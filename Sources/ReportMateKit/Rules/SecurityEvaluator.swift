import Foundation

/// Canonical-key → value map for one device, e.g. `["usage": "Shared"]`.
public typealias InventoryContext = [String: String]

/// Pure port of the web app's `evaluateSecurity` and `inventoryMapping`, so
/// a shared lab Mac with FileVault off is coloured the same in both apps.
public enum SecurityEvaluator {
    public static func evaluate(check: String, enabled: Bool?, context: InventoryContext, config: SecurityConfig) -> Severity {
        guard let enabled else { return .unknown }
        var severity = baseline(check: check, enabled: enabled, config: config)
        var bestSpecificity = -1
        for rule in config.rules {
            if rule.enabled == false { continue }
            if rule.check != check { continue }
            if !stateMatches(rule.state, enabled: enabled) { continue }
            let spec = specificity(of: rule.when, context: context)
            if spec < 0 { continue }
            if spec >= bestSpecificity {
                bestSpecificity = spec
                severity = rule.severity
            }
        }
        return severity
    }

    private static func stateMatches(_ state: RuleState?, enabled: Bool) -> Bool {
        guard let state, state != .any else { return true }
        return state == .enabled ? enabled : !enabled
    }

    private static func specificity(of when: RuleCondition?, context: InventoryContext) -> Int {
        guard let inventory = when?.inventory else { return 0 }
        var matched = 0
        for (key, op) in inventory {
            let value = context[key]
            if let list = op.in {
                guard let value, list.contains(value) else { return -1 }
            }
            if let eq = op.eq, value != eq { return -1 }
            if let ne = op.ne, value == ne { return -1 }
            matched += 1
        }
        return matched
    }

    private static func baseline(check: String, enabled: Bool, config: SecurityConfig) -> Severity {
        if let def = config.defaults[check] {
            return enabled ? def.enabledSeverity : def.disabledSeverity
        }
        return enabled ? .ok : .warning
    }
}

public struct MappedInventoryRow: Sendable, Hashable, Identifiable {
    public var id: String { key.rawValue }
    public var key: CanonicalInventoryKey
    public var label: String
    public var value: String
}

public enum InventoryMapping {
    private static func toSnake(_ key: String) -> String {
        var out = ""
        for (i, ch) in key.enumerated() {
            if ch.isUppercase, i > 0 { out.append("_") }
            out.append(ch.lowercased())
        }
        return out
    }

    /// Resolve a value tolerating snake/camel differences.
    public static func resolve(_ raw: JSONValue, sourceKey: String) -> String? {
        for k in [sourceKey, toSnake(sourceKey), JSONValue.snakeToCamel(sourceKey)] {
            if let v = raw[k].nonEmptyString { return v }
        }
        return nil
    }

    /// Ordered, visible rows for display.
    public static func rows(inventory raw: JSONValue, fields: [InventoryFieldMapping] = SettingsDocument.defaultInventoryFields) -> [MappedInventoryRow] {
        fields.filter(\.visible).sorted { $0.order < $1.order }.compactMap { f in
            guard let v = resolve(raw, sourceKey: f.sourceKey) else { return nil }
            return MappedInventoryRow(key: f.key, label: f.label, value: v)
        }
    }

    /// Context for the rules engine, including hidden fields.
    public static func context(inventory raw: JSONValue, fields: [InventoryFieldMapping] = SettingsDocument.defaultInventoryFields) -> InventoryContext {
        var ctx: InventoryContext = [:]
        for f in fields {
            if let v = resolve(raw, sourceKey: f.sourceKey) { ctx[f.key.rawValue] = v }
        }
        return ctx
    }
}
