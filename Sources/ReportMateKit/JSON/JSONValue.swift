import Foundation

/// A loosely typed JSON tree.
///
/// Module payloads from the ReportMate API are heterogeneous: the macOS client
/// emits osquery-style `snake_case` keys, the Windows client emits `camelCase`,
/// and both have drifted over time. Rather than a rigid `Codable` struct per
/// module, the app keeps the raw tree and reads it through the same fallback
/// chains the web dashboard uses. Every accessor is total (returns nil or a
/// default) so a missing or oddly shaped key can never crash a view.
public enum JSONValue: Sendable, Hashable {
    case null
    case bool(Bool)
    case number(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])

    // MARK: - Basic accessors

    public var isNull: Bool {
        if case .null = self { return true }
        return false
    }

    /// The value as a string. Numbers and booleans are coerced so a build
    /// number stored as `26200` reads the same as `"26200"`.
    public var string: String? {
        switch self {
        case .string(let s): return s
        case .number(let n):
            if n == n.rounded(), abs(n) < 1e15 { return String(Int64(n)) }
            return String(n)
        case .bool(let b): return b ? "true" : "false"
        default: return nil
        }
    }

    /// The string, trimmed, or nil when empty.
    public var nonEmptyString: String? {
        guard let s = string?.trimmingCharacters(in: .whitespacesAndNewlines), !s.isEmpty else { return nil }
        return s
    }

    public var double: Double? {
        switch self {
        case .number(let n): return n
        case .string(let s): return Double(s.trimmingCharacters(in: .whitespaces))
        case .bool(let b): return b ? 1 : 0
        default: return nil
        }
    }

    public var int: Int? {
        guard let d = double, d.isFinite, abs(d) < Double(Int.max) else { return nil }
        return Int(d)
    }

    /// Strict boolean.
    public var bool: Bool? {
        if case .bool(let b) = self { return b }
        return nil
    }

    /// Boolean the way the collectors mean it: `true`, `1`, `"1"`, `"true"`,
    /// `"yes"` all count as on. Anything else, including nil, is off.
    public var boolish: Bool {
        switch self {
        case .bool(let b): return b
        case .number(let n): return n != 0
        case .string(let s):
            let l = s.lowercased().trimmingCharacters(in: .whitespaces)
            return l == "true" || l == "1" || l == "yes"
        default: return false
        }
    }

    /// True only when the value is present and boolean-shaped (so callers can
    /// distinguish "explicitly false" from "not reported").
    public var boolishIfPresent: Bool? {
        switch self {
        case .null: return nil
        case .bool, .number: return boolish
        case .string(let s):
            let l = s.lowercased().trimmingCharacters(in: .whitespaces)
            if ["true", "false", "1", "0", "yes", "no"].contains(l) { return boolish }
            return nil
        default: return nil
        }
    }

    public var array: [JSONValue]? {
        if case .array(let a) = self { return a }
        return nil
    }

    public var object: [String: JSONValue]? {
        if case .object(let o) = self { return o }
        return nil
    }

    /// Array elements, or an empty array.
    public var elements: [JSONValue] { array ?? [] }

    public var isEmptyContainer: Bool {
        switch self {
        case .array(let a): return a.isEmpty
        case .object(let o): return o.isEmpty
        case .null: return true
        default: return false
        }
    }

    // MARK: - Subscripts

    public subscript(key: String) -> JSONValue {
        guard case .object(let o) = self else { return .null }
        return o[key] ?? .null
    }

    public subscript(index: Int) -> JSONValue {
        guard case .array(let a) = self, a.indices.contains(index) else { return .null }
        return a[index]
    }

    /// Dotted path lookup: `value["hardware.processor.name"]`.
    public subscript(path path: String) -> JSONValue {
        var current = self
        for part in path.split(separator: ".") {
            current = current[String(part)]
            if current.isNull { return .null }
        }
        return current
    }

    /// The first non-null value among several candidate keys. This is the
    /// Swift spelling of the web app's `a.snake_key || a.camelKey` chains.
    public func first(_ keys: String...) -> JSONValue {
        for k in keys {
            let v = self[k]
            if !v.isNull { return v }
        }
        return .null
    }

    /// First non-empty string among candidate keys.
    public func firstString(_ keys: String...) -> String? {
        for k in keys {
            if let s = self[k].nonEmptyString { return s }
        }
        return nil
    }

    /// First non-null number among candidate keys.
    public func firstDouble(_ keys: String...) -> Double? {
        for k in keys {
            if let d = self[k].double { return d }
        }
        return nil
    }

    // MARK: - Key normalisation

    /// Recursively converts every `snake_case` key to `camelCase`, the way
    /// the web app's `normalizeKeys` does, so one lookup covers both clients.
    public func normalizedKeys() -> JSONValue {
        switch self {
        case .array(let a): return .array(a.map { $0.normalizedKeys() })
        case .object(let o):
            var out: [String: JSONValue] = [:]
            out.reserveCapacity(o.count)
            for (k, v) in o {
                let camel = JSONValue.snakeToCamel(k)
                // Prefer an explicit camelCase key over a converted one when both exist.
                if out[camel] == nil || k == camel {
                    out[camel] = v.normalizedKeys()
                }
            }
            return .object(out)
        default: return self
        }
    }

    public static func snakeToCamel(_ key: String) -> String {
        guard key.contains("_") else { return key }
        var result = ""
        var upperNext = false
        for ch in key {
            if ch == "_" {
                upperNext = true
            } else if upperNext {
                result.append(ch.uppercased())
                upperNext = false
            } else {
                result.append(ch)
            }
        }
        return result
    }

    /// If the value is a JSON-encoded string, parse it; otherwise return self.
    /// Some osquery collectors wrap structured output as `{ "output": "{...}" }`.
    public func parsedIfString() -> JSONValue {
        if case .string(let s) = self,
           let data = s.data(using: .utf8),
           let parsed = try? JSONDecoder().decode(JSONValue.self, from: data) {
            return parsed
        }
        return self
    }

    /// Unwrap the `{ "output": "<json>" }` shape some collectors use.
    public func unwrappingOutput() -> JSONValue {
        let out = self["output"]
        if case .string = out, case let parsed = out.parsedIfString(), !parsed.isNull, parsed.string == nil {
            return parsed
        }
        return self
    }

    /// Single-item arrays are unwrapped; the API stores some modules as `[ {...} ]`.
    public func unwrappingSingleton() -> JSONValue {
        if case .array(let a) = self, a.count == 1 { return a[0] }
        return self
    }
}

// MARK: - Codable

extension JSONValue: Codable {
    private struct AnyKey: CodingKey {
        var stringValue: String
        var intValue: Int?
        init(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { self.stringValue = String(intValue); self.intValue = intValue }
    }

    public init(from decoder: Decoder) throws {
        if let keyed = try? decoder.container(keyedBy: AnyKey.self) {
            var dict: [String: JSONValue] = [:]
            for key in keyed.allKeys {
                dict[key.stringValue] = try keyed.decode(JSONValue.self, forKey: key)
            }
            self = .object(dict)
            return
        }
        if var unkeyed = try? decoder.unkeyedContainer() {
            var arr: [JSONValue] = []
            while !unkeyed.isAtEnd {
                arr.append(try unkeyed.decode(JSONValue.self))
            }
            self = .array(arr)
            return
        }
        let single = try decoder.singleValueContainer()
        if single.decodeNil() {
            self = .null
        } else if let b = try? single.decode(Bool.self) {
            self = .bool(b)
        } else if let d = try? single.decode(Double.self) {
            self = .number(d)
        } else if let s = try? single.decode(String.self) {
            self = .string(s)
        } else {
            throw DecodingError.dataCorruptedError(in: single, debugDescription: "Unsupported JSON value")
        }
    }

    public func encode(to encoder: Encoder) throws {
        switch self {
        case .null:
            var c = encoder.singleValueContainer(); try c.encodeNil()
        case .bool(let b):
            var c = encoder.singleValueContainer(); try c.encode(b)
        case .number(let n):
            var c = encoder.singleValueContainer()
            if n == n.rounded(), abs(n) < 1e15 { try c.encode(Int64(n)) } else { try c.encode(n) }
        case .string(let s):
            var c = encoder.singleValueContainer(); try c.encode(s)
        case .array(let a):
            var c = encoder.unkeyedContainer()
            for v in a { try c.encode(v) }
        case .object(let o):
            var c = encoder.container(keyedBy: AnyKey.self)
            for (k, v) in o.sorted(by: { $0.key < $1.key }) {
                try c.encode(v, forKey: AnyKey(stringValue: k))
            }
        }
    }
}

// MARK: - Literals

extension JSONValue: ExpressibleByStringLiteral, ExpressibleByIntegerLiteral, ExpressibleByFloatLiteral,
                     ExpressibleByBooleanLiteral, ExpressibleByNilLiteral, ExpressibleByArrayLiteral,
                     ExpressibleByDictionaryLiteral {
    public init(stringLiteral value: String) { self = .string(value) }
    public init(integerLiteral value: Int) { self = .number(Double(value)) }
    public init(floatLiteral value: Double) { self = .number(value) }
    public init(booleanLiteral value: Bool) { self = .bool(value) }
    public init(nilLiteral: ()) { self = .null }
    public init(arrayLiteral elements: JSONValue...) { self = .array(elements) }
    public init(dictionaryLiteral elements: (String, JSONValue)...) {
        self = .object(Dictionary(elements, uniquingKeysWith: { _, last in last }))
    }
}

// MARK: - Pretty printing

extension JSONValue {
    /// Pretty-printed JSON text for debug views.
    public var prettyPrinted: String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        guard let data = try? encoder.encode(self), let s = String(data: data, encoding: .utf8) else { return "" }
        return s
    }

    public static func parse(_ data: Data) throws -> JSONValue {
        try JSONDecoder().decode(JSONValue.self, from: data)
    }

    public static func parse(_ text: String) -> JSONValue? {
        guard let data = text.data(using: .utf8) else { return nil }
        return try? parse(data)
    }
}
