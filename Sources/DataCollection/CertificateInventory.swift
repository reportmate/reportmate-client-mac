import Foundation

/// Turns raw certificate rows into the payload the API classifies, and works out which
/// certificates have their private key alongside them.
///
/// The API decides whether a certificate is actionable, system-managed or part of the trust
/// store. It needs the facts the runner can see: the keychain path, whether the certificate is a
/// CA, its key usage, its SHA-1 and whether a private key pairs with it. Classification itself
/// stays in the API.
enum CertificateInventory {

    /// Certificates within this many days of `notAfter` are reported as expiring soon.
    static let expiringSoonDays = 30

    // MARK: - Private-key identities

    /// SHA-1 thumbprints of the identities listed by `security find-identity <keychain>`.
    ///
    /// Runs without `-v`, so the "Matching identities" section includes expired and untrusted
    /// identities as well as valid ones; a certificate with its key is still an identity after it
    /// expires, and that is exactly the case someone has to renew.
    ///
    /// Returns nil when the output is not recognisable `find-identity` output, so a failed lookup
    /// is never mistaken for "this keychain has no identities".
    static func parseIdentityHashes(_ output: String) -> Set<String>? {
        guard output.contains("identities found") || output.contains("Matching identities") else {
            return nil
        }

        var hashes = Set<String>()
        for rawLine in output.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard let close = line.firstIndex(of: ")"),
                  line[line.startIndex..<close].allSatisfy(\.isNumber),
                  line.startIndex != close else {
                continue
            }
            let rest = line[line.index(after: close)...].trimmingCharacters(in: .whitespaces)
            let token = rest.prefix { !$0.isWhitespace }
            if let hash = normalizeSHA1(String(token)) {
                hashes.insert(hash)
            }
        }
        return hashes
    }

    /// Upper-case hex SHA-1 with separators removed, or nil when it is not a SHA-1.
    static func normalizeSHA1(_ value: String?) -> String? {
        guard let value else { return nil }
        let hex = value.uppercased().filter { $0 != ":" && $0 != " " }
        guard hex.count == 40, hex.allSatisfy(\.isHexDigit) else { return nil }
        return hex
    }

    /// Keychains worth asking for identities: every distinct path the certificates came from.
    static func keychainPaths(of certificates: [[String: Any]]) -> [String] {
        let paths = certificates.compactMap { $0["path"] as? String }.filter { !$0.isEmpty }
        return Array(Set(paths)).sorted()
    }

    /// Sets `hasPrivateKey` on every certificate whose keychain was looked up successfully.
    ///
    /// `identities` maps a keychain path to the thumbprints found there. A keychain missing from
    /// the map failed its lookup, so its certificates get no `hasPrivateKey` at all rather than a
    /// `false` the API would trust. A certificate with no usable SHA-1 is left alone too.
    static func applyPrivateKeyFlags(
        to certificates: [[String: Any]],
        identities: [String: Set<String>]
    ) -> [[String: Any]] {
        certificates.map { cert in
            guard let path = cert["path"] as? String,
                  let hashes = identities[path],
                  let sha1 = normalizeSHA1(cert["sha1"] as? String) else {
                return cert
            }
            var updated = cert
            updated["hasPrivateKey"] = hashes.contains(sha1)
            return updated
        }
    }

    // MARK: - Row mapping

    /// Maps one `certificates` row (osquery column names; the bash fallback emits the same) to
    /// the payload shape.
    static func certificate(from item: [String: Any], now: Date = Date()) -> [String: Any] {
        var cert: [String: Any] = [:]

        cert["commonName"] = string(item["common_name"]) ?? ""
        cert["subject"] = string(item["subject"]) ?? ""
        cert["issuer"] = string(item["issuer"]) ?? ""
        cert["serialNumber"] = string(item["serial"]) ?? ""
        cert["keyAlgorithm"] = string(item["key_algorithm"]) ?? ""
        cert["signingAlgorithm"] = string(item["signing_algorithm"]) ?? ""
        cert["keyLength"] = int(item["key_strength"]) ?? 0
        cert["isSelfSigned"] = bool(item["self_signed"]) ?? false

        if let isCA = bool(item["ca"]) {
            cert["isCA"] = isCA
        }
        if let keyUsage = string(item["key_usage"]), !keyUsage.isEmpty {
            cert["keyUsage"] = keyUsage
        }
        if let sha1 = normalizeSHA1(string(item["sha1"])) {
            cert["sha1"] = sha1
        }

        if let path = string(item["path"]), !path.isEmpty {
            cert["path"] = path
            cert["storeLocation"] = path.hasPrefix("/Users/") ? "User" : "System"
        }

        let formatter = ISO8601DateFormatter()
        if let notBefore = double(item["not_valid_before"]) {
            cert["notBefore"] = formatter.string(from: Date(timeIntervalSince1970: notBefore))
        }

        if let notAfterSeconds = double(item["not_valid_after"]) {
            let notAfter = Date(timeIntervalSince1970: notAfterSeconds)
            let soon = Calendar.current.date(byAdding: .day, value: expiringSoonDays, to: now) ?? now
            cert["notAfter"] = formatter.string(from: notAfter)
            cert["daysUntilExpiry"] = Calendar.current.dateComponents([.day], from: now, to: notAfter).day ?? 0
            cert["isExpired"] = notAfter < now
            cert["isExpiringSoon"] = notAfter >= now && notAfter <= soon
            cert["status"] = notAfter < now ? "Expired" : (notAfter <= soon ? "ExpiringSoon" : "Valid")
        } else {
            cert["status"] = "Unknown"
            cert["isExpired"] = false
            cert["isExpiringSoon"] = false
            cert["daysUntilExpiry"] = 0
        }

        return cert
    }

    // MARK: - Loose value parsing (osquery returns strings, the fallback returns JSON types)

    private static func string(_ value: Any?) -> String? {
        switch value {
        case let text as String: return text
        case let number as NSNumber: return number.stringValue
        default: return nil
        }
    }

    private static func double(_ value: Any?) -> Double? {
        switch value {
        case let text as String: return Double(text.trimmingCharacters(in: .whitespaces))
        case let number as NSNumber: return number.doubleValue
        default: return nil
        }
    }

    private static func int(_ value: Any?) -> Int? {
        double(value).map { Int($0) }
    }

    private static func bool(_ value: Any?) -> Bool? {
        switch value {
        case let flag as Bool: return flag
        case let number as NSNumber: return number.intValue != 0
        case let text as String:
            switch text.trimmingCharacters(in: .whitespaces).lowercased() {
            case "1", "true", "yes": return true
            case "0", "false", "no": return false
            default: return nil
            }
        default: return nil
        }
    }
}
