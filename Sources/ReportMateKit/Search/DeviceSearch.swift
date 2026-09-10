import Foundation

/// Fuzzy device matching, ported from the web app's search field so the same
/// query ranks the same device first in both apps.
public enum DeviceSearch {
    static func normalize(_ value: String?) -> String {
        guard let value else { return "" }
        let lowered = value.lowercased()
        var out = ""
        var lastWasSpace = false
        for ch in lowered {
            if ch.isLetter || ch.isNumber {
                out.append(ch)
                lastWasSpace = false
            } else if !lastWasSpace {
                out.append(" ")
                lastWasSpace = true
            }
        }
        return out.trimmingCharacters(in: .whitespaces)
    }

    static func editDistance(_ a: String, _ b: String) -> Int {
        if a == b { return 0 }
        if a.isEmpty { return b.count }
        if b.isEmpty { return a.count }
        let a = Array(a), b = Array(b)
        var prev = Array(0...b.count)
        var cur = [Int](repeating: 0, count: b.count + 1)
        for i in 1...a.count {
            cur[0] = i
            for j in 1...b.count {
                let cost = a[i - 1] == b[j - 1] ? 0 : 1
                cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            }
            swap(&prev, &cur)
        }
        return prev[b.count]
    }

    static func score(token: String, against target: String) -> Int {
        if token.isEmpty || target.isEmpty { return 0 }
        var best = 0
        for word in target.split(separator: " ") {
            let w = String(word)
            if w.contains(token) { return 4 }
            let distance = editDistance(token, w)
            if distance <= 1 { best = max(best, 3); continue }
            if token.count >= 6, distance <= 2 { best = max(best, 2) }
        }
        if best > 0 { return best }
        // Subsequence match.
        var index = token.startIndex
        for ch in target {
            if ch == token[index] {
                index = token.index(after: index)
                if index == token.endIndex { return 1 }
            }
        }
        return 0
    }

    public static func matchScore(device: DeviceSummary, query: String) -> Int {
        let normalizedQuery = normalize(query)
        guard !normalizedQuery.isEmpty else { return 0 }
        let tokens = normalizedQuery.split(separator: " ").map(String.init)
        let targets = [
            normalize(device.name), normalize(device.serialNumber), normalize(device.inventory.assetTag),
            normalize(device.hostname), normalize(device.inventory.location),
        ].filter { !$0.isEmpty }
        var total = 0
        for token in tokens {
            var best = 0
            for t in targets { best = max(best, score(token: token, against: t)) }
            if best == 0 { return 0 }
            total += best
        }
        return total
    }

    /// Top matches, best first.
    public static func search(_ devices: [DeviceSummary], query: String, limit: Int = 8) -> [DeviceSummary] {
        let trimmed = query.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return [] }
        return devices
            .map { ($0, matchScore(device: $0, query: trimmed)) }
            .filter { $0.1 > 0 }
            .sorted { $0.1 > $1.1 }
            .prefix(limit)
            .map(\.0)
    }

    /// Resolve an identifier typed or pasted by the operator to a serial:
    /// exact serial, device id, asset tag, then names.
    public static func resolve(_ identifier: String, in devices: [DeviceSummary]) -> DeviceSummary? {
        let id = identifier.trimmingCharacters(in: .whitespaces)
        guard !id.isEmpty else { return nil }
        if let d = devices.first(where: { $0.serialNumber == id }) { return d }
        if let d = devices.first(where: { $0.deviceId == id }) { return d }
        if let d = devices.first(where: { $0.inventory.assetTag == id }) { return d }
        if let d = devices.first(where: { $0.name == id || $0.inventory.deviceName == id }) { return d }
        let upper = id.uppercased()
        if let d = devices.first(where: { $0.serialNumber.uppercased() == upper || $0.inventory.assetTag?.uppercased() == upper || $0.name.uppercased() == upper }) { return d }
        return nil
    }
}
