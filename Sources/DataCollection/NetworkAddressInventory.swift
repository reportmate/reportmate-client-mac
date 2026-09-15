import Darwin
import Foundation

struct NetworkAddressSummary: Equatable, Sendable {
    let localIpAddresses: [String]
    let hostnameAddresses: [String]
    let managementAddress: String?
}

/// Keeps default-route information separate from addresses advertised for the host.
/// A management candidate is promoted only when DNS and a current local interface agree.
enum NetworkAddressInventory {
    static func summarize(localAddresses: [String], hostnameAddresses: [String]) -> NetworkAddressSummary {
        let local = normalize(localAddresses)
        let resolved = normalize(hostnameAddresses)
        let localSet = Set(local)

        return NetworkAddressSummary(
            localIpAddresses: local,
            hostnameAddresses: resolved,
            managementAddress: resolved.first(where: localSet.contains)
        )
    }

    static func normalize(_ addresses: [String]) -> [String] {
        Array(Set(addresses.compactMap(canonicalUsableAddress))).sorted { left, right in
            let leftFamily = left.contains(":") ? 1 : 0
            let rightFamily = right.contains(":") ? 1 : 0
            return leftFamily == rightFamily ? left < right : leftFamily < rightFamily
        }
    }

    static func localInterfaceAddresses() -> [String] {
        var first: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&first) == 0, let first else { return [] }
        defer { freeifaddrs(first) }

        var addresses: [String] = []
        var current: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = current?.pointee {
            defer { current = entry.ifa_next }
            guard let address = entry.ifa_addr else { continue }
            let family = Int32(address.pointee.sa_family)
            guard family == AF_INET || family == AF_INET6 else { continue }
            guard entry.ifa_flags & UInt32(IFF_UP) != 0,
                  entry.ifa_flags & UInt32(IFF_LOOPBACK) == 0 else { continue }

            if let value = numericAddress(address) {
                addresses.append(value)
            }
        }
        return normalize(addresses)
    }

    static func resolve(hostnames: [String]) -> [String] {
        var addresses: [String] = []
        for hostname in Set(hostnames.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }) where !hostname.isEmpty {
            var result: UnsafeMutablePointer<addrinfo>?
            guard getaddrinfo(hostname, nil, nil, &result) == 0, let result else { continue }
            defer { freeaddrinfo(result) }

            var current: UnsafeMutablePointer<addrinfo>? = result
            while let entry = current?.pointee {
                defer { current = entry.ai_next }
                guard entry.ai_family == AF_INET || entry.ai_family == AF_INET6,
                      let address = entry.ai_addr,
                      let value = numericAddress(address) else { continue }
                addresses.append(value)
            }
        }
        return normalize(addresses)
    }

    private static func numericAddress(_ address: UnsafePointer<sockaddr>) -> String? {
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let length: socklen_t
        switch Int32(address.pointee.sa_family) {
        case AF_INET:
            length = socklen_t(MemoryLayout<sockaddr_in>.size)
        case AF_INET6:
            length = socklen_t(MemoryLayout<sockaddr_in6>.size)
        default:
            return nil
        }

        guard getnameinfo(address, length, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else {
            return nil
        }
        return String(cString: host)
    }

    private static func canonicalUsableAddress(_ rawValue: String) -> String? {
        let value = rawValue.split(separator: "%", maxSplits: 1).first.map(String.init) ?? rawValue

        let ipv4Parts = value.split(separator: ".", omittingEmptySubsequences: false)
        if ipv4Parts.count == 4,
           let octets = Optional(ipv4Parts.compactMap { UInt8($0) }),
           octets.count == 4 {
            guard octets[0] != 0,
                  octets[0] != 127,
                  !(octets[0] == 169 && octets[1] == 254),
                  octets[0] < 224 else { return nil }
            return octets.map(String.init).joined(separator: ".")
        }

        var ipv6 = in6_addr()
        guard inet_pton(AF_INET6, value, &ipv6) == 1 else { return nil }
        let bytes = withUnsafeBytes(of: &ipv6) { Array($0) }
        guard bytes.contains(where: { $0 != 0 }),
              bytes != [UInt8](repeating: 0, count: 15) + [1],
              !(bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80),
              !(bytes[0] == 0xfe && bytes[1] & 0xc0 == 0xc0),
              bytes[0] != 0xff else { return nil }

        var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &ipv6, &output, socklen_t(output.count)) != nil else { return nil }
        return String(cString: output)
    }
}
