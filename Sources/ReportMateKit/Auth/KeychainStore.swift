import Foundation
import Security

/// Generic-password Keychain storage for the app's API credentials.
public struct KeychainStore: Sendable {
    public static let defaultService = "com.github.reportmate.mac"

    public let service: String

    public init(service: String = KeychainStore.defaultService) {
        self.service = service
    }

    public enum Key: String, CaseIterable, Sendable {
        case apiBaseURL = "ApiBaseUrl"
        case apiKey = "ApiKey"
        case passphrase = "Passphrase"
        case oidcAudience = "OidcAudience"
        case authMethod = "AuthMethod"
    }

    public func get(_ key: Key) -> String? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: key.rawValue,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    public func set(_ value: String?, for key: Key) throws {
        guard let value, !value.isEmpty else {
            try delete(key)
            return
        }
        let data = Data(value.utf8)
        let base: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: key.rawValue,
        ]
        let update: [CFString: Any] = [kSecValueData: data]
        let status = SecItemUpdate(base as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            var add = base
            add[kSecValueData] = data
            let addStatus = SecItemAdd(add as CFDictionary, nil)
            guard addStatus == errSecSuccess else { throw KeychainError.saveFailed(status: addStatus, key: key.rawValue) }
        } else if status != errSecSuccess {
            throw KeychainError.saveFailed(status: status, key: key.rawValue)
        }
    }

    public func delete(_ key: Key) throws {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: key.rawValue,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.deleteFailed(status: status, key: key.rawValue)
        }
    }

    public func clearAll() {
        for key in Key.allCases { try? delete(key) }
    }
}

public enum KeychainError: LocalizedError {
    case saveFailed(status: OSStatus, key: String)
    case deleteFailed(status: OSStatus, key: String)

    public var errorDescription: String? {
        switch self {
        case .saveFailed(let status, let key): return "Could not save \(key) to the Keychain (OSStatus \(status))."
        case .deleteFailed(let status, let key): return "Could not remove \(key) from the Keychain (OSStatus \(status))."
        }
    }
}
