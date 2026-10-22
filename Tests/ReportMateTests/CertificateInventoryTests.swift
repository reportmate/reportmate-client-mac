import XCTest
@testable import ReportMate

final class CertificateInventoryTests: XCTestCase {
    private let expiredHash = "1111111111111111111111111111111111111111"
    private let validHash = "2222222222222222222222222222222222222222"

    private var sampleFindIdentityOutput: String {
        """
        Policy: X.509 Basic
          Matching identities
          1) \(expiredHash) "SAMPLE Expired Identity" (CSSMERR_TP_CERT_EXPIRED)
          2) \(validHash) "SAMPLE Device Identity"
             2 identities found

          Valid identities only
          1) \(validHash) "SAMPLE Device Identity"
             1 valid identities found
        """
    }

    func testFindIdentityParsingIncludesExpiredIdentities() {
        let hashes = CertificateInventory.parseIdentityHashes(sampleFindIdentityOutput)
        XCTAssertEqual(hashes, [expiredHash, validHash])
    }

    func testFindIdentityWithNoIdentitiesIsAnEmptySet() {
        let output = """
        Policy: X.509 Basic
          Matching identities
             0 identities found

          Valid identities only
             0 valid identities found
        """
        XCTAssertEqual(CertificateInventory.parseIdentityHashes(output), [])
    }

    func testUnrecognisedOutputIsAFailureNotAnEmptySet() {
        XCTAssertNil(CertificateInventory.parseIdentityHashes(""))
        XCTAssertNil(CertificateInventory.parseIdentityHashes("security: SecKeychainOpen: The specified keychain could not be found."))
    }

    func testTwoDigitIndexesParse() {
        let output = """
        Policy: X.509 Basic
          Matching identities
         10) \(validHash) "SAMPLE"
             10 identities found
        """
        XCTAssertEqual(CertificateInventory.parseIdentityHashes(output), [validHash])
    }

    func testSHA1Normalisation() {
        XCTAssertEqual(CertificateInventory.normalizeSHA1("ab:cd" + String(repeating: "0", count: 36)), "ABCD" + String(repeating: "0", count: 36))
        XCTAssertNil(CertificateInventory.normalizeSHA1("not-a-hash"))
        XCTAssertNil(CertificateInventory.normalizeSHA1(nil))
    }

    func testOsqueryRowMapsClassificationFields() {
        let row: [String: Any] = [
            "common_name": "SAMPLE Device",
            "subject": "CN=SAMPLE Device",
            "issuer": "CN=SAMPLE Issuing CA",
            "ca": "0",
            "self_signed": "0",
            "not_valid_before": "1700000000",
            "not_valid_after": "1900000000",
            "key_strength": "2048",
            "key_usage": "Key Encipherment, Digital Signature",
            "serial": "01",
            "sha1": validHash.lowercased(),
            "path": "/Users/sample/Library/Keychains/login.keychain-db",
        ]
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let cert = CertificateInventory.certificate(from: row, now: now)

        XCTAssertEqual(cert["isCA"] as? Bool, false)
        XCTAssertEqual(cert["keyUsage"] as? String, "Key Encipherment, Digital Signature")
        XCTAssertEqual(cert["sha1"] as? String, validHash)
        XCTAssertEqual(cert["keyLength"] as? Int, 2048)
        XCTAssertEqual(cert["isSelfSigned"] as? Bool, false)
        XCTAssertEqual(cert["storeLocation"] as? String, "User")
        XCTAssertEqual(cert["status"] as? String, "Valid")
        XCTAssertEqual(cert["notAfter"] as? String, "2030-03-17T17:46:40Z")
        XCTAssertNil(cert["hasPrivateKey"])
    }

    func testCAFlagAndMissingFieldsAreOmittedRatherThanGuessed() {
        let ca = CertificateInventory.certificate(from: ["ca": "1", "path": "/Library/Keychains/System.keychain"])
        XCTAssertEqual(ca["isCA"] as? Bool, true)
        XCTAssertEqual(ca["storeLocation"] as? String, "System")

        let bare = CertificateInventory.certificate(from: ["common_name": "SAMPLE"])
        XCTAssertNil(bare["isCA"])
        XCTAssertNil(bare["keyUsage"])
        XCTAssertNil(bare["sha1"])
        XCTAssertEqual(bare["status"] as? String, "Unknown")
    }

    func testPrivateKeyFlagsOnlyForKeychainsThatWereLookedUp() {
        let login = "/Users/sample/Library/Keychains/login.keychain-db"
        let system = "/Library/Keychains/System.keychain"
        let certificates: [[String: Any]] = [
            ["path": login, "sha1": expiredHash],
            ["path": login, "sha1": "3333333333333333333333333333333333333333"],
            ["path": login],
            ["path": system, "sha1": validHash],
        ]

        let flagged = CertificateInventory.applyPrivateKeyFlags(
            to: certificates,
            identities: [login: [expiredHash, validHash]]
        )

        XCTAssertEqual(flagged[0]["hasPrivateKey"] as? Bool, true)
        XCTAssertEqual(flagged[1]["hasPrivateKey"] as? Bool, false)
        XCTAssertNil(flagged[2]["hasPrivateKey"], "no SHA-1 means nothing to match")
        XCTAssertNil(flagged[3]["hasPrivateKey"], "a failed lookup must not read as false")
    }

    func testKeychainPathsAreDistinct() {
        let paths = CertificateInventory.keychainPaths(of: [
            ["path": "/b"], ["path": "/a"], ["path": "/b"], ["path": ""], [:],
        ])
        XCTAssertEqual(paths, ["/a", "/b"])
    }
}
