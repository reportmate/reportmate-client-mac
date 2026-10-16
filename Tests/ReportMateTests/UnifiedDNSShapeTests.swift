import XCTest
@testable import ReportMate

final class UnifiedDNSShapeTests: XCTestCase {
    func testUnifiedDNSUsesWindowsKeys() {
        let dns = NetworkModuleProcessor.unifiedDNS(
            nameservers: ["10.0.0.1", "1.1.1.1"],
            searchDomains: ["example.org"],
            domain: "example.org"
        )

        XCTAssertEqual(Set(dns.keys), ["servers", "domain", "searchDomains"])
        XCTAssertEqual(dns["servers"] as? [String], ["10.0.0.1", "1.1.1.1"])
        XCTAssertEqual(dns["searchDomains"] as? [String], ["example.org"])
        XCTAssertEqual(dns["domain"] as? String, "example.org")
    }

    func testMissingDomainSerializesAsEmptyString() throws {
        let dns = NetworkModuleProcessor.unifiedDNS(nameservers: [], searchDomains: [], domain: nil)

        XCTAssertEqual(dns["domain"] as? String, "")
        let data = try JSONSerialization.data(withJSONObject: dns, options: [.sortedKeys])
        XCTAssertEqual(String(data: data, encoding: .utf8), #"{"domain":"","searchDomains":[],"servers":[]}"#)
    }
}
