import XCTest
@testable import ReportMate

final class NetworkAddressInventoryTests: XCTestCase {
    func testDnsCorrelatedTunnelAddressIsSelectedWithoutReplacingRouteEvidence() {
        let summary = NetworkAddressInventory.summarize(
            localAddresses: ["192.168.1.157", "10.16.2.19"],
            hostnameAddresses: ["10.16.2.19"]
        )

        XCTAssertEqual(summary.managementAddress, "10.16.2.19")
        XCTAssertEqual(summary.localIpAddresses, ["10.16.2.19", "192.168.1.157"])
    }

    func testStaleDnsAnswerIsNotPromoted() {
        let summary = NetworkAddressInventory.summarize(
            localAddresses: ["192.168.1.157", "10.100.1.5"],
            hostnameAddresses: ["10.16.2.19"]
        )

        XCTAssertNil(summary.managementAddress)
        XCTAssertEqual(summary.hostnameAddresses, ["10.16.2.19"])
    }

    func testNormalizationRemovesUnusableAddressesAndIsDeterministic() {
        let result = NetworkAddressInventory.normalize([
            "fe80::1%en0", "127.0.0.1", "169.254.4.2", "10.16.2.19",
            "192.168.1.157", "10.16.2.19", "::1", "2001:db8::2", "not-an-address"
        ])

        XCTAssertEqual(result, ["10.16.2.19", "192.168.1.157", "2001:db8::2"])
    }

    func testIPv4IsPreferredWhenBothFamiliesMatch() {
        let summary = NetworkAddressInventory.summarize(
            localAddresses: ["2001:db8::2", "10.16.2.19"],
            hostnameAddresses: ["2001:db8::2", "10.16.2.19"]
        )

        XCTAssertEqual(summary.managementAddress, "10.16.2.19")
    }
}
