import Foundation
import XCTest
@testable import ReportMate

final class PeripheralDisplaysTests: XCTestCase {
    private let builtIn: [String: Any] = [
        "name": "Built-in Liquid Retina XDR Display",
        "type": "internal",
        "resolution": "3456 x 2234",
        "is_main_display": true,
        "online": true,
        "data_source": "model_lookup",
    ]

    func testLeavesOutTheBuiltInPanel() {
        XCTAssertTrue(PeripheralDisplays.displayDevices(from: [builtIn]).isEmpty)
    }

    func testProjectsAnExternalMonitorInTheWindowsShape() {
        let dell: [String: Any] = [
            "name": "DELL U2720Q",
            "type": "external",
            "resolution": "3840 x 2160",
            "serial_number": "ABC1234",
            "manufacturer": "DEL",
            "vendor_id": "10ac",
            "product_id": "d0e1",
            "connection_type": "DisplayPort",
            "is_main_display": true,
            "online": true,
            "mirror": false,
        ]

        let devices = PeripheralDisplays.displayDevices(from: [builtIn, dell])

        XCTAssertEqual(devices.count, 1)
        let device = devices[0]
        XCTAssertEqual(device["name"] as? String, "DELL U2720Q")
        XCTAssertEqual(device["model"] as? String, "DELL U2720Q")
        XCTAssertEqual(device["manufacturer"] as? String, "DEL")
        XCTAssertEqual(device["serialNumber"] as? String, "ABC1234")
        XCTAssertEqual(device["resolution"] as? String, "3840 x 2160")
        XCTAssertEqual(device["type"] as? String, "monitor")
        XCTAssertEqual(device["status"] as? String, "active")
        XCTAssertEqual(device["connectionType"] as? String, "DisplayPort")
        XCTAssertEqual(device["primary"] as? Bool, true)
        XCTAssertEqual(device["isExternal"] as? Bool, true)
    }

    func testNamesAppleFromTheVendorIdAndOmitsUnknowns() {
        let studio: [String: Any] = [
            "name": "Studio Display",
            "type": "external",
            "resolution": "Unknown",
            "vendor_id": "0x0610",
            "online": false,
        ]

        let device = PeripheralDisplays.displayDevices(from: [studio])[0]

        XCTAssertEqual(device["manufacturer"] as? String, "Apple")
        XCTAssertEqual(device["status"] as? String, "inactive")
        XCTAssertEqual(device["primary"] as? Bool, false)
        XCTAssertNil(device["resolution"])
        XCTAssertNil(device["serialNumber"])
    }

    func testMarksAMirroredDisplay() {
        let projector: [String: Any] = ["name": "EPSON PJ", "type": "external", "online": true, "mirror": true]
        XCTAssertEqual(PeripheralDisplays.displayDevices(from: [projector])[0]["status"] as? String, "mirrored")
    }
}
