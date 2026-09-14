import Foundation
import XCTest
@testable import ReportMate

final class EDIDDisplayTests: XCTestCase {
    /// Build an EDID base block by hand: manufacturer "WAC", product 0x037f, header
    /// serial 0x01020304, week 12 of 2021, a 3840 x 2160 preferred timing, then
    /// whichever text descriptors the test supplies.
    private func edid(serial: String? = "ABC1234567", name: String? = "Cintiq Pro 24", headerSerial: UInt32 = 0x0102_0304, week: UInt8 = 12) -> Data {
        var bytes = [UInt8](repeating: 0, count: 128)
        bytes[0..<8] = [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]
        bytes[8] = 0x5C
        bytes[9] = 0x23
        bytes[10] = 0x7F
        bytes[11] = 0x03
        bytes[12] = UInt8(headerSerial & 0xFF)
        bytes[13] = UInt8(headerSerial >> 8 & 0xFF)
        bytes[14] = UInt8(headerSerial >> 16 & 0xFF)
        bytes[15] = UInt8(headerSerial >> 24 & 0xFF)
        bytes[16] = week
        bytes[17] = 41

        bytes[54] = 0x04
        bytes[55] = 0x74
        bytes[56] = 0x00
        bytes[57] = 0x70
        bytes[58] = 0xF0
        bytes[59] = 0x70
        bytes[61] = 0x80

        func text(_ value: String, tag: UInt8, at offset: Int) {
            bytes[offset + 3] = tag
            var payload = Array(value.utf8.prefix(13))
            if payload.count < 13 {
                payload.append(0x0A)
                payload += [UInt8](repeating: 0x20, count: 13 - payload.count)
            }
            bytes[(offset + 5)..<(offset + 18)] = payload[0..<13]
        }
        if let serial { text(serial, tag: 0xFF, at: 72) }
        if let name { text(name, tag: 0xFC, at: 90) }
        return Data(bytes)
    }

    func testDecodesIdentityFields() throws {
        let display = try XCTUnwrap(EDIDDisplay(data: edid()))
        XCTAssertEqual(display.vendorId, "5c23")
        XCTAssertEqual(display.manufacturerCode, "WAC")
        XCTAssertEqual(display.productId, "37f")
        XCTAssertEqual(display.headerSerial, 0x0102_0304)
        XCTAssertEqual(display.serialNumber, "ABC1234567")
        XCTAssertEqual(display.name, "Cintiq Pro 24")
        XCTAssertEqual(display.manufactureWeek, 12)
        XCTAssertEqual(display.manufactureYear, 2021)
        XCTAssertEqual(display.resolution, "3840 x 2160")
    }

    func testFullLengthSerialHasNoTerminator() throws {
        let display = try XCTUnwrap(EDIDDisplay(data: edid(serial: "ABCDEFGHJKLMN")))
        XCTAssertEqual(display.serialNumber, "ABCDEFGHJKLMN")
    }

    func testMissingOrZeroSerialIsNil() throws {
        XCTAssertNil(try XCTUnwrap(EDIDDisplay(data: edid(serial: nil))).serialNumber)
        XCTAssertNil(try XCTUnwrap(EDIDDisplay(data: edid(serial: "0"))).serialNumber)
        XCTAssertNil(EDIDDisplay.usableSerial("0000000"))
        XCTAssertNil(EDIDDisplay.usableSerial("  "))
        XCTAssertEqual(EDIDDisplay.usableSerial(" A1 "), "A1")
    }

    func testModelYearWeekIsNotAWeek() throws {
        let display = try XCTUnwrap(EDIDDisplay(data: edid(week: 0xFF)))
        XCTAssertNil(display.manufactureWeek)
        XCTAssertEqual(display.manufactureYear, 2021)
    }

    func testAppleEDIDReportsNoManufactureDate() throws {
        var bytes = [UInt8](edid(serial: nil, name: "Studio Display"))
        bytes[8] = 0x06
        bytes[9] = 0x10
        let display = try XCTUnwrap(EDIDDisplay(data: Data(bytes)))
        XCTAssertEqual(display.vendorId, "610")
        XCTAssertEqual(display.manufacturerCode, "APP")
        XCTAssertNil(display.manufactureYear)
        XCTAssertNil(display.manufactureWeek)
    }

    func testRejectsNonEDID() {
        XCTAssertNil(EDIDDisplay(data: Data(repeating: 0, count: 128)))
        XCTAssertNil(EDIDDisplay(data: edid().prefix(100)))
    }

    func testJoinKeyMatchesSystemProfilerHex() throws {
        let display = try XCTUnwrap(EDIDDisplay(data: edid()))
        XCTAssertEqual(display.joinKey, EDIDDisplay.joinKey(vendorId: "5c23", productId: "037f", headerSerial: "01020304"))
        XCTAssertEqual(display.joinKey, EDIDDisplay.joinKey(vendorId: "0x5C23", productId: "37F", headerSerial: "0x1020304"))
    }

    func testRegistryWalkFindsNestedTransportOnce() {
        let transport: [String: Any] = [
            "IOObjectClass": "IOPortTransportStateDisplayPort",
            "IORegistryEntryID": 42,
            "ParentPortTypeDescription": "USB-C",
            "ProductName": "Cintiq Pro 24",
            "Active": true,
            "EDID": edid(),
        ]
        let tunnel: [String: Any] = [
            "IOObjectClass": "IOPortTransportStateCIO",
            "IORegistryEntryID": 41,
            "IORegistryEntryChildren": [transport],
        ]

        let displays = RegistryDisplay.collect(from: [tunnel, transport])
        XCTAssertEqual(displays.count, 1)
        XCTAssertEqual(displays.first?.name, "Cintiq Pro 24")
        XCTAssertEqual(displays.first?.connectionType, "USB-C")
        XCTAssertEqual(displays.first?.isBuiltIn, false)
        XCTAssertEqual(displays.first?.isActive, true)
    }

    func testIdenticalPanelsWithoutHeaderSerialStaySeparate() {
        let first: [String: Any] = ["IOObjectClass": "IOPortTransportStateDisplayPort", "IORegistryEntryID": 1, "ParentPortTypeDescription": "USB-C", "EDID": edid(serial: "UNIT0001", headerSerial: 0)]
        let second: [String: Any] = ["IOObjectClass": "IOPortTransportStateDisplayPort", "IORegistryEntryID": 2, "ParentPortTypeDescription": "HDMI", "EDID": edid(serial: "UNIT0002", headerSerial: 0)]

        let displays = RegistryDisplay.collect(from: [first, second])
        XCTAssertEqual(displays.map(\.edid.serialNumber), ["UNIT0001", "UNIT0002"])
    }

    /// Append a DisplayID extension carrying a product identification block (week 7 of
    /// 2025) and one Type VII timing of 6016 x 3384, and point the base block at it.
    private func withDisplayID(_ base: Data) -> Data {
        var bytes = [UInt8](base)
        bytes[126] = 1
        var ext = [UInt8](repeating: 0, count: 128)
        ext[0] = 0x70
        ext[1] = 0x20
        var blocks: [UInt8] = []
        blocks += [0x20, 0x00, 11, 0x00, 0x10, 0xFA, 0x34, 0x12, 0, 0, 0, 0, 7, 25]
        var timing = [UInt8](repeating: 0, count: 20)
        timing[4] = UInt8((6016 - 1) & 0xFF)
        timing[5] = UInt8((6016 - 1) >> 8)
        timing[12] = UInt8((3384 - 1) & 0xFF)
        timing[13] = UInt8((3384 - 1) >> 8)
        blocks += [0x22, 0x00, 20] + timing
        ext[2] = UInt8(blocks.count)
        ext[5..<(5 + blocks.count)] = blocks[...]
        return Data(bytes + ext)
    }

    func testDisplayIDOverridesBaseBlockDateAndResolution() throws {
        let display = try XCTUnwrap(EDIDDisplay(data: withDisplayID(edid())))
        XCTAssertEqual(display.manufactureYear, 2025)
        XCTAssertEqual(display.manufactureWeek, 7)
        XCTAssertEqual(display.resolution, "6016 x 3384")
        XCTAssertEqual(display.serialNumber, "ABC1234567")
    }

    private func transport(id: Int, serial: String?, headerSerial: UInt32 = 0x0102_0304) -> [String: Any] {
        ["IOObjectClass": "IOPortTransportStateDisplayPort", "IORegistryEntryID": id, "ParentPortTypeDescription": "USB-C", "EDID": edid(serial: serial, headerSerial: headerSerial)]
    }

    func testEnrichJoinsOnHeaderSerialNotName() {
        let registry = RegistryDisplay.collect(from: [transport(id: 1, serial: "UNIT0001", headerSerial: 0x11), transport(id: 2, serial: "UNIT0002", headerSerial: 0x22)])
        var rows: [[String: Any]] = [
            ["name": "Cintiq Pro 24", "type": "external", "vendor_id": "5c23", "product_id": "37f", "edid_header_serial": "22"],
            ["name": "Cintiq Pro 24", "type": "external", "vendor_id": "5c23", "product_id": "37f", "edid_header_serial": "11"],
        ]
        let filled = RegistryDisplay.enrich(&rows, from: registry)
        XCTAssertEqual(filled, [0: "UNIT0002", 1: "UNIT0001"])
        XCTAssertEqual(rows[0]["manufacturer"] as? String, "WAC")
        XCTAssertEqual(rows[0]["manufacture_year"] as? Int, 2021)
    }

    func testEnrichLeavesAmbiguousAndExistingSerialsAlone() {
        let registry = RegistryDisplay.collect(from: [transport(id: 1, serial: "UNIT0001", headerSerial: 0), transport(id: 2, serial: "UNIT0002", headerSerial: 0)])
        var rows: [[String: Any]] = [
            ["name": "Cintiq Pro 24", "type": "external", "vendor_id": "5c23", "product_id": "37f", "edid_header_serial": "0"],
            ["name": "Cintiq Pro 24", "type": "external", "vendor_id": "5c23", "product_id": "37f", "serial_number": "KEPT0001"],
            ["name": "Built-in", "type": "internal", "vendor_id": "5c23", "product_id": "37f"],
        ]
        XCTAssertTrue(RegistryDisplay.enrich(&rows, from: registry).isEmpty)
        XCTAssertNil(rows[0]["serial_number"])
        XCTAssertEqual(rows[1]["serial_number"] as? String, "KEPT0001")
        XCTAssertNil(rows[2]["serial_number"])
    }

    func testRegistryRowShape() throws {
        let display = try XCTUnwrap(RegistryDisplay.collect(from: [transport(id: 1, serial: nil)]).first)
        let row = display.displayInfo
        XCTAssertEqual(row["type"] as? String, "external")
        XCTAssertEqual(row["vendor_id"] as? String, "5c23")
        XCTAssertEqual(row["product_id"] as? String, "37f")
        XCTAssertEqual(row["connection_type"] as? String, "USB-C")
        XCTAssertEqual(row["data_source"] as? String, "ioregistry")
        XCTAssertNil(row["serial_number"])
    }

    func testIntelBacklightDisplayIsBuiltIn() {
        let panel: [String: Any] = [
            "IOObjectClass": "AppleBacklightDisplay",
            "DisplayProductName": ["en_US": "Color LCD"],
            "IODisplayEDID": edid(serial: nil, name: nil),
        ]
        let displays = RegistryDisplay.collect(from: [["IOObjectClass": "IODisplayConnect", "IORegistryEntryChildren": [panel]]])
        XCTAssertEqual(displays.first?.isBuiltIn, true)
        XCTAssertEqual(displays.first?.name, "Color LCD")
    }
}
