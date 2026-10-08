import Foundation

/// Projects the hardware module's display list into the peripherals `displayDevices` array.
///
/// The Windows client sends only attached monitors there (its `ExternalMonitor` rows), so a
/// built-in panel stays in `hardware.displays` and is left out here. Keys carry the Windows
/// names (`serialNumber`, `manufacturer`, `model`, `connectionType`, `isExternal`) plus the
/// ones the web Peripherals reader maps (`name`, `type`, `status`, `resolution`, `primary`).
enum PeripheralDisplays {
    /// EDID PNP code and USB vendor id Apple displays report.
    private static let appleCodes: Set<String> = ["APP", "610"]

    static func displayDevices(from displays: [[String: Any]]) -> [[String: Any]] {
        displays.compactMap { display -> [String: Any]? in
            guard display["type"] as? String == "external" else { return nil }

            let name = display["name"] as? String ?? "Unknown Display"
            let online = display["online"] as? Bool ?? false
            let mirrored = display["mirror"] as? Bool ?? false

            var device: [String: Any] = [
                "name": name,
                "model": name,
                "type": "monitor",
                "status": online ? (mirrored ? "mirrored" : "active") : "inactive",
                "primary": display["is_main_display"] as? Bool ?? false,
                "isExternal": true,
            ]
            if let resolution = display["resolution"] as? String, resolution != "Unknown" {
                device["resolution"] = resolution
            }
            if let manufacturer = manufacturer(of: display) {
                device["manufacturer"] = manufacturer
            }
            if let serial = display["serial_number"] as? String, !serial.isEmpty {
                device["serialNumber"] = serial
            }
            if let connection = display["connection_type"] as? String, !connection.isEmpty {
                device["connectionType"] = connection
            }
            if let vendorId = display["vendor_id"] as? String, !vendorId.isEmpty {
                device["vendorId"] = vendorId
            }
            if let productId = display["product_id"] as? String, !productId.isEmpty {
                device["productId"] = productId
            }
            return device
        }
    }

    /// The EDID manufacturer code, with Apple's spelled out; Apple displays listed by
    /// system_profiler carry only the vendor id.
    private static func manufacturer(of display: [String: Any]) -> String? {
        let code = (display["manufacturer"] as? String)?.trimmingCharacters(in: .whitespaces) ?? ""
        let rawVendor = (display["vendor_id"] as? String)?.lowercased() ?? ""
        let vendorId = String((rawVendor.hasPrefix("0x") ? rawVendor.dropFirst(2) : Substring(rawVendor)).drop { $0 == "0" })
        if appleCodes.contains(code.uppercased()) || appleCodes.contains(vendorId) {
            return "Apple"
        }
        return code.isEmpty ? nil : code
    }
}
