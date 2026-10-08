import Foundation

/// A display identity decoded from a raw EDID and its extension blocks.
///
/// The IO registry keeps the EDID a sink presented on its transport node, and that
/// node survives in states where `system_profiler SPDisplaysDataType` lists nothing,
/// such as a desktop Mac sitting at the login window with no console user. The EDID
/// also carries the human-readable serial (the 0xFF descriptor) that the registry's
/// `ProductAttributes.SerialNumber` does not: that key is the 32-bit header serial.
struct EDIDDisplay: Equatable, Sendable {
    /// 16-bit EDID manufacturer id as lowercase hex without a prefix ("610", "10ac")
    let vendorId: String
    /// Three-letter PNP code decoded from the manufacturer id ("APP", "DEL")
    let manufacturerCode: String
    /// 16-bit product code as lowercase hex without a prefix
    let productId: String
    /// 32-bit serial from the EDID header; zero when the panel does not set one
    let headerSerial: UInt32
    /// Text of the 0xFF display serial descriptor, trimmed; nil when absent or unusable
    let serialNumber: String?
    /// Text of the 0xFC display name descriptor, trimmed; nil when absent
    let name: String?
    /// Largest timing the EDID describes ("5120 x 2880"); nil when it describes none
    let resolution: String?

    private static let header: [UInt8] = [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]

    /// Decode an EDID, or nil when the bytes are not one.
    init?(data: Data) {
        let bytes = [UInt8](data)
        guard bytes.count >= 128, Array(bytes[0..<8]) == EDIDDisplay.header else {
            return nil
        }

        let manufacturer = UInt16(bytes[8]) << 8 | UInt16(bytes[9])
        vendorId = String(manufacturer, radix: 16)
        manufacturerCode = String(
            [10, 5, 0].compactMap { shift -> Character? in
                let letter = (manufacturer >> UInt16(shift)) & 0x1F
                guard (1...26).contains(letter) else { return nil }
                return Character(UnicodeScalar(UInt8(letter) + 0x40))
            }
        )
        productId = String(UInt16(bytes[10]) | UInt16(bytes[11]) << 8, radix: 16)
        headerSerial = UInt32(bytes[12]) | UInt32(bytes[13]) << 8 | UInt32(bytes[14]) << 16 | UInt32(bytes[15]) << 24

        var serial: String?
        var displayName: String?
        var timings: [(width: Int, height: Int)] = []
        for offset in stride(from: 54, through: 108, by: 18) {
            let block = Array(bytes[offset..<offset + 18])
            if block[0] == 0 && block[1] == 0 {
                switch block[3] {
                case 0xFF: serial = EDIDDisplay.descriptorText(block)
                case 0xFC: displayName = EDIDDisplay.descriptorText(block)
                default: break
                }
            } else if let timing = EDIDDisplay.detailedTiming(block) {
                timings.append(timing)
            }
        }

        // The manufacture week and year bytes are deliberately not decoded. No single year
        // offset agrees with what system_profiler and Windows report for the same panels
        // (1980 is ten years early for some vendors, 1990 is years early for others), and a
        // wrong date is worse than none once it reaches inventory.

        // Extension blocks. Panels that describe themselves in DisplayID (Apple's among
        // them) keep their native timing there and put a lower one in the base block.
        let extensionCount = min(Int(bytes[126]), bytes.count / 128 - 1)
        if extensionCount > 0 {
            for index in 1...extensionCount {
                let block = Array(bytes[(index * 128)..<(index * 128 + 128)])
                switch block[0] {
                case 0x02:
                    timings += EDIDDisplay.ceaTimings(block)
                case 0x70:
                    timings += EDIDDisplay.displayIDTimings(block)
                default:
                    break
                }
            }
        }

        serialNumber = EDIDDisplay.usableSerial(serial)
        name = displayName
        resolution = timings.max { $0.width * $0.height < $1.width * $1.height }
            .map { "\($0.width) x \($0.height)" }
    }

    /// Key that ties this EDID to a `system_profiler` display row, which reports the
    /// same vendor id, product id and header serial as hex strings.
    var joinKey: String {
        EDIDDisplay.joinKey(vendorId: vendorId, productId: productId, headerSerial: String(headerSerial, radix: 16))
    }

    static func joinKey(vendorId: String, productId: String, headerSerial: String) -> String {
        [vendorId, productId, headerSerial]
            .map { value -> String in
                let lowered = value.lowercased()
                let bare = lowered.hasPrefix("0x") ? String(lowered.dropFirst(2)) : lowered
                let trimmed = bare.drop { $0 == "0" }
                return trimmed.isEmpty ? "0" : String(trimmed)
            }
            .joined(separator: ":")
    }

    /// A serial worth reporting: not empty and not a run of zeros, which panels and
    /// `system_profiler` both use to mean "no serial".
    static func usableSerial(_ value: String?) -> String? {
        guard let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines), !trimmed.isEmpty else {
            return nil
        }
        return trimmed.allSatisfy { $0 == "0" } ? nil : trimmed
    }

    /// Descriptor text is up to 13 bytes, terminated by a line feed and space padded.
    private static func descriptorText(_ block: [UInt8]) -> String? {
        let payload = block[5..<18].prefix { $0 != 0x0A }
        let text = String(decoding: payload.filter { $0 >= 0x20 && $0 < 0x7F }, as: UTF8.self)
            .trimmingCharacters(in: .whitespaces)
        return text.isEmpty ? nil : text
    }

    /// Active area of an 18-byte detailed timing descriptor.
    private static func detailedTiming(_ block: [UInt8]) -> (width: Int, height: Int)? {
        guard block.count >= 18, block[0] != 0 || block[1] != 0 else { return nil }
        let width = Int(block[2]) | Int(block[4] >> 4) << 8
        let height = Int(block[5]) | Int(block[7] >> 4) << 8
        return plausible(width, height)
    }

    /// Detailed timings in a CTA-861 extension, which start at the offset in byte 2.
    private static func ceaTimings(_ block: [UInt8]) -> [(width: Int, height: Int)] {
        let start = Int(block[2])
        guard start >= 4 else { return [] }
        return stride(from: start, through: 127 - 18, by: 18).compactMap { offset in
            detailedTiming(Array(block[offset..<offset + 18]))
        }
    }

    /// Timings from a DisplayID extension section. Data blocks follow a five-byte section
    /// header as tag, revision, payload length, payload.
    private static func displayIDTimings(_ block: [UInt8]) -> [(width: Int, height: Int)] {
        var timings: [(width: Int, height: Int)] = []
        let end = min(5 + Int(block[2]), block.count)
        var offset = 5
        while offset + 3 <= end {
            let tag = block[offset]
            let length = Int(block[offset + 2])
            let payloadStart = offset + 3
            guard tag != 0, payloadStart + length <= end else { break }
            let payload = Array(block[payloadStart..<payloadStart + length])

            switch tag {
            case 0x03, 0x22:
                // Type I and Type VII detailed timings: 20 bytes each, active pixels stored
                // minus one at bytes 4-5 (horizontal) and 12-13 (vertical).
                for descriptor in stride(from: 0, through: payload.count - 20, by: 20) {
                    let width = (Int(payload[descriptor + 4]) | Int(payload[descriptor + 5]) << 8) + 1
                    let height = (Int(payload[descriptor + 12]) | Int(payload[descriptor + 13]) << 8) + 1
                    if let timing = plausible(width, height) {
                        timings.append(timing)
                    }
                }
            default:
                break
            }
            offset = payloadStart + length
        }
        return timings
    }

    private static func plausible(_ width: Int, _ height: Int) -> (width: Int, height: Int)? {
        (320...16384).contains(width) && (200...16384).contains(height) ? (width, height) : nil
    }
}

/// A display found in the IO registry by the EDID on its transport node.
struct RegistryDisplay: Equatable, Sendable {
    let edid: EDIDDisplay
    /// Name the registry gives the sink, preferred over the EDID name descriptor
    let productName: String?
    /// Physical connection when the registry states one ("USB-C", "HDMI", "DisplayPort")
    let connectionType: String?
    /// True for a panel built into the machine rather than attached to a port
    let isBuiltIn: Bool
    /// Whether the transport reports the link active; nil when it does not say
    let isActive: Bool?

    var name: String {
        if let productName, !productName.isEmpty { return productName }
        return edid.name ?? "Unknown Display"
    }

    /// Walk `ioreg -a` output and collect every node carrying an EDID. `ioreg -r` prints
    /// a nested match again under its parent's subtree, so a node is counted once by its
    /// registry entry id. Two identical panels without header serials stay two displays.
    static func collect(from entries: [[String: Any]]) -> [RegistryDisplay] {
        var found: [RegistryDisplay] = []
        var seen: Set<String> = []
        for entry in entries {
            walk(entry, into: &found, seen: &seen)
        }
        return found
    }

    private static func walk(_ node: [String: Any], into found: inout [RegistryDisplay], seen: inout Set<String>) {
        let raw = (node["EDID"] as? Data) ?? (node["IODisplayEDID"] as? Data)
        if let raw, let edid = EDIDDisplay(data: raw) {
            let identity = (node["IORegistryEntryID"] as? Int).map(String.init) ?? "\(edid.joinKey)#\(found.count)"
            if !seen.contains(identity) {
                seen.insert(identity)
                found.append(RegistryDisplay(node: node, edid: edid))
            }
        }
        for child in node["IORegistryEntryChildren"] as? [[String: Any]] ?? [] {
            walk(child, into: &found, seen: &seen)
        }
    }

    private init(node: [String: Any], edid: EDIDDisplay) {
        self.edid = edid

        // Intel Macs name the sink in a localized dictionary; Apple Silicon transport
        // nodes carry a plain ProductName.
        if let plain = node["ProductName"] as? String {
            productName = plain.trimmingCharacters(in: .whitespaces)
        } else if let localized = node["DisplayProductName"] as? [String: String] {
            productName = (localized["en_US"] ?? localized.values.first)?.trimmingCharacters(in: .whitespaces)
        } else {
            productName = nil
        }

        let objectClass = node["IOObjectClass"] as? String ?? ""
        // A transport node hangs off a physical port; a built-in panel has none. On
        // Intel the built-in panel is the backlight-capable display class.
        isBuiltIn = objectClass == "AppleBacklightDisplay"
            || (objectClass.hasPrefix("IOPortTransportState") && node["ParentPortTypeDescription"] == nil)

        if let port = node["ParentPortTypeDescription"] as? String, !port.isEmpty {
            connectionType = port
        } else if let transport = node["TransportTypeDescription"] as? String, !transport.isEmpty {
            connectionType = transport
        } else {
            connectionType = nil
        }
        isActive = node["Active"] as? Bool
    }

    /// A display row built from the IO registry alone, in the shape system_profiler rows use.
    var displayInfo: [String: Any] {
        var info: [String: Any] = [
            "name": name,
            "type": isBuiltIn ? "internal" : "external",
            "resolution": edid.resolution ?? "Unknown",
            "vendor_id": edid.vendorId,
            "product_id": edid.productId,
            "is_main_display": false,
            "online": isActive ?? false,
            "data_source": "ioregistry",
        ]
        if let serial = edid.serialNumber {
            info["serial_number"] = serial
        }
        if !edid.manufacturerCode.isEmpty {
            info["manufacturer"] = edid.manufacturerCode
        }
        if let connectionType {
            info["connection_type"] = connectionType
        }
        return info
    }

    /// Fill external display rows from the EDID on the same connector. A row joins on the
    /// vendor id, product id and header serial system_profiler reports in hex (carried in
    /// `edid_header_serial`); failing that, on vendor and product id when exactly one row
    /// and one EDID share them. Never by name, which collapses identical panels onto one
    /// serial. Returns the serials it filled, by row index.
    @discardableResult
    static func enrich(_ displays: inout [[String: Any]], from registry: [RegistryDisplay]) -> [Int: String] {
        var filled: [Int: String] = [:]
        guard !registry.isEmpty else { return filled }

        func modelKey(_ vendorId: String, _ productId: String) -> String {
            EDIDDisplay.joinKey(vendorId: vendorId, productId: productId, headerSerial: "0")
        }
        let registryByKey = Dictionary(grouping: registry) { $0.edid.joinKey }
        let registryByModel = Dictionary(grouping: registry) { modelKey($0.edid.vendorId, $0.edid.productId) }
        let rowsByModel = Dictionary(grouping: displays.indices) { index -> String in
            modelKey(displays[index]["vendor_id"] as? String ?? "", displays[index]["product_id"] as? String ?? "")
        }

        for i in displays.indices where displays[i]["type"] as? String == "external" {
            guard let vendorId = displays[i]["vendor_id"] as? String,
                  let productId = displays[i]["product_id"] as? String else {
                continue
            }

            var match: RegistryDisplay?
            if let headerSerial = displays[i]["edid_header_serial"] as? String,
               let candidates = registryByKey[EDIDDisplay.joinKey(vendorId: vendorId, productId: productId, headerSerial: headerSerial)] {
                match = candidates.count == 1 ? candidates[0] : nil
            } else if let candidates = registryByModel[modelKey(vendorId, productId)], candidates.count == 1,
                      rowsByModel[modelKey(vendorId, productId)]?.count == 1 {
                match = candidates[0]
            }
            guard let edid = match?.edid else { continue }

            if displays[i]["serial_number"] == nil, let serial = edid.serialNumber {
                displays[i]["serial_number"] = serial
                filled[i] = serial
            }
            if displays[i]["manufacturer"] == nil, !edid.manufacturerCode.isEmpty {
                displays[i]["manufacturer"] = edid.manufacturerCode
            }
        }
        return filled
    }

    /// Vendor id system_profiler reports when macOS read no EDID at all: ASCII "unkn".
    static let unknownVendorId = "756e6b6e"
    /// Name a row gets when nothing on the machine can say what the display is.
    static let unidentifiedName = "Unidentified Display"

    /// system_profiler names a display with the literal localization key
    /// `spdisplays_display` when its EDID has no name descriptor. Not a name, and it reads
    /// as a monitor model downstream.
    static func hasUnresolvedName(_ row: [String: Any]) -> Bool {
        let name = (row["name"] as? String ?? "").trimmingCharacters(in: .whitespaces)
        return name.isEmpty || name == "spdisplays_display"
    }

    /// A row whose vendor id is real, rather than missing or `756e6b6e` (ASCII "unkn"),
    /// which system_profiler reports when macOS read no EDID at all: KVMs, adapters,
    /// virtual and AirPlay displays.
    static func hasEDID(_ row: [String: Any]) -> Bool {
        guard let vendorId = row["vendor_id"] as? String, !vendorId.isEmpty else { return false }
        let lowered = vendorId.lowercased()
        let bare = lowered.hasPrefix("0x") ? String(lowered.dropFirst(2)) : lowered
        return bare != unknownVendorId
    }

    /// External rows `resolveUnnamed` acts on: an unresolved name, or no EDID behind them.
    static func isUnresolved(_ row: [String: Any]) -> Bool {
        hasUnresolvedName(row) || !hasEDID(row)
    }

    /// Name unresolved external rows from the EDID on their connector, and mark the rest
    /// `unidentified` so consumers skip them by rule rather than by an unrecognised name.
    ///
    /// A row with a real vendor id joins as `enrich` does, on vendor, product and header
    /// serial or on a unique vendor and product. A row with no EDID has nothing to join
    /// on, so it takes the registry's one active, attached EDID that no other row claims,
    /// and only when it is the only external row without an EDID: two such rows and two
    /// spare EDIDs could pair either way. A row with no EDID that system_profiler did name
    /// (an AirPlay target, say) keeps that name and adopts nothing; it is only flagged.
    /// Returns the names it recovered, by row index.
    @discardableResult
    static func resolveUnnamed(_ displays: inout [[String: Any]], from registry: [RegistryDisplay]) -> [Int: String] {
        var resolved: [Int: String] = [:]
        let external = displays.indices.filter { displays[$0]["type"] as? String == "external" }
        let unresolved = external.filter { isUnresolved(displays[$0]) }
        guard !unresolved.isEmpty else { return resolved }

        func modelKey(_ vendorId: String, _ productId: String) -> String {
            EDIDDisplay.joinKey(vendorId: vendorId, productId: productId, headerSerial: "0")
        }

        let attached = registry.filter { !$0.isBuiltIn }
        let registryByKey = Dictionary(grouping: attached) { $0.edid.joinKey }
        let registryByModel = Dictionary(grouping: attached) { modelKey($0.edid.vendorId, $0.edid.productId) }
        let rowsByModel = Dictionary(grouping: displays.indices.filter { hasEDID(displays[$0]) }) { index -> String in
            modelKey(displays[index]["vendor_id"] as? String ?? "", displays[index]["product_id"] as? String ?? "")
        }

        // Every attached EDID whose model some row with a real vendor id already reports
        // is spoken for, matched or not. An EDID on a link the registry reports inactive
        // (a monitor switched off or on another input) is not the display in the session.
        let claimedModels = Set(rowsByModel.keys)
        let spare = attached.filter {
            $0.isActive != false && !claimedModels.contains(modelKey($0.edid.vendorId, $0.edid.productId))
        }
        let withoutEDID = external.filter { !hasEDID(displays[$0]) }
        func nameOf(_ display: RegistryDisplay) -> String? {
            if let productName = display.productName, !productName.isEmpty { return productName }
            return display.edid.name
        }

        for i in unresolved {
            var match: RegistryDisplay?
            if hasEDID(displays[i]) {
                let vendorId = displays[i]["vendor_id"] as? String ?? ""
                let productId = displays[i]["product_id"] as? String ?? ""
                if let headerSerial = displays[i]["edid_header_serial"] as? String,
                   let candidates = registryByKey[EDIDDisplay.joinKey(vendorId: vendorId, productId: productId, headerSerial: headerSerial)] {
                    match = candidates.count == 1 ? candidates[0] : nil
                } else if let candidates = registryByModel[modelKey(vendorId, productId)], candidates.count == 1,
                          rowsByModel[modelKey(vendorId, productId)]?.count == 1 {
                    match = candidates[0]
                }
            } else if !hasUnresolvedName(displays[i]) {
                displays[i]["unidentified"] = true
                continue
            } else if withoutEDID.count == 1, spare.count == 1, nameOf(spare[0]) != nil {
                // Adopt the EDID's identity only when it also names the display: a row
                // flagged unidentified never carries another display's serial.
                match = spare[0]
                let edid = spare[0].edid
                displays[i]["vendor_id"] = edid.vendorId
                displays[i]["product_id"] = edid.productId
                if displays[i]["serial_number"] == nil, let serial = edid.serialNumber {
                    displays[i]["serial_number"] = serial
                }
                if displays[i]["manufacturer"] == nil, !edid.manufacturerCode.isEmpty {
                    displays[i]["manufacturer"] = edid.manufacturerCode
                }
                if displays[i]["connection_type"] == nil, let connectionType = spare[0].connectionType {
                    displays[i]["connection_type"] = connectionType
                }
            }

            if let recovered = match.flatMap(nameOf) {
                displays[i]["name"] = recovered
                displays[i]["unidentified"] = false
                resolved[i] = recovered
            } else {
                displays[i]["name"] = unidentifiedName
                displays[i]["unidentified"] = true
            }
        }
        return resolved
    }
}
