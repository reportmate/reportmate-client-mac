import Foundation

/// Peripherals module reader. Port of the shape handling in `PeripheralsTab.tsx`:
/// the Windows flat input list regrouped into the Mac nested shape, audio split
/// into outputs and microphones, Bluetooth pruned to real peripherals.
public struct PeripheralsInfo: Sendable, Hashable {
    public struct USBDevice: Sendable, Hashable, Identifiable {
        public var id: String { name + (serialNumber ?? "") + (locationId ?? "") + String(index) }
        public var index: Int
        public var name: String
        public var vendor: String?
        public var vendorId: String?
        public var productId: String?
        public var serialNumber: String?
        public var speed: String?
        public var linkSpeed: String?
        public var locationId: String?
        public var powerAllocated: String?
        public var usbVersion: String?
        public var isRemovable: Bool?
        public var deviceType: String?
        public var connectionType: String?
        init(index: Int, json d: JSONValue) {
            self.index = index
            name = d["name"].nonEmptyString ?? d["model"].nonEmptyString ?? "Unknown USB Device"
            vendor = d["vendor"].nonEmptyString
            vendorId = d["vendorId"].nonEmptyString
            productId = d["productId"].nonEmptyString ?? d["modelId"].nonEmptyString
            serialNumber = d["serialNumber"].nonEmptyString
            speed = d["speed"].nonEmptyString
            linkSpeed = d["linkSpeed"].nonEmptyString
            locationId = d["locationId"].nonEmptyString
            powerAllocated = d["powerAllocated"].nonEmptyString
            usbVersion = d["usbVersion"].nonEmptyString
            isRemovable = d["isRemovable"].boolishIfPresent
            deviceType = d["deviceType"].nonEmptyString
            connectionType = d["connectionType"].nonEmptyString
        }
    }

    public struct InputDevice: Sendable, Hashable, Identifiable {
        public var id: String { name + (serialNumber ?? "") + (connectionType ?? "") + String(index) }
        public var index: Int
        public var name: String
        public var vendor: String?
        public var vendorId: String?
        public var productId: String?
        public var serialNumber: String?
        public var isBuiltIn: Bool?
        public var connectionType: String?
        public var deviceType: String?
        public var supportsForceTouch: Bool?
        public var tabletType: String?
        init(index: Int, json d: JSONValue) {
            self.index = index
            name = d["name"].nonEmptyString ?? ""
            vendor = d["vendor"].nonEmptyString
            vendorId = d["vendorId"].nonEmptyString
            productId = d["productId"].nonEmptyString ?? d["modelId"].nonEmptyString
            serialNumber = d["serialNumber"].nonEmptyString
            isBuiltIn = d["isBuiltIn"].boolishIfPresent
            connectionType = d["connectionType"].nonEmptyString
            deviceType = d["deviceType"].nonEmptyString
            supportsForceTouch = d["supportsForcTouch"].boolishIfPresent ?? d["supportsForceTouch"].boolishIfPresent
            tabletType = d["tabletType"].nonEmptyString
        }
        static func bluetoothKeyboard(_ b: BluetoothDevice) -> InputDevice {
            var d = InputDevice(index: 10_000 + b.index, json: ["name": .string(b.name)])
            d.isBuiltIn = false
            d.connectionType = "Bluetooth"
            d.deviceType = "Keyboard"
            return d
        }
    }

    public struct AudioDevice: Sendable, Hashable, Identifiable {
        public var id: String { name + (type ?? "") + String(index) }
        public var index: Int
        public var name: String
        public var manufacturer: String?
        public var type: String?
        public var isDefault: Bool
        public var isInput: Bool
        public var isOutput: Bool
        public var isBuiltIn: Bool?
        public var connectionType: String?
        init(index: Int, json d: JSONValue) {
            self.index = index
            name = d["name"].nonEmptyString ?? ""
            manufacturer = d["manufacturer"].nonEmptyString
            type = d["type"].nonEmptyString
            isDefault = d["isDefault"].boolish
            isInput = d["isInput"].boolish
            isOutput = d["isOutput"].boolish
            isBuiltIn = d["isBuiltIn"].boolishIfPresent
            connectionType = d["connectionType"].nonEmptyString
        }
    }

    public struct BluetoothDevice: Sendable, Hashable, Identifiable {
        public var id: String { name + (address ?? "") + String(index) }
        public var index: Int
        public var name: String
        public var address: String?
        public var isConnected: Bool
        public var isPaired: Bool
        public var deviceType: String?
        public var deviceCategory: String?
        public var batteryLevel: Int?
        init(index: Int, json d: JSONValue) {
            self.index = index
            name = d["name"].nonEmptyString ?? ""
            address = d["address"].nonEmptyString
            isConnected = d["isConnected"].boolish
            isPaired = d["isPaired"].boolish
            deviceType = d["deviceType"].nonEmptyString
            deviceCategory = d["deviceCategory"].nonEmptyString
            batteryLevel = d["batteryLevel"].int
        }

        /// HomePods, phones, watches and other Macs are not peripherals.
        var isPeripheral: Bool {
            let n = name.lowercased()
            let c = (deviceCategory ?? "").lowercased()
            for word in ["homepod", "apple watch", "iphone", "ipad", "macbook", "imac", "mac mini", "mac pro", "mac studio"] where n.contains(word) { return false }
            if ["computer", "phone", "tablet", "watch"].contains(c) { return false }
            return true
        }
    }

    public struct ThunderboltDevice: Sendable, Hashable, Identifiable {
        public var id: String { name + (uid ?? "") + String(index) }
        public var index: Int
        public var name: String
        public var vendor: String?
        public var deviceId: String?
        public var uid: String?
        public var deviceType: String?
        init(index: Int, json d: JSONValue) {
            self.index = index
            name = d["name"].nonEmptyString ?? "Thunderbolt Device"
            vendor = d["vendor"].nonEmptyString
            deviceId = d["deviceId"].nonEmptyString
            uid = d["uid"].nonEmptyString
            deviceType = d["deviceType"].nonEmptyString
        }
    }

    public struct CupsFilter: Sendable, Hashable {
        public var name: String
        public var path: String?
        public var version: String?
    }

    public struct Printer: Sendable, Hashable, Identifiable {
        public var id: String { name + (uri ?? "") + String(index) }
        public var index: Int
        public var name: String
        public var uri: String?
        public var connectionType: String?
        public var status: String?
        public var stateReasons: [String]
        public var isDefault: Bool
        public var manufacturer: String?
        public var model: String?
        public var identifier: String?
        public var ppd: String?
        public var cupsVersion: String?
        public var scanningSupport: String?
        public var faxSupport: String?
        public var cupsFilters: [CupsFilter]
        init(index: Int, json d: JSONValue) {
            self.index = index
            name = d["name"].nonEmptyString ?? ""
            uri = d["uri"].nonEmptyString
            connectionType = d["connectionType"].nonEmptyString
            status = d["status"].nonEmptyString
            stateReasons = d["stateReasons"].elements.compactMap(\.string).filter { !$0.isEmpty && $0 != "none" }
            isDefault = d["isDefault"].boolish
            manufacturer = d["manufacturer"].nonEmptyString ?? d["make"].nonEmptyString
            model = d["model"].nonEmptyString
            identifier = d["identifier"].nonEmptyString
            ppd = d["ppd"].nonEmptyString
            cupsVersion = d["cupsVersion"].nonEmptyString
            scanningSupport = d["scanningSupport"].nonEmptyString
            faxSupport = d["faxSupport"].nonEmptyString
            cupsFilters = d["cupsFilters"].elements.compactMap { f in
                guard let n = f["name"].nonEmptyString else { return nil }
                return CupsFilter(name: n, path: f["path"].nonEmptyString, version: f["version"].nonEmptyString)
            }
        }
    }

    public struct Scanner: Sendable, Hashable, Identifiable {
        public var id: String { name + String(index) }
        public var index: Int
        public var name: String
        public var manufacturer: String?
        public var connectionType: String?
        public var status: String?
        public var scannerType: String?
        init(index: Int, json d: JSONValue) {
            self.index = index
            name = d["name"].nonEmptyString ?? "Scanner"
            manufacturer = d["manufacturer"].nonEmptyString
            connectionType = d["connectionType"].nonEmptyString
            status = d["status"].nonEmptyString
            scannerType = d["scannerType"].nonEmptyString
        }
    }

    public struct ExternalStorage: Sendable, Hashable, Identifiable {
        public var id: String { name + (mountPoint ?? "") + String(index) }
        public var index: Int
        public var name: String
        public var devicePath: String?
        public var mountPoint: String?
        public var fileSystem: String?
        public var totalSize: String?
        public var protocolName: String?
        public var storageType: String?
        init(index: Int, json d: JSONValue) {
            self.index = index
            name = d["name"].nonEmptyString ?? ""
            devicePath = d["devicePath"].nonEmptyString
            mountPoint = d["mountPoint"].nonEmptyString
            fileSystem = d["fileSystem"].nonEmptyString
            totalSize = d["totalSize"].nonEmptyString
            protocolName = d["protocol"].nonEmptyString
            storageType = d["storageType"].nonEmptyString
        }
        /// `getStorageName`: the volume name, else the last mount-point segment.
        public var displayName: String {
            if !name.isEmpty, name != "External Storage" { return name }
            if let mp = mountPoint {
                if mp == "/" { return "System Drive" }
                return mp.split(separator: "/").last.map(String.init) ?? "External Storage"
            }
            return "External Storage"
        }
    }

    public enum Category: String, Sendable, CaseIterable, Identifiable {
        case storage, usbThunderbolt = "usb-thunderbolt", audio, input, printers, scanners, microphones, bluetooth
        public var id: String { rawValue }
        public var label: String {
            switch self {
            case .storage: return "External Storage"
            case .usbThunderbolt: return "USB & Thunderbolt"
            case .audio: return "Audio"
            case .input: return "Input Devices"
            case .printers: return "Printers"
            case .scanners: return "Scanners"
            case .microphones: return "Microphones"
            case .bluetooth: return "Bluetooth"
            }
        }
    }

    public var usbDevices: [USBDevice]
    public var thunderboltDevices: [ThunderboltDevice]
    public var keyboards: [InputDevice]
    public var mice: [InputDevice]
    public var trackpads: [InputDevice]
    public var tablets: [InputDevice]
    public var audioOutputs: [AudioDevice]
    public var microphones: [AudioDevice]
    public var bluetoothDevices: [BluetoothDevice]
    public var printers: [Printer]
    public var scanners: [Scanner]
    public var externalStorage: [ExternalStorage]
    public var raw: JSONValue
    public var hasData: Bool

    public init(modules: JSONValue) {
        raw = modules["peripherals"].unwrappingSingleton()
        hasData = !raw.isNull && !raw.isEmptyContainer
        usbDevices = raw["usbDevices"].elements.enumerated().map { USBDevice(index: $0.offset, json: $0.element) }
        thunderboltDevices = raw["thunderboltDevices"].elements.enumerated().map { ThunderboltDevice(index: $0.offset, json: $0.element) }

        let allBluetooth = raw["bluetoothDevices"].elements.enumerated().map { BluetoothDevice(index: $0.offset, json: $0.element) }
        bluetoothDevices = allBluetooth.filter(\.isPeripheral)

        // Mac: nested object. Windows: one flat list tagged by deviceType.
        let input = raw["inputDevices"]
        var kb: [InputDevice] = [], mi: [InputDevice] = [], tp: [InputDevice] = [], tb: [InputDevice] = []
        if let flat = input.array {
            let all = flat.enumerated().map { InputDevice(index: $0.offset, json: $0.element) }
            func of(_ types: [String]) -> [InputDevice] { all.filter { types.contains(($0.deviceType ?? "").lowercased()) } }
            kb = of(["keyboard"]); mi = of(["mouse"]); tp = of(["trackpad", "touchpad"]); tb = of(["graphics tablet", "tablet", "pen display", "pen tablet"])
        } else {
            kb = input["keyboards"].elements.enumerated().map { InputDevice(index: $0.offset, json: $0.element) }
            mi = input["mice"].elements.enumerated().map { InputDevice(index: $0.offset, json: $0.element) }
            tp = input["trackpads"].elements.enumerated().map { InputDevice(index: $0.offset, json: $0.element) }
            tb = input["tablets"].elements.enumerated().map { InputDevice(index: $0.offset, json: $0.element) }
        }
        // Bluetooth keyboards join the keyboard list.
        kb += allBluetooth.filter { $0.deviceType == "Keyboard" || $0.deviceCategory == "Keyboard" }.map(InputDevice.bluetoothKeyboard)
        keyboards = kb; mice = mi; trackpads = tp; tablets = tb

        let audio = raw["audioDevices"].elements.enumerated().map { AudioDevice(index: $0.offset, json: $0.element) }
        audioOutputs = audio.filter { $0.isOutput || $0.type == "Output" }
        microphones = audio.filter { $0.isInput || $0.type == "Input" }

        printers = raw["printers"].elements.enumerated().map { Printer(index: $0.offset, json: $0.element) }
            .sorted { a, b in a.isDefault != b.isDefault ? a.isDefault : a.index < b.index }
        scanners = raw["scanners"].elements.enumerated().map { Scanner(index: $0.offset, json: $0.element) }
        externalStorage = raw["externalStorage"].elements.enumerated().map { ExternalStorage(index: $0.offset, json: $0.element) }
    }

    public var inputCount: Int { keyboards.count + mice.count + trackpads.count + tablets.count }

    public func count(for category: Category) -> Int {
        switch category {
        case .storage: return externalStorage.count
        case .usbThunderbolt: return usbDevices.count + thunderboltDevices.count
        case .audio: return audioOutputs.count
        case .input: return inputCount
        case .printers: return printers.count
        case .scanners: return scanners.count
        case .microphones: return microphones.count
        case .bluetooth: return bluetoothDevices.count
        }
    }

    public static let penInputLabel = "Pen Input"
}
