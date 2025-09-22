import Foundation

/// Peripherals module data model for macOS - encompasses all peripheral device types
public struct PeripheralsData: ModuleDataModel, Sendable {
    public var moduleId: String { "peripherals" }
    public let collectionTimestamp: Date
    public let success: Bool
    public let errorMessage: String?
    
    // Additional peripherals-specific properties
    public let deviceId: String
    
    // Peripheral device categories
    public let usbDevices: [USBDevice]
    public let inputDevices: [InputDevice]
    public let audioDevices: [AudioDevice]
    public let bluetoothDevices: [BluetoothDevice]
    public let cameraDevices: [CameraDevice]
    public let storageDevices: [PeripheralStorageDevice]
    public let thunderboltDevices: [ThunderboltDevice]
    
    public init(
        deviceId: String,
        collectionTimestamp: Date = Date(),
        success: Bool = true,
        errorMessage: String? = nil,
        usbDevices: [USBDevice] = [],
        inputDevices: [InputDevice] = [],
        audioDevices: [AudioDevice] = [],
        bluetoothDevices: [BluetoothDevice] = [],
        cameraDevices: [CameraDevice] = [],
        storageDevices: [PeripheralStorageDevice] = [],
        thunderboltDevices: [ThunderboltDevice] = []
    ) {
        self.deviceId = deviceId
        self.collectionTimestamp = collectionTimestamp
        self.success = success
        self.errorMessage = errorMessage
        self.usbDevices = usbDevices
        self.inputDevices = inputDevices
        self.audioDevices = audioDevices
        self.bluetoothDevices = bluetoothDevices
        self.cameraDevices = cameraDevices
        self.storageDevices = storageDevices
        self.thunderboltDevices = thunderboltDevices
    }
}

/// USB device information
public struct USBDevice: Codable, Sendable {
    public let name: String
    public let deviceId: String?
    public let vendor: String
    public let vendorId: String?
    public let product: String
    public let productId: String?
    public let serialNumber: String?
    public let speed: String? // USB 2.0, USB 3.0, USB 3.1, etc.
    public let location: String?
    public let power: String? // Bus Powered, Self Powered
    public let deviceClass: String?
    public let deviceSubclass: String?
    public let deviceProtocol: String?
    public let isAppleDevice: Bool
    public let isExternal: Bool
    
    public init(
        name: String = "",
        deviceId: String? = nil,
        vendor: String = "",
        vendorId: String? = nil,
        product: String = "",
        productId: String? = nil,
        serialNumber: String? = nil,
        speed: String? = nil,
        location: String? = nil,
        power: String? = nil,
        deviceClass: String? = nil,
        deviceSubclass: String? = nil,
        deviceProtocol: String? = nil,
        isAppleDevice: Bool = false,
        isExternal: Bool = true
    ) {
        self.name = name
        self.deviceId = deviceId
        self.vendor = vendor
        self.vendorId = vendorId
        self.product = product
        self.productId = productId
        self.serialNumber = serialNumber
        self.speed = speed
        self.location = location
        self.power = power
        self.deviceClass = deviceClass
        self.deviceSubclass = deviceSubclass
        self.deviceProtocol = deviceProtocol
        self.isAppleDevice = isAppleDevice
        self.isExternal = isExternal
    }
}

/// Input device information (keyboards, mice, trackpads, etc.)
public struct InputDevice: Codable, Sendable {
    public let name: String
    public let deviceId: String?
    public let vendor: String
    public let product: String
    public let serialNumber: String?
    public let deviceType: String // Keyboard, Mouse, Trackpad, Tablet, etc.
    public let connectionType: String // USB, Bluetooth, Built-in
    public let isAppleDevice: Bool
    public let isBuiltIn: Bool
    public let isWireless: Bool
    public let batteryLevel: Int? // For wireless devices
    
    public init(
        name: String = "",
        deviceId: String? = nil,
        vendor: String = "",
        product: String = "",
        serialNumber: String? = nil,
        deviceType: String = "",
        connectionType: String = "",
        isAppleDevice: Bool = false,
        isBuiltIn: Bool = false,
        isWireless: Bool = false,
        batteryLevel: Int? = nil
    ) {
        self.name = name
        self.deviceId = deviceId
        self.vendor = vendor
        self.product = product
        self.serialNumber = serialNumber
        self.deviceType = deviceType
        self.connectionType = connectionType
        self.isAppleDevice = isAppleDevice
        self.isBuiltIn = isBuiltIn
        self.isWireless = isWireless
        self.batteryLevel = batteryLevel
    }
}

/// Audio device information
public struct AudioDevice: Codable, Sendable {
    public let name: String
    public let deviceId: String?
    public let manufacturer: String
    public let model: String
    public let serialNumber: String?
    public let deviceType: String // Input, Output, Input/Output
    public let connectionType: String // Built-in, USB, Bluetooth, 3.5mm, etc.
    public let sampleRate: String?
    public let bitDepth: String?
    public let channels: Int?
    public let isDefault: Bool
    public let isBuiltIn: Bool
    
    public init(
        name: String = "",
        deviceId: String? = nil,
        manufacturer: String = "",
        model: String = "",
        serialNumber: String? = nil,
        deviceType: String = "",
        connectionType: String = "",
        sampleRate: String? = nil,
        bitDepth: String? = nil,
        channels: Int? = nil,
        isDefault: Bool = false,
        isBuiltIn: Bool = false
    ) {
        self.name = name
        self.deviceId = deviceId
        self.manufacturer = manufacturer
        self.model = model
        self.serialNumber = serialNumber
        self.deviceType = deviceType
        self.connectionType = connectionType
        self.sampleRate = sampleRate
        self.bitDepth = bitDepth
        self.channels = channels
        self.isDefault = isDefault
        self.isBuiltIn = isBuiltIn
    }
}

/// Bluetooth device information
public struct BluetoothDevice: Codable, Sendable {
    public let name: String
    public let address: String // MAC address
    public let deviceClass: String
    public let majorDeviceClass: String
    public let minorDeviceClass: String
    public let manufacturer: String?
    public let isConnected: Bool
    public let isPaired: Bool
    public let rssi: Int? // Signal strength
    public let batteryLevel: Int?
    public let lastConnected: Date?
    
    public init(
        name: String = "",
        address: String = "",
        deviceClass: String = "",
        majorDeviceClass: String = "",
        minorDeviceClass: String = "",
        manufacturer: String? = nil,
        isConnected: Bool = false,
        isPaired: Bool = false,
        rssi: Int? = nil,
        batteryLevel: Int? = nil,
        lastConnected: Date? = nil
    ) {
        self.name = name
        self.address = address
        self.deviceClass = deviceClass
        self.majorDeviceClass = majorDeviceClass
        self.minorDeviceClass = minorDeviceClass
        self.manufacturer = manufacturer
        self.isConnected = isConnected
        self.isPaired = isPaired
        self.rssi = rssi
        self.batteryLevel = batteryLevel
        self.lastConnected = lastConnected
    }
}

/// Camera device information
public struct CameraDevice: Codable, Sendable {
    public let name: String
    public let deviceId: String?
    public let manufacturer: String
    public let model: String
    public let serialNumber: String?
    public let connectionType: String // Built-in, USB, Thunderbolt
    public let maxResolution: String?
    public let supportedFormats: [String]
    public let isBuiltIn: Bool
    public let isDefault: Bool
    public let isInUse: Bool
    
    public init(
        name: String = "",
        deviceId: String? = nil,
        manufacturer: String = "",
        model: String = "",
        serialNumber: String? = nil,
        connectionType: String = "",
        maxResolution: String? = nil,
        supportedFormats: [String] = [],
        isBuiltIn: Bool = false,
        isDefault: Bool = false,
        isInUse: Bool = false
    ) {
        self.name = name
        self.deviceId = deviceId
        self.manufacturer = manufacturer
        self.model = model
        self.serialNumber = serialNumber
        self.connectionType = connectionType
        self.maxResolution = maxResolution
        self.supportedFormats = supportedFormats
        self.isBuiltIn = isBuiltIn
        self.isDefault = isDefault
        self.isInUse = isInUse
    }
}

/// External storage device information for peripherals module
public struct PeripheralStorageDevice: Codable, Sendable {
    public let name: String
    public let deviceId: String?
    public let manufacturer: String
    public let model: String
    public let serialNumber: String?
    public let capacity: String
    public let connectionType: String // USB, Thunderbolt, FireWire
    public let fileSystem: String?
    public let mountPoint: String?
    public let isRemovable: Bool
    public let isEncrypted: Bool
    public let isMounted: Bool
    public let diskType: String? // SSD, HDD, USB Flash
    
    public init(
        name: String = "",
        deviceId: String? = nil,
        manufacturer: String = "",
        model: String = "",
        serialNumber: String? = nil,
        capacity: String = "",
        connectionType: String = "",
        fileSystem: String? = nil,
        mountPoint: String? = nil,
        isRemovable: Bool = false,
        isEncrypted: Bool = false,
        isMounted: Bool = false,
        diskType: String? = nil
    ) {
        self.name = name
        self.deviceId = deviceId
        self.manufacturer = manufacturer
        self.model = model
        self.serialNumber = serialNumber
        self.capacity = capacity
        self.connectionType = connectionType
        self.fileSystem = fileSystem
        self.mountPoint = mountPoint
        self.isRemovable = isRemovable
        self.isEncrypted = isEncrypted
        self.isMounted = isMounted
        self.diskType = diskType
    }
}

/// Thunderbolt device information
public struct ThunderboltDevice: Codable, Sendable {
    public let name: String
    public let deviceId: String?
    public let vendor: String
    public let deviceType: String
    public let port: String?
    public let linkSpeed: String?
    public let linkWidth: String?
    public let isActive: Bool
    public let firmwareVersion: String?
    
    public init(
        name: String = "",
        deviceId: String? = nil,
        vendor: String = "",
        deviceType: String = "",
        port: String? = nil,
        linkSpeed: String? = nil,
        linkWidth: String? = nil,
        isActive: Bool = false,
        firmwareVersion: String? = nil
    ) {
        self.name = name
        self.deviceId = deviceId
        self.vendor = vendor
        self.deviceType = deviceType
        self.port = port
        self.linkSpeed = linkSpeed
        self.linkWidth = linkWidth
        self.isActive = isActive
        self.firmwareVersion = firmwareVersion
    }
}