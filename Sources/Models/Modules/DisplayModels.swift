import Foundation

/// Display module data model for macOS
public struct DisplayData: ModuleDataModel, Sendable {
    public let moduleId: String = "displays"
    public let collectionTimestamp: Date
    public let success: Bool
    public let errorMessage: String?
    
    // Additional display-specific properties
    public let deviceId: String
    
    // Exclude moduleId from coding since it has a fixed value
    enum CodingKeys: String, CodingKey {
        case collectionTimestamp
        case success
        case errorMessage
        case deviceId
        case displays
        case displayAdapters
        case displaySettings
        case colorProfiles
    }
    
    // Display devices and configuration
    public let displays: [DisplayDevice]
    public let displayAdapters: [DisplayAdapter]
    public let displaySettings: DisplayConfiguration
    public let colorProfiles: [ColorProfile]
    
    public init(
        deviceId: String,
        collectionTimestamp: Date = Date(),
        success: Bool = true,
        errorMessage: String? = nil,
        displays: [DisplayDevice] = [],
        displayAdapters: [DisplayAdapter] = [],
        displaySettings: DisplayConfiguration = DisplayConfiguration(),
        colorProfiles: [ColorProfile] = []
    ) {
        self.deviceId = deviceId
        self.collectionTimestamp = collectionTimestamp
        self.success = success
        self.errorMessage = errorMessage
        self.displays = displays
        self.displayAdapters = displayAdapters
        self.displaySettings = displaySettings
        self.colorProfiles = colorProfiles
    }
}

/// Individual display device information
public struct DisplayDevice: Codable, Sendable {
    // Identity
    public let name: String
    public let deviceId: String
    public let manufacturer: String
    public let model: String
    public let serialNumber: String?
    
    // Connection and Type  
    public let connectionType: String // Thunderbolt, USB-C, HDMI, DisplayPort, etc.
    public let isInternal: Bool
    public let isExternal: Bool
    public let isPrimary: Bool
    public let isActive: Bool
    public let isEnabled: Bool
    public let isMirrored: Bool
    
    // Physical Properties
    public let diagonalSizeInches: Double?
    public let widthMm: Int?
    public let heightMm: Int?
    public let aspectRatio: Double?
    public let pixelsPerInch: Double?
    
    // Current Display Settings
    public let currentResolution: Resolution
    public let currentRefreshRate: Int
    public let currentColorDepth: Int
    public let currentScaling: Double
    public let currentOrientation: String
    public let currentColorSpace: String
    
    // Supported Capabilities
    public let maxResolution: Resolution
    public let supportedResolutions: [Resolution]
    public let supportedRefreshRates: [Int]
    public let maxColorDepth: Int
    public let capabilities: [String]
    
    // Color Management
    public let colorProfile: String?
    public let gamma: Double?
    public let brightness: Double?
    public let contrast: Double?
    
    // Position and Layout
    public let positionX: Int
    public let positionY: Int
    public let displayIndex: Int
    public let rotation: Int // degrees
    
    public init(
        name: String,
        deviceId: String,
        manufacturer: String = "",
        model: String = "",
        serialNumber: String? = nil,
        connectionType: String = "",
        isInternal: Bool = false,
        isExternal: Bool = false,
        isPrimary: Bool = false,
        isActive: Bool = false,
        isEnabled: Bool = false,
        isMirrored: Bool = false,
        diagonalSizeInches: Double? = nil,
        widthMm: Int? = nil,
        heightMm: Int? = nil,
        aspectRatio: Double? = nil,
        pixelsPerInch: Double? = nil,
        currentResolution: Resolution = Resolution(),
        currentRefreshRate: Int = 0,
        currentColorDepth: Int = 0,
        currentScaling: Double = 1.0,
        currentOrientation: String = "landscape",
        currentColorSpace: String = "",
        maxResolution: Resolution = Resolution(),
        supportedResolutions: [Resolution] = [],
        supportedRefreshRates: [Int] = [],
        maxColorDepth: Int = 0,
        capabilities: [String] = [],
        colorProfile: String? = nil,
        gamma: Double? = nil,
        brightness: Double? = nil,
        contrast: Double? = nil,
        positionX: Int = 0,
        positionY: Int = 0,
        displayIndex: Int = 0,
        rotation: Int = 0
    ) {
        self.name = name
        self.deviceId = deviceId
        self.manufacturer = manufacturer
        self.model = model
        self.serialNumber = serialNumber
        self.connectionType = connectionType
        self.isInternal = isInternal
        self.isExternal = isExternal
        self.isPrimary = isPrimary
        self.isActive = isActive
        self.isEnabled = isEnabled
        self.isMirrored = isMirrored
        self.diagonalSizeInches = diagonalSizeInches
        self.widthMm = widthMm
        self.heightMm = heightMm
        self.aspectRatio = aspectRatio
        self.pixelsPerInch = pixelsPerInch
        self.currentResolution = currentResolution
        self.currentRefreshRate = currentRefreshRate
        self.currentColorDepth = currentColorDepth
        self.currentScaling = currentScaling
        self.currentOrientation = currentOrientation
        self.currentColorSpace = currentColorSpace
        self.maxResolution = maxResolution
        self.supportedResolutions = supportedResolutions
        self.supportedRefreshRates = supportedRefreshRates
        self.maxColorDepth = maxColorDepth
        self.capabilities = capabilities
        self.colorProfile = colorProfile
        self.gamma = gamma
        self.brightness = brightness
        self.contrast = contrast
        self.positionX = positionX
        self.positionY = positionY
        self.displayIndex = displayIndex
        self.rotation = rotation
    }
}

/// Display adapter (graphics card) information
public struct DisplayAdapter: Codable, Sendable {
    public let name: String
    public let deviceId: String
    public let vendor: String
    public let model: String
    public let chipset: String?
    public let vramMB: Int
    public let driverVersion: String?
    public let pcieSlot: String?
    public let busType: String
    public let connectedDisplays: [String] // Display device IDs
    public let capabilities: [String]
    
    public init(
        name: String = "",
        deviceId: String = "",
        vendor: String = "",
        model: String = "",
        chipset: String? = nil,
        vramMB: Int = 0,
        driverVersion: String? = nil,
        pcieSlot: String? = nil,
        busType: String = "",
        connectedDisplays: [String] = [],
        capabilities: [String] = []
    ) {
        self.name = name
        self.deviceId = deviceId
        self.vendor = vendor
        self.model = model
        self.chipset = chipset
        self.vramMB = vramMB
        self.driverVersion = driverVersion
        self.pcieSlot = pcieSlot
        self.busType = busType
        self.connectedDisplays = connectedDisplays
        self.capabilities = capabilities
    }
}

/// Overall display configuration
public struct DisplayConfiguration: Codable, Sendable {
    public let totalDisplays: Int
    public let activeDisplays: Int
    public let primaryDisplayId: String?
    public let arrangementMode: String // Extended, Mirrored, Single
    public let totalResolution: Resolution // Combined resolution
    public let supportsRetina: Bool
    public let supportsHDR: Bool
    public let supportsTrueTone: Bool
    public let supportsWideColor: Bool
    
    public init(
        totalDisplays: Int = 0,
        activeDisplays: Int = 0,
        primaryDisplayId: String? = nil,
        arrangementMode: String = "",
        totalResolution: Resolution = Resolution(),
        supportsRetina: Bool = false,
        supportsHDR: Bool = false,
        supportsTrueTone: Bool = false,
        supportsWideColor: Bool = false
    ) {
        self.totalDisplays = totalDisplays
        self.activeDisplays = activeDisplays
        self.primaryDisplayId = primaryDisplayId
        self.arrangementMode = arrangementMode
        self.totalResolution = totalResolution
        self.supportsRetina = supportsRetina
        self.supportsHDR = supportsHDR
        self.supportsTrueTone = supportsTrueTone
        self.supportsWideColor = supportsWideColor
    }
}

/// Color profile information
public struct ColorProfile: Codable, Sendable {
    public let name: String
    public let path: String
    public let displayDeviceId: String?
    public let colorSpace: String
    public let description: String?
    public let isDefault: Bool
    public let whitePoint: [Double]? // x, y coordinates
    public let gamut: String?
    
    public init(
        name: String = "",
        path: String = "",
        displayDeviceId: String? = nil,
        colorSpace: String = "",
        description: String? = nil,
        isDefault: Bool = false,
        whitePoint: [Double]? = nil,
        gamut: String? = nil
    ) {
        self.name = name
        self.path = path
        self.displayDeviceId = displayDeviceId
        self.colorSpace = colorSpace
        self.description = description
        self.isDefault = isDefault
        self.whitePoint = whitePoint
        self.gamut = gamut
    }
}

/// Resolution information
public struct Resolution: Codable, Sendable {
    public let width: Int
    public let height: Int
    public let isHiDPI: Bool
    public let scaleFactor: Double
    
    public init(
        width: Int = 0,
        height: Int = 0,
        isHiDPI: Bool = false,
        scaleFactor: Double = 1.0
    ) {
        self.width = width
        self.height = height
        self.isHiDPI = isHiDPI
        self.scaleFactor = scaleFactor
    }
    
    public var description: String {
        return "\(width)x\(height)\(isHiDPI ? " (Retina)" : "")"
    }
}