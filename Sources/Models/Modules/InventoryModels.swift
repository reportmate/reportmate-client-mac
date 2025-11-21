import Foundation

/// Inventory module data models for macOS ReportMate client
/// These models represent file system inventory and asset tracking

public struct InventoryData: ModuleDataModel, Sendable {
    public var moduleId: String { "inventory" }
    public let collectionTimestamp: Date
    public let success: Bool
    public let errorMessage: String?
    
    public let deviceName: String
    public let serialNumber: String
    public let assetTag: String
    public let uuid: String
    public let location: String
    public let owner: String
    public let department: String
    public let purchaseDate: Date?
    public let warrantyExpiration: Date?
    
    // Additional fields from external inventory source
    public let catalog: String
    public let usage: String
    
    public init(
        collectionTimestamp: Date = Date(),
        success: Bool = true,
        errorMessage: String? = nil,
        deviceName: String = "",
        serialNumber: String = "",
        assetTag: String = "",
        uuid: String = "",
        location: String = "",
        owner: String = "",
        department: String = "",
        purchaseDate: Date? = nil,
        warrantyExpiration: Date? = nil,
        catalog: String = "",
        usage: String = ""
    ) {
        self.collectionTimestamp = collectionTimestamp
        self.success = success
        self.errorMessage = errorMessage
        self.deviceName = deviceName
        self.serialNumber = serialNumber
        self.assetTag = assetTag
        self.uuid = uuid
        self.location = location
        self.owner = owner
        self.department = department
        self.purchaseDate = purchaseDate
        self.warrantyExpiration = warrantyExpiration
        self.catalog = catalog
        self.usage = usage
    }
}
