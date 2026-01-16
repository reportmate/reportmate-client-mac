import Foundation

/// Inventory module processor for collecting inventory information
public class InventoryModuleProcessor: BaseModuleProcessor, @unchecked Sendable {
    
    public init(configuration: ReportMateConfiguration) {
        super.init(moduleId: "inventory", configuration: configuration)
    }
    
    public override func collectData() async throws -> ModuleData {
        let inventoryData = try await collectInventoryInfo()
        return inventoryData
    }
    
    private func collectInventoryInfo() async throws -> InventoryData {
        let rawData = try await executeWithFallback(
            osquery: """
            SELECT uuid, hardware_serial, computer_name 
            FROM system_info;
            """,
            bash: """
            echo "{"
            echo "  \\"serial\\": \\"$(system_profiler SPHardwareDataType | grep 'Serial Number' | awk '{print $4}')\\","
            echo "  \\"uuid\\": \\"$(system_profiler SPHardwareDataType | grep 'Hardware UUID' | awk '{print $3}')\\","
            echo "  \\"hostname\\": \\"$(hostname)\\""
            echo "}"
            """
        )
        
        var finalData: [String: Any] = rawData
        
        // Handle osquery result (wrapped in "items")
        if let items = rawData["items"] as? [[String: Any]], let firstRow = items.first {
            finalData = firstRow
        }
        
        // Collect file inventory info
        let fileInfo = collectFileInventoryInfo()
        
        // Map raw dictionary to InventoryData struct
        // Handle different key names from different sources (osquery vs bash/python)
        
        // OSQuery returns: uuid, hardware_serial, computer_name
        // Bash/Python returns: uuid, serial, hostname
        
        let serialNumber = (finalData["hardware_serial"] as? String) ?? (finalData["serial"] as? String) ?? ""
        let uuid = (finalData["uuid"] as? String) ?? ""
        let deviceName = (finalData["computer_name"] as? String) ?? (finalData["hostname"] as? String) ?? ""
        
        return InventoryData(
            deviceName: deviceName,
            serialNumber: serialNumber,
            assetTag: fileInfo["asset"] ?? "",
            uuid: uuid,
            location: fileInfo["location"] ?? "",
            owner: fileInfo["allocation"] ?? "",
            department: fileInfo["area"] ?? "",
            purchaseDate: nil,
            warrantyExpiration: nil,
            catalog: fileInfo["catalog"] ?? "",
            usage: fileInfo["usage"] ?? ""
        )
    }
    
    private func collectFileInventoryInfo() -> [String: String] {
        let inventoryPath = "/Library/Management/Inventory.yaml"
        var results: [String: String] = [:]
        
        guard FileManager.default.fileExists(atPath: inventoryPath),
              let content = try? String(contentsOfFile: inventoryPath, encoding: .utf8) else {
            return [:]
        }
        
        let lines = content.components(separatedBy: .newlines)
        for line in lines {
            let trimmedLine = line.trimmingCharacters(in: .whitespaces)
            if trimmedLine.isEmpty || trimmedLine.hasPrefix("#") || trimmedLine.hasPrefix("---") {
                continue
            }
            
            let parts = trimmedLine.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            if parts.count == 2 {
                let key = parts[0]
                var value = parts[1]
                // Strip quotes from YAML values
                if value.hasPrefix("\"") && value.hasSuffix("\"") && value.count >= 2 {
                    value = String(value.dropFirst().dropLast())
                } else if value.hasPrefix("'") && value.hasSuffix("'") && value.count >= 2 {
                    value = String(value.dropFirst().dropLast())
                }
                results[key] = value
            }
        }
        
        return results
    }
}
