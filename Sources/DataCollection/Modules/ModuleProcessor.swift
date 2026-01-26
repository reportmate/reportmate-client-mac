import Foundation

/// Protocol for module processors that collect specific types of data
public protocol ModuleProcessor: Sendable {
    var moduleId: String { get }
    var configuration: ReportMateConfiguration { get }
    
    /// Collect data for this module
    func collectData() async throws -> ModuleData
    
    /// Validate collected data
    func validateData(_ data: ModuleData) -> Bool
}

/// Base implementation for module processors that provides common functionality
open class BaseModuleProcessor: ModuleProcessor, @unchecked Sendable {
    public let moduleId: String
    public let configuration: ReportMateConfiguration
    
    public init(moduleId: String, configuration: ReportMateConfiguration) {
        self.moduleId = moduleId
        self.configuration = configuration
    }
    
    /// Default data collection - subclasses should override
    open func collectData() async throws -> ModuleData {
        fatalError("Subclasses must implement collectData()")
    }
    
    /// Default validation - can be overridden by subclasses
    open func validateData(_ data: ModuleData) -> Bool {
        return true
    }
    
    /// Execute osquery with fallback to bash
    /// 
    /// Strategy:
    /// 1. Try osquery first (including extension tables when extension is enabled)
    /// 2. Fall back to bash if osquery fails or returns empty results
    /// 3. Extension tables require the macadmins extension to be loaded
    public func executeWithFallback(
        osquery: String? = nil,
        bash: String? = nil
    ) async throws -> [String: Any] {
        var osqueryEmpty = false
        
        // Try osquery first
        if let osqueryCmd = osquery {
            do {
                let osqueryService = OSQueryService(configuration: configuration)
                if await osqueryService.isAvailable() {
                    ConsoleFormatter.writeDebug("Trying osquery for module \(moduleId)...")
                    let results = try await osqueryService.executeQuery(osqueryCmd)
                    
                    // Check if results are empty - this often happens with extension tables
                    // when the extension hasn't registered yet
                    if results.isEmpty {
                        osqueryEmpty = true
                        ConsoleFormatter.writeDebug("OSQuery returned empty results, trying bash fallback...")
                    } else if results.count == 1, let first = results.first {
                        ConsoleFormatter.writeDebug("OSQuery succeeded for module \(moduleId)")
                        return first
                    } else {
                        ConsoleFormatter.writeDebug("OSQuery succeeded for module \(moduleId) with \(results.count) results")
                        return ["items": results]
                    }
                }
            } catch {
                ConsoleFormatter.writeDebug("OSQuery failed, using bash fallback: \(error)")
            }
        }
        
        // Try bash fallback (if osquery failed, not available, or returned empty)
        if let bashCmd = bash {
            do {
                ConsoleFormatter.writeDebug("Trying bash fallback for module \(moduleId)...")
                let output = try await BashService.execute(bashCmd)
                ConsoleFormatter.writeDebug("Bash output length: \(output.count) characters")
                
                // Try to parse as JSON
                if let data = output.data(using: .utf8),
                   let jsonObject = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) {
                    if let dict = jsonObject as? [String: Any] {
                        ConsoleFormatter.writeDebug("Bash succeeded for module \(moduleId), returned dict")
                        return dict
                    } else if let array = jsonObject as? [Any] {
                        ConsoleFormatter.writeDebug("Bash succeeded for module \(moduleId), returned array")
                        return ["items": array]
                    }
                }
                
                ConsoleFormatter.writeDebug("Bash output not JSON, returning as string")
                return ["output": output]
            } catch {
                ConsoleFormatter.writeError("Bash fallback failed: \(error)")
            }
        }
        
        // All fallbacks exhausted - return empty data instead of crashing
        // If osquery returned empty but bash wasn't provided, return the empty result
        if osqueryEmpty {
            return ["items": []]
        }
        
        ConsoleFormatter.writeWarning("All data sources exhausted for module \(moduleId), returning empty data")
        return [:]
    }
}