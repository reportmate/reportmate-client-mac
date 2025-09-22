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
    
    /// Execute osquery with fallback to bash/python
    internal func executeWithFallback(
        osquery: String? = nil,
        bash: String? = nil,
        python: String? = nil
    ) async throws -> [String: Any] {
        
        // Try osquery first
        if let osqueryCmd = osquery {
            do {
                let osqueryService = OSQueryService(configuration: configuration)
                if await osqueryService.isAvailable() {
                    let results = try await osqueryService.executeQuery(osqueryCmd)
                    return ["osquery": results]
                }
            } catch {
                print("OSQuery failed, trying bash fallback: \(error)")
            }
        }
        
        // Try bash fallback
        if let bashCmd = bash {
            do {
                let output = try await BashService.execute(bashCmd)
                return ["bash": output]
            } catch {
                print("Bash failed, trying python fallback: \(error)")
            }
        }
        
        // Try python fallback
        if let pythonScript = python {
            do {
                let result = try await PythonService.executeScript(pythonScript)
                return result
            } catch {
                print("Python fallback failed: \(error)")
                throw error
            }
        }
        
        // throw ModuleError.moduleNotFound(moduleId)
        fatalError("No data source available for module: \(moduleId)")
    }
}