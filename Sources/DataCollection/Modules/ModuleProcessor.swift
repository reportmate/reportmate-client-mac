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
    /// 
    /// Three-tier fallback strategy:
    /// 1. Try osquery (with macadmins extension if available - provides mdm, macos_profiles, alt_system_info, etc.)
    /// 2. Try bash command fallback
    /// 3. Try python script fallback
    ///
    /// The extension is automatically loaded by OSQueryService when available.
    /// Extension tables: mdm, macos_profiles, filevault_users, alt_system_info, unified_log, pending_apple_updates, etc.
    internal func executeWithFallback(
        osquery: String? = nil,
        bash: String? = nil,
        python: String? = nil
    ) async throws -> [String: Any] {
        
        // Try osquery first (extension loaded automatically if available)
        if let osqueryCmd = osquery {
            do {
                let osqueryService = OSQueryService(configuration: configuration)
                if await osqueryService.isAvailable() {
                    let results = try await osqueryService.executeQuery(osqueryCmd)
                    // Unwrap single result, or return as items
                    if results.count == 1, let first = results.first {
                        return first
                    }
                    return ["items": results]
                }
            } catch {
                print("⚠️ OSQuery failed (extension tables may not be available), trying bash fallback: \(error)")
            }
        }
        
        // Try bash fallback
        if let bashCmd = bash {
            do {
                let output = try await BashService.execute(bashCmd)
                
                // Try to parse as JSON
                if let data = output.data(using: .utf8),
                   let jsonObject = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) {
                    if let dict = jsonObject as? [String: Any] {
                        return dict
                    } else if let array = jsonObject as? [Any] {
                        return ["items": array]
                    }
                }
                
                return ["output": output]
            } catch {
                print("⚠️ Bash fallback failed, trying python fallback: \(error)")
            }
        }
        
        // Try python fallback
        if let pythonScript = python {
            do {
                let result = try await PythonService.executeScript(pythonScript)
                return result
            } catch {
                print("❌ Python fallback failed: \(error)")
                throw error
            }
        }
        
        // throw ModuleError.moduleNotFound(moduleId)
        fatalError("No data source available for module: \(moduleId)")
    }
}