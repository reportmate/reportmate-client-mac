import ArgumentParser
import Foundation
import Logging
import AsyncHTTPClient
import Darwin

/// ReportMate macOS Client
/// Native Swift application for collecting device telemetry using osquery
struct ReportMateClient: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "runner",
        abstract: "ReportMate macOS Client - Device telemetry collection",
        version: "1.0.0",
        subcommands: [
            RunCommand.self,
            TestCommand.self,
            InfoCommand.self,
            InstallCommand.self
        ],
        defaultSubcommand: RunCommand.self
    )
}

// MARK: - Run Command
struct RunCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "run",
        abstract: "Execute data collection and transmission"
    )
    
    @Flag(name: .long, help: "Force collection even if cache is recent")
    var force: Bool = false
    
    @Option(name: .long, help: "Override device identifier")
    var deviceId: String?
    
    @Option(name: .long, help: "Override API URL")
    var apiUrl: String?
    
    @Flag(name: .long, help: "Enable verbose logging")
    var verbose: Bool = false
    
    func run() async throws {
        let logger = Logger(label: "reportmate.client")
        
        do {
            let client = try await ReportMateCore()
            let result = await client.executeDataCollection(
                force: force,
                deviceId: deviceId,
                apiUrl: apiUrl,
                verbose: verbose
            )
            
            switch result {
            case .success(let summary):
                print("✅ Data collection completed successfully")
                print("📊 Collected data from \(summary.moduleCount) modules")
                print("📤 Transmitted \(summary.recordCount) records")
                
            case .failure(let error):
                print("❌ Data collection failed: \(error.localizedDescription)")
                throw ExitCode.failure
            }
            
        } catch {
            logger.error("Failed to initialize ReportMate client: \(error)")
            throw ExitCode.failure
        }
    }
}

// MARK: - Test Command  
struct TestCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "test",
        abstract: "Test configuration and connectivity"
    )
    
    @Flag(name: .long, help: "Enable verbose output")
    var verbose: Bool = false
    
    func run() async throws {
        let logger = Logger(label: "reportmate.test")
        
        do {
            let client = try await ReportMateCore()
            let result = await client.testConfiguration(verbose: verbose)
            
            switch result {
            case .success(let diagnostics):
                print("✅ Configuration test passed")
                if verbose {
                    print("\n🔧 Configuration Details:")
                    print("   API URL: \(diagnostics.apiUrl)")
                    print("   Device ID: \(diagnostics.deviceId)")
                    print("   Enabled Modules: \(diagnostics.enabledModules.joined(separator: ", "))")
                    print("   osquery Available: \(diagnostics.osqueryAvailable ? "Yes" : "No")")
                    print("   API Connectivity: \(diagnostics.apiConnectivity ? "OK" : "Failed")")
                }
                
            case .failure(let error):
                print("❌ Configuration test failed: \(error.localizedDescription)")
                throw ExitCode.failure
            }
            
        } catch {
            logger.error("Test failed: \(error)")
            throw ExitCode.failure
        }
    }
}

// MARK: - Info Command
struct InfoCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "info",
        abstract: "Display system and configuration information"
    )
    
    @Flag(name: .long, help: "Output in JSON format")
    var json: Bool = false
    
    func run() async throws {
        let client = try await ReportMateCore()
        let info = await client.getSystemInfo()
        
        if json {
            let encoder = JSONEncoder()
            encoder.outputFormatting = .prettyPrinted
            let data = try encoder.encode(info)
            print(String(data: data, encoding: .utf8) ?? "")
        } else {
            print("🖥️  ReportMate System Information")
            print("═══════════════════════════════════")
            print("Device: \(info.deviceName) (\(info.deviceModel))")
            print("OS: \(info.osName) \(info.osVersion)")
            print("Architecture: \(info.architecture)")
            print("Serial: \(info.serialNumber)")
            print("ReportMate Version: \(info.reportMateVersion)")
            print("Configuration Source: \(info.configurationSource)")
        }
    }
}

// MARK: - Install Command
struct InstallCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "install",
        abstract: "Configure ReportMate client"
    )
    
    @Option(name: .long, help: "ReportMate API URL")
    var apiUrl: String
    
    @Option(name: .long, help: "Custom device identifier")
    var deviceId: String?
    
    @Option(name: .long, help: "API authentication key")
    var apiKey: String?
    
    func run() async throws {
        let client = try await ReportMateCore()
        let result = await client.configure(
            apiUrl: apiUrl,
            deviceId: deviceId,
            apiKey: apiKey
        )
        
        switch result {
        case .success:
            print("✅ ReportMate configured successfully")
            print("🔧 Configuration saved to system preferences")
            
        case .failure(let error):
            print("❌ Configuration failed: \(error.localizedDescription)")
            throw ExitCode.failure
        }
    }
}

// Entry point
let group = DispatchGroup()
group.enter()

Task {
    await ReportMateClient.main()
    group.leave()
}

group.wait()