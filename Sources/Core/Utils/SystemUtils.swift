import Foundation

/// Utility class for retrieving system information
public class SystemUtils {
    
    /// Retrieves the system serial number
    public static func getSerialNumber() -> String {
        // Try to get serial number using ioreg (most reliable on macOS)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/ioreg")
        process.arguments = ["-l"]
        
        let pipe = Pipe()
        process.standardOutput = pipe
        
        do {
            try process.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8) {
                // Look for IOPlatformSerialNumber
                let lines = output.components(separatedBy: .newlines)
                for line in lines {
                    if line.contains("IOPlatformSerialNumber") {
                        let parts = line.components(separatedBy: "=")
                        if parts.count > 1 {
                            return parts[1].trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: "\"", with: "")
                        }
                    }
                }
            }
        } catch {
            print("Error retrieving serial number: \(error)")
        }
        
        // Fallback to system_profiler if ioreg fails
        let profilerProcess = Process()
        profilerProcess.executableURL = URL(fileURLWithPath: "/usr/sbin/system_profiler")
        profilerProcess.arguments = ["SPHardwareDataType"]
        
        let profilerPipe = Pipe()
        profilerProcess.standardOutput = profilerPipe
        
        do {
            try profilerProcess.run()
            let data = profilerPipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8) {
                let lines = output.components(separatedBy: .newlines)
                for line in lines {
                    if line.contains("Serial Number") {
                        let parts = line.components(separatedBy: ":")
                        if parts.count > 1 {
                            return parts[1].trimmingCharacters(in: .whitespacesAndNewlines)
                        }
                    }
                }
            }
        } catch {
            print("Error retrieving serial number via system_profiler: \(error)")
        }
        
        return "UNKNOWN"
    }
    
    /// Retrieves the OS version
    public static func getOSVersion() -> String {
        let processInfo = ProcessInfo.processInfo
        let osVersion = processInfo.operatingSystemVersion
        return "\(osVersion.majorVersion).\(osVersion.minorVersion).\(osVersion.patchVersion)"
    }
    
    /// Retrieves the hardware model
    public static func getHardwareModel() -> String {
        var size = 0
        sysctlbyname("hw.model", nil, &size, nil, 0)
        var model = [CChar](repeating: 0, count: size)
        sysctlbyname("hw.model", &model, &size, nil, 0)
        
        // Handle deprecated String(cString:)
        if let last = model.last, last == 0 {
            model.removeLast()
        }
        let uint8Array = model.map { UInt8(bitPattern: $0) }
        return String(decoding: uint8Array, as: UTF8.self)
    }
    
    /// Retrieves the processor architecture
    public static func getArchitecture() -> String {
        #if arch(x86_64)
        return "x86_64"
        #elseif arch(arm64)
        return "arm64"
        #else
        return "unknown"
        #endif
    }
}
