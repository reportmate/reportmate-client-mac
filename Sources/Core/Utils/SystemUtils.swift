import Foundation
import IOKit

/// Utility class for retrieving system information
public class SystemUtils {

    /// Retrieves the system serial number.
    ///
    /// Read straight from the IO registry. This previously shelled out to `ioreg -l` and grepped
    /// its output for `IOPlatformSerialNumber`, with `system_profiler SPHardwareDataType` as a
    /// fallback — two unbounded subprocess reads on the path that establishes device identity,
    /// which runs before the payload can be assembled. A hang in either meant the device never
    /// reported at all.
    ///
    /// `ioreg -l` also serialises the *entire* IO registry — megabytes of text — to find one
    /// string that `IORegistryEntryCreateCFProperty` returns directly. Removing the subprocess
    /// removes the need to bound it, and keeps this function synchronous so no caller changes.
    public static func getSerialNumber() -> String {
        let matching = IOServiceMatching("IOPlatformExpertDevice")
        let service = IOServiceGetMatchingService(kIOMainPortDefault, matching)
        guard service != IO_OBJECT_NULL else {
            print("Error retrieving serial number: IOPlatformExpertDevice not found")
            return "UNKNOWN"
        }
        defer { IOObjectRelease(service) }

        guard let property = IORegistryEntryCreateCFProperty(
            service,
            kIOPlatformSerialNumberKey as CFString,
            kCFAllocatorDefault,
            0
        ) else {
            print("Error retrieving serial number: IOPlatformSerialNumber unset")
            return "UNKNOWN"
        }

        let serial = (property.takeRetainedValue() as? String)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

        return serial.isEmpty ? "UNKNOWN" : serial
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
