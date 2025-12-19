import Foundation

/// Centralized version management for ReportMate macOS client
/// Version format: YYYY.MM.DD.HHMM (build timestamp)
public enum AppVersion {
    /// The current application version
    /// This is automatically set at build time via environment variable or defaults to current timestamp
    public static var current: String {
        // Check for build-time version from environment
        if let envVersion = ProcessInfo.processInfo.environment["REPORTMATE_VERSION"],
           !envVersion.isEmpty {
            return envVersion
        }
        
        // Generate timestamp-based version: YYYY.MM.DD.HHMM
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy.MM.dd.HHmm"
        formatter.timeZone = TimeZone(identifier: "UTC")
        return formatter.string(from: Date())
    }
    
    /// Short version for display
    public static var short: String {
        let parts = current.split(separator: ".")
        if parts.count >= 3 {
            return "\(parts[0]).\(parts[1]).\(parts[2])"
        }
        return current
    }
    
    /// Build number (HHMM portion or full version)
    public static var build: String {
        let parts = current.split(separator: ".")
        if parts.count >= 4 {
            return String(parts[3])
        }
        return current
    }
}
