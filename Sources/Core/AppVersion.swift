import Foundation

/// Centralized version management for ReportMate macOS client
/// Version format: YYYY.MM.DD.HHMM (build timestamp)
/// This file is auto-generated at build time - do not edit manually
public enum AppVersion {
    /// The current application version (generated at build time)
    public static let current: String = "YYYY.MM.DD.HHMM"
    
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
