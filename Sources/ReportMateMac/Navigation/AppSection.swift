import SwiftUI

/// Top-level sections, mirroring the web app's routes: the fleet views on
/// top, then one report per module.
enum AppSection: String, CaseIterable, Identifiable, Hashable, Codable {
    case dashboard, devices, events
    case installs, applications, system, management, identity, hardware, peripherals, security, network

    var id: String { rawValue }

    var title: String {
        switch self {
        case .dashboard: return "Dashboard"
        case .devices: return "Devices"
        case .events: return "Events"
        case .installs: return "Installs"
        case .applications: return "Applications"
        case .system: return "System"
        case .management: return "Management"
        case .identity: return "Identity"
        case .hardware: return "Hardware"
        case .peripherals: return "Peripherals"
        case .security: return "Security"
        case .network: return "Network"
        }
    }

    var systemImage: String {
        switch self {
        case .dashboard: return "square.grid.2x2"
        case .devices: return "laptopcomputer"
        case .events: return "clock"
        case .installs: return "arrow.down.circle"
        case .applications: return "app.badge"
        case .system: return "gearshape"
        case .management: return "checkmark.shield"
        case .identity: return "person.2"
        case .hardware: return "cpu"
        case .peripherals: return "cable.connector"
        case .security: return "lock"
        case .network: return "wifi"
        }
    }

    /// The web route this section corresponds to.
    var webPath: String { self == .dashboard ? "/dashboard" : "/\(rawValue)" }

    var isReport: Bool {
        switch self {
        case .dashboard, .devices, .events: return false
        default: return true
        }
    }

    static var fleet: [AppSection] { allCases.filter { !$0.isReport } }
    static var reports: [AppSection] { allCases.filter(\.isReport) }

    var keyEquivalent: KeyEquivalent {
        let index = AppSection.allCases.firstIndex(of: self) ?? 0
        let digits = Array("123456789")
        return index < digits.count ? KeyEquivalent(digits[index]) : KeyEquivalent("0")
    }

    var accent: Color {
        switch self {
        case .dashboard: return .blue
        case .devices: return .blue
        case .events: return .gray
        case .installs: return .green
        case .applications: return .blue
        case .system: return .purple
        case .management: return .yellow
        case .identity: return .indigo
        case .hardware: return .orange
        case .peripherals: return .cyan
        case .security: return .red
        case .network: return .teal
        }
    }
}

/// A navigation destination pushed on the detail stack.
enum Route: Hashable {
    case device(serial: String, tab: DeviceTab?, filter: String?)
    case applicationUsage(appName: String)

    static func device(_ serial: String) -> Route { .device(serial: serial, tab: nil, filter: nil) }
}
