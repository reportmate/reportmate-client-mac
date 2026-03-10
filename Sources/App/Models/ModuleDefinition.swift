import Foundation

struct ModuleDefinition: Identifiable, Sendable {
    let id: String
    let displayName: String
    let systemImage: String
    let description: String

    static let all: [ModuleDefinition] = [
        .init(id: "hardware", displayName: "Hardware", systemImage: "cpu", description: "CPU, memory, storage, battery"),
        .init(id: "system", displayName: "System", systemImage: "desktopcomputer", description: "OS version, uptime, timezone"),
        .init(id: "network", displayName: "Network", systemImage: "network", description: "Interfaces, Wi-Fi, IP addresses"),
        .init(id: "security", displayName: "Security", systemImage: "lock.shield", description: "FileVault, Firewall, SIP, Gatekeeper"),
        .init(id: "applications", displayName: "Applications", systemImage: "app.badge", description: "Installed apps and usage"),
        .init(id: "management", displayName: "Management", systemImage: "building.2", description: "MDM enrollment and management"),
        .init(id: "inventory", displayName: "Inventory", systemImage: "list.clipboard", description: "Asset tracking and inventory"),
        .init(id: "profiles", displayName: "Profiles", systemImage: "person.badge.shield.checkmark", description: "Configuration profiles"),
        .init(id: "displays", displayName: "Displays", systemImage: "display", description: "Connected displays"),
        .init(id: "printers", displayName: "Printers", systemImage: "printer", description: "Configured printers"),
        .init(id: "peripherals", displayName: "Peripherals", systemImage: "cable.connector", description: "USB and Thunderbolt devices"),
        .init(id: "installs", displayName: "Installs", systemImage: "arrow.down.app", description: "Recent software installs"),
        .init(id: "identity", displayName: "Identity", systemImage: "person.circle", description: "User identity and directory services"),
    ]
}
