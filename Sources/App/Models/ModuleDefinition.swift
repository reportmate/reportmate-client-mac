import Foundation

struct ModuleDefinition: Identifiable, Sendable {
    let id: String
    let displayName: String
    let systemImage: String
    let description: String

    static let all: [ModuleDefinition] = [
        .init(id: "inventory", displayName: "Inventory", systemImage: "list.clipboard", description: "Asset tracking and inventory"),
        .init(id: "installs", displayName: "Installs", systemImage: "arrow.down.circle", description: "Recent software installs"),
        .init(id: "applications", displayName: "Applications", systemImage: "app.badge", description: "Installed apps and usage"),
        .init(id: "system", displayName: "System", systemImage: "gearshape", description: "OS version, uptime, timezone"),
        .init(id: "management", displayName: "Management", systemImage: "shield.checkered", description: "MDM enrollment and management"),
        .init(id: "identity", displayName: "Identity", systemImage: "person.2", description: "User identity and directory services"),
        .init(id: "hardware", displayName: "Hardware", systemImage: "cpu", description: "CPU, memory, storage, battery"),
        .init(id: "peripherals", displayName: "Peripherals", systemImage: "cable.connector", description: "USB and Thunderbolt devices"),
        .init(id: "security", displayName: "Security", systemImage: "lock", description: "FileVault, Firewall, SIP, Gatekeeper"),
        .init(id: "network", displayName: "Network", systemImage: "wifi", description: "Interfaces, Wi-Fi, IP addresses"),
    ]
}
