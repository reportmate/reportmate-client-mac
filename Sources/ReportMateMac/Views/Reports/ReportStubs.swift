import SwiftUI
import ReportMateKit

// Temporary generic report and tab views. Each is replaced by a faithful port
// of the corresponding web page as the parity work proceeds; the generic
// version keeps the app usable in the meantime.

struct GenericFleetReport: View {
    let section: AppSection
    @State private var model: FleetReportModel

    init(section: AppSection, path: String) {
        self.section = section
        _model = State(initialValue: FleetReportModel(path: path))
    }

    var body: some View {
        FleetReportContainer(section: section, model: model) { rows in
            Table(rows) {
                TableColumn("Device") { DeviceLink(row: $0, tab: DeviceTab(rawValue: section.rawValue)) }.width(min: 180, ideal: 240)
                TableColumn("Serial") { Text($0.serialNumber).appFont(.body, design: .monospaced) }.width(min: 110, ideal: 140)
                TableColumn("Asset") { Text($0.inventory.assetTag ?? "-").appFont(.body, design: .monospaced) }.width(min: 80, ideal: 110)
                TableColumn("Usage") { r in if let u = r.inventory.usage { Pill(u, tone: .blue) } else { Text("-") } }.width(90)
                TableColumn("Catalog") { r in if let c = r.inventory.catalog { Pill(c, tone: DevicesView.catalogTone(c)) } else { Text("-") } }.width(100)
                TableColumn("Location") { Text($0.inventory.location ?? "-").appFont(.body) }.width(min: 90, ideal: 130)
                TableColumn("Last Seen") { Text(TimeFormatting.relative($0.lastSeen)).appFont(.body).foregroundStyle(.secondary) }.width(110)
            }
        }
    }
}

struct InstallsReportView: View { var body: some View { GenericFleetReport(section: .installs, path: "/installs") } }
struct ApplicationsReportView: View { var body: some View { GenericFleetReport(section: .applications, path: "/applications") } }

struct ApplicationUsageDetailView: View {
    let appName: String
    var body: some View {
        EmptyStateView(title: appName, message: "Application usage detail is being ported.", systemImage: "app.badge")
    }
}
