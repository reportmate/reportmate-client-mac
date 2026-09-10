import SwiftUI
import ReportMateKit

/// Recent Events on the dashboard: bundled, filtered (Info and System hidden
/// by default), with the connection dot in the header.
struct RecentEventsWidget: View {
    @Environment(AppState.self) private var appState
    let events: [FleetEvent]
    let connectionStatus: DashboardModel.ConnectionStatus
    let lastUpdate: Date?
    private static let defaultHidden: Set<EventKind> = [.info, .system]
    @State private var hidden: Set<EventKind> = RecentEventsWidget.defaultHidden

    private var bundled: [BundledEvent] {
        let all = EventBundling.bundle(events)
        return hidden.isEmpty ? all : all.filter { !hidden.contains($0.kind) }
    }

    var body: some View {
        Card {
            VStack(spacing: 0) {
                CardHeader("Recent Events", subtitle: "Live activity from fleet", action: { appState.section = .events }) {
                    HStack(spacing: 10) {
                        EventTypeFilterMenu(hidden: $hidden, defaultHidden: RecentEventsWidget.defaultHidden)
                        connectionDot
                    }
                }
                if events.isEmpty {
                    EmptyStateView(title: "No events yet", message: "Waiting for fleet activity", systemImage: "clock")
                        .frame(minHeight: 300)
                } else if bundled.isEmpty {
                    Text("No events match the current filter").appFont(.callout).foregroundStyle(.secondary).padding(30)
                        .frame(maxWidth: .infinity, minHeight: 300)
                } else {
                    ScrollView {
                        EventsTableView(events: bundled)
                    }
                    .frame(height: 560)
                }
            }
        }
    }

    private var connectionDot: some View {
        let (color, text, tip): (Color, String, String) = {
            switch connectionStatus {
            case .polling: return (.blue, "Polling", "Polling the API every 30 seconds")
            case .connecting: return (.yellow, "Connecting", "Loading events")
            case .error: return (.red, "Offline", "Connection failed, events may be delayed")
            }
        }()
        return HStack(spacing: 5) {
            Circle().fill(color).frame(width: 8, height: 8)
            Text(text).appFont(.caption, weight: .medium).foregroundStyle(color)
        }
        .padding(.horizontal, 8).padding(.vertical, 4)
        .background(Color.subtleBackground, in: Capsule())
        .help(lastUpdate.map { "\(tip). Last update \(TimeFormatting.relative($0))" } ?? tip)
    }
}
