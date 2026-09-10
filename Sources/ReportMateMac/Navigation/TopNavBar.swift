import SwiftUI

/// The web app's header navigation: Dashboard, Devices, Events, then the
/// reports. Wide windows show every report as its own tab; narrow ones
/// collapse the reports into a menu, like the web's Reports dropdown.
struct TopNavBar: View {
    @Environment(AppState.self) private var appState

    var body: some View {
        HStack(spacing: 12) {
            brand
            ViewThatFits(in: .horizontal) {
                HStack(spacing: 4) {
                    ForEach(AppSection.fleet) { tab($0) }
                    Divider().frame(height: 18).padding(.horizontal, 4)
                    ForEach(AppSection.reports) { tab($0) }
                }
                HStack(spacing: 4) {
                    ForEach(AppSection.fleet) { tab($0) }
                    reportsMenu
                }
            }
            Spacer(minLength: 8)
            connection
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 7)
        .background(Color.cardBackground)
        .overlay(alignment: .bottom) { Divider() }
    }

    private var brand: some View {
        Button { select(.dashboard) } label: {
            HStack(spacing: 6) {
                Image(systemName: "chart.bar.doc.horizontal.fill").foregroundStyle(.blue)
                Text("ReportMate").appFont(.callout, weight: .semibold)
            }
        }
        .buttonStyle(.plain)
        .help("Dashboard")
    }

    private func select(_ section: AppSection) {
        appState.path = NavigationPath()
        appState.section = section
    }

    private func tab(_ section: AppSection) -> some View {
        let active = appState.section == section
        return Button { select(section) } label: {
            HStack(spacing: 5) {
                Image(systemName: section.systemImage).appFont(fixed: 11)
                Text(section.title).appFont(.callout, weight: active ? .semibold : .regular)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(active ? section.accent.opacity(0.14) : Color.clear, in: RoundedRectangle(cornerRadius: 6))
            .foregroundStyle(active ? section.accent : Color.secondary)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .focusable(false)
        .help("\(section.title) (⌘\(String(section.keyEquivalent.character)))")
    }

    private var reportsMenu: some View {
        let current = appState.section.isReport ? appState.section : nil
        return Menu {
            ForEach(AppSection.reports) { section in
                Button { select(section) } label: { Label(section.title, systemImage: section.systemImage) }
            }
        } label: {
            HStack(spacing: 5) {
                Image(systemName: current?.systemImage ?? "doc.text.magnifyingglass").appFont(fixed: 11)
                Text(current.map { "Reports · \($0.title)" } ?? "Reports").appFont(.callout, weight: current == nil ? .regular : .semibold)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(current.map { $0.accent.opacity(0.14) } ?? Color.clear, in: RoundedRectangle(cornerRadius: 6))
            .foregroundStyle(current?.accent ?? Color.secondary)
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
    }

    private var connection: some View {
        HStack(spacing: 6) {
            Circle().fill(appState.isConfigured ? (appState.authProblem == nil ? Color.green : Color.red) : Color.gray).frame(width: 7, height: 7)
            Text(appState.isConfigured ? hostLabel : "Not connected")
                .appFont(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
        }
        .help(appState.authProblem ?? appState.configuration.normalizedBaseURL)
    }

    private var hostLabel: String {
        URL(string: appState.configuration.normalizedBaseURL)?.host ?? appState.configuration.normalizedBaseURL
    }
}
