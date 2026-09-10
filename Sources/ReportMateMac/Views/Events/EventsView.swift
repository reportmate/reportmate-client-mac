import SwiftUI
import ReportMateKit

/// The fleet events feed (`/events`) with a type filter, search, paging and
/// the ingest-failures report (`/events/failures`) as a second mode.
struct EventsView: View {
    enum Mode: String, CaseIterable, Identifiable {
        case feed = "Events", failures = "Check-in Failures"
        var id: String { rawValue }
    }

    @Environment(AppState.self) private var appState
    @State private var mode: Mode = .feed
    @State private var events: [FleetEvent] = []
    @State private var total = 0
    @State private var loading = false
    @State private var error: String?
    @State private var search = ""
    private static let defaultHidden: Set<EventKind> = [.info, .system]
    @State private var hidden: Set<EventKind> = EventsView.defaultHidden
    @State private var pageSize = 200

    private var bundled: [BundledEvent] {
        var list = EventBundling.bundle(events)
        if !hidden.isEmpty { list = list.filter { !hidden.contains($0.kind) } }
        if appState.platformFilter != .all { list = list.filter { appState.platformFilter.includes($0.platform) } }
        let q = search.trimmingCharacters(in: .whitespaces).lowercased()
        if !q.isEmpty {
            list = list.filter { e in
                e.message.lowercased().contains(q) || e.device.lowercased().contains(q) || (e.deviceName ?? "").lowercased().contains(q) || (e.assetTag ?? "").lowercased().contains(q)
            }
        }
        return list
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Picker("", selection: $mode) { ForEach(Mode.allCases) { Text($0.rawValue).tag($0) } }
                    .pickerStyle(.segmented).fixedSize()
                Spacer()
                if mode == .feed {
                    EventTypeFilterMenu(hidden: $hidden, defaultHidden: EventsView.defaultHidden)
                    HStack(spacing: 6) {
                        Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                        TextField("Search events…", text: $search).textFieldStyle(.plain)
                    }
                    .padding(.horizontal, 10).padding(.vertical, 6)
                    .background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 8))
                    .frame(width: 240)
                }
            }
            .padding(.horizontal, 16).padding(.vertical, 10)
            .overlay(alignment: .bottom) { Divider() }

            switch mode {
            case .feed: feed
            case .failures: IngestFailuresView()
            }
        }
        .navigationTitle("Events")
        .task(id: appState.configuration) { await load() }
        .onChange(of: appState.refreshRequested) { _, _ in Task { await load() } }
    }

    @ViewBuilder
    private var feed: some View {
        if loading, events.isEmpty {
            LoadingView(message: "Loading events…")
        } else if let error, events.isEmpty {
            ErrorBanner(message: error) { Task { await load() } }.padding()
            Spacer()
        } else {
            ScrollView {
                VStack(spacing: 0) {
                    HStack {
                        Text("\(bundled.count) of \(total) events").appFont(.caption).foregroundStyle(.secondary)
                        Spacer()
                        if events.count < total {
                            Button("Load more") { Task { await loadMore() } }.appFont(.caption).disabled(loading)
                        }
                        if loading { ProgressView().controlSize(.small) }
                    }
                    .padding(.horizontal, 16).padding(.vertical, 8)
                    if bundled.isEmpty {
                        EmptyStateView(title: "No events match", message: "Adjust the type filter or search.", systemImage: "clock")
                    } else {
                        EventsTableView(events: bundled, autoFetchRows: 80, maxRows: 500)
                    }
                }
            }
        }
    }

    private func load() async {
        loading = true
        error = nil
        do {
            let page = try await appState.api.events(limit: pageSize)
            events = page.events
            total = page.total
        } catch {
            self.error = error.localizedDescription
            appState.note(error)
        }
        loading = false
    }

    private func loadMore() async {
        loading = true
        do {
            let page = try await appState.api.events(limit: pageSize, offset: events.count)
            let known = Set(events.map(\.id))
            events.append(contentsOf: page.events.filter { !known.contains($0.id) })
            total = page.total
        } catch {
            self.error = error.localizedDescription
        }
        loading = false
    }
}

/// Rejected device check-ins: the devices that reached the server but were
/// turned away, grouped by reason, with the raw rows below.
struct IngestFailuresView: View {
    @Environment(AppState.self) private var appState
    @State private var page: IngestFailuresPage?
    @State private var loading = false
    @State private var error: String?
    @State private var outcome = "rejected"
    @State private var hours = 168
    @State private var serial = ""
    @State private var reason: String?

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Picker("Outcome", selection: $outcome) {
                    Text("Rejected").tag("rejected"); Text("Retried").tag("retried"); Text("Accepted (repaired)").tag("accepted"); Text("All").tag("all")
                }
                .fixedSize()
                Picker("Window", selection: $hours) {
                    Text("24 hours").tag(24); Text("7 days").tag(168); Text("30 days").tag(720); Text("90 days").tag(2160)
                }
                .fixedSize()
                TextField("Serial contains…", text: $serial).textFieldStyle(.roundedBorder).frame(width: 180)
                if let reason { Pill(reason, tone: .red); Button("Clear") { self.reason = nil }.appFont(.caption) }
                Spacer()
                if let p = page {
                    HStack(spacing: 10) {
                        countPill("rejected", p.rejected, .red)
                        countPill("retried", p.retried, .yellow)
                        countPill("accepted", p.accepted, .green)
                    }
                }
            }
            .padding(.horizontal, 16).padding(.vertical, 10)
            .overlay(alignment: .bottom) { Divider() }

            if loading, page == nil {
                LoadingView(message: "Loading check-in failures…")
            } else if let error, page == nil {
                ErrorBanner(message: error) { Task { await load() } }.padding()
                Spacer()
            } else if let page {
                ScrollView {
                    VStack(alignment: .leading, spacing: 16) {
                        if !page.summary.isEmpty {
                            Card {
                                VStack(spacing: 0) {
                                    CardHeader("By reason", subtitle: "Click a reason to filter", systemImage: "list.bullet.rectangle", tone: .red)
                                    VStack(spacing: 6) {
                                        ForEach(page.summary) { s in
                                            Button { reason = s.reason } label: {
                                                HStack {
                                                    Text(s.reason).appFont(.body, design: .monospaced)
                                                    Spacer()
                                                    Text("\(s.devices) devices").appFont(.caption).foregroundStyle(.secondary)
                                                    Text("\(s.count)").appFont(.body, weight: .semibold).monospacedDigit().frame(width: 50, alignment: .trailing)
                                                    Text(TimeFormatting.relative(s.lastSeen)).appFont(.caption).foregroundStyle(.tertiary).frame(width: 110, alignment: .trailing)
                                                }
                                                .contentShape(Rectangle())
                                            }
                                            .buttonStyle(.plain)
                                        }
                                    }
                                    .padding(16)
                                }
                            }
                        }
                        Card {
                            VStack(spacing: 0) {
                                CardHeader("Check-ins", subtitle: "\(page.failures.count) of \(page.total) in the last \(hours) hours", systemImage: "exclamationmark.octagon", tone: .orange)
                                if page.failures.isEmpty {
                                    EmptyStateView(title: "Nothing recorded", message: "No device check-ins matched this window.", systemImage: "checkmark.circle")
                                } else {
                                    Table(page.failures) {
                                        TableColumn("Time") { f in Text(TimeFormatting.exact(f.ts)).appFont(.caption, design: .monospaced) }.width(140)
                                        TableColumn("Outcome") { f in Pill(f.outcome, tone: f.outcome == "rejected" ? .red : f.outcome == "retried" ? .yellow : .green) }.width(90)
                                        TableColumn("Reason") { f in Text(f.reason).appFont(.caption, design: .monospaced) }.width(min: 140, ideal: 180)
                                        TableColumn("Device") { f in
                                            VStack(alignment: .leading) {
                                                Text(f.deviceName ?? f.serialNumber ?? "—").appFont(.body)
                                                if let s = f.serialNumber, f.deviceName != nil { Text(s).appFont(.caption, design: .monospaced).foregroundStyle(.secondary) }
                                            }
                                        }
                                        TableColumn("Platform") { f in Text(f.platform ?? "—").appFont(.caption) }.width(80)
                                        TableColumn("Client") { f in Text(f.clientVersion ?? "—").appFont(.caption) }.width(90)
                                        TableColumn("Detail") { f in Text(f.detail ?? "").appFont(.caption).foregroundStyle(.secondary).lineLimit(2).help(f.detail ?? "") }
                                        TableColumn("From") { f in Text(f.clientIp ?? "").appFont(.caption, design: .monospaced).foregroundStyle(.secondary) }.width(110)
                                    }
                                    .frame(minHeight: 300, idealHeight: CGFloat(page.failures.count) * 30 + 40)
                                }
                            }
                        }
                    }
                    .padding(16)
                }
            }
        }
        .task(id: "\(outcome)|\(hours)|\(serial)|\(reason ?? "")") { await load() }
        .onChange(of: appState.refreshRequested) { _, _ in Task { await load() } }
    }

    private func countPill(_ label: String, _ n: Int, _ tone: Tone) -> some View {
        HStack(spacing: 4) {
            Text("\(n)").appFont(.caption, weight: .semibold).monospacedDigit()
            Text(label).appFont(.caption)
        }
        .foregroundStyle(tone.color)
    }

    private func load() async {
        loading = true
        error = nil
        do {
            page = try await appState.api.ingestFailures(limit: 200, serial: serial.isEmpty ? nil : serial, reason: reason, hours: hours, outcome: outcome)
        } catch {
            self.error = error.localizedDescription
            appState.note(error)
        }
        loading = false
    }
}
