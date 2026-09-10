import SwiftUI
import ReportMateKit

/// The fleet events feed (`/events`) and the ingest-failures report
/// (`/events/failures`) as a second mode. Port of `ClientEventsPage.tsx`:
/// a date range, kind chips (success, warnings and errors by default;
/// System and Info show alone), search, infinite scroll and a live refresh.
struct EventsView: View {
    enum Mode: String, CaseIterable, Identifiable {
        case feed = "Events", failures = "Check-in Failures"
        var id: String { rawValue }
    }

    @Environment(AppState.self) private var appState
    @State private var mode: Mode = .feed
    @State private var model = EventsFeedModel()
    @State private var search = ""

    private static let soloKinds: Set<EventKind> = [.system, .info]

    private var linkQuery: [String: String] {
        if mode == .failures { return ["failures": "1"] }
        var q: [String: String] = [:]
        if model.active != EventsFeedModel.defaultKinds { q["filter"] = model.active.map(\.rawValue).sorted().joined(separator: ",") }
        return q
    }

    private var filtered: [BundledEvent] {
        var list = EventBundling.bundle(model.events)
        if appState.platformFilter != .all { list = list.filter { appState.platformFilter.includes($0.platform) } }
        list = list.filter { e in
            let kinds = e.bundledKinds.isEmpty ? [e.kind] : e.bundledKinds
            return kinds.contains { model.active.contains($0) }
        }
        let q = search.trimmingCharacters(in: .whitespaces).lowercased()
        if !q.isEmpty {
            list = list.filter { e in
                e.id.lowercased().contains(q) || e.device.lowercased().contains(q) || e.bundledKinds.contains { $0.rawValue.contains(q) }
                    || e.message.lowercased().contains(q) || (e.deviceName ?? "").lowercased().contains(q) || (e.assetTag ?? "").lowercased().contains(q)
            }
        }
        return list
    }

    var body: some View {
        @Bindable var m = model
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Picker("", selection: $mode) { ForEach(Mode.allCases) { Text($0.rawValue).tag($0) } }
                    .pickerStyle(.segmented).fixedSize()
                if mode == .feed {
                    VStack(alignment: .leading, spacing: 1) {
                        Text("Events Feed").appFont(.callout, weight: .semibold)
                        Text("Real-time activity from fleet").appFont(.caption2).foregroundStyle(.secondary)
                    }
                    Spacer()
                    HStack(spacing: 6) {
                        Text("Date Range:").appFont(.caption).foregroundStyle(.secondary)
                        DatePicker("", selection: $m.startDate, in: ...m.endDate, displayedComponents: .date).labelsHidden()
                        Text("–").foregroundStyle(.secondary)
                        DatePicker("", selection: $m.endDate, in: m.startDate..., displayedComponents: .date).labelsHidden()
                    }
                    HStack(spacing: 6) {
                        Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                        TextField("Search events...", text: $search).textFieldStyle(.plain)
                        if !search.isEmpty { Button { search = "" } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary) }.buttonStyle(.plain) }
                    }
                    .padding(.horizontal, 10).padding(.vertical, 6)
                    .background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 8))
                    .frame(width: 240)
                } else {
                    Spacer()
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
        .task(id: "\(appState.configuration.normalizedBaseURL)|\(model.startDate.timeIntervalSince1970)|\(model.endDate.timeIntervalSince1970)") {
            await model.reload(api: appState.api)
        }
        .task(id: appState.configuration.normalizedBaseURL) {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(60))
                guard !Task.isCancelled else { break }
                await model.refreshLatest(api: appState.api)
            }
        }
        .onChange(of: model.active) { _, _ in model.scheduleReload(api: appState.api) }
        .onChange(of: appState.pendingDeepLink, initial: true) { _, _ in
            guard let link = appState.consumeDeepLink(for: .events) else { return }
            if case .eventsFailures = link.target { mode = .failures; return }
            mode = .feed
            let kinds = (link.query["filter"] ?? "").split(separator: ",").compactMap { EventKind(rawValue: String($0).lowercased()) }
            if !kinds.isEmpty { model.active = Set(kinds) }
        }
        .onChange(of: linkQuery, initial: true) { _, q in appState.linkQuery = q }
        .onChange(of: appState.refreshRequested) { _, _ in Task { await model.reload(api: appState.api) } }
    }

    private var chips: some View {
        HStack(spacing: 6) {
            ForEach(EventKind.filterOrder, id: \.self) { kind in
                let on = model.active.contains(kind)
                Button { toggle(kind) } label: {
                    HStack(spacing: 5) {
                        EventKindIcon(kind: kind).scaleEffect(0.75).frame(width: 16, height: 16)
                        Text(chipLabel(kind)).appFont(.caption, weight: .medium)
                    }
                    .padding(.horizontal, 10).padding(.vertical, 4)
                    .background(on ? chipColor(kind).opacity(0.22) : chipColor(kind).opacity(0.08), in: Capsule())
                    .overlay(Capsule().stroke(on ? chipColor(kind).opacity(0.7) : Color.clear))
                    .foregroundStyle(chipColor(kind))
                }
                .buttonStyle(.plain)
                .focusable(false)
            }
            Spacer()
            Text(model.events.count < model.loadedTotal || model.hasMore ? "\(filtered.count) shown" : "Showing all \(model.events.count) events")
                .appFont(.caption).foregroundStyle(.secondary)
            if model.loading || model.loadingMore { ProgressView().controlSize(.small) }
        }
        .padding(.horizontal, 16).padding(.vertical, 8)
        .background(Color.subtleBackground)
        .overlay(alignment: .bottom) { Divider() }
    }

    private func chipLabel(_ kind: EventKind) -> String {
        switch kind {
        case .warning: return "Warnings"
        case .error: return "Errors"
        default: return kind.displayName
        }
    }

    private func chipColor(_ kind: EventKind) -> Color {
        switch kind {
        case .success: return .green
        case .warning: return .yellow
        case .error: return .red
        case .info: return .blue
        case .system: return .purple
        }
    }

    /// System and Info show alone; the other three toggle together.
    private func toggle(_ kind: EventKind) {
        if Self.soloKinds.contains(kind) {
            if model.active.contains(kind), model.active.count == 1 { model.active = EventsFeedModel.defaultKinds } else { model.active = [kind] }
            return
        }
        var next = model.active.subtracting(Self.soloKinds)
        if next.contains(kind) { next.remove(kind) } else { next.insert(kind) }
        model.active = next
    }

    @ViewBuilder
    private var feed: some View {
        if model.loading, model.events.isEmpty {
            LoadingView(message: "Loading events…")
        } else if let error = model.error, model.events.isEmpty {
            ErrorBanner(message: error) { Task { await model.reload(api: appState.api) } }.padding()
            Spacer()
        } else {
            chips
            ScrollView {
                VStack(spacing: 0) {
                    if filtered.isEmpty {
                        EmptyStateView(title: model.events.isEmpty ? "No events yet" : "No events match the current filter",
                                       message: model.events.isEmpty ? "Waiting for fleet activity" : "Adjust the type filter, date range or search.", systemImage: "clock")
                    } else {
                        EventsTableView(events: filtered, style: .feed, autoFetchRows: 80, maxRows: 2000, onNearEnd: { model.loadMore(api: appState.api) })
                    }
                    if model.loadingMore {
                        ProgressView().controlSize(.small).padding(12)
                    } else if !model.hasMore, !model.events.isEmpty {
                        Text("Showing all \(model.events.count.formatted()) events").appFont(.caption).foregroundStyle(.secondary).padding(12)
                    }
                }
            }
        }
    }
}

/// Paged, live-refreshing event cache for the feed.
@MainActor
@Observable
final class EventsFeedModel {
    static let defaultKinds: Set<EventKind> = [.success, .warning, .error]
    static let pageSize = 100

    var events: [FleetEvent] = []
    var active: Set<EventKind> = EventsFeedModel.defaultKinds
    var startDate: Date = Calendar.current.startOfDay(for: Date().addingTimeInterval(-48 * 3600))
    var endDate: Date = Calendar.current.startOfDay(for: Date())
    var loading = false
    var loadingMore = false
    var hasMore = true
    var loadedTotal = 0
    var error: String?
    private var offset = 0
    private var reloadTask: Task<Void, Never>?
    private var moreTask: Task<Void, Never>?

    private var rangeStart: Date { Calendar.current.startOfDay(for: startDate) }
    private var rangeEnd: Date { Calendar.current.date(byAdding: .day, value: 1, to: Calendar.current.startOfDay(for: endDate))!.addingTimeInterval(-0.001) }

    private func merge(_ incoming: [FleetEvent]) {
        var byId: [String: FleetEvent] = [:]
        for e in events { byId[e.id] = e }
        for e in incoming { byId[e.id] = e }
        events = byId.values.sorted { ($0.ts ?? .distantPast) > ($1.ts ?? .distantPast) }
    }

    private func fetch(api: ReportMateAPI, offset: Int) async throws -> EventsPage {
        try await api.events(limit: Self.pageSize, offset: offset, kinds: active.sorted { $0.rawValue < $1.rawValue }, startDate: rangeStart, endDate: rangeEnd)
    }

    func reload(api: ReportMateAPI) async {
        reloadTask?.cancel()
        loading = true
        error = nil
        events = []
        offset = 0
        hasMore = true
        do {
            let page = try await fetch(api: api, offset: 0)
            merge(page.events)
            loadedTotal = page.total
            hasMore = page.events.count >= Self.pageSize
            offset = page.events.count
        } catch {
            self.error = error.localizedDescription
        }
        loading = false
    }

    /// Debounced reload after the chips change (the web waits 300 ms).
    func scheduleReload(api: ReportMateAPI) {
        reloadTask?.cancel()
        guard !active.isEmpty else { return }
        reloadTask = Task {
            try? await Task.sleep(for: .milliseconds(300))
            guard !Task.isCancelled else { return }
            await reload(api: api)
        }
    }

    func loadMore(api: ReportMateAPI) {
        guard hasMore, !loading, !loadingMore, moreTask == nil else { return }
        loadingMore = true
        moreTask = Task {
            defer { moreTask = nil; loadingMore = false }
            do {
                let page = try await fetch(api: api, offset: offset)
                merge(page.events)
                loadedTotal = page.total
                hasMore = page.events.count >= Self.pageSize
                offset += page.events.count
            } catch {
                self.error = error.localizedDescription
            }
        }
    }

    /// Pull the newest page and merge it, the way the web refreshes every minute.
    func refreshLatest(api: ReportMateAPI) async {
        guard !loading else { return }
        let today = Calendar.current.startOfDay(for: Date())
        if endDate < today, Calendar.current.isDate(endDate, inSameDayAs: today.addingTimeInterval(-86400)) {
            endDate = today
            return
        }
        if let page = try? await fetch(api: api, offset: 0) { merge(page.events); loadedTotal = page.total }
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
