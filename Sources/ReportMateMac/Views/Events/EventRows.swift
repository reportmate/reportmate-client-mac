import SwiftUI
import AppKit
import ReportMateKit

/// Payload cache shared by every events list so a row's details load once.
@MainActor
@Observable
final class EventPayloadCache {
    static let shared = EventPayloadCache()
    private(set) var payloads: [String: JSONValue] = [:]
    private var inflight: [String: Task<JSONValue, Error>] = [:]

    func payload(for id: String) -> JSONValue? { payloads[id] }

    func load(_ id: String, api: ReportMateAPI) async -> JSONValue? {
        if let p = payloads[id] { return p }
        if let task = inflight[id] { return try? await task.value }
        let task = Task { try await api.eventPayload(id) }
        inflight[id] = task
        defer { inflight[id] = nil }
        if let p = try? await task.value {
            payloads[id] = p
            return p
        }
        return nil
    }
}

/// The circular status icon in the Type column.
struct EventKindIcon: View {
    let kind: EventKind
    var removal = false

    var body: some View {
        let (color, symbol): (Color, String) = removal ? (.purple, "checkmark") : {
            switch kind {
            case .success: return (.green, "checkmark")
            case .warning: return (.yellow, "exclamationmark")
            case .error: return (.red, "xmark")
            case .info: return (.blue, "info")
            case .system: return (.purple, "bolt.fill")
            }
        }()
        ZStack {
            Circle().fill(color.opacity(0.85))
            Image(systemName: symbol).appFont(fixed: 10, weight: .bold).foregroundStyle(.white)
        }
        .frame(width: 22, height: 22)
        .help(removal ? "Removed" : kind.displayName)
    }
}

/// The message cell: the items a run installed, warned about or failed on,
/// or the summary text while the payload loads.
struct EventInlineLinesView: View {
    @Environment(AppState.self) private var appState
    let event: BundledEvent
    var autoFetch = true
    var itemsOnly = true
    @State private var payload: JSONValue?
    @State private var loading = false

    private var shouldFetch: Bool { [.success, .warning, .error].contains(event.kind) }

    var body: some View {
        let details = EventInlineDetails.extract(payload ?? event.payload)
        let errors = itemsOnly ? EventInlineDetails.itemsOnly(details.errors) : details.errors
        let warnings = itemsOnly ? EventInlineDetails.itemsOnly(details.warnings) : details.warnings
        let successTone: Color = (details.isRemoval || event.isRemoval) ? .purple : .green
        VStack(alignment: .leading, spacing: 3) {
            if errors.isEmpty, warnings.isEmpty, details.successes.isEmpty {
                Text(event.message)
                    .appFont(.body)
                    .foregroundStyle(summaryColor(successTone))
                    .fixedSize(horizontal: false, vertical: true)
                if loading { Text("Loading details…").appFont(.caption).foregroundStyle(.tertiary).italic() }
            } else {
                ForEach(Array(errors.enumerated()), id: \.offset) { _, line in lineView(line, tone: .red) }
                ForEach(Array(warnings.enumerated()), id: \.offset) { _, line in lineView(line, tone: .yellow) }
                ForEach(details.successes, id: \.self) { s in
                    Text(s).appFont(.body).foregroundStyle(successTone).fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .task(id: event.id) {
            guard !event.isBundle, autoFetch, shouldFetch, payload == nil, event.payload == nil else { return }
            if let cached = EventPayloadCache.shared.payload(for: event.id) { payload = cached; return }
            loading = true
            payload = await EventPayloadCache.shared.load(event.id, api: appState.api)
            loading = false
        }
    }

    private func summaryColor(_ successTone: Color) -> Color {
        switch event.kind {
        case .success: return successTone
        case .warning: return .yellow
        case .error: return .red
        default: return .primary
        }
    }

    @ViewBuilder
    private func lineView(_ line: InlineLine, tone: Color) -> some View {
        if line.isMessage {
            Text(line.text)
                .appFont(.caption, design: .monospaced)
                .foregroundStyle(tone)
                .padding(.horizontal, 8).padding(.vertical, 5)
                .background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 6))
                .fixedSize(horizontal: false, vertical: true)
        } else {
            Text(line.text).appFont(.body).foregroundStyle(tone).fixedSize(horizontal: false, vertical: true)
        }
    }
}

/// Loads every payload behind a row (one per bundled event id).
@MainActor
@Observable
final class EventPayloads {
    var payloads: [String: JSONValue] = [:]
    var loading = false

    func load(_ ids: [String], api: ReportMateAPI) async {
        loading = true
        for id in ids {
            if let p = await EventPayloadCache.shared.load(id, api: api) { payloads[id] = p }
        }
        loading = false
    }
}

/// Expanded detail under an event row: every line of the payload, then the raw JSON.
struct EventDetailsView: View {
    @Environment(AppState.self) private var appState
    let event: BundledEvent
    var includeRaw = true
    @State private var store = EventPayloads()
    @State private var showRaw = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if store.loading, store.payloads.isEmpty {
                ProgressView().controlSize(.small)
            }
            ForEach(event.eventIds, id: \.self) { id in
                if let p = store.payloads[id] {
                    let details = EventInlineDetails.extract(p)
                    if !details.isEmpty {
                        VStack(alignment: .leading, spacing: 4) {
                            ForEach(Array(details.errors.enumerated()), id: \.offset) { _, l in detailLine(l, .red) }
                            ForEach(Array(details.warnings.enumerated()), id: \.offset) { _, l in detailLine(l, .yellow) }
                            ForEach(details.successes, id: \.self) { s in Text(s).appFont(.callout).foregroundStyle(details.isRemoval ? .purple : .green) }
                        }
                    }
                    metadata(p)
                }
            }
            if includeRaw {
                if !store.payloads.isEmpty {
                    DisclosureGroup("Raw payload", isExpanded: $showRaw) {
                        ScrollView(.horizontal) {
                            Text(EventPayloadText.format(event: event, payloads: store.payloads))
                                .appFont(.caption, design: .monospaced)
                                .textSelection(.enabled)
                                .padding(8)
                        }
                        .frame(maxHeight: 320)
                        .background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 6))
                    }
                    .appFont(.caption)
                } else if !store.loading {
                    Text("No payload recorded for this event.").appFont(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .task(id: event.id) { await store.load(event.eventIds, api: appState.api) }
    }

    private func detailLine(_ line: InlineLine, _ tone: Color) -> some View {
        Text(line.text)
            .appFont(line.isMessage ? .caption : .callout, design: line.isMessage ? .monospaced : .default)
            .foregroundStyle(tone)
            .fixedSize(horizontal: false, vertical: true)
    }

    @ViewBuilder
    private func metadata(_ p: JSONValue) -> some View {
        let pairs: [(String, String)] = [
            ("Run type", p.firstString("run_type", "runType") ?? ""),
            ("Session", p.firstString("session_id", "sessionId") ?? ""),
            ("Duration", p["duration_seconds"].double.map { TimeFormatting.duration(seconds: $0) } ?? ""),
            ("Modules", EventBundling.moduleNames(in: p).joined(separator: ", ")),
            ("Client", p.firstString("client_version", "clientVersion") ?? p["metadata"]["clientVersion"].string ?? ""),
        ].filter { !$0.1.isEmpty }
        if !pairs.isEmpty {
            HStack(spacing: 14) {
                ForEach(pairs, id: \.0) { pair in
                    HStack(spacing: 4) {
                        Text(pair.0).appFont(.caption).foregroundStyle(.tertiary)
                        Text(pair.1).appFont(.caption).foregroundStyle(.secondary)
                    }
                }
            }
        }
    }
}

/// The web `formatFullPayload`: a bundle summary followed by each event's JSON.
enum EventPayloadText {
    static func format(event: BundledEvent, payloads: [String: JSONValue]) -> String {
        if event.isBundle {
            var modules = Set<String>()
            for id in event.eventIds {
                guard let p = payloads[id] else { continue }
                EventBundling.moduleNames(in: p).forEach { modules.insert($0) }
                if !p["full_installs_data"].isNull || !p["module_status"].isNull || (!p["session_id"].isNull && (!p["success_count"].isNull || !p["error_count"].isNull)) {
                    modules.insert("installs")
                }
            }
            var out = "Bundle Summary:\n- Event Count: \(event.count)\n"
            if !modules.isEmpty { out += "- Modules: \(modules.map { $0.prefix(1).uppercased() + $0.dropFirst() }.sorted().joined(separator: ", "))\n" }
            out += "- Event Types: \(event.bundledKinds.map(\.rawValue).joined(separator: ", "))\n"
            out += "- Message: \(event.message)\n\nIndividual Event Payloads:\n\(String(repeating: "=", count: 50))\n\n"
            for (i, id) in event.eventIds.enumerated() {
                out += "Event \(i + 1) (ID: \(id)):\n\(String(repeating: "-", count: 30))\n"
                if let p = payloads[id] {
                    if !p["full_installs_data"].isNull || !p["module_status"].isNull {
                        out += "Module(s): Installs\n"
                        if let rt = p.firstString("run_type", "runType") { out += "Run Type: \(rt)\n" }
                        if let sid = p.firstString("session_id", "sessionId") { out += "Session ID: \(sid)\n" }
                        out += "\n--- Installs Data ---\n"
                    }
                    out += p.string ?? p.prettyPrinted
                } else {
                    out += "Error: payload unavailable"
                }
                out += "\n\n"
            }
            return out
        }
        guard let p = payloads[event.id] ?? event.payload else { return "No payload available" }
        return p.string ?? p.prettyPrinted
    }

    /// Lines matching `search` (case-insensitive) with one line of context
    /// either side, the match highlighted; the whole text when not searching.
    static func highlighted(_ text: String, search: String) -> AttributedString {
        let q = search.trimmingCharacters(in: .whitespaces)
        guard q.count >= 2 else { return AttributedString(text) }
        let lines = text.components(separatedBy: "\n")
        var keep = Set<Int>()
        for (i, line) in lines.enumerated() where line.range(of: q, options: .caseInsensitive) != nil {
            if i > 0 { keep.insert(i - 1) }
            keep.insert(i)
            if i < lines.count - 1 { keep.insert(i + 1) }
        }
        if keep.isEmpty { return AttributedString("No lines match \"\(q)\".") }
        var out = AttributedString()
        var last = -2
        for i in keep.sorted() {
            if i > last + 1, !out.characters.isEmpty {
                var gap = AttributedString("…\n")
                gap.foregroundColor = .secondary
                out += gap
            }
            out += highlightLine(lines[i], q)
            out += AttributedString("\n")
            last = i
        }
        return out
    }

    private static func highlightLine(_ line: String, _ q: String) -> AttributedString {
        var out = AttributedString()
        var rest = line[...]
        while let r = rest.range(of: q, options: .caseInsensitive) {
            out += AttributedString(String(rest[..<r.lowerBound]))
            var hit = AttributedString(String(rest[r]))
            hit.backgroundColor = Color.yellow.opacity(0.5)
            hit.inlinePresentationIntent = .stronglyEmphasized
            out += hit
            rest = rest[r.upperBound...]
        }
        out += AttributedString(String(rest))
        return out
    }
}

/// "Last Run Summary" / "Packages with Issues" above an installs event's details.
struct LastRunSummaryView: View {
    let summary: LastRunSummary

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Text(summary.title).appFont(.callout, weight: .semibold)
                if let rt = summary.runType { Pill(rt, tone: .gray) }
                if let s = summary.successCount, s > 0 { Pill("\(s) succeeded", tone: .green) }
                if let e = summary.errorCount, e > 0 { Pill("\(e) failed", tone: .red) }
            }
            if summary.hasItems {
                Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 4) {
                    GridRow {
                        Text("PACKAGE").appFont(.caption2, weight: .semibold).foregroundStyle(.secondary)
                        Text("VERSION").appFont(.caption2, weight: .semibold).foregroundStyle(.secondary)
                        Text("STATUS").appFont(.caption2, weight: .semibold).foregroundStyle(.secondary)
                    }
                    ForEach(summary.items) { item in
                        GridRow {
                            Text(item.name).appFont(.caption, weight: .medium).lineLimit(1)
                            Text(item.version.isEmpty ? "-" : item.version).appFont(.caption, design: .monospaced).foregroundStyle(.secondary)
                            Pill(item.status, tone: tone(item.status))
                        }
                    }
                }
            } else if summary.hasCounts {
                Text("No individual package details available in this event payload.").appFont(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(10)
        .background(Color.cardBackground, in: RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.cardBorder))
    }

    private func tone(_ status: String) -> Tone {
        switch status.lowercased() {
        case "installed", "success", "completed", "up to date": return .green
        case "pending", "pending update", "available": return .cyan
        case "warning": return .yellow
        case "error", "failed": return .red
        case "removed": return .purple
        default: return .gray
        }
    }
}

/// The events page's expanded row: id and time, the run summary, details,
/// and the raw payload with copy and search.
struct EventExpandedPanel: View {
    @Environment(AppState.self) private var appState
    let event: BundledEvent
    @State private var store = EventPayloads()
    @State private var search = ""

    private var summary: LastRunSummary? {
        for id in event.eventIds { if let p = store.payloads[id], let s = LastRunSummary.parse(p), !s.isEmpty { return s } }
        return nil
    }

    var body: some View {
        let text = EventPayloadText.format(event: event, payloads: store.payloads)
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                Text(event.isBundle ? "Bundle of \(event.count)" : "#\(event.id)").appFont(.caption, design: .monospaced).foregroundStyle(.secondary)
                    .help(event.isBundle ? "Bundle: \(event.eventIds.joined(separator: ", "))" : "#\(event.id)")
                Text(TimeFormatting.exact(event.ts)).appFont(.caption).foregroundStyle(.secondary)
                if store.loading { ProgressView().controlSize(.mini) }
            }
            if let summary { LastRunSummaryView(summary: summary) }
            EventDetailsView(event: event, includeRaw: false)
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 8) {
                    Text(store.payloads.isEmpty ? "Raw Payload (from events list)" : "Raw Payload").appFont(.callout, weight: .semibold)
                    Spacer()
                    HStack(spacing: 6) {
                        Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                        TextField("Search payload...", text: $search).textFieldStyle(.plain)
                        if !search.isEmpty { Button { search = "" } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary) }.buttonStyle(.plain) }
                    }
                    .padding(.horizontal, 8).padding(.vertical, 4)
                    .background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 6))
                    .frame(width: 220)
                    CopyButton(value: text)
                }
                if store.loading, store.payloads.isEmpty {
                    Text("Loading full payload...").appFont(.caption).foregroundStyle(.secondary)
                } else {
                    ScrollView([.horizontal, .vertical]) {
                        Text(EventPayloadText.highlighted(text, search: search))
                            .appFont(.caption, design: .monospaced)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(8)
                    }
                    .frame(maxHeight: 360)
                    .background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 6))
                }
            }
        }
        .task(id: event.id) { await store.load(event.eventIds, api: appState.api) }
    }
}

/// The events table body shared by the dashboard widget, the fleet feed and
/// the per-device Events tab.
struct EventsTableView: View {
    enum Style { case compact, feed }

    @Environment(AppState.self) private var appState
    let events: [BundledEvent]
    var style: Style = .compact
    var showDevice = true
    var autoFetchRows = 60
    var maxRows = 250
    var onOpenDevice: ((BundledEvent) -> Void)? = nil
    /// Called when the reader is a few rows from the end (infinite scroll).
    var onNearEnd: (() -> Void)? = nil
    @State private var expanded: Set<String> = []

    private var deviceWidth: CGFloat { style == .feed ? 230 : 190 }

    var body: some View {
        let shown = Array(events.prefix(maxRows).enumerated())
        LazyVStack(spacing: 0, pinnedViews: [.sectionHeaders]) {
            Section {
                ForEach(shown, id: \.element.id) { index, event in
                    let isOpen = expanded.contains(event.id)
                    VStack(spacing: 0) {
                        HStack(alignment: .top, spacing: 10) {
                            HStack(spacing: 4) {
                                Image(systemName: "chevron.right").appFont(fixed: 9, weight: .semibold).foregroundStyle(.tertiary)
                                    .rotationEffect(.degrees(isOpen ? 90 : 0))
                                EventKindIcon(kind: event.kind, removal: event.isRemoval)
                            }
                            .frame(width: 52, alignment: .leading)
                            if style == .feed, showDevice { deviceCell(event) }
                            EventInlineLinesView(event: event, autoFetch: index < autoFetchRows)
                                .frame(maxWidth: .infinity, alignment: .leading)
                            if style == .compact, showDevice { deviceCell(event) }
                            Text(TimeFormatting.relative(event.ts)).appFont(.body).foregroundStyle(.secondary)
                                .frame(width: 120, alignment: .leading)
                                .help(TimeFormatting.exact(event.ts))
                            if style == .feed {
                                Button { toggle(event.id) } label: {
                                    Image(systemName: isOpen ? "chevron.up.circle" : "doc.text.magnifyingglass").foregroundStyle(.secondary)
                                }
                                .buttonStyle(.plain)
                                .help(isOpen ? "Collapse" : "Show payload")
                                .frame(width: 40, alignment: .center)
                            }
                        }
                        .padding(.horizontal, 12).padding(.vertical, 8)
                        .contentShape(Rectangle())
                        .onTapGesture { toggle(event.id) }
                        .onAppear { if let onNearEnd, index >= shown.count - 5 { onNearEnd() } }
                        if isOpen {
                            Group {
                                if style == .feed {
                                    EventExpandedPanel(event: event)
                                } else {
                                    EventDetailsView(event: event)
                                }
                            }
                            .padding(.horizontal, 24).padding(.vertical, 10)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color.subtleBackground)
                        }
                        Divider()
                    }
                }
            } header: {
                HStack(spacing: 10) {
                    Text("TYPE").frame(width: 52, alignment: .leading)
                    if style == .feed, showDevice { Text("DEVICE").frame(width: deviceWidth, alignment: .leading) }
                    Text("MESSAGE").frame(maxWidth: .infinity, alignment: .leading)
                    if style == .compact, showDevice { Text("DEVICE").frame(width: deviceWidth, alignment: .leading) }
                    Text("TIME").frame(width: 120, alignment: .leading)
                    if style == .feed { Text("PAYLOAD").frame(width: 40, alignment: .center) }
                }
                .appFont(.caption2, weight: .semibold).foregroundStyle(.secondary).kerning(0.5)
                .padding(.horizontal, 12).padding(.vertical, 8)
                .background(Color.cardBackground)
                .overlay(alignment: .bottom) { Divider() }
            }
        }
    }

    private func deviceCell(_ event: BundledEvent) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Button {
                if let onOpenDevice { onOpenDevice(event) } else { open(event) }
            } label: {
                Text(deviceName(event)).appFont(.body, weight: .medium).lineLimit(1).truncationMode(.middle)
            }
            .buttonStyle(.link)
            .help(event.deviceName ?? event.device)
            if style == .feed {
                HStack(spacing: 6) {
                    Text(event.device).appFont(.caption2, design: .monospaced).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                    if let tag = event.assetTag { Pill(tag, tone: .gray) }
                }
            }
        }
        .frame(width: deviceWidth, alignment: .leading)
    }

    private func toggle(_ id: String) {
        if expanded.contains(id) { expanded.remove(id) } else { expanded.insert(id) }
    }

    private func deviceName(_ event: BundledEvent) -> String {
        if let n = event.deviceName, n != event.device, n.lowercased() != "unknown" { return n }
        if let mapped = appState.deviceNameMap[event.device] { return mapped }
        return event.device.isEmpty ? "Unknown Device" : event.device
    }

    private func open(_ event: BundledEvent) {
        let moduleId = EventLinks.moduleId(kind: event.kind, message: event.message, payload: event.payload)
        let tab = moduleId.flatMap { DeviceTab(rawValue: $0) }
        let filter = moduleId == "installs" ? EventLinks.installsFilter(for: event.kind) : nil
        appState.open(device: event.device, tab: tab, filter: filter)
    }
}

/// Type filter menu: check boxes for success, warnings, errors, system, info.
struct EventTypeFilterMenu: View {
    @Binding var hidden: Set<EventKind>
    let defaultHidden: Set<EventKind>

    private var customized: Bool { hidden != defaultHidden }

    var body: some View {
        Menu {
            ForEach(EventKind.filterOrder, id: \.self) { kind in
                Button {
                    if hidden.contains(kind) { hidden.remove(kind) } else { hidden.insert(kind) }
                } label: {
                    Label(kind.displayName, systemImage: hidden.contains(kind) ? "square" : "checkmark.square.fill")
                }
            }
            Divider()
            Button("Reset") { hidden = defaultHidden }
        } label: {
            HStack(spacing: 4) {
                Image(systemName: "slider.horizontal.3")
                Text("Filter")
                if customized { Pill("\(EventKind.allCases.count - hidden.count)", tone: .blue) }
            }
            .appFont(.caption, weight: .medium)
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
    }
}
