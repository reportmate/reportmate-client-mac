import SwiftUI
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

/// Expanded detail under an event row: every line of the payload, then the raw JSON.
struct EventDetailsView: View {
    @Environment(AppState.self) private var appState
    let event: BundledEvent
    @State private var payloads: [String: JSONValue] = [:]
    @State private var loading = false
    @State private var showRaw = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if loading, payloads.isEmpty {
                ProgressView().controlSize(.small)
            }
            ForEach(event.eventIds, id: \.self) { id in
                if let p = payloads[id] {
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
            if !payloads.isEmpty {
                DisclosureGroup("Raw payload", isExpanded: $showRaw) {
                    ScrollView(.horizontal) {
                        Text(payloads.count == 1 ? (payloads.values.first?.prettyPrinted ?? "") : JSONValue.array(event.eventIds.compactMap { payloads[$0] }).prettyPrinted)
                            .appFont(.caption, design: .monospaced)
                            .textSelection(.enabled)
                            .padding(8)
                    }
                    .frame(maxHeight: 320)
                    .background(Color.subtleBackground, in: RoundedRectangle(cornerRadius: 6))
                }
                .appFont(.caption)
            } else if !loading {
                Text("No payload recorded for this event.").appFont(.caption).foregroundStyle(.secondary)
            }
        }
        .task(id: event.id) {
            loading = true
            for id in event.eventIds {
                if let p = await EventPayloadCache.shared.load(id, api: appState.api) { payloads[id] = p }
            }
            loading = false
        }
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

/// The events table body shared by the dashboard widget, the fleet feed and
/// the per-device Events tab.
struct EventsTableView: View {
    @Environment(AppState.self) private var appState
    let events: [BundledEvent]
    var showDevice = true
    var autoFetchRows = 60
    var maxRows = 250
    var onOpenDevice: ((BundledEvent) -> Void)? = nil
    @State private var expanded: Set<String> = []

    var body: some View {
        LazyVStack(spacing: 0, pinnedViews: [.sectionHeaders]) {
            Section {
                ForEach(Array(events.prefix(maxRows).enumerated()), id: \.element.id) { index, event in
                    let isOpen = expanded.contains(event.id)
                    VStack(spacing: 0) {
                        HStack(alignment: .top, spacing: 10) {
                            HStack(spacing: 4) {
                                Image(systemName: "chevron.right").appFont(fixed: 9, weight: .semibold).foregroundStyle(.tertiary)
                                    .rotationEffect(.degrees(isOpen ? 90 : 0))
                                EventKindIcon(kind: event.kind, removal: event.isRemoval)
                            }
                            .frame(width: 52, alignment: .leading)
                            EventInlineLinesView(event: event, autoFetch: index < autoFetchRows)
                                .frame(maxWidth: .infinity, alignment: .leading)
                            if showDevice {
                                Button {
                                    if let onOpenDevice { onOpenDevice(event) } else { open(event) }
                                } label: {
                                    Text(deviceName(event)).appFont(.body, weight: .medium).lineLimit(1).truncationMode(.middle)
                                }
                                .buttonStyle(.link)
                                .frame(width: 190, alignment: .leading)
                            }
                            Text(TimeFormatting.relative(event.ts)).appFont(.body).foregroundStyle(.secondary)
                                .frame(width: 120, alignment: .leading)
                                .help(TimeFormatting.exact(event.ts))
                        }
                        .padding(.horizontal, 12).padding(.vertical, 8)
                        .contentShape(Rectangle())
                        .onTapGesture { toggle(event.id) }
                        if isOpen {
                            EventDetailsView(event: event)
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
                    Text("MESSAGE").frame(maxWidth: .infinity, alignment: .leading)
                    if showDevice { Text("DEVICE").frame(width: 190, alignment: .leading) }
                    Text("TIME").frame(width: 120, alignment: .leading)
                }
                .appFont(.caption2, weight: .semibold).foregroundStyle(.secondary).kerning(0.5)
                .padding(.horizontal, 12).padding(.vertical, 8)
                .background(Color.cardBackground)
                .overlay(alignment: .bottom) { Divider() }
            }
        }
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
