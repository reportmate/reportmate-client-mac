import SwiftUI
import AppKit
import ReportMateKit

// MARK: - Palette

/// The web app's Tailwind accents, as SwiftUI colours.
enum Tone: Hashable {
    case blue, green, yellow, red, purple, indigo, teal, orange, cyan, pink, gray, emerald, violet

    var color: Color {
        switch self {
        case .blue: return .blue
        case .green, .emerald: return .green
        case .yellow: return .yellow
        case .red: return .red
        case .purple: return .purple
        case .indigo: return .indigo
        case .teal: return .teal
        case .orange: return .orange
        case .cyan: return .cyan
        case .pink: return .pink
        case .gray: return .secondary
        case .violet: return Color(red: 0.55, green: 0.36, blue: 0.96)
        }
    }

    static func forSeverity(_ severity: Severity) -> Tone {
        switch severity {
        case .ok: return .green
        case .warning: return .yellow
        case .danger: return .red
        case .neutral: return .gray
        case .unknown: return .yellow
        }
    }

    static func forStatus(_ status: DeviceStatus) -> Tone {
        switch status {
        case .active: return .green
        case .stale: return .yellow
        case .missing: return .gray
        case .warning: return .orange
        case .error: return .red
        case .archived: return .gray
        }
    }

    static func forEvent(_ kind: EventKind) -> Tone {
        switch kind {
        case .success: return .green
        case .warning: return .yellow
        case .error: return .red
        case .info: return .blue
        case .system: return .purple
        }
    }
}

extension Color {
    static var cardBackground: Color { Color(nsColor: .controlBackgroundColor) }
    static var cardBorder: Color { Color.secondary.opacity(0.18) }
    static var subtleBackground: Color { Color.secondary.opacity(0.06) }

    init(hex: String) {
        var s = hex.trimmingCharacters(in: .whitespaces)
        if s.hasPrefix("#") { s.removeFirst() }
        var value: UInt64 = 0
        Scanner(string: s).scanHexInt64(&value)
        let r = Double((value >> 16) & 0xFF) / 255
        let g = Double((value >> 8) & 0xFF) / 255
        let b = Double(value & 0xFF) / 255
        self.init(red: r, green: g, blue: b)
    }
}

// MARK: - Cards

/// The rounded card every widget and report sits in.
struct Card<Content: View>: View {
    var padding: CGFloat = 0
    @ViewBuilder var content: Content

    var body: some View {
        content
            .padding(padding)
            .background(Color.cardBackground)
            .clipShape(RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.cardBorder, lineWidth: 1))
    }
}

/// Card header: tinted icon, title, subtitle and an optional trailing view.
struct CardHeader<Trailing: View>: View {
    let title: String
    var subtitle: String? = nil
    var systemImage: String? = nil
    var tone: Tone = .blue
    var action: (() -> Void)? = nil
    @ViewBuilder var trailing: Trailing

    init(_ title: String, subtitle: String? = nil, systemImage: String? = nil, tone: Tone = .blue, action: (() -> Void)? = nil, @ViewBuilder trailing: () -> Trailing = { EmptyView() }) {
        self.title = title
        self.subtitle = subtitle
        self.systemImage = systemImage
        self.tone = tone
        self.action = action
        self.trailing = trailing()
    }

    var body: some View {
        HStack(spacing: 12) {
            if let systemImage {
                ZStack {
                    RoundedRectangle(cornerRadius: 8).fill(tone.color.opacity(0.15))
                    Image(systemName: systemImage).foregroundStyle(tone.color).appFont(fixed: 15, weight: .medium)
                }
                .frame(width: 36, height: 36)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(title).appFont(.title3, weight: .semibold)
                if let subtitle { Text(subtitle).appFont(.caption).foregroundStyle(.secondary) }
            }
            Spacer(minLength: 0)
            trailing
            if action != nil {
                Image(systemName: "chevron.right").foregroundStyle(.tertiary).appFont(.caption)
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .contentShape(Rectangle())
        .onTapGesture { action?() }
        .overlay(alignment: .bottom) { Divider() }
    }
}

// MARK: - Stats

/// A labelled value the way the web `Stat` renders: small grey label, value below.
struct StatRow: View {
    let label: String
    let value: String?
    var mono = false
    var copyable = false
    var sublabel: String? = nil
    var tone: Tone? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label).appFont(.caption).foregroundStyle(.secondary)
            HStack(spacing: 6) {
                Text(value ?? "Unknown")
                    .appFont(.body, design: mono ? .monospaced : .default)
                    .foregroundStyle(tone?.color ?? .primary)
                    .lineLimit(2)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
                if copyable, let value, !value.isEmpty { CopyButton(value: value) }
            }
            if let sublabel { Text(sublabel).appFont(.caption2).foregroundStyle(.secondary) }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// Label left, coloured pill right.
struct StatusBadgeRow: View {
    let label: String
    let status: String
    var tone: Tone = .gray
    var indented = false

    var body: some View {
        HStack {
            Text(label).appFont(.callout).foregroundStyle(.secondary)
            Spacer()
            Pill(status, tone: tone)
        }
        .padding(.leading, indented ? 16 : 0)
    }
}

/// Small rounded status chip.
struct Pill: View {
    let text: String
    var tone: Tone = .gray
    var filled = false

    init(_ text: String, tone: Tone = .gray, filled: Bool = false) {
        self.text = text
        self.tone = tone
        self.filled = filled
    }

    var body: some View {
        Text(text)
            .appFont(.caption, weight: .medium)
            .padding(.horizontal, 9)
            .padding(.vertical, 3)
            .background(filled ? tone.color : tone.color.opacity(0.15), in: Capsule())
            .foregroundStyle(filled ? Color.white : (tone == .gray ? Color.primary : tone.color))
            .lineLimit(1)
    }
}

/// Selectable filter pill (the Selections accordion).
struct FilterPill: View {
    let text: String
    let selected: Bool
    var tone: Tone = .blue
    var size: CGFloat = 11
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(text)
                .appFont(fixed: size, weight: selected ? .semibold : .regular)
                .padding(.horizontal, 10)
                .padding(.vertical, 4)
                .background(selected ? tone.color.opacity(0.18) : Color.clear, in: Capsule())
                .overlay(Capsule().stroke(selected ? tone.color.opacity(0.6) : Color.secondary.opacity(0.35), lineWidth: 1))
                .foregroundStyle(selected ? tone.color : Color.primary)
        }
        .buttonStyle(.plain)
        .focusable(false)
    }
}

/// Copies a value to the pasteboard with a brief check-mark confirmation.
struct CopyButton: View {
    let value: String
    @State private var copied = false

    var body: some View {
        Button {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(value, forType: .string)
            copied = true
            Task { try? await Task.sleep(for: .seconds(1.5)); copied = false }
        } label: {
            Image(systemName: copied ? "checkmark" : "doc.on.doc")
                .appFont(fixed: 10)
                .foregroundStyle(copied ? Color.green : Color.secondary)
        }
        .buttonStyle(.plain)
        .focusable(false)
        .help(copied ? "Copied" : "Copy to clipboard")
    }
}

/// The grey Apple or Windows glyph shown beside device names.
struct PlatformBadge: View {
    let platform: Platform
    var size: CGFloat = 12

    var body: some View {
        Image(systemName: platform.systemImage)
            .appFont(fixed: size)
            .foregroundStyle(.secondary.opacity(0.7))
            .help(platform.displayName)
    }
}

struct StatusText: View {
    let status: DeviceStatus
    var body: some View {
        Text(status.displayName)
            .appFont(.callout, weight: .medium)
            .foregroundStyle(Tone.forStatus(status).color)
    }
}

// MARK: - States

struct EmptyStateView: View {
    let title: String
    var message: String? = nil
    var systemImage: String = "tray"

    var body: some View {
        VStack(spacing: 8) {
            Image(systemName: systemImage).font(.system(size: 30)).foregroundStyle(.tertiary)
            Text(title).appFont(.headline)
            if let message { Text(message).appFont(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center) }
        }
        .frame(maxWidth: .infinity)
        .padding(32)
    }
}

struct LoadingView: View {
    var message: String = "Loading…"
    var body: some View {
        VStack(spacing: 10) {
            ProgressView()
            Text(message).appFont(.callout).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(40)
    }
}

struct ErrorBanner: View {
    let message: String
    var retry: (() -> Void)? = nil

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red)
            Text(message).appFont(.callout).textSelection(.enabled)
            Spacer()
            if let retry { Button("Try Again", action: retry) }
        }
        .padding(12)
        .background(Color.red.opacity(0.08), in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.red.opacity(0.3)))
    }
}

/// Shown in every section when the API is not configured yet.
struct NotConfiguredView: View {
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: "server.rack").font(.system(size: 40)).foregroundStyle(.tertiary)
            Text("Connect to ReportMate").appFont(.title2, weight: .semibold)
            Text("Enter the API URL and a credential in Settings to load the fleet.")
                .appFont(.callout).foregroundStyle(.secondary)
            Button("Open Settings…") { openSettings() }.keyboardShortcut(",", modifiers: .command)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - Section header row

struct SectionLabel: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text.uppercased())
            .appFont(.caption2, weight: .semibold)
            .foregroundStyle(.secondary)
            .kerning(0.6)
    }
}

// MARK: - Sortable table header helpers

struct SortIndicator: View {
    let active: Bool
    let ascending: Bool
    var body: some View {
        if active {
            Image(systemName: ascending ? "chevron.up" : "chevron.down").appFont(fixed: 9).foregroundStyle(.secondary)
        }
    }
}

extension View {
    /// Attaches a `.help` only when text is non-empty.
    @ViewBuilder
    func optionalHelp(_ text: String?) -> some View {
        if let text, !text.isEmpty { self.help(text) } else { self }
    }
}

/// Horizontal percentage bar.
struct BarRow: View {
    let label: String
    let count: Int
    let total: Int
    var tone: Tone = .purple
    var labelWidth: CGFloat = 140

    var body: some View {
        HStack(spacing: 8) {
            Text(label).appFont(.caption).foregroundStyle(.secondary).frame(width: labelWidth, alignment: .leading).lineLimit(1).truncationMode(.tail).help(label)
            GeometryReader { geo in
                ZStack(alignment: .leading) {
                    Capsule().fill(Color.secondary.opacity(0.12))
                    Capsule().fill(tone.color.opacity(0.85))
                        .frame(width: total > 0 ? max(2, geo.size.width * CGFloat(count) / CGFloat(total)) : 0)
                }
            }
            .frame(height: 8)
            Text("\(count)").appFont(.caption).monospacedDigit().foregroundStyle(.secondary).frame(width: 34, alignment: .trailing)
        }
    }
}
