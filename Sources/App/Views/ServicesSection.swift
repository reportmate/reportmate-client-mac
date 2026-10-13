//
//  ServicesSection.swift
//
//  Prefs card listing the launchd jobs this tool ships, read-only, as an
//  accordion: each job is one collapsed row with its label and state, and
//  disclosing the row shows the fields ReportMate collects for a launchd
//  service. There are deliberately no start, stop or reload controls here.
//

import SwiftUI

struct ServicesSection: View {
    /// File-name prefixes of the plists the package installs in
    /// /Library/LaunchDaemons and /Library/LaunchAgents.
    let prefixes: [String]
    /// Further folders whose plists are all this tool's daemons, such as a
    /// helper embedded in the app bundle.
    var extraDaemonDirectories: [String] = []

    @State private var jobs: [LaunchdJob] = []
    @State private var hasLoaded = false
    @State private var expanded: Set<String> = []

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 6) {
                if jobs.isEmpty {
                    Text(hasLoaded ? "None of this tool's launchd jobs are installed on this Mac." : "Reading launchd\u{2026}")
                        .foregroundStyle(.secondary)
                }
                ForEach(jobs) { job in
                    if job.id != jobs.first?.id {
                        Divider()
                    }
                    ServiceRow(job: job, isExpanded: expansion(for: job.id))
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.vertical, 8)
        } label: {
            Label("Services", systemImage: "gearshape.2")
                .font(.headline)
        }
        .task {
            // Re-read while the tab is visible so the state stays current.
            // Disclosure state is keyed by job id, so it survives each refresh.
            while !Task.isCancelled {
                let latest = await LaunchdServices.load(prefixes: prefixes, extraDaemonDirectories: extraDaemonDirectories)
                jobs = latest
                hasLoaded = true
                try? await Task.sleep(for: .seconds(10))
            }
        }
    }

    private func expansion(for id: String) -> Binding<Bool> {
        Binding(
            get: { expanded.contains(id) },
            set: { isOpen in
                if isOpen { expanded.insert(id) } else { expanded.remove(id) }
            }
        )
    }
}

/// One job: a native DisclosureGroup. The collapsed row carries the label, a
/// one-line summary and the state; disclosing it adds the rest of the fields.
private struct ServiceRow: View {
    let job: LaunchdJob
    @Binding var isExpanded: Bool

    var body: some View {
        DisclosureGroup(isExpanded: $isExpanded) {
            detail
                .padding(.top, 6)
                .padding(.bottom, 4)
                .padding(.leading, 18)
        } label: {
            HStack(alignment: .firstTextBaseline, spacing: 12) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(job.label)
                        .font(.body.monospaced())
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Text(job.summary)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.tail)
                }
                .help(job.label)
                Spacer(minLength: 0)
                ServiceStateLabel(state: job.state)
            }
        }
        .disclosureGroupStyle(WholeRowDisclosureStyle())
    }

    private var detail: some View {
        Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 12, verticalSpacing: 4) {
            ForEach(job.fields) { field in
                GridRow {
                    Text(field.name)
                        .foregroundStyle(.secondary)
                        .gridColumnAlignment(.trailing)
                    value(field)
                }
                .accessibilityElement(children: .combine)
            }
        }
        .font(.callout)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    @ViewBuilder
    private func value(_ field: LaunchdJob.Field) -> some View {
        if field.isPath {
            Text(field.value)
                .font(.callout.monospaced())
                .lineLimit(1)
                .truncationMode(.middle)
                .textSelection(.enabled)
                .help(field.value)
        } else {
            Text(field.value)
                .foregroundStyle(field.isSet ? .primary : .secondary)
                .monospacedDigit()
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
        }
    }
}

/// A disclosure row that toggles from anywhere on it, as Finder's list view
/// does: one click expands it, the next collapses it. The row takes keyboard
/// focus (Tab with Full Keyboard Access) and Space or Return toggles it.
private struct WholeRowDisclosureStyle: DisclosureGroupStyle {
    func makeBody(configuration: Configuration) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Image(systemName: "chevron.right")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .rotationEffect(.degrees(configuration.isExpanded ? 90 : 0))
                    .frame(width: 12)
                    .accessibilityHidden(true)
                configuration.label
            }
            .padding(.vertical, 2)
            .contentShape(Rectangle())
            .onTapGesture { toggle(configuration) }
            .focusable()
            .onKeyPress(keys: [.space, .return]) { _ in
                toggle(configuration)
                return .handled
            }
            .accessibilityElement(children: .combine)
            .accessibilityAddTraits(.isButton)
            .accessibilityValue(configuration.isExpanded ? "Expanded" : "Collapsed")
            .accessibilityAction { toggle(configuration) }

            if configuration.isExpanded {
                configuration.content
            }
        }
    }

    private func toggle(_ configuration: Configuration) {
        withAnimation(.easeInOut(duration: 0.15)) {
            configuration.isExpanded.toggle()
        }
    }
}

/// The state dot and text on the right of each row. Each state has its own
/// symbol shape as well as its colour, so it reads without colour too.
private struct ServiceStateLabel: View {
    let state: LaunchdJob.State

    var body: some View {
        Label {
            Text(state.displayName)
        } icon: {
            Image(systemName: symbol)
                .foregroundStyle(tint)
                .imageScale(.small)
                .accessibilityHidden(true)
        }
        .font(.callout)
        .fixedSize()
    }

    private var symbol: String {
        switch state {
        case .running: return "circle.fill"
        case .loaded: return "circle"
        case .disabled: return "minus.circle.fill"
        case .notLoaded: return "circle.dashed"
        case .unknown: return "questionmark.circle"
        }
    }

    private var tint: Color {
        switch state {
        case .running: return .green
        case .disabled: return .orange
        default: return .secondary
        }
    }
}

/// One line at the top of Prefs, in the manner of System Settings' "This
/// setting has been configured by a profile." Shown only when a profile
/// forces at least one of the app's keys.
struct ProfileManagedBanner: View {
    var body: some View {
        Label("Settings shown in gray have been configured by a profile.", systemImage: "lock.fill")
            .font(.callout)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .center)
            .accessibilityElement(children: .combine)
    }
}
