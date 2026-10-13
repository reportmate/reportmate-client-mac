//
//  ServicesSection.swift
//
//  Prefs card listing the launchd jobs this tool ships, read-only: label,
//  whether launchd has it loaded or running, its last exit code, and when it
//  runs. There are deliberately no start, stop or reload controls here.
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

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 12) {
                if jobs.isEmpty {
                    Text(hasLoaded ? "None of this tool's launchd jobs are installed on this Mac." : "Reading launchd\u{2026}")
                        .foregroundStyle(.secondary)
                }
                ForEach(jobs) { job in
                    if job.id != jobs.first?.id {
                        Divider()
                    }
                    jobRow(job)
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
            while !Task.isCancelled {
                let latest = await LaunchdServices.load(prefixes: prefixes, extraDaemonDirectories: extraDaemonDirectories)
                jobs = latest
                hasLoaded = true
                try? await Task.sleep(for: .seconds(10))
            }
        }
    }

    @ViewBuilder
    private func jobRow(_ job: LaunchdJob) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline) {
                Text(job.label)
                    .font(.body.monospaced())
                    .textSelection(.enabled)
                Spacer()
                stateLabel(job.state)
            }
            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 12, verticalSpacing: 4) {
                GridRow {
                    Text("Type").foregroundStyle(.secondary)
                    Text(job.kind.displayName)
                }
                GridRow {
                    Text("Runs").foregroundStyle(.secondary)
                    Text(job.schedule)
                        .fixedSize(horizontal: false, vertical: true)
                }
                GridRow {
                    Text("Last exit").foregroundStyle(.secondary)
                    Text(job.lastExitCode ?? "Has not exited")
                        .monospacedDigit()
                }
                GridRow {
                    Text("Plist").foregroundStyle(.secondary)
                    Text(job.plistPath)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                        .help(job.plistPath)
                }
            }
            .font(.callout)
        }
        .accessibilityElement(children: .combine)
    }

    @ViewBuilder
    private func stateLabel(_ state: LaunchdJob.State) -> some View {
        let running: Bool = {
            if case .running = state { return true }
            return false
        }()
        Label {
            Text(state.displayName)
        } icon: {
            Image(systemName: running ? "circle.fill" : "circle")
                .foregroundStyle(running ? Color.green : Color.secondary)
                .imageScale(.small)
        }
        .font(.callout)
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
