import SwiftUI
import ReportMateKit

@main
struct ReportMateMacApp: App {
    @State private var appState = AppState()
    @AppStorage(AppFontScale.storageKey) private var fontScale: Double = AppFontScale.default

    init() {
        NSApplication.shared.setActivationPolicy(.regular)
        NSApplication.shared.activate(ignoringOtherApps: true)
        // One window with many sections, not a document app: hide the tab bar items.
        NSWindow.allowsAutomaticWindowTabbing = false
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(appState)
                .appFontScale(fontScale)
                .frame(minWidth: 960, minHeight: 620)
        }
        .defaultSize(width: 1380, height: 900)
        .commands {
            AppCommands()
        }

        Settings {
            SettingsView()
                .environment(appState)
                .appFontScale(fontScale)
        }
    }
}

/// Menu bar commands: section switching, search, refresh, back/forward.
struct AppCommands: Commands {
    @FocusedValue(\.appState) private var appState

    var body: some Commands {
        CommandGroup(replacing: .newItem) {}
        CommandMenu("Go") {
            ForEach(Array(AppSection.allCases.enumerated()), id: \.element) { index, section in
                Button(section.title) { appState?.navigate(to: section) }
                    .keyboardShortcut(section.keyEquivalent, modifiers: .command)
            }
            Divider()
            Button("Back") { appState?.goBack() }
                .keyboardShortcut("[", modifiers: .command)
                .disabled(!(appState?.canGoBack ?? false))
        }
        CommandGroup(after: .toolbar) {
            Button("Find Device…") { appState?.showSearch = true }
                .keyboardShortcut("k", modifiers: .command)
            Button("Refresh") { appState?.refreshRequested += 1 }
                .keyboardShortcut("r", modifiers: .command)
            Divider()
            Button("Show All Platforms") { appState?.platformFilter = .all }
                .keyboardShortcut("0", modifiers: [.command, .shift])
            Button("Show macOS Only") { appState?.platformFilter = .macOS }
                .keyboardShortcut("m", modifiers: [.command, .shift])
            Button("Show Windows Only") { appState?.platformFilter = .windows }
                .keyboardShortcut("w", modifiers: [.command, .shift])
        }
    }
}

struct AppStateFocusedKey: FocusedValueKey {
    typealias Value = AppState
}

extension FocusedValues {
    var appState: AppState? {
        get { self[AppStateFocusedKey.self] }
        set { self[AppStateFocusedKey.self] = newValue }
    }
}
