import Foundation
import ReportMate

/// The app's main executable is also the collector.
///
/// macOS privacy controls (Full Disk Access and the rest) identify a process by
/// its code. When the collector was its own binary in Contents/MacOS, it showed up
/// beside the app as a second, unbundled client that needed its own grant. Running
/// the collector from the app's main executable puts both under the app's bundle
/// identifier, so one grant covers them.
///
/// The LaunchDaemons, the helper and the CLI wrappers all start
/// `Contents/MacOS/managedreportsrunner`, a symlink to this executable. That name
/// selects collector mode. Launching the app from Finder or the Dock opens the
/// window as before.
@main
enum AppEntry {
    @MainActor
    static func main() {
        if LaunchMode.isCommandLine(CommandLine.arguments) {
            Task {
                await ReportMateClient.main()
                exit(EXIT_SUCCESS)
            }
            dispatchMain()
        } else {
            ReportMateApp.main()
        }
    }
}

enum LaunchMode {
    static let runnerName = "managedreportsrunner"

    /// True when this process should run the collector instead of the window:
    /// it was started under the runner's name, or given arguments other than the
    /// ones AppKit and Xcode pass to an app (`-psn_…`, `-NS… <value>`, `-Apple… <value>`).
    static func isCommandLine(_ arguments: [String]) -> Bool {
        guard let first = arguments.first else { return false }
        if URL(fileURLWithPath: first).lastPathComponent == runnerName { return true }
        var rest = arguments.dropFirst()[...]
        while let arg = rest.popFirst() {
            if arg.hasPrefix("-psn_") { continue }
            if arg.hasPrefix("-NS") || arg.hasPrefix("-Apple") {
                _ = rest.popFirst()
                continue
            }
            return true
        }
        return false
    }
}
