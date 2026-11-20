import Foundation
import Helper
import ReportMate
import Watcher

/// The app's one executable, `Contents/MacOS/managedreportsrunner`.
///
/// macOS privacy controls (Full Disk Access and the rest) identify a process by
/// its code, so every Mach-O in the bundle is a row of its own in Privacy &
/// Security. The window, the privileged helper, the usage watcher and the
/// collector are therefore one executable, and its arguments choose the role:
///
/// - none: open the window
/// - `--helper`: serve the privileged XPC helper (its LaunchDaemon passes this)
/// - `--appusage [options]`: run the application usage watcher
/// - `--register-daemons` / `--unregister-daemons`: register or remove the
///   LaunchDaemons with SMAppService (the package's scripts run these as root)
/// - anything else: the collector's command line
@main
enum AppEntry {
    @MainActor
    static func main() {
        let arguments = CommandLine.arguments
        switch LaunchMode(arguments) {
        case .window:
            ReportMateApp.main()
        case .helper:
            HelperDaemon.run()
        case .appUsage:
            ReportMateAppUsage.main(Array(arguments.dropFirst(2)))
        case .registerDaemons:
            exit(DaemonRegistration.registerAll() ? EXIT_SUCCESS : EXIT_FAILURE)
        case .unregisterDaemons:
            exit(DaemonRegistration.unregisterAll() ? EXIT_SUCCESS : EXIT_FAILURE)
        case .collector:
            Task {
                await ReportMateClient.main()
                exit(EXIT_SUCCESS)
            }
            dispatchMain()
        }
    }
}

enum LaunchMode: Equatable {
    case window
    case helper
    case appUsage
    case registerDaemons
    case unregisterDaemons
    case collector

    /// The role for these process arguments. Arguments AppKit and Xcode pass
    /// to an app (`-psn_…`, `-NS… <value>`, `-Apple… <value>`) are not the
    /// caller's, so a launch with only those still opens the window.
    init(_ arguments: [String]) {
        var rest = arguments.dropFirst()[...]
        var own: [String] = []
        while let arg = rest.popFirst() {
            if arg.hasPrefix("-psn_") { continue }
            if arg.hasPrefix("-NS") || arg.hasPrefix("-Apple") {
                _ = rest.popFirst()
                continue
            }
            own.append(arg)
        }
        switch own.first {
        case nil: self = .window
        case "--helper": self = .helper
        case "--appusage": self = .appUsage
        case "--register-daemons": self = .registerDaemons
        case "--unregister-daemons": self = .unregisterDaemons
        default: self = .collector
        }
    }
}
