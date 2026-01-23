import Foundation

/// Enhanced console formatter for human legible verbose output
/// Matches Windows client ConsoleFormatter.cs for consistent cross-platform experience
///
/// Verbose levels:
/// - 0: Errors only (silent)
/// - 1: + Warnings (-v)
/// - 2: + Info and progress bars (-vv)
/// - 3: + Debug messages (-vvv)
public final class ConsoleFormatter: @unchecked Sendable {
    /// Thread-safe storage for verbose level (0-3)
    nonisolated(unsafe) private static var _verboseLevel: Int = 0
    private static let lock = NSLock()
    
    // ANSI color codes for terminal output
    private enum ColorCode: String {
        case header = "\u{001B}[36m"      // Cyan
        case section = "\u{001B}[33m"     // Yellow
        case success = "\u{001B}[32m"     // Green
        case warning = "\u{001B}[38;5;208m"  // Orange (256-color mode)
        case error = "\u{001B}[31m"       // Red
        case info = "\u{001B}[37m"        // White
        case debug = "\u{001B}[90m"       // Gray
        case progress = "\u{001B}[34m"    // Blue
        case accent = "\u{001B}[35m"      // Magenta
        case reset = "\u{001B}[0m"
    }
    
    /// Set verbose level (0=silent, 1=warnings, 2=info+progress, 3=debug)
    public static func setVerboseLevel(_ level: Int) {
        lock.lock()
        defer { lock.unlock() }
        _verboseLevel = max(0, min(3, level))
    }
    
    /// Set verbose mode (legacy compatibility - level 2 enables progress)
    public static func setVerboseMode(_ verbose: Bool) {
        setVerboseLevel(verbose ? 2 : 0)
    }
    
    /// Get current verbose level
    public static var verboseLevel: Int {
        lock.lock()
        defer { lock.unlock() }
        return _verboseLevel
    }
    
    /// Check if verbose mode is enabled (level >= 2)
    public static var isVerbose: Bool {
        return verboseLevel >= 2
    }
    
    /// Check if debug mode is enabled (level >= 3, i.e. -vvv)
    public static var isDebug: Bool {
        return verboseLevel >= 3
    }
    
    /// Write a styled header line
    public static func writeHeader(_ text: String) {
        guard isVerbose else { return }
        
        lock.lock()
        defer { lock.unlock() }
        
        print()
        writeColoredLine("═══════════════════════════════════════════════════════════════════", .accent)
        writeColoredLine("  \(text.uppercased())", .header)
        writeColoredLine("═══════════════════════════════════════════════════════════════════", .accent)
        print()
    }
    
    /// Write a section header with optional subtitle
    public static func writeSection(_ title: String, subtitle: String? = nil) {
        guard isVerbose else { return }
        
        lock.lock()
        defer { lock.unlock() }
        
        print()
        writeColoredLine(">> \(title)", .section)
        if let subtitle = subtitle {
            writeColoredLine("   \(subtitle)", .info)
        }
        writeColoredLine("─────────────────────────────────────────────────────────────", .accent)
    }
    
    /// Write a success message
    public static func writeSuccess(_ message: String) {
        guard isVerbose else { return }
        writeColoredLine("[OK] \(message)", .success)
    }
    
    /// Write an info message with optional indentation
    public static func writeInfo(_ message: String, indent: Int = 0) {
        guard isVerbose else { return }
        let prefix = String(repeating: "  ", count: indent)
        writeColoredLine("\(prefix)• \(message)", .info)
    }
    
    /// Write a warning message
    public static func writeWarning(_ message: String) {
        guard isVerbose else { return }
        writeColoredLine("[WARN] \(message)", .warning)
    }
    
    /// Write an error message
    public static func writeError(_ message: String) {
        guard isVerbose else { return }
        writeColoredLine("[ERROR] \(message)", .error)
    }
    
    /// Write a debug message (only shown with -vvv, level 3)
    public static func writeDebug(_ message: String) {
        guard isDebug else { return }
        writeColoredLine("[DEBUG] \(message)", .debug)
    }
    
    /// Write a progress indicator
    public static func writeProgress(_ operation: String, detail: String = "") {
        guard isVerbose else { return }
        let message = detail.isEmpty ? "[...] \(operation)..." : "[...] \(operation): \(detail)"
        writeColoredLine(message, .progress)
    }
    
    /// Write a key-value pair with styled formatting
    public static func writeKeyValue(_ key: String, value: Any?, indent: Int = 1) {
        guard isVerbose else { return }
        
        lock.lock()
        defer { lock.unlock() }
        
        let prefix = String(repeating: "  ", count: indent)
        let valueStr = value.map { "\($0)" } ?? "Not Set"
        
        print("\(prefix)\(ColorCode.accent.rawValue)\(key): \(ColorCode.reset.rawValue)\(ColorCode.info.rawValue)\(valueStr)\(ColorCode.reset.rawValue)")
    }
    
    /// Write query progress with visual progress bar
    /// Matches Windows: [01/55] [█░░░░░░░░░░░░░░░░░░░] 2% system_info
    public static func writeQueryProgress(queryName: String, current: Int, total: Int, result: String? = nil) {
        guard isVerbose else { return }
        
        let percentage = Double(current) / Double(total) * 100.0
        let progressBar = createProgressBar(percentage: percentage, width: 20)
        let resultText = result.map { " | \($0)" } ?? ""
        
        // Format: [01/55] [██░░░░░░░░░░░░░░░░░░] 5% query_name
        let paddedCurrent = String(format: "%02d", current)
        let paddedTotal = String(format: "%02d", total)
        
        writeColoredLine("[\(paddedCurrent)/\(paddedTotal)] \(progressBar) \(Int(percentage))% \(queryName)\(resultText)", .progress)
    }
    
    /// Write module summary with timing
    public static func writeModuleSummary(moduleName: String, queryCount: Int, duration: TimeInterval) {
        guard isVerbose else { return }
        
        let durationText: String
        if duration < 1.0 {
            durationText = "\(Int(duration * 1000))ms"
        } else {
            durationText = String(format: "%.1fs", duration)
        }
        
        writeColoredLine("  [OK] \(moduleName): \(queryCount) queries completed in \(durationText)", .success)
    }
    
    /// Write collection summary
    public static func writeCollectionSummary(_ summary: [String: Any]) {
        guard isVerbose else { return }
        
        writeSection("Collection Summary")
        
        for (key, value) in summary {
            writeKeyValue(key, value: value)
        }
    }
    
    /// Write a separator line
    public static func writeSeparator() {
        guard isVerbose else { return }
        writeColoredLine("─────────────────────────────────────────────────────────────", .accent)
    }
    
    // MARK: - Private Helpers
    
    /// Create a visual progress bar
    /// [████████░░░░░░░░░░░░] for given percentage
    private static func createProgressBar(percentage: Double, width: Int) -> String {
        let filled = Int(percentage / 100.0 * Double(width))
        let empty = width - filled
        
        let filledBar = String(repeating: "█", count: max(0, filled))
        let emptyBar = String(repeating: "░", count: max(0, empty))
        
        return "[\(filledBar)\(emptyBar)]"
    }
    
    /// Write a colored line to stdout
    private static func writeColoredLine(_ text: String, _ color: ColorCode) {
        // Check if stdout is a terminal (not redirected)
        let isTerminal = isatty(fileno(stdout)) != 0
        
        if isTerminal {
            print("\(color.rawValue)\(text)\(ColorCode.reset.rawValue)")
        } else {
            print(text)
        }
    }
}
