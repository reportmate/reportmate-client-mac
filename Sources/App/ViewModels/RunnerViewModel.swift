import Foundation

@MainActor
@Observable
final class RunnerViewModel {

    var selectedModules: Set<String> = Set(ModuleDefinition.all.map(\.id))
    var isRunning = false
    var outputText = ""
    var exitStatus: Int32?

    private var logFileHandle: FileHandle?
    private var pollingTask: Task<Void, Never>?
    private var currentLogPath: String?

    // MARK: - Public API

    func run() {
        guard !isRunning else { return }
        guard !selectedModules.isEmpty else { return }

        isRunning = true
        exitStatus = nil
        outputText = ""

        let runnerPath = Self.resolveRunnerPath()
        let modules = selectedModules.sorted().joined(separator: ",")
        let logPath = NSTemporaryDirectory() + "reportmate-gui-\(UUID().uuidString.prefix(8)).log"

        // Create empty log file for polling
        FileManager.default.createFile(atPath: logPath, contents: nil)
        currentLogPath = logPath
        logFileHandle = FileHandle(forReadingAtPath: logPath)

        // Write a temp shell script to avoid nested escaping
        let scriptPath = NSTemporaryDirectory() + "reportmate-run-\(UUID().uuidString.prefix(8)).sh"
        let scriptContent = """
            #!/bin/sh
            "\(runnerPath)" -vv --run-modules "\(modules)" > "\(logPath)" 2>&1
            exit 0
            """

        do {
            try scriptContent.write(toFile: scriptPath, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes(
                [.posixPermissions: NSNumber(value: Int16(0o755))],
                ofItemAtPath: scriptPath
            )
        } catch {
            outputText = "Error: Failed to create run script: \(error.localizedDescription)\n"
            isRunning = false
            return
        }

        // Start polling the log file for output
        startPolling()

        // Launch privileged process
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = [
            "-e",
            "do shell script \"\(scriptPath)\" with administrator privileges",
        ]
        process.terminationHandler = { @Sendable [weak self] proc in
            let status = proc.terminationStatus
            try? FileManager.default.removeItem(atPath: scriptPath)
            Task { @MainActor [weak self] in
                self?.handleCompletion(status: status)
            }
        }

        do {
            try process.run()
        } catch {
            outputText += "Error: Failed to launch. \(error.localizedDescription)\n"
            isRunning = false
            cleanup()
        }
    }

    func selectAll() {
        selectedModules = Set(ModuleDefinition.all.map(\.id))
    }

    func deselectAll() {
        selectedModules = []
    }

    // MARK: - Private

    private func startPolling() {
        pollingTask = Task { [weak self] in
            while !Task.isCancelled {
                self?.readNewOutput()
                try? await Task.sleep(for: .milliseconds(250))
            }
        }
    }

    private func readNewOutput() {
        guard let handle = logFileHandle else { return }
        let data = handle.availableData
        if !data.isEmpty, let text = String(data: data, encoding: .utf8) {
            outputText += text
        }
    }

    private func handleCompletion(status: Int32) {
        pollingTask?.cancel()
        pollingTask = nil
        readNewOutput()
        exitStatus = status
        isRunning = false

        if status == 0 {
            outputText += "\n--- Collection completed successfully ---\n"
        } else if status == -1 || status == -128 {
            outputText += "\n--- Authentication cancelled ---\n"
        } else {
            outputText += "\n--- Collection finished (exit code: \(status)) ---\n"
        }

        logFileHandle?.closeFile()
        logFileHandle = nil
        if let path = currentLogPath {
            try? FileManager.default.removeItem(atPath: path)
            currentLogPath = nil
        }
    }

    private func cleanup() {
        pollingTask?.cancel()
        pollingTask = nil
        logFileHandle?.closeFile()
        logFileHandle = nil
        if let path = currentLogPath {
            try? FileManager.default.removeItem(atPath: path)
            currentLogPath = nil
        }
    }

    nonisolated static func resolveRunnerPath() -> String {
        // First try inside same app bundle
        let inBundle = Bundle.main.bundlePath + "/Contents/MacOS/managedreportsrunner"
        if FileManager.default.fileExists(atPath: inBundle) {
            return inBundle
        }
        // Standard install locations
        let standardPath = "/Applications/Utilities/ReportMate.app/Contents/MacOS/managedreportsrunner"
        if FileManager.default.fileExists(atPath: standardPath) {
            return standardPath
        }
        // Legacy / wrapper
        return "/usr/local/reportmate/managedreportsrunner"
    }
}
