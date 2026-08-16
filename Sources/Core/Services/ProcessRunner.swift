import Foundation

/// Result of a bounded external process run.
public struct ProcessRunResult: Sendable {
    public let standardOutput: String
    public let standardError: String
    public let exitCode: Int32
    /// True when the process was killed because it exceeded its time budget.
    public let timedOut: Bool
}

/// Runs external processes under a hard time budget.
///
/// Two properties matter, and the obvious implementation has neither:
///
/// 1. **Output is drained concurrently.** Reading stdout to EOF and only then reading stderr
///    deadlocks whenever a command writes more than a pipe buffer (64 KB) to stderr: the child
///    blocks writing stderr, the parent blocks reading stdout, and neither moves. That is a hang
///    with no misbehaving command involved at all.
///
/// 2. **The timeout does not depend on EOF.** A command launched as `/bin/bash -c "..."` passes
///    its inherited pipe to its own children, so killing bash alone does not close the write end
///    — a wedged grandchild keeps it open and a blocking read waits forever. This drains through
///    readability handlers and resolves the timeout independently, so a surviving grandchild can
///    delay cleanup but can never stall collection.
///
/// Best-effort teardown then walks the process tree, because killing only the direct child
/// leaves the grandchild that actually wedged still running.
public enum ProcessRunner {

    /// Default budget for a single external command. Individual collectors may pass more when a
    /// command is legitimately slow; nothing should run unbounded.
    public static let defaultTimeout: TimeInterval = 180

    /// Grace period between SIGTERM and SIGKILL, matching the osquery runner.
    private static let terminationGracePeriod: TimeInterval = 2

    public static func run(
        executable: String,
        arguments: [String],
        timeout: TimeInterval = defaultTimeout,
        label: String? = nil
    ) async throws -> ProcessRunResult {
        let description = label ?? ([executable] + arguments).joined(separator: " ")
        let box = ProcessBox()

        return try await withThrowingTaskGroup(of: RunOutcome.self) { group in
            group.addTask {
                let result = try await runToCompletion(
                    executable: executable,
                    arguments: arguments,
                    box: box
                )
                return .completed(result)
            }

            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                return .timedOut
            }

            defer { group.cancelAll() }

            while let outcome = try await group.next() {
                switch outcome {
                case .completed(let result):
                    return result

                case .timedOut:
                    ConsoleFormatter.writeDebug(
                        "Command exceeded its \(Int(timeout))s budget, terminating: \(description)"
                    )
                    box.terminate()
                    try? await Task.sleep(nanoseconds: UInt64(terminationGracePeriod * 1_000_000_000))
                    box.forceKillTree()

                    // Report rather than throw. A timed-out collector should degrade to an empty
                    // result like any other failure, not abort the module around it.
                    return ProcessRunResult(
                        standardOutput: box.drainedOutput(),
                        standardError: box.drainedError(),
                        exitCode: -1,
                        timedOut: true
                    )
                }
            }

            return ProcessRunResult(standardOutput: "", standardError: "", exitCode: -1, timedOut: false)
        }
    }

    /// Convenience for the overwhelmingly common `/bin/bash -c` case.
    public static func bash(
        _ command: String,
        timeout: TimeInterval = defaultTimeout
    ) async throws -> ProcessRunResult {
        try await run(
            executable: "/bin/bash",
            arguments: ["-c", command],
            timeout: timeout,
            label: command
        )
    }

    private enum RunOutcome {
        case completed(ProcessRunResult)
        case timedOut
    }

    private static func runToCompletion(
        executable: String,
        arguments: [String],
        box: ProcessBox
    ) async throws -> ProcessRunResult {
        try await withCheckedThrowingContinuation { continuation in
            let task = Process()
            task.executableURL = URL(fileURLWithPath: executable)
            task.arguments = arguments

            let outputPipe = Pipe()
            let errorPipe = Pipe()
            task.standardOutput = outputPipe
            task.standardError = errorPipe

            // Drain both pipes as data arrives. Nothing here blocks, so neither stream can
            // back-pressure the other into a deadlock.
            outputPipe.fileHandleForReading.readabilityHandler = { handle in
                let data = handle.availableData
                if !data.isEmpty { box.appendOutput(data) }
            }
            errorPipe.fileHandleForReading.readabilityHandler = { handle in
                let data = handle.availableData
                if !data.isEmpty { box.appendError(data) }
            }

            task.terminationHandler = { finished in
                // Collect whatever is still buffered before tearing the handlers down.
                let remainingOut = outputPipe.fileHandleForReading.availableData
                if !remainingOut.isEmpty { box.appendOutput(remainingOut) }
                let remainingErr = errorPipe.fileHandleForReading.availableData
                if !remainingErr.isEmpty { box.appendError(remainingErr) }

                outputPipe.fileHandleForReading.readabilityHandler = nil
                errorPipe.fileHandleForReading.readabilityHandler = nil

                guard box.claimCompletion() else { return }
                continuation.resume(returning: ProcessRunResult(
                    standardOutput: box.drainedOutput(),
                    standardError: box.drainedError(),
                    exitCode: finished.terminationStatus,
                    timedOut: false
                ))
            }

            do {
                try task.run()
                box.attach(task)
            } catch {
                outputPipe.fileHandleForReading.readabilityHandler = nil
                errorPipe.fileHandleForReading.readabilityHandler = nil
                guard box.claimCompletion() else { return }
                continuation.resume(throwing: BashError.processLaunchFailed(error))
            }
        }
    }
}

/// Shared handle to a running Process plus its accumulated output, so the timeout path can kill
/// it and read what it managed to produce from outside the task that launched it. Process is not
/// Sendable across concurrency boundaries, hence the lock-guarded wrapper.
final class ProcessBox: @unchecked Sendable {
    private let lock = NSLock()
    private var process: Process?
    private var outputData = Data()
    private var errorData = Data()
    private var completionClaimed = false

    func attach(_ process: Process) {
        lock.lock(); defer { lock.unlock() }
        self.process = process
    }

    func appendOutput(_ data: Data) {
        lock.lock(); defer { lock.unlock() }
        outputData.append(data)
    }

    func appendError(_ data: Data) {
        lock.lock(); defer { lock.unlock() }
        errorData.append(data)
    }

    func drainedOutput() -> String {
        lock.lock(); defer { lock.unlock() }
        return String(data: outputData, encoding: .utf8) ?? ""
    }

    func drainedError() -> String {
        lock.lock(); defer { lock.unlock() }
        return String(data: errorData, encoding: .utf8) ?? ""
    }

    /// Ensures the continuation is resumed exactly once across the completion and timeout paths.
    func claimCompletion() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if completionClaimed { return false }
        completionClaimed = true
        return true
    }

    func terminate() {
        lock.lock(); defer { lock.unlock() }
        guard let process = process, process.isRunning else { return }
        process.terminate()
    }

    /// SIGKILL the process and every descendant. Killing only the direct child leaves the
    /// grandchild that actually wedged holding the inherited pipe.
    func forceKillTree() {
        lock.lock()
        let pid = (process?.isRunning == true) ? process?.processIdentifier : nil
        lock.unlock()
        guard let pid = pid else { return }

        for descendant in Self.descendants(of: pid).reversed() {
            kill(descendant, SIGKILL)
        }
        kill(pid, SIGKILL)
    }

    /// Breadth-first walk of the process tree via pgrep, deepest last.
    private static func descendants(of pid: pid_t, depth: Int = 0) -> [pid_t] {
        guard depth < 8 else { return [] }
        let children = pgrepChildren(of: pid)
        var all: [pid_t] = []
        for child in children {
            all.append(child)
            all.append(contentsOf: descendants(of: child, depth: depth + 1))
        }
        return all
    }

    private static func pgrepChildren(of pid: pid_t) -> [pid_t] {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        task.arguments = ["-P", String(pid)]
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice

        do {
            try task.run()
        } catch {
            return []
        }

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()

        return (String(data: data, encoding: .utf8) ?? "")
            .split(separator: "\n")
            .compactMap { pid_t($0.trimmingCharacters(in: .whitespaces)) }
    }
}
