import SwiftUI

struct RunnerView: View {

    @State private var viewModel = RunnerViewModel()

    var body: some View {
        VStack(spacing: 0) {
            moduleSelectionArea
            Divider()
            outputArea
        }
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button(viewModel.isRunning ? "Running…" : "Run Collection") {
                    viewModel.run()
                }
                .disabled(viewModel.isRunning || viewModel.selectedModules.isEmpty)
                .keyboardShortcut(.return, modifiers: .command)
            }
        }
    }

    // MARK: - Module Selection

    private var moduleSelectionArea: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Modules")
                    .font(.headline)
                Spacer()
                Button("Select All") { viewModel.selectAll() }
                    .buttonStyle(.link)
                    .disabled(viewModel.isRunning)
                Text("·").foregroundStyle(.secondary)
                Button("Deselect All") { viewModel.deselectAll() }
                    .buttonStyle(.link)
                    .disabled(viewModel.isRunning)
            }

            LazyVGrid(columns: [GridItem(.adaptive(minimum: 160))], spacing: 6) {
                ForEach(ModuleDefinition.all) { module in
                    Toggle(isOn: moduleBinding(module.id)) {
                        Label {
                            VStack(alignment: .leading, spacing: 1) {
                                Text(module.displayName)
                                Text(module.description)
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                            }
                        } icon: {
                            Image(systemName: module.systemImage)
                                .frame(width: 16)
                        }
                    }
                    .toggleStyle(.checkbox)
                    .disabled(viewModel.isRunning)
                }
            }
        }
        .padding()
    }

    // MARK: - Output Area

    private var outputArea: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text("Output")
                    .font(.headline)
                Spacer()

                if viewModel.isRunning {
                    ProgressView()
                        .controlSize(.small)
                    Text("Running with elevated privileges…")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else if let status = viewModel.exitStatus {
                    Image(systemName: status == 0 ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                        .foregroundStyle(status == 0 ? .green : .orange)
                    Text(status == 0 ? "Completed" : "Finished (exit \(status))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                if !viewModel.outputText.isEmpty {
                    Button {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(viewModel.outputText, forType: .string)
                    } label: {
                        Image(systemName: "doc.on.doc")
                    }
                    .help("Copy output to clipboard")
                }
            }
            .padding(.horizontal)
            .padding(.top, 8)

            ScrollViewReader { proxy in
                ScrollView {
                    VStack(alignment: .leading, spacing: 0) {
                        if viewModel.outputText.isEmpty && !viewModel.isRunning {
                            Text("Select modules and click Run Collection to begin.")
                                .foregroundStyle(.tertiary)
                                .frame(maxWidth: .infinity, alignment: .center)
                                .padding(.top, 40)
                        } else {
                            Text(viewModel.outputText)
                                .font(.system(.caption, design: .monospaced))
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        Color.clear.frame(height: 1).id("bottom")
                    }
                    .padding(.horizontal)
                    .padding(.bottom, 8)
                }
                .background(Color(nsColor: .textBackgroundColor))
                .onChange(of: viewModel.outputText) {
                    proxy.scrollTo("bottom", anchor: .bottom)
                }
            }
        }
        .frame(minHeight: 250)
    }

    // MARK: - Helpers

    private func moduleBinding(_ id: String) -> Binding<Bool> {
        Binding(
            get: { viewModel.selectedModules.contains(id) },
            set: { isOn in
                if isOn { viewModel.selectedModules.insert(id) }
                else { viewModel.selectedModules.remove(id) }
            }
        )
    }
}
