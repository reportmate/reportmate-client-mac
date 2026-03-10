//
//  ConsoleView.swift
//  ReportMate
//
//  Real-time log output display. Color-coded by log level,
//  monospaced font, auto-scrolls to bottom.
//

import SwiftUI

struct ConsoleView: View {
    let outputLines: [XPCClient.OutputLine]

    var body: some View {
        ScrollViewReader { scrollProxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 1) {
                    ForEach(outputLines) { line in
                        Text(line.text)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(color(for: line.level))
                            .textSelection(.enabled)
                            .id(line.id)
                    }
                }
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .background(.black.opacity(0.85))
            .clipShape(RoundedRectangle(cornerRadius: 6))
            .onChange(of: outputLines.count) {
                if let last = outputLines.last {
                    withAnimation(.easeOut(duration: 0.1)) {
                        scrollProxy.scrollTo(last.id, anchor: .bottom)
                    }
                }
            }
        }
    }

    private func color(for level: XPCClient.OutputLine.LogLevel) -> Color {
        switch level {
        case .error:   .red
        case .warning: .orange
        case .success: .green
        case .debug:   .gray
        case .info:    .white
        }
    }
}
