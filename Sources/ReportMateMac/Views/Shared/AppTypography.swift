import SwiftUI

/// App-wide text sizing. macOS has no Dynamic Type, so the app carries its own
/// multiplier (a slider in Settings) applied to the macOS text-style sizes.
enum AppTextStyle: String, CaseIterable {
    case largeTitle, title, title2, title3, headline, body, callout, subheadline, footnote, caption, caption2

    var basePointSize: CGFloat {
        switch self {
        case .largeTitle: return 26
        case .title: return 22
        case .title2: return 17
        case .title3: return 16
        case .headline: return 14
        case .body: return 13
        case .callout: return 13
        case .subheadline: return 12
        case .footnote: return 11
        case .caption: return 11
        case .caption2: return 10
        }
    }

    var baseWeight: Font.Weight? { self == .headline ? .semibold : nil }

    func font(scale: Double, weight: Font.Weight? = nil, design: Font.Design = .default) -> Font {
        let size = (basePointSize * CGFloat(AppFontScale.clamp(scale))).rounded()
        return .system(size: size, weight: weight ?? baseWeight ?? .regular, design: design)
    }
}

enum AppFontScale {
    static let storageKey = "ui.fontScale"
    static let range: ClosedRange<Double> = 0.9...1.6
    static let step: Double = 0.05
    static let `default`: Double = 1.0

    static func clamp(_ value: Double) -> Double { min(max(value, range.lowerBound), range.upperBound) }
    static func label(_ value: Double) -> String { "\(Int((value * 100).rounded()))%" }
}

private struct AppFontScaleKey: EnvironmentKey {
    static let defaultValue: Double = AppFontScale.default
}

extension EnvironmentValues {
    var appFontScale: Double {
        get { self[AppFontScaleKey.self] }
        set { self[AppFontScaleKey.self] = newValue }
    }
}

private struct AppFontModifier: ViewModifier {
    @Environment(\.appFontScale) private var scale
    let style: AppTextStyle
    let weight: Font.Weight?
    let design: Font.Design

    func body(content: Content) -> some View {
        content.font(style.font(scale: scale, weight: weight, design: design))
    }
}

private struct AppFixedFontModifier: ViewModifier {
    @Environment(\.appFontScale) private var scale
    let base: CGFloat
    let weight: Font.Weight
    let design: Font.Design

    func body(content: Content) -> some View {
        let size = (base * CGFloat(AppFontScale.clamp(scale))).rounded()
        return content.font(.system(size: size, weight: weight, design: design))
    }
}

extension View {
    func appFont(_ style: AppTextStyle, weight: Font.Weight? = nil, design: Font.Design = .default) -> some View {
        modifier(AppFontModifier(style: style, weight: weight, design: design))
    }

    func appFont(fixed base: CGFloat, weight: Font.Weight = .regular, design: Font.Design = .default) -> some View {
        modifier(AppFixedFontModifier(base: base, weight: weight, design: design))
    }

    func appFontScale(_ scale: Double) -> some View {
        environment(\.appFontScale, AppFontScale.clamp(scale))
    }
}
