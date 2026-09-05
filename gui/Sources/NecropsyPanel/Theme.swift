#if canImport(SwiftUI)
import SwiftUI
import NecropsyKit

/// Colour and layout the panel needs, expressed so the host's design tokens
/// can replace it.
///
/// The pentest GUI owns the design language. Rather than invent a second one,
/// this maps Necropsy's shared vocabulary -- risk bands, severities, evidence
/// grades -- onto semantic colours the host can override in one place. The
/// point of sharing `RiskBand` with the pentest module is that a "high" from
/// either renders identically.
public struct NecropsyTheme: Sendable {
    public var minimal: Color = .secondary
    public var low: Color = .blue
    public var moderate: Color = .yellow
    public var high: Color = .orange
    public var severe: Color = .red
    public var inferred: Color = .secondary

    public init() {}

    public func color(for band: RiskBand) -> Color {
        switch band {
        case .minimal: return minimal
        case .low: return low
        case .moderate: return moderate
        case .high: return high
        case .severe: return severe
        }
    }

    public func color(for severity: Severity) -> Color {
        switch severity {
        case .info: return minimal
        case .low: return low
        case .medium: return moderate
        case .high: return high
        case .critical: return severe
        }
    }
}

private struct NecropsyThemeKey: EnvironmentKey {
    static let defaultValue = NecropsyTheme()
}

public extension EnvironmentValues {
    var necropsyTheme: NecropsyTheme {
        get { self[NecropsyThemeKey.self] }
        set { self[NecropsyThemeKey.self] = newValue }
    }
}

/// A severity or risk chip. One component so both modules' output matches.
public struct BandChip: View {
    let text: String
    let color: Color

    public init(text: String, color: Color) {
        self.text = text
        self.color = color
    }

    public var body: some View {
        Text(text.uppercased())
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.18), in: Capsule())
            .foregroundStyle(color)
    }
}

/// Marks anything a model wrote. Used everywhere AI output is shown, because
/// an unlabelled summary reads as fact.
public struct AIBadge: View {
    let confidence: Double?

    public init(confidence: Double? = nil) {
        self.confidence = confidence
    }

    public var body: some View {
        HStack(spacing: 3) {
            Image(systemName: "sparkles")
            if let confidence {
                Text("AI · \(Int(confidence * 100))%")
            } else {
                Text("AI")
            }
        }
        .font(.caption2)
        .foregroundStyle(.secondary)
        .help("Model-generated. Verify before acting on it.")
    }
}
#endif
