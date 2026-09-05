#if canImport(SwiftUI)
import SwiftUI
import NecropsyKit

/// The per-case ATT&CK matrix.
///
/// The one thing this view must not do is render an inferred capability the
/// same as an observed behaviour. A cell's border and badge carry the evidence
/// grade, and the caveat is one hover away -- because "the sample imports
/// VirtualAllocEx" and "the sample created a remote thread" are different
/// claims and a flat heatmap erases the difference.
public struct AttackHeatmapView: View {
    @EnvironmentObject private var store: CaseStore
    @Environment(\.necropsyTheme) private var theme
    @State private var selected: TechniqueCell?

    public init() {}

    public var body: some View {
        if let coverage = store.coverage {
            ScrollView([.horizontal, .vertical]) {
                VStack(alignment: .leading, spacing: 12) {
                    header(coverage)
                    matrix(coverage)
                    if !coverage.detectionGaps.isEmpty {
                        gaps(coverage)
                    }
                    ForEach(coverage.notes, id: \.self) { note in
                        Label(note, systemImage: "exclamationmark.circle")
                            .font(.callout)
                            .foregroundStyle(theme.moderate)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .padding()
            }
            .inspector(isPresented: Binding(
                get: { selected != nil }, set: { if !$0 { selected = nil } }
            )) {
                if let cell = selected { TechniqueInspector(cell: cell) }
            }
        } else {
            ProgressView()
        }
    }

    private func header(_ coverage: AttackCoverage) -> some View {
        HStack(spacing: 16) {
            Text("ATT&CK v\(coverage.attackVersion)").font(.headline)
            Label("\(coverage.observedCount) observed", systemImage: "eye")
            Label("\(coverage.inferredCount) inferred", systemImage: "questionmark.circle")
                .foregroundStyle(.secondary)
            if coverage.unmappedFindingCount > 0 {
                Text("\(coverage.unmappedFindingCount) findings not on the matrix")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private func matrix(_ coverage: AttackCoverage) -> some View {
        HStack(alignment: .top, spacing: 10) {
            ForEach(coverage.tactics) { tactic in
                VStack(alignment: .leading, spacing: 6) {
                    Text(tactic.name)
                        .font(.caption.weight(.semibold))
                        .frame(width: 168, alignment: .leading)
                    ForEach(tactic.techniques) { cell in
                        Button { selected = cell } label: {
                            TechniqueTile(cell: cell)
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
        }
    }

    private func gaps(_ coverage: AttackCoverage) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Detection gaps").font(.headline)
            Text("Techniques in this case the lab's telemetry could not have seen.")
                .font(.caption).foregroundStyle(.secondary)
            ForEach(coverage.detectionGaps) { gap in
                HStack {
                    Text(gap.techniqueId).font(.caption.monospaced())
                    Text(gap.techniqueName).font(.caption)
                    Spacer()
                    Text("missing Sysmon \(gap.missingSysmonCodes.joined(separator: ", "))")
                        .font(.caption).foregroundStyle(theme.moderate)
                }
            }
        }
    }
}

struct TechniqueTile: View {
    let cell: TechniqueCell
    @Environment(\.necropsyTheme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 4) {
                Text(cell.id).font(.caption2.monospaced())
                Spacer()
                if cell.evidenceGrade == .observed {
                    Image(systemName: "eye.fill").font(.caption2)
                } else if cell.evidenceGrade == .observedEmulated {
                    Image(systemName: "eye.trianglebadge.exclamationmark").font(.caption2)
                }
            }
            Text(cell.name).font(.caption).lineLimit(2)
        }
        .padding(6)
        .frame(width: 168, alignment: .leading)
        .background(theme.color(for: cell.maxSeverity).opacity(fillOpacity), in: rect)
        .overlay(rect.strokeBorder(borderColor, style: borderStyle))
        .help(cell.caveat ?? cell.name)
    }

    private var rect: RoundedRectangle { RoundedRectangle(cornerRadius: 5) }

    // Observed evidence gets a solid fill and border; inferred is washed out
    // and dashed, so the difference is legible at a glance across the matrix.
    private var fillOpacity: Double { cell.evidenceGrade == .inferred ? 0.10 : 0.28 }
    private var borderColor: Color {
        cell.evidenceGrade == .inferred ? theme.inferred : theme.color(for: cell.maxSeverity)
    }
    private var borderStyle: StrokeStyle {
        cell.evidenceGrade == .inferred ? StrokeStyle(lineWidth: 1, dash: [3, 2])
                                        : StrokeStyle(lineWidth: 1.5)
    }
}

struct TechniqueInspector: View {
    let cell: TechniqueCell
    @Environment(\.necropsyTheme) private var theme

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 10) {
                Text(cell.name).font(.title3.weight(.semibold))
                HStack {
                    Text(cell.id).font(.caption.monospaced())
                    BandChip(
                        text: cell.maxSeverity.rawValue,
                        color: theme.color(for: cell.maxSeverity)
                    )
                    BandChip(text: cell.evidenceGrade.rawValue, color: theme.inferred)
                }
                if let caveat = cell.caveat {
                    Label(caveat, systemImage: "exclamationmark.triangle")
                        .font(.callout)
                        .foregroundStyle(theme.moderate)
                        .fixedSize(horizontal: false, vertical: true)
                }
                labelled("Findings", "\(cell.findingCount) from \(cell.producers.joined(separator: ", "))")
                if !cell.subtechniques.isEmpty {
                    labelled("Sub-techniques", cell.subtechniques.joined(separator: ", "))
                }
                if !cell.sysmonEventCodes.isEmpty {
                    labelled("Detected by Sysmon", cell.sysmonEventCodes.joined(separator: ", "))
                }
                Link("Open on attack.mitre.org", destination: URL(string: cell.url)!)
                    .font(.callout)
            }
            .padding()
        }
    }

    private func labelled(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.callout)
        }
    }
}
#endif
