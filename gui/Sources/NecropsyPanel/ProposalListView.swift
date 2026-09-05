#if canImport(SwiftUI)
import SwiftUI
import NecropsyKit

/// The orchestration loop, rendered.
///
/// A stage finishes, results push into the next stage, and the operator
/// chooses -- with blast radius visible *before* the click. That is why the
/// risk factors are expanded inline rather than hidden behind a disclosure:
/// the number alone does not tell you that a run will contact live C2 from an
/// attributable address.
public struct ProposalListView: View {
    @EnvironmentObject private var store: CaseStore
    @Environment(\.necropsyTheme) private var theme
    @State private var confirming: ActionProposal?
    @State private var note: String = ""

    public init() {}

    public var body: some View {
        List {
            if store.proposals.isEmpty {
                ContentUnavailableView(
                    "Nothing awaiting a decision",
                    systemImage: "checkmark.circle",
                    description: Text("Analysis stages propose next steps here as they finish.")
                )
            }
            ForEach(store.proposals) { proposal in
                ProposalRow(proposal: proposal) { confirming = $0 }
            }
        }
        .confirmationDialog(
            confirming.map { "Authorise: \($0.title)" } ?? "",
            isPresented: Binding(
                get: { confirming != nil },
                set: { if !$0 { confirming = nil } }
            ),
            titleVisibility: .visible
        ) {
            if let proposal = confirming {
                Button("Authorise", role: proposal.band.rank >= RiskBand.high.rank
                       ? .destructive : nil) {
                    Task {
                        await store.accept(proposal, note: note.isEmpty ? nil : note)
                        note = ""
                        confirming = nil
                    }
                }
                Button("Reject", role: .cancel) {
                    Task {
                        await store.reject(proposal, note: note.isEmpty ? nil : note)
                        note = ""
                        confirming = nil
                    }
                }
            }
        } message: {
            if let proposal = confirming {
                Text(proposal.rationale)
            }
        }
    }
}

struct ProposalRow: View {
    let proposal: ActionProposal
    let onAuthorise: (ActionProposal) -> Void
    @Environment(\.necropsyTheme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline) {
                BandChip(
                    text: "\(proposal.riskBand) \(String(format: "%.1f", proposal.riskScore))",
                    color: theme.color(for: proposal.band)
                )
                Text(proposal.title).font(.headline)
                Spacer()
                if let cost = proposal.estimatedCostS {
                    Text(cost >= 60 ? "~\(cost / 60) min" : "~\(cost)s")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }

            Text(proposal.rationale)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            // Blast radius, itemised. A mitigating factor renders in the same
            // list with its sign, so "isolated" visibly earns its lower score.
            ForEach(proposal.riskFactors, id: \.code) { factor in
                HStack(spacing: 6) {
                    Image(systemName: factor.isMitigating
                          ? "arrow.down.circle" : "exclamationmark.triangle")
                        .foregroundStyle(factor.isMitigating ? Color.secondary : theme.high)
                    Text(factor.label).font(.caption)
                    Spacer()
                    Text(String(format: "%+.1f", factor.signedWeight))
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                }
            }

            if proposal.available {
                Button("Authorise…") { onAuthorise(proposal) }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
            } else if let reason = proposal.unavailableReason {
                // Shown, not hidden: the operator sees the whole decision
                // space and what this machine cannot do.
                Label(reason, systemImage: "wrench.and.screwdriver")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.vertical, 4)
        .opacity(proposal.available ? 1 : 0.65)
    }
}
#endif
