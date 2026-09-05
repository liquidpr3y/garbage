#if canImport(SwiftUI)
import SwiftUI
import NecropsyKit

/// Detonation runs for a case.
///
/// An unreadable run is rendered as a warning, never as an empty timeline. A
/// blank list and "the sample did nothing" look identical, and only one of
/// them is true -- so the verdict text leads and the event count follows.
public struct SandboxTimelineView: View {
    @EnvironmentObject private var store: CaseStore
    @Environment(\.necropsyTheme) private var theme

    public init() {}

    public var body: some View {
        List {
            if store.detonations.isEmpty {
                ContentUnavailableView(
                    "No detonations",
                    systemImage: "play.slash",
                    description: Text("Authorise a detonation proposal to run this sample.")
                )
            }
            ForEach(store.detonations) { run in
                DetonationRow(run: run)
            }
        }
    }
}

struct DetonationRow: View {
    let run: Detonation
    @Environment(\.necropsyTheme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Image(systemName: run.readable ? "checkmark.seal" : "exclamationmark.triangle.fill")
                    .foregroundStyle(run.readable ? Color.secondary : theme.moderate)
                Text(run.target).font(.headline)
                BandChip(text: run.fidelity, color: fidelityColor)
                if run.egress {
                    BandChip(text: "egress", color: theme.severe)
                }
                Spacer()
                Text("\(run.telemetryEvents) events · \(run.runSeconds)s")
                    .font(.caption).foregroundStyle(.secondary)
            }

            // The verdict is the product of a run, not the event list.
            if let verdict = run.verdictNote {
                Text(verdict)
                    .font(.callout)
                    .foregroundStyle(run.readable ? .primary : theme.moderate)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if let note = run.telemetryNote, !run.readable {
                Text(note).font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if !run.reverted {
                Label("Snapshot was not reverted — check the lab before the next run",
                      systemImage: "exclamationmark.octagon")
                    .font(.caption).foregroundStyle(theme.severe)
            }
        }
        .padding(.vertical, 4)
    }

    private var fidelityColor: Color {
        switch run.fidelity {
        case "native", "interpreted": return .secondary
        case "emulated": return theme.moderate
        default: return theme.severe
        }
    }
}
#endif
