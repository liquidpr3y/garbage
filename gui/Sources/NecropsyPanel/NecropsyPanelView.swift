#if canImport(SwiftUI)
import SwiftUI
import NecropsyKit

/// The Necropsy panel, as mounted inside the pentest GUI's single pane.
///
/// The host owns the window and the outer navigation; this is what it puts in
/// the content area when the operator selects the malware-analysis module. The
/// panel list is fetched rather than hardcoded, so a panel whose backing tool
/// is missing on this host appears disabled with the reason instead of failing
/// on click.
public struct NecropsyPanelView: View {
    @StateObject private var store: CaseStore
    @State private var module: ModuleDescriptor?
    @State private var selectedPanel: String = "cases"

    private let client: NecropsyClient

    public init(client: NecropsyClient, baseURL: URL, caseId: String) {
        self.client = client
        _store = StateObject(wrappedValue: CaseStore(client: client, baseURL: baseURL, caseId: caseId))
    }

    public var body: some View {
        NavigationSplitView {
            List(selection: $selectedPanel) {
                ForEach(module?.panels ?? []) { panel in
                    Label(panel.title, systemImage: panel.icon)
                        .tag(panel.id)
                        .disabled(!panel.enabled)
                        .help(panel.disabledReason ?? panel.description)
                }
            }
            .navigationSplitViewColumnWidth(min: 160, ideal: 190)
        } detail: {
            content
                .toolbar { toolbar }
        }
        .environmentObject(store)
        .task {
            module = try? await client.moduleDescriptor()
            await store.load()
            store.startStreaming()
        }
        .onDisappear { store.stopStreaming() }
    }

    @ViewBuilder
    private var content: some View {
        switch selectedPanel {
        case "attack": AttackHeatmapView()
        case "sandbox": SandboxTimelineView()
        case "report": ReportView(client: client, caseId: store.caseId)
        default: CaseDetailView()
        }
    }

    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        ToolbarItem(placement: .status) {
            if let note = store.streamNote {
                // A missing broker is a normal state, not a failure banner.
                Label(note, systemImage: "bolt.slash")
                    .font(.caption).foregroundStyle(.secondary).help(note)
            } else if store.liveUpdates {
                Label("Live", systemImage: "bolt.fill").font(.caption).foregroundStyle(.secondary)
            }
        }
        ToolbarItem {
            Button { Task { await store.load() } } label: {
                Image(systemName: "arrow.clockwise")
            }
            .disabled(store.isLoading)
        }
    }
}

/// Case overview: findings, the merged timeline, and what needs a decision.
public struct CaseDetailView: View {
    @EnvironmentObject private var store: CaseStore
    @Environment(\.necropsyTheme) private var theme

    public init() {}

    public var body: some View {
        HSplitView {
            VStack(alignment: .leading) {
                if let error = store.error {
                    Label(error, systemImage: "xmark.octagon")
                        .foregroundStyle(theme.severe).padding(.horizontal)
                }
                if let summary = store.detail?.summary {
                    VStack(alignment: .leading, spacing: 4) {
                        HStack { Text("Summary").font(.headline); AIBadge() }
                        Text(summary).font(.callout).fixedSize(horizontal: false, vertical: true)
                    }
                    .padding(.horizontal)
                }
                List(store.findings) { finding in
                    FindingRow(finding: finding)
                }
            }
            ProposalListView().frame(minWidth: 320)
        }
    }
}

struct FindingRow: View {
    let finding: Finding
    @Environment(\.necropsyTheme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack {
                BandChip(
                    text: finding.severity.rawValue, color: theme.color(for: finding.severity)
                )
                Text(finding.title).font(.callout)
                Spacer()
                if finding.producer == "ai" {
                    AIBadge(confidence: finding.confidence)
                } else {
                    Text("\(Int(finding.confidence * 100))%")
                        .font(.caption2).foregroundStyle(.secondary)
                }
            }
            if !finding.attackTechniqueIds.isEmpty {
                Text(finding.attackTechniqueIds.joined(separator: " · "))
                    .font(.caption2.monospaced()).foregroundStyle(.secondary)
            }
        }
    }
}

/// The AI report pane. Everything here is labelled as model-written.
public struct ReportView: View {
    let client: NecropsyClient
    let caseId: String
    @State private var report: [String: JSONValue]?
    @State private var message: String?

    public init(client: NecropsyClient, caseId: String) {
        self.client = client
        self.caseId = caseId
    }

    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                if let message {
                    ContentUnavailableView(
                        "No report yet", systemImage: "doc.text", description: Text(message)
                    )
                }
                if let body = report?["report"]?.objectValue {
                    HStack { Text("Case report").font(.title3.weight(.semibold)); AIBadge() }
                    section("Executive summary", body["executive_summary"])
                    section("Technical narrative", body["technical_narrative"])
                    section("Assessment", body["assessment"])
                    list("Recommended actions", body["recommended_actions"])
                    list("Intelligence notes", body["intelligence_notes"])
                    // Most important field on the page: what was not established.
                    list("Evidence gaps", body["evidence_gaps"])
                }
            }
            .padding()
        }
        .task {
            do { report = try await client.report(caseId) }
            catch { message = (error as? NecropsyError)?.errorDescription }
        }
    }

    @ViewBuilder
    private func section(_ title: String, _ value: JSONValue?) -> some View {
        if let text = value?.stringValue, !text.isEmpty {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.headline)
                Text(text).font(.callout).fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    @ViewBuilder
    private func list(_ title: String, _ value: JSONValue?) -> some View {
        if let items = value?.arrayValue, !items.isEmpty {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.headline)
                ForEach(Array(items.enumerated()), id: \.offset) { _, item in
                    Label(item.displayText, systemImage: "circle.fill")
                        .labelStyle(BulletLabelStyle())
                        .font(.callout)
                }
            }
        }
    }
}

struct BulletLabelStyle: LabelStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            configuration.icon.font(.system(size: 4)).foregroundStyle(.secondary)
            configuration.title.fixedSize(horizontal: false, vertical: true)
        }
    }
}
#endif
