#if canImport(SwiftUI)
import Foundation
import SwiftUI
import NecropsyKit

/// View state for one case.
///
/// Loads once, then follows the live event stream. When the stream reports
/// itself unavailable -- an install with no broker analyses fine, it just has
/// no push -- the panel says so and offers refresh instead of silently going
/// stale.
@MainActor
public final class CaseStore: ObservableObject {
    @Published public private(set) var detail: CaseDetail?
    @Published public private(set) var timeline: [TimelineEntry] = []
    @Published public private(set) var findings: [Finding] = []
    @Published public private(set) var proposals: [ActionProposal] = []
    @Published public private(set) var coverage: AttackCoverage?
    @Published public private(set) var detonations: [Detonation] = []
    @Published public private(set) var isLoading = false
    @Published public private(set) var error: String?
    @Published public private(set) var liveUpdates = false
    @Published public private(set) var streamNote: String?

    private let client: NecropsyClient
    private let baseURL: URL
    public let caseId: String
    private var streamTask: Task<Void, Never>?

    public init(client: NecropsyClient, baseURL: URL, caseId: String) {
        self.client = client
        self.baseURL = baseURL
        self.caseId = caseId
    }

    deinit { streamTask?.cancel() }

    public func load() async {
        isLoading = true
        error = nil
        do {
            async let detail = client.caseDetail(caseId)
            async let timeline = client.timeline(caseId)
            async let findings = client.findings(caseId)
            async let proposals = client.actions(caseId)
            async let coverage = client.attackCoverage(caseId)
            async let detonations = client.detonations(caseId)

            self.detail = try await detail
            self.timeline = try await timeline
            self.findings = try await findings
            self.proposals = try await proposals
            self.coverage = try await coverage
            self.detonations = try await detonations
        } catch {
            self.error = (error as? NecropsyError)?.errorDescription ?? error.localizedDescription
        }
        isLoading = false
    }

    public func startStreaming() {
        streamTask?.cancel()
        streamTask = Task { [weak self] in
            guard let self else { return }
            let stream = CaseEventStream(baseURL: baseURL, caseId: caseId)
            do {
                for try await message in await stream.messages() {
                    switch message {
                    case .ready:
                        self.liveUpdates = true
                        self.streamNote = nil
                    case .unavailable(let reason):
                        self.liveUpdates = false
                        self.streamNote =
                            "Live updates unavailable (\(reason)). Analysis is unaffected; refresh to see new results."
                    case .event:
                        // Events tell us *that* something changed; the panel
                        // re-reads rather than trying to patch local state,
                        // which would drift from the server's view.
                        await self.load()
                    }
                }
            } catch {
                self.liveUpdates = false
                self.streamNote = "Live updates stopped: \(error.localizedDescription)"
            }
        }
    }

    public func stopStreaming() {
        streamTask?.cancel()
        streamTask = nil
        liveUpdates = false
    }

    /// Authorise a proposal. The only route to running analysis.
    public func accept(_ proposal: ActionProposal, note: String?) async {
        do {
            _ = try await client.accept(actionId: proposal.id, note: note)
            await load()
        } catch {
            self.error = (error as? NecropsyError)?.errorDescription ?? error.localizedDescription
        }
    }

    public func reject(_ proposal: ActionProposal, note: String?) async {
        do {
            _ = try await client.reject(actionId: proposal.id, note: note)
            await load()
        } catch {
            self.error = (error as? NecropsyError)?.errorDescription ?? error.localizedDescription
        }
    }
}
#endif
