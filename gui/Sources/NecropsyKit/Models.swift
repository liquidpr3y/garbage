import Foundation

// Models for the endpoints the panel binds to. Field names use Swift casing;
// the client's decoder converts from the API's snake_case. `Tests/` decodes
// fixtures captured from the running Python API, so a rename on either side
// fails there rather than in someone's Xcode preview.

// MARK: - Module self-description

public struct PanelDescriptor: Codable, Identifiable, Sendable {
    public let id: String
    public let title: String
    /// SF Symbols name, for the host shell's navigation.
    public let icon: String
    public let path: String
    public let stream: String?
    public let description: String
    public let enabled: Bool
    /// Why this panel is unusable here. Shown instead of letting it look
    /// available and fail on click.
    public let disabledReason: String?
}

public struct ModuleDescriptor: Codable, Sendable {
    public let slug: String
    public let title: String
    public let version: String
    public let migrationHead: String
    public let riskBands: [String]
    public let panels: [PanelDescriptor]
}

// MARK: - Cases

public enum CaseStatus: String, Codable, Sendable {
    case open, analysing, contained, closed
}

public struct CaseSummary: Codable, Identifiable, Sendable {
    public let id: String
    public let name: String
    public let status: CaseStatus
    public let severity: Severity
    public let summary: String?
    public let tags: [String]
    public let hostEngagementRef: String?
    /// Gates everything in the AI panel. False by default since Phase 1.
    public let aiDisclosureAllowed: Bool
    public let createdAt: Date
    public let updatedAt: Date
}

public struct CaseDetail: Codable, Identifiable, Sendable {
    public let id: String
    public let name: String
    public let status: CaseStatus
    public let severity: Severity
    public let summary: String?
    public let tags: [String]
    public let hostEngagementRef: String?
    public let aiDisclosureAllowed: Bool
    public let createdAt: Date
    public let updatedAt: Date
    public let counts: [String: Int]

    public var sampleCount: Int { counts["samples"] ?? 0 }
    public var findingCount: Int { counts["findings"] ?? 0 }
    public var openActionCount: Int { counts["open_actions"] ?? 0 }
}

// MARK: - Timeline

public enum TimelineKind: String, Codable, Sendable {
    case job, finding, action, audit
}

/// One merged timeline row. The API returns a heterogeneous list on purpose --
/// the operator's question is "what happened to this case", not "show me the
/// jobs table" -- so the optional fields vary by `kind`.
public struct TimelineEntry: Codable, Identifiable, Sendable {
    public let at: Date
    public let kind: TimelineKind
    public let id: String
    public let title: String
    public let state: String?
    public let severity: Severity?
    public let confidence: Double?
    public let producer: String?
    public let attackTechniqueIds: [String]?
    public let killChainPhase: String?
    public let riskScore: Double?
    public let riskBand: String?
    public let available: Bool?
    public let decidedBy: String?
    public let actor: String?
    public let error: String?
}

// MARK: - Findings and proposals

public struct Finding: Codable, Identifiable, Sendable {
    public let id: String
    public let caseId: String
    public let sampleId: String?
    public let jobId: String?
    public let producer: String
    public let type: String
    public let title: String
    public let description: String?
    /// Severity and confidence are separate: a high-severity low-confidence AI
    /// inference must not render like a YARA hit.
    public let severity: Severity
    public let confidence: Double
    public let attackTechniqueIds: [String]
    public let killChainPhase: String?
    public let evidence: [String: JSONValue]
    public let createdAt: Date
}

public enum ActionState: String, Codable, Sendable {
    case proposed, accepted, rejected, executed, expired
}

public struct ActionProposal: Codable, Identifiable, Sendable {
    public let id: String
    public let caseId: String
    public let sampleId: String?
    public let originJobId: String?
    public let kind: String
    public let title: String
    public let rationale: String
    public let riskScore: Double
    public let riskBand: String
    public let riskFactors: [RiskFactor]
    public let estimatedCostS: Int?
    public let params: [String: JSONValue]
    public let available: Bool
    public let unavailableReason: String?
    public let state: ActionState
    public let decidedBy: String?
    public let decidedAt: Date?
    public let decisionNote: String?
    public let resultingJobId: String?
    public let createdAt: Date

    public var band: RiskBand { RiskBand(rawValue: riskBand) ?? RiskBand(score: riskScore) }
}

public struct AcceptResponse: Codable, Sendable {
    public let action: ActionProposal
    public let jobId: String?
}

// MARK: - Samples

public struct Sample: Codable, Identifiable, Sendable {
    public let id: String
    public let sha256: String
    public let sha1: String
    public let md5: String
    public let tlsh: String?
    public let ssdeep: String?
    public let size: Int
    public let mime: String?
    public let magic: String?
    public let fileType: String
    public let arch: String
    public let entropy: Double?
    public let storageState: String
    public let identity: [String: JSONValue]
    public let firstSeenAt: Date
}

public struct SampleDetail: Codable, Sendable {
    public let id: String
    public let sha256: String
    public let sha1: String
    public let md5: String
    public let tlsh: String?
    public let ssdeep: String?
    public let size: Int
    public let mime: String?
    public let magic: String?
    public let fileType: String
    public let arch: String
    public let entropy: Double?
    public let storageState: String
    public let identity: [String: JSONValue]
    public let firstSeenAt: Date
    public let otherCases: [[String: String]]
}

public struct CaseSample: Codable, Identifiable, Sendable {
    public let id: String
    public let caseId: String
    public let observedFilename: String?
    public let source: String
    public let submittedBy: String
    public let note: String?
    public let addedAt: Date
    public let sample: Sample
}

// MARK: - Decompilation

public struct FunctionSummary: Codable, Identifiable, Sendable {
    public let id: String
    public let name: String
    public let address: String
    public let size: Int
    public let isThunk: Bool
    public let parameterCount: Int
    public let calls: [String]
    public let hasDecompilation: Bool
    public let hasAiSummary: Bool
}

public struct FunctionDetail: Codable, Identifiable, Sendable {
    public let id: String
    public let sampleId: String
    public let jobId: String?
    public let name: String
    public let address: String
    public let size: Int
    public let isThunk: Bool
    public let callingConvention: String?
    public let parameterCount: Int
    public let calls: [String]
    public let decompiled: String?
    public let decompileError: String?
    public let codeSha256: String?
    /// Model-written and labelled as such wherever it is shown.
    public let aiSummary: String?
    public let aiSummarisedAt: Date?
    public let createdAt: Date
}

public struct FunctionStats: Codable, Sendable {
    public let total: Int
    public let thunks: Int
    public let decompiled: Int
    public let aiSummarised: Int
}

// MARK: - ATT&CK

public struct TechniqueCell: Codable, Identifiable, Sendable {
    public let id: String
    public let name: String
    public let tactics: [String]
    public let isSubtechnique: Bool
    public let parent: String?
    public let platforms: [String]
    public let logSources: [String]
    public let sysmonEventCodes: [String]
    public let url: String
    public let findingCount: Int
    public let maxSeverity: Severity
    public let maxConfidence: Double
    public let producers: [String]
    public let subtechniques: [String]
    public let evidenceGrade: EvidenceGrade
    /// Non-nil whenever the evidence is weaker than it looks.
    public let caveat: String?
    public let findingIds: [String]
}

public struct TacticColumn: Codable, Identifiable, Sendable {
    public let shortname: String
    public let id: String?
    public let name: String
    public let techniqueCount: Int
    public let maxSeverity: Severity
    public let techniques: [TechniqueCell]
}

public struct DetectionGap: Codable, Identifiable, Sendable {
    public let techniqueId: String
    public let techniqueName: String
    public let requiredSysmonCodes: [String]
    public let missingSysmonCodes: [String]
    public let logSources: [String]

    public var id: String { techniqueId }
}

public struct AttackCoverage: Codable, Sendable {
    public let caseId: String
    public let attackVersion: String
    public let techniqueCount: Int
    public let observedCount: Int
    public let inferredCount: Int
    public let unmappedFindingCount: Int
    public let tactics: [TacticColumn]
    public let killChain: [String: [String]]
    public let killChainNote: String
    public let detectionGaps: [DetectionGap]
    public let notes: [String]
}

// MARK: - Sandbox

public struct Detonation: Codable, Identifiable, Sendable {
    public let id: String
    public let caseId: String
    public let sampleId: String
    public let jobId: String?
    public let target: String
    public let targetArch: String
    public let targetOs: String
    public let snapshot: String
    public let egress: Bool
    /// native / interpreted / emulated / unsupported.
    public let fidelity: String
    public let fingerprint: [String: JSONValue]
    public let guestPath: String?
    public let guestHostname: String?
    public let execDetail: String?
    public let startedAt: Date
    public let finishedAt: Date?
    public let runSeconds: Int
    public let telemetryEvents: Int
    public let telemetrySource: String?
    public let telemetryNote: String?
    public let networkSummary: [String: JSONValue]
    public let behaviourSummary: [String: JSONValue]
    /// False means this run supports no conclusion. The panel must not render
    /// an unreadable run as a quiet one.
    public let readable: Bool
    public let verdictNote: String?
    public let state: String
    public let error: String?
    public let reverted: Bool
}

// MARK: - Status

public struct SandboxStatus: Codable, Sendable {
    public let enabled: Bool
    public let ready: Bool
    public let reason: String?
    public let target: String?
    public let knownTargets: [String]
    public let capabilities: [String: JSONValue]?
    public let pcapInterface: String?
    public let elasticReady: Bool
    public let elasticNote: String
    public let runSeconds: Int
}

public struct ToolingStatus: Codable, Sendable {
    public let lief: Bool
    public let yara: Bool
    public let tlsh: Bool
    public let libmagic: Bool
    public let rizin: Bool
    public let rizinPath: String?
    public let ghidra: Bool
    public let yaraRuleSources: [[String: JSONValue]]
}

public struct AIStatus: Codable, Sendable {
    public let sdkInstalled: Bool
    public let credentials: Bool
    public let credentialSource: String?
    public let model: String
    public let effort: String
    public let maxFunctions: Int
    public let goodwareDir: String?
    public let goodwareConfigured: Bool
}

public struct AttackStatus: Codable, Sendable {
    public let attackVersion: String
    public let techniqueCount: Int
    public let tacticCount: Int
    public let sigmaAvailable: Bool
    public let sigmaRuleCount: Int
    public let sigmaSources: [String]
    public let findingSink: String
}

// MARK: - Events

public enum EventType: String, Codable, Sendable {
    case caseCreated = "case.created"
    case caseUpdated = "case.updated"
    case sampleIngested = "sample.ingested"
    case jobQueued = "job.queued"
    case jobStarted = "job.started"
    case jobSucceeded = "job.succeeded"
    case jobFailed = "job.failed"
    case findingCreated = "finding.created"
    case actionProposed = "action.proposed"
    case actionDecided = "action.decided"
}

public struct CaseEvent: Codable, Sendable {
    public let type: EventType
    public let caseId: String
    public let at: Date
    public let payload: [String: JSONValue]
}
