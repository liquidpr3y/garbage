import XCTest
@testable import NecropsyKit

/// Decode fixtures captured from the running Python API.
///
/// This is the cross-language half of the contract check: `contract/surface.json`
/// catches a route or field disappearing on the Python side, and these tests
/// catch the Swift models drifting from what the API actually emits. A rename
/// on either side fails a build instead of showing up as an empty pane.
///
/// Regenerate with: `python tools/generate_gui_fixtures.py gui/Fixtures`
final class FixtureDecodingTests: XCTestCase {
    private let decoder = NecropsyClient.makeDecoder()

    /// Fixtures are located relative to this source file rather than bundled.
    /// They are a repo artefact regenerated from the Python API, not something
    /// that ships inside the framework.
    private static let fixtureDirectory: URL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()   // NecropsyKitTests
        .deletingLastPathComponent()   // Tests
        .deletingLastPathComponent()   // gui
        .appendingPathComponent("Fixtures")

    private func fixture(_ name: String) throws -> Data {
        let url = Self.fixtureDirectory.appendingPathComponent("\(name).json")
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw XCTSkip(
                "fixture \(name).json missing; run tools/generate_gui_fixtures.py gui/Fixtures"
            )
        }
        return try Data(contentsOf: url)
    }

    private func decode<T: Decodable>(_ type: T.Type, _ name: String) throws -> T {
        try decoder.decode(type, from: try fixture(name))
    }

    // MARK: - Module and navigation

    func testModuleDescriptor() throws {
        let module = try decode(ModuleDescriptor.self, "module")
        XCTAssertEqual(module.slug, "necropsy")
        XCTAssertFalse(module.panels.isEmpty)
        XCTAssertEqual(module.riskBands, ["minimal", "low", "moderate", "high", "severe"])

        // A panel that cannot work here must say why, so the shell can grey it
        // out rather than let it fail on click.
        for panel in module.panels where !panel.enabled {
            XCTAssertNotNil(panel.disabledReason, "\(panel.id) is disabled with no reason")
            XCTAssertFalse(panel.disabledReason!.isEmpty)
        }
        XCTAssertTrue(module.panels.contains { $0.id == "cases" && $0.enabled })
    }

    // MARK: - Cases

    func testCaseListAndDetail() throws {
        let cases = try decode([CaseSummary].self, "case_list")
        XCTAssertFalse(cases.isEmpty)
        XCTAssertEqual(cases[0].severity, .medium)
        XCTAssertFalse(cases[0].aiDisclosureAllowed, "disclosure is off by default")

        let detail = try decode(CaseDetail.self, "case_detail")
        XCTAssertGreaterThan(detail.sampleCount, 0)
        XCTAssertGreaterThan(detail.findingCount, 0)
    }

    func testTimelineDecodesEveryRowKind() throws {
        let entries = try decode([TimelineEntry].self, "timeline")
        XCTAssertFalse(entries.isEmpty)

        let kinds = Set(entries.map(\.kind))
        XCTAssertTrue(kinds.contains(.finding))
        XCTAssertTrue(kinds.contains(.audit))
        // Newest first, as the panel renders it.
        XCTAssertEqual(entries.map(\.at), entries.map(\.at).sorted(by: >))
    }

    // MARK: - Findings and proposals

    func testFindingsCarrySeverityConfidenceAndAttack() throws {
        let findings = try decode([Finding].self, "findings")
        XCTAssertFalse(findings.isEmpty)
        XCTAssertTrue(findings.contains { !$0.attackTechniqueIds.isEmpty })
        XCTAssertTrue(findings.allSatisfy { (0...1).contains($0.confidence) })

        // Schema-free evidence still has to decode.
        let withEvidence = findings.first { !$0.evidence.isEmpty }
        XCTAssertNotNil(withEvidence)
    }

    func testProposalsCarryRiskFactors() throws {
        let actions = try decode([ActionProposal].self, "actions")
        XCTAssertFalse(actions.isEmpty)

        let detonate = actions.first { $0.kind == "detonate" }
        XCTAssertNotNil(detonate)
        XCTAssertFalse(detonate!.available, "no sandbox configured in the fixture run")
        XCTAssertNotNil(detonate!.unavailableReason)

        // Mitigating factors are what let the panel show why isolated scores
        // lower than egress-permitted.
        let allFactors = actions.flatMap(\.riskFactors)
        XCTAssertTrue(allFactors.contains { $0.isMitigating })
        XCTAssertTrue(allFactors.allSatisfy { $0.direction == 1 || $0.direction == -1 })
    }

    func testProposalBandMatchesScore() throws {
        for action in try decode([ActionProposal].self, "actions") {
            XCTAssertEqual(
                action.band, RiskBand(score: action.riskScore),
                "band/score mismatch on \(action.kind)"
            )
        }
    }

    // MARK: - Samples and static analysis

    func testSampleDetail() throws {
        let sample = try decode(SampleDetail.self, "sample_detail")
        XCTAssertEqual(sample.sha256.count, 64)
        XCTAssertEqual(sample.fileType, "pe")
        XCTAssertFalse(sample.identity.isEmpty)
    }

    func testCaseSamples() throws {
        let links = try decode([CaseSample].self, "case_samples")
        XCTAssertFalse(links.isEmpty)
        XCTAssertEqual(links[0].observedFilename, "loader.exe")
    }

    func testStaticReportAndStrings() throws {
        let report = try decode([String: JSONValue].self, "static_report")
        XCTAssertNotNil(report["pe"]?["imphash"]?.stringValue)
        XCTAssertNotNil(report["detection_quality"])

        let strings = try decode([String: JSONValue].self, "strings")
        XCTAssertNotNil(strings["iocs"])
        XCTAssertNotNil(strings["summary"]?["total_unique"]?.intValue)
    }

    func testFunctionsAndStats() throws {
        _ = try decode([FunctionSummary].self, "functions")
        let stats = try decode(FunctionStats.self, "function_stats")
        XCTAssertGreaterThanOrEqual(stats.total, 0)
    }

    // MARK: - ATT&CK

    func testAttackCoverage() throws {
        let coverage = try decode(AttackCoverage.self, "attack")
        XCTAssertFalse(coverage.attackVersion.isEmpty)
        XCTAssertGreaterThan(coverage.techniqueCount, 0)
        XCTAssertFalse(coverage.tactics.isEmpty)
        XCTAssertFalse(coverage.killChainNote.isEmpty)

        // Everything in a static-only case is inferred, and every inferred
        // cell must carry the caveat the panel renders.
        let cells = coverage.tactics.flatMap(\.techniques)
        XCTAssertTrue(cells.allSatisfy { $0.evidenceGrade == .inferred })
        for cell in cells where cell.evidenceGrade.needsCaveat {
            XCTAssertNotNil(cell.caveat, "\(cell.id) needs a caveat but has none")
        }
    }

    func testDetectionGapsDecode() throws {
        let coverage = try decode(AttackCoverage.self, "attack")
        for gap in coverage.detectionGaps {
            XCTAssertFalse(gap.missingSysmonCodes.isEmpty)
            XCTAssertFalse(gap.techniqueName.isEmpty)
        }
    }

    // MARK: - Sandbox and status

    func testDetonationsDecodeWhenEmpty() throws {
        XCTAssertEqual(try decode([Detonation].self, "detonations").count, 0)
    }

    func testStatusEndpoints() throws {
        let sandbox = try decode(SandboxStatus.self, "sandbox_status")
        XCTAssertFalse(sandbox.ready)
        XCTAssertNotNil(sandbox.reason)

        let tooling = try decode(ToolingStatus.self, "tooling")
        XCTAssertTrue(tooling.yara)

        let ai = try decode(AIStatus.self, "ai_status")
        XCTAssertTrue(ai.sdkInstalled)

        let attack = try decode(AttackStatus.self, "attack_status")
        XCTAssertGreaterThan(attack.techniqueCount, 600)
    }

    // MARK: - Events

    func testEventsDecode() throws {
        let finding = try decode(CaseEvent.self, "event_finding")
        XCTAssertEqual(finding.type, .findingCreated)
        XCTAssertEqual(finding.payload["severity"]?.stringValue, "high")

        let action = try decode(CaseEvent.self, "event_action")
        XCTAssertEqual(action.type, .actionProposed)
        XCTAssertEqual(action.payload["risk_band"]?.stringValue, "high")
        XCTAssertEqual(action.payload["available"]?.boolValue, false)
    }
}
