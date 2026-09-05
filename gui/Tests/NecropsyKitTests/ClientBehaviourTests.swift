import XCTest
@testable import NecropsyKit

/// Behaviour the panel depends on that is not about decoding.
final class ClientBehaviourTests: XCTestCase {

    // MARK: - Error mapping

    func testUnavailableIsDistinctFromServerError() throws {
        // 409 is "this install cannot do that" -- Ghidra missing, no sandbox --
        // and must render as a reason, not a crash banner or a retry prompt.
        let body = #"{"detail":"Dynamic analysis is disabled. Set NECROPSY_SANDBOX_ENABLED=true"}"#
            .data(using: .utf8)!
        guard case .unavailable(let detail) = NecropsyClient.mapError(status: 409, data: body) else {
            return XCTFail("409 must map to .unavailable")
        }
        XCTAssertTrue(detail.contains("NECROPSY_SANDBOX_ENABLED"))
        XCTAssertFalse(NecropsyError.unavailable(detail).isRetryable)
    }

    func testForbiddenCarriesThePolicyReason() throws {
        let body = #"{"detail":"this case has ai_disclosure_allowed set to false"}"#
            .data(using: .utf8)!
        guard case .forbidden(let detail) = NecropsyClient.mapError(status: 403, data: body) else {
            return XCTFail("403 must map to .forbidden")
        }
        XCTAssertTrue(detail.contains("ai_disclosure_allowed"))
    }

    func testConfirmationRequiredIsItsOwnCase() throws {
        // 428 on ingest is deliberate friction, not a failure.
        let body = #"{"detail":"Set header X-Necropsy-Confirm-Malware: true"}"#.data(using: .utf8)!
        guard case .confirmationRequired = NecropsyClient.mapError(status: 428, data: body) else {
            return XCTFail("428 must map to .confirmationRequired")
        }
    }

    func testServerErrorsAreRetryable() {
        let error = NecropsyClient.mapError(status: 503, data: Data())
        XCTAssertTrue(error.isRetryable)
    }

    func testMalformedErrorBodyStillProducesAMessage() {
        let error = NecropsyClient.mapError(status: 500, data: "not json".data(using: .utf8)!)
        XCTAssertNotNil(error.errorDescription)
    }

    // MARK: - Risk vocabulary

    func testRiskBandsMatchTheBackendThresholds() {
        XCTAssertEqual(RiskBand(score: 0.3), .minimal)
        XCTAssertEqual(RiskBand(score: 1.9), .minimal)
        XCTAssertEqual(RiskBand(score: 2.0), .low)
        XCTAssertEqual(RiskBand(score: 3.9), .low)
        XCTAssertEqual(RiskBand(score: 4.0), .moderate)
        XCTAssertEqual(RiskBand(score: 6.4), .moderate)
        XCTAssertEqual(RiskBand(score: 6.5), .high)
        XCTAssertEqual(RiskBand(score: 8.4), .high)
        XCTAssertEqual(RiskBand(score: 8.5), .severe)
        XCTAssertEqual(RiskBand(score: 10), .severe)
    }

    func testSeverityIsOrdered() {
        XCTAssertTrue(Severity.info < Severity.low)
        XCTAssertTrue(Severity.high < Severity.critical)
        XCTAssertEqual(
            [Severity.high, .info, .critical, .low].sorted(),
            [.info, .low, .high, .critical]
        )
    }

    func testEvidenceGradeDrivesTheCaveatBadge() {
        XCTAssertFalse(EvidenceGrade.observed.needsCaveat)
        XCTAssertTrue(EvidenceGrade.observedEmulated.needsCaveat)
        XCTAssertTrue(EvidenceGrade.inferred.needsCaveat)
    }

    // MARK: - Stream control frames

    func testStreamControlFramesAreRecognised() async {
        let stream = CaseEventStream(
            baseURL: URL(string: "http://localhost:8010/api/v1/necropsy")!, caseId: "c-1"
        )
        guard case .ready(let caseId)? = stream.parse(
            #"{"type":"stream.ready","case_id":"c-1"}"#
        ) else {
            return XCTFail("stream.ready must be recognised")
        }
        XCTAssertEqual(caseId, "c-1")

        // No broker is a normal state the panel renders, not an error.
        guard case .unavailable(let reason)? = stream.parse(
            #"{"type":"stream.unavailable","detail":"Connection refused"}"#
        ) else {
            return XCTFail("stream.unavailable must be recognised")
        }
        XCTAssertTrue(reason.contains("refused"))
    }

    func testStreamParsesAnEvent() {
        let stream = CaseEventStream(
            baseURL: URL(string: "http://localhost:8010/api/v1/necropsy")!, caseId: "c-1"
        )
        let json = """
        {"type":"finding.created","case_id":"c-1","at":"2026-09-05T12:00:00.123456+00:00",
         "payload":{"title":"Wrote an autorun registry value","severity":"high"}}
        """
        guard case .event(let event)? = stream.parse(json) else {
            return XCTFail("an event frame must decode")
        }
        XCTAssertEqual(event.type, .findingCreated)
        XCTAssertEqual(event.payload["severity"]?.stringValue, "high")
    }

    func testStreamIgnoresGarbage() {
        let stream = CaseEventStream(
            baseURL: URL(string: "http://localhost:8010/api/v1/necropsy")!, caseId: "c-1"
        )
        XCTAssertNil(stream.parse("not json at all"))
    }

    // MARK: - JSONValue

    func testJSONValueRendersEvidenceForDisplay() throws {
        let json = #"{"paths":["HKCU\\Run\\x"],"count":3,"packed":true,"note":null}"#
        let value = try JSONDecoder().decode(JSONValue.self, from: json.data(using: .utf8)!)
        XCTAssertEqual(value["count"]?.intValue, 3)
        XCTAssertEqual(value["packed"]?.boolValue, true)
        XCTAssertEqual(value["note"]?.displayText, "-")
        XCTAssertEqual(value["paths"]?.arrayValue?.count, 1)
    }
}
