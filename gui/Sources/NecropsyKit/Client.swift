import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Errors the panel has to render, kept distinguishable on purpose.
public enum NecropsyError: Error, LocalizedError, Sendable {
    /// The backend refused because this install cannot do the work -- no
    /// sandbox, no Ghidra, no credentials. Carries the operator-facing reason.
    case unavailable(String)
    /// A policy refusal, e.g. the case forbids AI disclosure.
    case forbidden(String)
    case notFound(String)
    case confirmationRequired(String)
    case server(status: Int, detail: String)
    case transport(String)
    case decoding(String)

    public var errorDescription: String? {
        switch self {
        case .unavailable(let detail): return detail
        case .forbidden(let detail): return detail
        case .notFound(let detail): return detail
        case .confirmationRequired(let detail): return detail
        case .server(let status, let detail): return "Server error \(status): \(detail)"
        case .transport(let detail): return "Could not reach Necropsy: \(detail)"
        case .decoding(let detail): return "Unexpected response shape: \(detail)"
        }
    }

    /// Whether the panel should offer a retry button.
    public var isRetryable: Bool {
        switch self {
        case .transport, .server: return true
        default: return false
        }
    }
}

/// Talks to one Necropsy mount.
///
/// The base URL is the mount prefix, so the same client works against the
/// sidecar (`http://127.0.0.1:8010/api/v1/necropsy`) and against the mounted
/// module inside the pentest backend (`http://127.0.0.1:8000/api/v1/necropsy`).
/// Moving from one to the other is a URL change and nothing else.
public actor NecropsyClient {
    public let baseURL: URL
    private let session: URLSession
    private let decoder: JSONDecoder
    private let encoder: JSONEncoder

    public init(baseURL: URL, session: URLSession = .shared) {
        self.baseURL = baseURL
        self.session = session

        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        decoder.dateDecodingStrategy = .custom { decoder in
            let text = try decoder.singleValueContainer().decode(String.self)
            if let date = NecropsyClient.iso8601WithFraction.date(from: text) {
                return date
            }
            if let date = NecropsyClient.iso8601.date(from: text) {
                return date
            }
            throw DecodingError.dataCorruptedError(
                in: try decoder.singleValueContainer(),
                debugDescription: "unrecognised timestamp \(text)"
            )
        }
        self.decoder = decoder

        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        self.encoder = encoder
    }

    // FastAPI emits fractional seconds and often no timezone suffix, so both
    // shapes have to parse or every list view comes back empty.
    nonisolated static let iso8601WithFraction: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()

    nonisolated static let iso8601: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter
    }()

    /// Exposed so tests can decode fixtures with exactly the client's rules.
    public nonisolated static func makeDecoder() -> JSONDecoder {
        let probe = NecropsyClient(baseURL: URL(string: "http://localhost")!)
        return probe.decoderForTesting
    }

    nonisolated var decoderForTesting: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        decoder.dateDecodingStrategy = .custom { decoder in
            let text = try decoder.singleValueContainer().decode(String.self)
            if let date = NecropsyClient.iso8601WithFraction.date(from: text) { return date }
            if let date = NecropsyClient.iso8601.date(from: text) { return date }
            throw DecodingError.dataCorruptedError(
                in: try decoder.singleValueContainer(),
                debugDescription: "unrecognised timestamp \(text)"
            )
        }
        return decoder
    }

    // MARK: - Transport

    private func request(
        _ method: String,
        _ path: String,
        query: [String: String] = [:],
        body: Data? = nil,
        headers: [String: String] = [:]
    ) async throws -> Data {
        var components = URLComponents(
            url: baseURL.appendingPathComponent(path.hasPrefix("/") ? String(path.dropFirst()) : path),
            resolvingAgainstBaseURL: false
        )
        if !query.isEmpty {
            components?.queryItems = query.map { URLQueryItem(name: $0.key, value: $0.value) }
        }
        guard let url = components?.url else {
            throw NecropsyError.transport("could not build a URL for \(path)")
        }

        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = method
        urlRequest.httpBody = body
        if body != nil {
            urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        for (key, value) in headers {
            urlRequest.setValue(value, forHTTPHeaderField: key)
        }

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: urlRequest)
        } catch {
            throw NecropsyError.transport(error.localizedDescription)
        }

        guard let http = response as? HTTPURLResponse else {
            throw NecropsyError.transport("no HTTP response")
        }
        guard (200..<300).contains(http.statusCode) else {
            throw Self.mapError(status: http.statusCode, data: data)
        }
        return data
    }

    /// Map FastAPI's `{"detail": ...}` onto cases the panel renders differently.
    nonisolated static func mapError(status: Int, data: Data) -> NecropsyError {
        let detail: String
        if let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let value = object["detail"] {
            detail = String(describing: value)
        } else {
            detail = String(data: data, encoding: .utf8) ?? "(no body)"
        }

        switch status {
        case 404: return .notFound(detail)
        case 403: return .forbidden(detail)
        case 409: return .unavailable(detail)
        case 428: return .confirmationRequired(detail)
        default: return .server(status: status, detail: detail)
        }
    }

    private func get<T: Decodable>(_ path: String, query: [String: String] = [:]) async throws -> T {
        let data = try await request("GET", path, query: query)
        do {
            return try decoder.decode(T.self, from: data)
        } catch {
            throw NecropsyError.decoding("\(path): \(error)")
        }
    }

    // MARK: - Module

    public func moduleDescriptor() async throws -> ModuleDescriptor {
        try await get("meta/module")
    }

    // MARK: - Cases

    public func cases(status: CaseStatus? = nil) async throws -> [CaseSummary] {
        var query: [String: String] = [:]
        if let status { query["status"] = status.rawValue }
        return try await get("cases", query: query)
    }

    public func caseDetail(_ caseId: String) async throws -> CaseDetail {
        try await get("cases/\(caseId)")
    }

    public func timeline(_ caseId: String) async throws -> [TimelineEntry] {
        try await get("cases/\(caseId)/timeline")
    }

    public func findings(_ caseId: String) async throws -> [Finding] {
        try await get("cases/\(caseId)/findings")
    }

    public func samples(_ caseId: String) async throws -> [CaseSample] {
        try await get("cases/\(caseId)/samples")
    }

    public func sample(sha256: String) async throws -> SampleDetail {
        try await get("samples/\(sha256)")
    }

    // MARK: - Proposals

    public func actions(_ caseId: String, state: ActionState? = .proposed) async throws
        -> [ActionProposal]
    {
        var query: [String: String] = [:]
        if let state { query["state"] = state.rawValue }
        return try await get("cases/\(caseId)/actions", query: query)
    }

    /// Authorise a proposal. The only route to running analysis, detonation
    /// included -- the acceptance is the record that a named human said yes.
    public func accept(actionId: String, note: String? = nil) async throws -> AcceptResponse {
        let body = try encoder.encode(["note": note])
        let data = try await request("POST", "actions/\(actionId)/accept", body: body)
        do {
            return try decoder.decode(AcceptResponse.self, from: data)
        } catch {
            throw NecropsyError.decoding("accept: \(error)")
        }
    }

    public func reject(actionId: String, note: String? = nil) async throws -> ActionProposal {
        let body = try encoder.encode(["note": note])
        let data = try await request("POST", "actions/\(actionId)/reject", body: body)
        return try decoder.decode(ActionProposal.self, from: data)
    }

    // MARK: - Static analysis

    public func staticReport(sha256: String) async throws -> [String: JSONValue] {
        try await get("samples/\(sha256)/static")
    }

    public func strings(sha256: String, contains: String? = nil, limit: Int = 1000) async throws
        -> [String: JSONValue]
    {
        var query = ["limit": String(limit)]
        if let contains, !contains.isEmpty { query["contains"] = contains }
        return try await get("samples/\(sha256)/strings", query: query)
    }

    public func functions(sha256: String, search: String? = nil, includeThunks: Bool = false)
        async throws -> [FunctionSummary]
    {
        var query = ["include_thunks": includeThunks ? "true" : "false"]
        if let search, !search.isEmpty { query["q"] = search }
        return try await get("samples/\(sha256)/functions", query: query)
    }

    public func function(_ functionId: String) async throws -> FunctionDetail {
        try await get("functions/\(functionId)")
    }

    public func functionStats(sha256: String) async throws -> FunctionStats {
        try await get("samples/\(sha256)/function-stats")
    }

    // MARK: - ATT&CK

    public func attackCoverage(_ caseId: String, collectedSysmonCodes: [String] = [])
        async throws -> AttackCoverage
    {
        var query: [String: String] = [:]
        if !collectedSysmonCodes.isEmpty {
            query["sysmon_codes"] = collectedSysmonCodes.joined(separator: ",")
        }
        return try await get("cases/\(caseId)/attack", query: query)
    }

    // MARK: - Sandbox

    public func detonations(_ caseId: String) async throws -> [Detonation] {
        try await get("cases/\(caseId)/detonations")
    }

    public func detonationTimeline(_ detonationId: String) async throws -> [String: JSONValue] {
        try await get("detonations/\(detonationId)/timeline")
    }

    // MARK: - AI

    public func report(_ caseId: String) async throws -> [String: JSONValue] {
        try await get("cases/\(caseId)/report")
    }

    public func yaraRules(_ caseId: String) async throws -> [String: JSONValue] {
        try await get("cases/\(caseId)/yara")
    }

    // MARK: - Status

    public func sandboxStatus() async throws -> SandboxStatus { try await get("sandbox/status") }
    public func toolingStatus() async throws -> ToolingStatus { try await get("analysis/tooling") }
    public func aiStatus() async throws -> AIStatus { try await get("ai/status") }
    public func attackStatus() async throws -> AttackStatus { try await get("attack/status") }
}
