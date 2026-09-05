import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Live case events over the module's WebSocket.
///
/// Workers cannot hold a socket, so they publish to Redis and the API process
/// fans out; from the panel's side that is one stream per case. The stream can
/// legitimately be unavailable -- an install with no broker still analyses
/// perfectly well, it just has no live updates -- so `unavailable` is a normal
/// outcome the panel renders, not an error state.
public enum CaseStreamMessage: Sendable {
    case ready(caseId: String)
    /// No broker on this install; the panel should fall back to polling.
    case unavailable(reason: String)
    case event(CaseEvent)
}

public actor CaseEventStream {
    private let url: URL
    private let session: URLSession
    private let decoder: JSONDecoder
    private var task: URLSessionWebSocketTask?

    /// - Parameter baseURL: the module mount, e.g. `http://host:8010/api/v1/necropsy`
    public init(baseURL: URL, caseId: String, session: URLSession = .shared) {
        var components = URLComponents(
            url: baseURL.appendingPathComponent("ws/cases/\(caseId)"),
            resolvingAgainstBaseURL: false
        )
        // The stream lives on the same mount as the REST surface, so derive
        // the scheme rather than making the caller configure a second URL.
        components?.scheme = (baseURL.scheme == "https") ? "wss" : "ws"
        self.url = components?.url ?? baseURL
        self.session = session
        self.decoder = NecropsyClient.makeDecoder()
    }

    public func messages() -> AsyncThrowingStream<CaseStreamMessage, Error> {
        AsyncThrowingStream { continuation in
            Task {
                let socket = session.webSocketTask(with: url)
                await self.store(socket)
                socket.resume()

                do {
                    while true {
                        let message = try await socket.receive()
                        guard let text = Self.text(of: message) else { continue }
                        if let parsed = self.parse(text) {
                            continuation.yield(parsed)
                        }
                    }
                } catch {
                    continuation.finish(throwing: error)
                }
            }
            continuation.onTermination = { _ in
                Task { await self.cancel() }
            }
        }
    }

    private func store(_ socket: URLSessionWebSocketTask) { self.task = socket }

    public func cancel() {
        task?.cancel(with: .goingAway, reason: nil)
        task = nil
    }

    nonisolated static func text(of message: URLSessionWebSocketTask.Message) -> String? {
        switch message {
        case .string(let text): return text
        case .data(let data): return String(data: data, encoding: .utf8)
        @unknown default: return nil
        }
    }

    nonisolated func parse(_ text: String) -> CaseStreamMessage? {
        guard let data = text.data(using: .utf8) else { return nil }

        // The server sends two control frames before any events.
        if let control = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let type = control["type"] as? String {
            if type == "stream.ready" {
                return .ready(caseId: control["case_id"] as? String ?? "")
            }
            if type == "stream.unavailable" {
                return .unavailable(reason: control["detail"] as? String ?? "unknown")
            }
        }

        guard let event = try? decoder.decode(CaseEvent.self, from: data) else { return nil }
        return .event(event)
    }
}
