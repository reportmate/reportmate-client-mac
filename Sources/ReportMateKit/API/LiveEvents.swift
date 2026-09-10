import Foundation

/// The `/negotiate` answer: a Web PubSub client URL (token embedded) or the
/// reason the hub is unavailable.
public struct NegotiateResult: Sendable, Hashable {
    public var url: URL?
    public var accessToken: String?
    public var error: String?

    public init(json: JSONValue) {
        url = json["url"].nonEmptyString.flatMap(URL.init(string:))
        accessToken = json["accessToken"].nonEmptyString
        error = json["error"].nonEmptyString
    }
}

/// One frame of the Azure Web PubSub JSON subprotocol (`json.webpubsub.azure.v1`).
struct WebPubSubMessage {
    var type: String
    var data: JSONValue

    init?(text: String) {
        guard let json = JSONValue.parse(text), let type = json["type"].string else { return nil }
        self.type = type
        data = json["data"]
    }
}

extension ReportMateAPI {
    /// Mint a Web PubSub client token for the fleet event stream. The API
    /// returns 200 with an `error` field when the hub is not configured, so a
    /// caller checks the result rather than catching.
    public func negotiate(device: String = "dashboard") async throws -> NegotiateResult {
        NegotiateResult(json: try await getJSON("/negotiate", query: ["device": device]))
    }
}

/// The live fleet event stream over Azure Web PubSub, as an async sequence of
/// events. The stream ends with an error when the socket closes, so the caller
/// decides whether to reconnect or fall back to polling.
public enum LiveEventStream {
    public static let subprotocol = "json.webpubsub.azure.v1"

    public enum Frame: Sendable {
        /// The socket answered its first ping: the hub accepted the token.
        case open
        case event(FleetEvent)
    }

    public struct Closed: Error, Sendable {
        public var code: Int?
        public var reason: String?
    }

    /// Reports the handshake so the caller can show Live before any event arrives.
    final class OpenDelegate: NSObject, URLSessionWebSocketDelegate, @unchecked Sendable {
        var onOpen: (@Sendable () -> Void)?
        func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didOpenWithProtocol protocol: String?) { onOpen?() }
    }

    public static func frames(url: URL) -> AsyncThrowingStream<Frame, Error> {
        AsyncThrowingStream { continuation in
            let delegate = OpenDelegate()
            delegate.onOpen = { continuation.yield(.open) }
            let session = URLSession(configuration: .default, delegate: delegate, delegateQueue: nil)
            let task = session.webSocketTask(with: url, protocols: [subprotocol])
            task.resume()
            let reader = Task {
                do {
                    while !Task.isCancelled {
                        let message = try await task.receive()
                        let text: String?
                        switch message {
                        case .string(let s): text = s
                        case .data(let d): text = String(data: d, encoding: .utf8)
                        @unknown default: text = nil
                        }
                        guard let text, let frame = WebPubSubMessage(text: text), frame.type == "message" else { continue }
                        let event = FleetEvent(json: frame.data)
                        if !event.id.isEmpty { continuation.yield(.event(event)) }
                    }
                    continuation.finish()
                } catch {
                    let code = task.closeCode == .invalid ? nil : task.closeCode.rawValue
                    let reason = task.closeReason.flatMap { String(data: $0, encoding: .utf8) }
                    continuation.finish(throwing: Closed(code: code, reason: reason ?? error.localizedDescription))
                }
            }
            continuation.onTermination = { _ in
                reader.cancel()
                task.cancel(with: .normalClosure, reason: nil)
                session.finishTasksAndInvalidate()
            }
        }
    }
}
