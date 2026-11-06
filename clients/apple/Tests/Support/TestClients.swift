import Foundation

struct SentMessage: Equatable {
    let roomID: Room.ID
    let text: String
}

@MainActor
final class RecordingChatClient: ChatClient {
    private(set) var sent: [SentMessage] = []
    private var history: [Room.ID: [Message]] = [:]
    func loadRooms() async throws -> [Room] { [] }
    func messages(in roomID: Room.ID) -> [Message] { history[roomID, default: []] }
    func send(_ text: String, to roomID: Room.ID) async throws {
        sent.append(SentMessage(roomID: roomID, text: text))
        history[roomID, default: []].append(
            Message(id: UUID(), author: "test", text: text, sentAt: Date(timeIntervalSince1970: 0)))
    }
}

@MainActor
final class SuspendedChatClient: ChatClient {
    let starts: AsyncStream<Void>
    private let continuation: AsyncStream<Void>.Continuation
    private var pending: CheckedContinuation<[Room], any Error>?
    private(set) var calls = 0

    init() {
        (starts, continuation) = AsyncStream.makeStream(of: Void.self)
    }

    func loadRooms() async throws -> [Room] {
        calls += 1
        return try await withCheckedThrowingContinuation {
            pending = $0
            continuation.yield(())
        }
    }

    func finish(_ result: Result<[Room], any Error>) {
        let request = pending
        pending = nil
        request?.resume(with: result)
    }

    func messages(in roomID: Room.ID) -> [Message] { [] }
    func send(_ text: String, to roomID: Room.ID) async throws {}
}

@MainActor
final class SuspendedSendClient: ChatClient {
    let starts: AsyncStream<Void>
    private let continuation: AsyncStream<Void>.Continuation
    private var pending: CheckedContinuation<Void, any Error>?
    private let recording = RecordingChatClient()
    private(set) var calls = 0

    init() {
        (starts, continuation) = AsyncStream.makeStream(of: Void.self)
    }

    func loadRooms() async throws -> [Room] { [] }
    func messages(in roomID: Room.ID) -> [Message] { recording.messages(in: roomID) }

    func send(_ text: String, to roomID: Room.ID) async throws {
        calls += 1
        try await withCheckedThrowingContinuation {
            pending = $0
            continuation.yield(())
        }
        try await recording.send(text, to: roomID)
    }

    func finish(_ result: Result<Void, any Error>) {
        let request = pending
        pending = nil
        request?.resume(with: result)
    }
}
