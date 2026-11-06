import Foundation

@testable import Risala

struct SentMessage: Equatable {
    let roomID: Room.ID
    let text: String
}

/// Suspends each call until the test finishes it; `starts` signals when a call begins.
@MainActor
final class PendingCalls<Value: Sendable> {
    let starts: AsyncStream<Void>
    private let started: AsyncStream<Void>.Continuation
    private var pending: CheckedContinuation<Value, any Error>?
    private(set) var count = 0

    init() {
        (starts, started) = AsyncStream.makeStream(of: Void.self)
    }

    func wait() async throws -> Value {
        count += 1
        return try await withCheckedThrowingContinuation {
            pending = $0
            started.yield(())
        }
    }

    func finish(_ result: Result<Value, any Error>) {
        let call = pending
        pending = nil
        call?.resume(with: result)
    }
}

/// An in-memory library: sends append to room history and reach every subscribed timeline.
@MainActor
final class TestChatClient: ChatClient {
    private typealias Changes = AsyncThrowingStream<TimelineChange, any Error>

    /// Room loads always wait for the test.
    let roomLoads = PendingCalls<[Room]>()
    let sends = PendingCalls<Void>()
    let olderPages = PendingCalls<Void>()
    let subscriptions: AsyncStream<Room.ID>
    private let subscribed: AsyncStream<Room.ID>.Continuation
    private let holdsSends: Bool
    private let holdsOlderPages: Bool
    private(set) var sent: [SentMessage] = []
    private var history: [Room.ID: [Message]] = [:]
    private var subscribers: [Room.ID: [Changes.Continuation]] = [:]
    private var nextMessageID = 0

    init(holdsSends: Bool = false, holdsOlderPages: Bool = false) {
        self.holdsSends = holdsSends
        self.holdsOlderPages = holdsOlderPages
        (subscriptions, subscribed) = AsyncStream.makeStream(of: Room.ID.self)
    }

    func seed(_ texts: [String], in roomID: Room.ID) {
        history[roomID, default: []] += texts.map(makeMessage)
    }

    /// Delivers a message from another participant.
    func receive(_ text: String, in roomID: Room.ID) {
        let message = makeMessage(text)
        history[roomID, default: []].append(message)
        push(.appended([message]), to: roomID)
    }

    func push(_ change: TimelineChange, to roomID: Room.ID) {
        for subscriber in subscribers[roomID, default: []] {
            subscriber.yield(change)
        }
    }

    func failTimeline(in roomID: Room.ID, with error: any Error) {
        for subscriber in subscribers.removeValue(forKey: roomID) ?? [] {
            subscriber.finish(throwing: error)
        }
    }

    func makeMessage(_ text: String) -> Message {
        nextMessageID += 1
        return Message(
            id: Message.ID(rawValue: "m\(nextMessageID)"), author: "test", text: text,
            sentAt: Date(timeIntervalSince1970: 0))
    }

    // Witnesses default to the protocol's nonisolated requirements; keep them on MainActor.
    @MainActor func loadRooms() async throws -> [Room] {
        try await roomLoads.wait()
    }

    @MainActor func timeline(in roomID: Room.ID, limit: Int) async throws -> TimelineSubscription {
        let (changes, continuation) = Changes.makeStream()
        subscribers[roomID, default: []].append(continuation)
        subscribed.yield(roomID)
        let initial = page(in: roomID, before: history[roomID, default: []].count, limit: limit)
        return TimelineSubscription(initial: initial, changes: changes)
    }

    @MainActor func messages(in roomID: Room.ID, before cursor: PageCursor, limit: Int) async throws
        -> MessagePage
    {
        if holdsOlderPages { try await olderPages.wait() }
        return page(in: roomID, before: Int(cursor.rawValue) ?? 0, limit: limit)
    }

    @MainActor func send(_ text: String, to roomID: Room.ID) async throws {
        if holdsSends { try await sends.wait() }
        sent.append(SentMessage(roomID: roomID, text: text))
        let message = makeMessage(text)
        history[roomID, default: []].append(message)
        push(.appended([message]), to: roomID)
    }

    /// Cursors are history offsets, opaque to the model under test.
    private func page(in roomID: Room.ID, before end: Int, limit: Int) -> MessagePage {
        let start = max(0, end - limit)
        return MessagePage(
            messages: Array(history[roomID, default: []][start..<end]),
            olderCursor: start > 0 ? PageCursor(rawValue: String(start)) : nil)
    }
}
