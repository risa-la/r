import Foundation

@testable import Risala

struct SentMessage: Equatable {
    let roomID: Room.ID
    let text: String
}

struct OutboxAction: Equatable {
    enum Kind { case retry, discard }
    let kind: Kind
    let messageID: Message.ID
    let roomID: Room.ID
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

/// One timeline subscription: it shows a room's history from `lowest` up.
@MainActor
private final class FakeTimeline {
    let roomID: Room.ID
    let continuation: AsyncThrowingStream<TimelineBatch, any Error>.Continuation
    var lowest: Int

    init(
        roomID: Room.ID, continuation: AsyncThrowingStream<TimelineBatch, any Error>.Continuation,
        lowest: Int
    ) {
        self.roomID = roomID
        self.continuation = continuation
        self.lowest = lowest
    }

    var isAtStart: Bool { lowest == 0 }

    func yield(_ changes: [TimelineChange]) {
        continuation.yield(TimelineBatch(changes: changes, isAtStart: isAtStart))
    }
}

/// An in-memory library: sends append to room history and reach every subscribed timeline
/// as index changes, the way librisala reports them.
@MainActor
final class TestChatClient: ChatClient {
    /// Room loads always wait for the test.
    let roomLoads = PendingCalls<[Room]>()
    let sends = PendingCalls<Void>()
    let olderPages = PendingCalls<Void>()
    let subscriptions: AsyncStream<Room.ID>
    private let subscribed: AsyncStream<Room.ID>.Continuation
    private let holdsSends: Bool
    private let holdsOlderPages: Bool
    private(set) var sent: [SentMessage] = []
    private(set) var outboxActions: [OutboxAction] = []
    private(set) var olderRequests = 0
    private var history: [Room.ID: [Message]] = [:]
    private var timelines: [FakeTimeline] = []
    private var roomListeners: [AsyncThrowingStream<[Room], any Error>.Continuation] = []
    private var nextMessageID = 0

    init(holdsSends: Bool = false, holdsOlderPages: Bool = false) {
        self.holdsSends = holdsSends
        self.holdsOlderPages = holdsOlderPages
        (subscriptions, subscribed) = AsyncStream.makeStream(of: Room.ID.self)
    }

    /// Adds history without telling subscribers, as a change they missed would.
    func seed(_ texts: [String], in roomID: Room.ID) {
        history[roomID, default: []] += texts.map { makeMessage($0) }
    }

    /// Delivers a message from another participant.
    func receive(_ text: String, in roomID: Room.ID) {
        append(makeMessage(text), to: roomID)
    }

    /// Adds the account's message that failed to send.
    @discardableResult
    func addFailed(_ text: String, in roomID: Room.ID) -> Message {
        let message = makeMessage(text, delivery: .failed(possiblySent: false))
        append(message, to: roomID)
        return message
    }

    func push(_ batch: TimelineBatch, to roomID: Room.ID) {
        for timeline in timelines where timeline.roomID == roomID {
            timeline.continuation.yield(batch)
        }
    }

    func failTimeline(in roomID: Room.ID, with error: any Error) {
        for timeline in timelines where timeline.roomID == roomID {
            timeline.continuation.finish(throwing: error)
        }
        timelines.removeAll { $0.roomID == roomID }
    }

    /// Replaces the room list for every room subscriber.
    func pushRooms(_ rooms: [Room]) {
        for listener in roomListeners {
            listener.yield(rooms)
        }
    }

    /// Ends every room subscription with `error`, or without one as if the library stopped.
    func endRooms(throwing error: (any Error)? = nil) {
        for listener in roomListeners {
            listener.finish(throwing: error)
        }
        roomListeners.removeAll()
    }

    func makeMessage(_ text: String, delivery: Message.Delivery = .sent) -> Message {
        nextMessageID += 1
        return Message(
            id: Message.ID(rawValue: "m\(nextMessageID)"), author: "test", text: text,
            sentAt: Date(timeIntervalSince1970: 0), isOwn: delivery != .sent,
            delivery: delivery)
    }

    // Witnesses default to the protocol's nonisolated requirements; keep them on MainActor.
    @MainActor func rooms() async throws -> RoomListSubscription {
        let initial = try await roomLoads.wait()
        let (updates, continuation) = AsyncThrowingStream<[Room], any Error>.makeStream()
        roomListeners.append(continuation)
        return RoomListSubscription(initial: initial, updates: updates)
    }

    @MainActor func timeline(in roomID: Room.ID, limit: Int) async throws -> TimelineSubscription {
        let (batches, continuation) = AsyncThrowingStream<TimelineBatch, any Error>.makeStream()
        let all = history[roomID, default: []]
        let timeline = FakeTimeline(
            roomID: roomID, continuation: continuation, lowest: max(0, all.count - limit))
        timelines.append(timeline)
        subscribed.yield(roomID)
        return TimelineSubscription(
            initial: Array(all[timeline.lowest...]),
            isAtStart: timeline.isAtStart,
            batches: batches,
            loadOlder: { [self, timeline] limit in
                try await self.loadOlder(timeline, limit: limit)
            })
    }

    @MainActor func send(_ text: String, to roomID: Room.ID) async throws {
        if holdsSends { try await sends.wait() }
        sent.append(SentMessage(roomID: roomID, text: text))
        append(makeMessage(text), to: roomID)
    }

    /// Marks the message as sending again, in place.
    @MainActor func retry(_ messageID: Message.ID, in roomID: Room.ID) async throws {
        outboxActions.append(OutboxAction(kind: .retry, messageID: messageID, roomID: roomID))
        guard let index = history[roomID]?.firstIndex(where: { $0.id == messageID }),
            let old = history[roomID]?[index]
        else { return }
        let message = Message(
            id: old.id, author: old.author, text: old.text, sentAt: old.sentAt, isOwn: true,
            delivery: .sending)
        history[roomID]?[index] = message
        for timeline in timelines where timeline.roomID == roomID && index >= timeline.lowest {
            timeline.yield([.update(message, at: index - timeline.lowest)])
        }
    }

    @MainActor func discard(_ messageID: Message.ID, in roomID: Room.ID) async throws {
        outboxActions.append(OutboxAction(kind: .discard, messageID: messageID, roomID: roomID))
        guard let index = history[roomID]?.firstIndex(where: { $0.id == messageID }) else {
            return
        }
        history[roomID]?.remove(at: index)
        for timeline in timelines where timeline.roomID == roomID {
            if index >= timeline.lowest {
                timeline.yield([.remove(at: index - timeline.lowest)])
            } else {
                timeline.lowest -= 1
            }
        }
    }

    private func append(_ message: Message, to roomID: Room.ID) {
        history[roomID, default: []].append(message)
        let index = history[roomID, default: []].count - 1
        for timeline in timelines where timeline.roomID == roomID {
            timeline.yield([.insert(message, at: index - timeline.lowest)])
        }
    }

    /// Delivers the page below the subscription's window as inserts at the top.
    private func loadOlder(_ timeline: FakeTimeline, limit: Int) async throws {
        olderRequests += 1
        if holdsOlderPages { try await olderPages.wait() }
        let all = history[timeline.roomID, default: []]
        let lowest = max(0, timeline.lowest - limit)
        let page = all[lowest..<timeline.lowest]
        timeline.lowest = lowest
        timeline.yield(page.enumerated().map { TimelineChange.insert($0.element, at: $0.offset) })
    }
}
