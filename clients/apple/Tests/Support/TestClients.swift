import Foundation

@testable import Risala

struct SentMessage: Equatable {
    let chatID: Chat.ID
    let text: String
}

struct OutboxAction: Equatable {
    enum Kind { case retry, discard }
    let kind: Kind
    let messageID: Message.ID
    let chatID: Chat.ID
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

/// One timeline subscription: it shows a chat's history from `lowest` up.
@MainActor
private final class FakeTimeline {
    let chatID: Chat.ID
    let continuation: AsyncThrowingStream<TimelineBatch, any Error>.Continuation
    var lowest: Int

    init(
        chatID: Chat.ID, continuation: AsyncThrowingStream<TimelineBatch, any Error>.Continuation,
        lowest: Int
    ) {
        self.chatID = chatID
        self.continuation = continuation
        self.lowest = lowest
    }

    var isAtStart: Bool { lowest == 0 }

    func yield(_ changes: [TimelineChange]) {
        continuation.yield(TimelineBatch(changes: changes, isAtStart: isAtStart))
    }
}

/// An in-memory library: sends append to chat history and reach every subscribed timeline
/// as index changes, the way librisala reports them.
@MainActor
final class TestChatClient: ChatClient {
    /// Chat list loads always wait for the test.
    let chatLoads = PendingCalls<[Chat]>()
    let sends = PendingCalls<Void>()
    let olderPages = PendingCalls<Void>()
    let subscriptions: AsyncStream<Chat.ID>
    private let subscribed: AsyncStream<Chat.ID>.Continuation
    /// Signals each chat list subscription once the client can deliver its batches.
    let chatSubscriptions: AsyncStream<Void>
    private let chatSubscribed: AsyncStream<Void>.Continuation
    private let holdsSends: Bool
    private let holdsOlderPages: Bool
    private(set) var sent: [SentMessage] = []
    private(set) var outboxActions: [OutboxAction] = []
    private(set) var olderRequests = 0
    private var history: [Chat.ID: [Message]] = [:]
    private var timelines: [FakeTimeline] = []
    private var chatListeners: [AsyncThrowingStream<ChatListBatch, any Error>.Continuation] = []
    /// The filter of each chat list subscription, in order.
    private(set) var chatFilters: [ChatFilter] = []
    private(set) var loadMoreRequests = 0
    private var nextMessageID = 0

    init(holdsSends: Bool = false, holdsOlderPages: Bool = false) {
        self.holdsSends = holdsSends
        self.holdsOlderPages = holdsOlderPages
        (subscriptions, subscribed) = AsyncStream.makeStream(of: Chat.ID.self)
        (chatSubscriptions, chatSubscribed) = AsyncStream.makeStream(of: Void.self)
    }

    /// Adds history without telling subscribers, as a change they missed would.
    func seed(_ texts: [String], in chatID: Chat.ID) {
        history[chatID, default: []] += texts.map { makeMessage($0) }
    }

    /// Delivers a message from another participant.
    func receive(_ text: String, in chatID: Chat.ID) {
        append(makeMessage(text), to: chatID)
    }

    /// Adds the account's message that failed to send.
    @discardableResult
    func addFailed(_ text: String, in chatID: Chat.ID) -> Message {
        let message = makeMessage(text, delivery: .failed(possiblySent: false))
        append(message, to: chatID)
        return message
    }

    func push(_ batch: TimelineBatch, to chatID: Chat.ID) {
        for timeline in timelines where timeline.chatID == chatID {
            timeline.continuation.yield(batch)
        }
    }

    func failTimeline(in chatID: Chat.ID, with error: any Error) {
        for timeline in timelines where timeline.chatID == chatID {
            timeline.continuation.finish(throwing: error)
        }
        timelines.removeAll { $0.chatID == chatID }
    }

    /// Replaces the chat list for every subscriber.
    func pushChats(_ chats: [Chat]) {
        push(ChatListBatch(changes: [.reset(chats)], counts: counts(chats)))
    }

    func push(_ batch: ChatListBatch) {
        for listener in chatListeners {
            listener.yield(batch)
        }
    }

    /// Ends every chat list subscription, normally or with `error`, as a library that
    /// lost its session would.
    func endChats(throwing error: (any Error)? = nil) {
        for listener in chatListeners {
            listener.finish(throwing: error)
        }
        chatListeners.removeAll()
    }

    func counts(_ chats: [Chat]) -> ChatCounts {
        ChatCounts(unreadChats: chats.count { $0.unreadCount > 0 }, total: chats.count)
    }

    func makeMessage(_ text: String, delivery: Message.Delivery = .sent) -> Message {
        nextMessageID += 1
        return Message(
            id: Message.ID(rawValue: "m\(nextMessageID)"), author: "test", text: text,
            sentAt: Date(timeIntervalSince1970: 0), isOwn: delivery != .sent,
            delivery: delivery)
    }

    // Witnesses default to the protocol's nonisolated requirements; keep them on MainActor.
    @MainActor func chats(_ filter: ChatFilter, limit: Int) async throws -> ChatListSubscription {
        chatFilters.append(filter)
        let initial = try await chatLoads.wait()
        let (batches, continuation) = AsyncThrowingStream<ChatListBatch, any Error>.makeStream()
        chatListeners.append(continuation)
        chatSubscribed.yield(())
        return ChatListSubscription(
            initial: initial, counts: counts(initial), batches: batches,
            loadMore: { [self] _ in await MainActor.run { self.loadMoreRequests += 1 } })
    }

    /// Every chat the library has, newest first, for `chat(_:)` and searches.
    var library: [Chat] = []
    /// When set, `chat(_:)` fails with it.
    var lookupError: (any Error)?

    @MainActor func chats(matching query: String, limit: Int) async throws -> [Chat] {
        let query = MatchQuery(query)
        return Array(
            library.filter { chat in query.map { chat.rank($0) != nil } ?? true }.prefix(limit))
    }

    @MainActor func chat(_ id: Chat.ID) async throws -> Chat? {
        if let lookupError { throw lookupError }
        return library.first { $0.id == id }
    }

    /// What `spaces()` returns; set it before the model subscribes.
    var spaceState = Spaces.empty

    @MainActor func spaces() async throws -> SpacesSubscription {
        SpacesSubscription(initial: spaceState, updates: AsyncThrowingStream { _ in })
    }

    @MainActor func setFavourite(_ isFavourite: Bool, space: Space.ID) async throws {}

    @MainActor func setFavourite(_ isFavourite: Bool, for chatID: Chat.ID) async throws {}

    /// The read marker each chat's timeline opens with.
    var firstUnread: [Chat.ID: Message.ID] = [:]

    @MainActor func timeline(in chatID: Chat.ID, limit: Int) async throws -> TimelineSubscription {
        let (batches, continuation) = AsyncThrowingStream<TimelineBatch, any Error>.makeStream()
        let all = history[chatID, default: []]
        let timeline = FakeTimeline(
            chatID: chatID, continuation: continuation, lowest: max(0, all.count - limit))
        timelines.append(timeline)
        subscribed.yield(chatID)
        return TimelineSubscription(
            initial: Array(all[timeline.lowest...]),
            isAtStart: timeline.isAtStart,
            batches: batches,
            loadOlder: { [self, timeline] limit in
                try await self.loadOlder(timeline, limit: limit)
            },
            firstUnread: firstUnread[chatID])
    }

    @MainActor func send(_ text: String, to chatID: Chat.ID) async throws {
        if holdsSends { try await sends.wait() }
        sent.append(SentMessage(chatID: chatID, text: text))
        append(makeMessage(text), to: chatID)
    }

    /// Marks the message as sending again, in place.
    @MainActor func retry(_ messageID: Message.ID, in chatID: Chat.ID) async throws {
        outboxActions.append(OutboxAction(kind: .retry, messageID: messageID, chatID: chatID))
        guard let index = history[chatID]?.firstIndex(where: { $0.id == messageID }),
            let old = history[chatID]?[index]
        else { return }
        let message = Message(
            id: old.id, author: old.author, text: old.text, sentAt: old.sentAt, isOwn: true,
            delivery: .sending)
        history[chatID]?[index] = message
        for timeline in timelines where timeline.chatID == chatID && index >= timeline.lowest {
            timeline.yield([.update(message, at: index - timeline.lowest)])
        }
    }

    @MainActor func discard(_ messageID: Message.ID, in chatID: Chat.ID) async throws {
        outboxActions.append(OutboxAction(kind: .discard, messageID: messageID, chatID: chatID))
        guard let index = history[chatID]?.firstIndex(where: { $0.id == messageID }) else {
            return
        }
        history[chatID]?.remove(at: index)
        for timeline in timelines where timeline.chatID == chatID {
            if index >= timeline.lowest {
                timeline.yield([.remove(at: index - timeline.lowest)])
            } else {
                timeline.lowest -= 1
            }
        }
    }

    private func append(_ message: Message, to chatID: Chat.ID) {
        history[chatID, default: []].append(message)
        let index = history[chatID, default: []].count - 1
        for timeline in timelines where timeline.chatID == chatID {
            timeline.yield([.insert(message, at: index - timeline.lowest)])
        }
    }

    /// Delivers the page below the subscription's window as inserts at the top.
    private func loadOlder(_ timeline: FakeTimeline, limit: Int) async throws {
        olderRequests += 1
        if holdsOlderPages { try await olderPages.wait() }
        let all = history[timeline.chatID, default: []]
        let lowest = max(0, timeline.lowest - limit)
        let page = all[lowest..<timeline.lowest]
        timeline.lowest = lowest
        timeline.yield(page.enumerated().map { TimelineChange.insert($0.element, at: $0.offset) })
    }
}
