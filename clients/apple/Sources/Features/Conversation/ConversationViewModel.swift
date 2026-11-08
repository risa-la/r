import Foundation
import OSLog
import Observation

@Observable
final class ConversationViewModel {
    /// Identifies one timeline subscription; changes on every selection and retry.
    struct TimelineID: Hashable {
        let chatID: Chat.ID
        fileprivate let generation: Int
    }

    static let pageSize = 50
    /// Batches that do not fit the items in a row before the timeline counts as failed.
    static let maxResubscriptions = 3
    private static let logger = Logger(subsystem: "la.risa.apple", category: "conversation")

    private struct ComposerState {
        var draft = ""
        var revision = 0
        var isSending = false
        var sendFailed = false
    }

    private let client: (any ChatClient)?
    private var composers: [Chat.ID: ComposerState] = [:]
    private var generation = 0
    private var loadOlder: (@Sendable (Int) async throws -> Void)?
    private(set) var chat: Chat?
    private(set) var messages: [Message] = []
    private(set) var isAtStart = false
    private(set) var isLoadingOlder = false
    private(set) var timelineFailed = false
    private(set) var sendRevision = 0
    /// Where the timeline says "new": the first unread message when the chat opened.
    /// It stays put while the chat is open, as messages are read.
    private(set) var firstUnread: Message.ID?
    /// Failed messages with a retry or discard in flight.
    private(set) var busyMessages: Set<Message.ID> = []

    var timelineID: TimelineID? {
        chat.map { TimelineID(chatID: $0.id, generation: generation) }
    }

    var draft: String {
        get { chat.map { composers[$0.id]?.draft ?? "" } ?? "" }
        set {
            guard let chat else { return }
            composers[chat.id, default: ComposerState()].draft = newValue
            composers[chat.id, default: ComposerState()].revision += 1
        }
    }

    var isSending: Bool {
        chat.map { composers[$0.id]?.isSending ?? false } ?? false
    }

    var sendFailed: Bool {
        chat.map { composers[$0.id]?.sendFailed ?? false } ?? false
    }

    var canSend: Bool {
        !isSending && client != nil && chat != nil
            && !draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    /// Whether the subscribed timeline may have older messages to load.
    var hasOlderMessages: Bool {
        loadOlder != nil && !isAtStart
    }

    var canLoadOlder: Bool {
        hasOlderMessages && !isLoadingOlder
    }

    init(client: (any ChatClient)? = nil) {
        self.client = client
    }

    func select(_ chat: Chat?) {
        guard chat?.id != self.chat?.id else {
            // The same chat with newer details, such as a new preview, keeps its timeline.
            if chat != self.chat { self.chat = chat }
            return
        }
        self.chat = chat
        resetTimeline()
    }

    func retryTimeline() {
        resetTimeline(keepingMessages: true)
    }

    /// Applies the selected chat's timeline until cancelled; run it from a task keyed by `timelineID`.
    ///
    /// A batch that does not fit the current items leaves them readable and subscribes
    /// again, which starts from a fresh snapshot.
    func observeTimeline() async {
        guard let client, let id = timelineID else { return }
        var resubscriptions = 0
        var isFirstSubscription = true
        do {
            while true {
                let subscription = try await client.timeline(in: id.chatID, limit: Self.pageSize)
                guard isCurrent(id) else { return }
                if isFirstSubscription {
                    firstUnread = subscription.firstUnread
                    isFirstSubscription = false
                }
                messages = subscription.initial
                isAtStart = subscription.isAtStart
                loadOlder = subscription.loadOlder
                isLoadingOlder = false
                timelineFailed = false
                var fits = true
                for try await batch in subscription.batches {
                    guard isCurrent(id) else { return }
                    guard apply(batch) else {
                        fits = false
                        break
                    }
                    resubscriptions = 0
                }
                guard isCurrent(id), !fits else { return }
                loadOlder = nil
                resubscriptions += 1
                Self.logger.error("timeline batch did not fit; resubscribing")
                guard resubscriptions <= Self.maxResubscriptions else {
                    timelineFailed = true
                    return
                }
            }
        } catch {
            guard isCurrent(id), !(error is CancellationError) else { return }
            loadOlder = nil
            timelineFailed = true
            Self.logger.error("timeline failed; code=\((error as NSError).code)")
        }
    }

    /// Asks for older messages; they arrive through `observeTimeline()`.
    func loadOlderMessages() async {
        guard let id = timelineID, let loadOlder, canLoadOlder else { return }
        isLoadingOlder = true
        defer { if timelineID == id { isLoadingOlder = false } }
        do {
            try await loadOlder(Self.pageSize)
        } catch {
            guard isCurrent(id), !(error is CancellationError) else { return }
            Self.logger.error("older messages failed; code=\((error as NSError).code)")
        }
    }

    func sendMessage() async {
        guard canSend, let client, let chat else { return }
        let chatID = chat.id
        let submittedDraft = draft
        let revision = composers[chatID, default: ComposerState()].revision
        composers[chatID, default: ComposerState()].isSending = true
        composers[chatID]?.sendFailed = false
        defer { composers[chatID]?.isSending = false }

        do {
            try await client.send(
                submittedDraft.trimmingCharacters(in: .whitespacesAndNewlines), to: chatID)
            if composers[chatID]?.revision == revision {
                composers[chatID]?.draft = ""
            }
            if self.chat?.id == chatID {
                sendRevision += 1
            }
        } catch {
            guard !Task.isCancelled, !(error is CancellationError) else { return }
            composers[chatID]?.sendFailed = true
            Self.logger.error("send failed; code=\((error as NSError).code)")
        }
    }

    /// Sends a failed message again. The outcome shows in the timeline.
    func retry(_ message: Message) async {
        await act(on: message) { client, id, chatID in
            try await client.retry(id, in: chatID)
        }
    }

    /// Removes a failed message without sending it.
    func discard(_ message: Message) async {
        await act(on: message) { client, id, chatID in
            try await client.discard(id, in: chatID)
        }
    }

    private func act(
        on message: Message,
        _ action: (any ChatClient, Message.ID, Chat.ID) async throws -> Void
    ) async {
        // Only a failed message shown in the selected chat, once at a time.
        guard let client, let chatID = chat?.id, case .failed = message.delivery,
            !busyMessages.contains(message.id), messages.contains(where: { $0.id == message.id })
        else { return }
        busyMessages.insert(message.id)
        defer { busyMessages.remove(message.id) }
        do {
            try await action(client, message.id, chatID)
        } catch {
            guard !(error is CancellationError) else { return }
            Self.logger.error("outbox action failed; code=\((error as NSError).code)")
        }
    }

    private func resetTimeline(keepingMessages: Bool = false) {
        generation += 1
        if !keepingMessages {
            messages = []
            isAtStart = false
            firstUnread = nil
        }
        loadOlder = nil
        isLoadingOlder = false
        timelineFailed = false
    }

    private func isCurrent(_ id: TimelineID) -> Bool {
        !Task.isCancelled && timelineID == id
    }

    /// Applies a whole batch, or nothing when a change does not fit the items.
    private func apply(_ batch: TimelineBatch) -> Bool {
        guard let items = messages.applying(batch.changes) else { return false }
        messages = items
        isAtStart = batch.isAtStart
        timelineFailed = false
        return true
    }
}
