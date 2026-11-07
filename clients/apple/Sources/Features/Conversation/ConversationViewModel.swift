import Foundation
import OSLog
import Observation

@Observable
final class ConversationViewModel {
    /// Identifies one timeline subscription; changes on every selection and retry.
    struct TimelineID: Hashable {
        let roomID: Room.ID
        fileprivate let generation: Int
    }

    static let pageSize = 50
    private static let logger = Logger(subsystem: "la.risa.apple", category: "conversation")

    private struct ComposerState {
        var draft = ""
        var revision = 0
        var isSending = false
        var sendFailed = false
    }

    private let client: (any ChatClient)?
    private var composers: [Room.ID: ComposerState] = [:]
    private var generation = 0
    private var olderCursor: PageCursor?
    private(set) var room: Room?
    private(set) var messages: [Message] = []
    private(set) var isLoadingOlder = false
    private(set) var timelineFailed = false
    private(set) var sendRevision = 0

    var timelineID: TimelineID? {
        room.map { TimelineID(roomID: $0.id, generation: generation) }
    }

    var draft: String {
        get { room.map { composers[$0.id]?.draft ?? "" } ?? "" }
        set {
            guard let room else { return }
            composers[room.id, default: ComposerState()].draft = newValue
            composers[room.id, default: ComposerState()].revision += 1
        }
    }

    var isSending: Bool {
        room.map { composers[$0.id]?.isSending ?? false } ?? false
    }

    var sendFailed: Bool {
        room.map { composers[$0.id]?.sendFailed ?? false } ?? false
    }

    var canSend: Bool {
        !isSending && client != nil && room != nil
            && !draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    var canLoadOlder: Bool {
        olderCursor != nil && !isLoadingOlder
    }

    init(client: (any ChatClient)? = nil) {
        self.client = client
    }

    func select(_ room: Room?) {
        guard room?.id != self.room?.id else { return }
        self.room = room
        resetTimeline()
    }

    func retryTimeline() {
        resetTimeline(keepingMessages: true)
    }

    /// Applies the selected room's timeline until cancelled; run it from a task keyed by `timelineID`.
    func observeTimeline() async {
        guard let client, let id = timelineID else { return }
        do {
            let subscription = try await client.timeline(in: id.roomID, limit: Self.pageSize)
            guard isCurrent(id) else { return }
            apply(.reset(subscription.initial))
            for try await change in subscription.changes {
                guard isCurrent(id) else { return }
                apply(change)
            }
        } catch {
            guard isCurrent(id), !(error is CancellationError) else { return }
            timelineFailed = true
            Self.logger.error("timeline failed; code=\((error as NSError).code)")
        }
    }

    func loadOlderMessages() async {
        guard let client, let id = timelineID, let cursor = olderCursor, !isLoadingOlder else {
            return
        }
        isLoadingOlder = true
        defer { if timelineID == id { isLoadingOlder = false } }
        do {
            let page = try await client.messages(
                in: id.roomID, before: cursor, limit: Self.pageSize)
            // A reset while loading replaces the cursor and makes this page stale.
            guard isCurrent(id), olderCursor == cursor else { return }
            messages.insert(contentsOf: page.messages, at: 0)
            olderCursor = page.olderCursor
        } catch {
            guard isCurrent(id), !(error is CancellationError) else { return }
            Self.logger.error("older messages failed; code=\((error as NSError).code)")
        }
    }

    func sendMessage() async {
        guard canSend, let client, let room else { return }
        let roomID = room.id
        let submittedDraft = draft
        let revision = composers[roomID, default: ComposerState()].revision
        composers[roomID, default: ComposerState()].isSending = true
        composers[roomID]?.sendFailed = false
        defer { composers[roomID]?.isSending = false }

        do {
            try await client.send(
                submittedDraft.trimmingCharacters(in: .whitespacesAndNewlines), to: roomID)
            if composers[roomID]?.revision == revision {
                composers[roomID]?.draft = ""
            }
            if self.room?.id == roomID {
                sendRevision += 1
            }
        } catch {
            guard !Task.isCancelled, !(error is CancellationError) else { return }
            composers[roomID]?.sendFailed = true
            Self.logger.error("send failed; code=\((error as NSError).code)")
        }
    }

    private func resetTimeline(keepingMessages: Bool = false) {
        generation += 1
        if !keepingMessages {
            messages = []
            olderCursor = nil
        }
        isLoadingOlder = false
        timelineFailed = false
    }

    private func isCurrent(_ id: TimelineID) -> Bool {
        !Task.isCancelled && timelineID == id
    }

    private func apply(_ change: TimelineChange) {
        timelineFailed = false
        switch change {
        case .reset(let page):
            messages = page.messages
            olderCursor = page.olderCursor
        case .appended(let appended):
            messages.append(contentsOf: appended)
        }
    }
}
