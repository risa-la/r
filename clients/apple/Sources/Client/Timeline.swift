import Foundation

/// One change to a timeline's items. Edits, deletions, reactions, and history filled
/// in mid-timeline arrive as updates and insertions.
typealias TimelineChange = ListChange<Message>

/// Changes the library made together; apply all of them, or none.
nonisolated struct TimelineBatch: Sendable {
    /// May be empty when only `isAtStart` changed.
    let changes: [TimelineChange]
    /// Whether the items now reach the start of the conversation's history.
    let isAtStart: Bool
}

/// A window on a room's messages, oldest first, and the batches that change it.
nonisolated struct TimelineSubscription: Sendable {
    /// A bounded recent window, followed by `batches` with no gap between them.
    let initial: [Message]
    /// Whether `initial` reaches the start of the conversation's history.
    let isAtStart: Bool
    /// Cancelling the consuming task ends the subscription.
    let batches: AsyncThrowingStream<TimelineBatch, any Error>
    /// Asks for up to `limit` older messages, from the cache first and then the
    /// server. Returns once requested; the messages arrive as `batches`.
    let loadOlder: @Sendable (_ limit: Int) async throws -> Void
    /// The first message after the read marker when the timeline opened, where the
    /// timeline says "new"; `nil` when everything was read.
    var firstUnread: Message.ID? = nil
}
