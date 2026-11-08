import Foundation

/// One change to a timeline's items, to apply in order. Indices refer to the items
/// as they are after the changes before it.
nonisolated enum TimelineChange: Hashable, Sendable {
    /// Replaces every item, such as after a reconnect or when the consumer fell behind.
    case reset([Message])
    /// Inserts an item; later items move up.
    case insert(Message, at: Int)
    /// Replaces the item at an index with a newer state of the same item; the ID stays.
    case update(Message, at: Int)
    /// Removes the item at an index; later items move down.
    case remove(at: Int)
}

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
}
