import Foundation

/// Library-provided position for requesting older history; opaque to the client.
nonisolated struct PageCursor: Hashable, Sendable {
    let rawValue: String
}

nonisolated struct MessagePage: Sendable {
    /// Oldest first, in library order.
    let messages: [Message]
    /// `nil` when no older history exists.
    let olderCursor: PageCursor?
}

nonisolated enum TimelineChange: Sendable {
    /// Replaces the timeline, such as after a reconnect or when the consumer fell behind.
    case reset(MessagePage)
    case appended([Message])
}

nonisolated struct TimelineSubscription: Sendable {
    let initial: MessagePage
    let changes: AsyncThrowingStream<TimelineChange, any Error>
}
