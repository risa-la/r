import Foundation

/// The app's boundary to the shared librisala session.
///
/// Requirements are nonisolated: callers stay on MainActor, while conformers
/// run storage and FFI work off it, marking such methods `@concurrent`.
nonisolated protocol ChatClient: Sendable {
    /// Cached room summaries; must not wait for connection, authentication, or sync.
    func loadRooms() async throws -> [Room]

    /// A bounded recent page followed by its changes, with no gap between them.
    /// Cancelling the consuming task ends the subscription.
    func timeline(in roomID: Room.ID, limit: Int) async throws -> TimelineSubscription

    /// The page before `cursor`, in library order.
    func messages(in roomID: Room.ID, before cursor: PageCursor, limit: Int) async throws
        -> MessagePage

    /// Returns when the client accepts responsibility for the message, not on delivery.
    /// Accepted messages arrive through `timeline(in:limit:)`.
    func send(_ text: String, to roomID: Room.ID) async throws
}
