import Foundation

/// The app's boundary to the shared librisala session.
///
/// Requirements are nonisolated: callers stay on MainActor, while conformers
/// run storage and FFI work off it, marking such methods `@concurrent`.
nonisolated protocol ChatClient: Sendable {
    /// Cached rooms followed by updates; the snapshot must not wait for connection,
    /// authentication, or sync.
    func rooms() async throws -> RoomListSubscription

    /// A bounded recent window followed by its changes, with no gap between them.
    /// Older messages are requested through the subscription.
    func timeline(in roomID: Room.ID, limit: Int) async throws -> TimelineSubscription

    /// Returns when the client accepts responsibility for the message, not on delivery.
    /// The message then shows in `timeline(in:limit:)` as sending until the server
    /// stores it, or as failed.
    func send(_ text: String, to roomID: Room.ID) async throws

    /// Sends a failed message again; it keeps its place until the new attempt shows.
    func retry(_ messageID: Message.ID, in roomID: Room.ID) async throws

    /// Removes a failed message from the timeline without sending it.
    func discard(_ messageID: Message.ID, in roomID: Room.ID) async throws
}
