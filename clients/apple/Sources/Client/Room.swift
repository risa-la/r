import Foundation

nonisolated struct Room: Identifiable, Hashable, Sendable {
    /// Library-provided identifier; opaque to the client. It identifies the account
    /// as well as the conversation, since one library session can hold several accounts.
    nonisolated struct ID: Hashable, Sendable {
        let rawValue: String
    }

    let id: ID
    let name: String
    let topic: String
}

/// The account's rooms now, followed by each later room list.
nonisolated struct RoomListSubscription: Sendable {
    /// Cached rooms, read without waiting for connection, authentication, or sync.
    let initial: [Room]
    /// Each element replaces the whole list, such as after a join, a part, or a new
    /// conversation. Cancelling the consuming task ends the subscription; any other
    /// end, with or without an error, means updates stopped and the list may be stale.
    let updates: AsyncThrowingStream<[Room], any Error>
}
