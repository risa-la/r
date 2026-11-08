import Foundation

/// The app's boundary to the shared librisala session.
///
/// Requirements are nonisolated: callers stay on MainActor, while conformers
/// run storage and FFI work off it, marking such methods `@concurrent`.
nonisolated protocol ChatClient: Sendable {
    /// The chats that match `filter`, newest activity first: up to `limit` cached rows
    /// followed by their changes. The first rows must not wait for connection,
    /// authentication, or sync. A different filter is a new subscription.
    func chats(_ filter: ChatFilter, limit: Int) async throws -> ChatListSubscription

    /// Every chat whose name contains `query`, ignoring case and diacritics, newest
    /// activity first, up to `limit`; an empty query matches every chat. A one-time
    /// read of the cache across every space and filter, for the command line, which
    /// ranks the results itself.
    func chats(matching query: String, limit: Int) async throws -> [Chat]

    /// The chat with `id`, read from the cache, or `nil` when there is no such chat,
    /// such as one the person left. Restores a selection beyond the loaded rows.
    func chat(_ id: Chat.ID) async throws -> Chat?

    /// The person's identities and their spaces, with each space's state and
    /// counts, followed by changes.
    func spaces() async throws -> SpacesSubscription

    /// A bounded recent window followed by its changes, with no gap between them.
    /// Older messages are requested through the subscription.
    func timeline(in chatID: Chat.ID, limit: Int) async throws -> TimelineSubscription

    /// Returns when the client accepts responsibility for the message, not on delivery.
    /// The message then shows in `timeline(in:limit:)` as sending until the server
    /// stores it, or as failed.
    func send(_ text: String, to chatID: Chat.ID) async throws

    /// Sends a failed message again; it keeps its place until the new attempt shows.
    func retry(_ messageID: Message.ID, in chatID: Chat.ID) async throws

    /// Removes a failed message from the timeline without sending it.
    func discard(_ messageID: Message.ID, in chatID: Chat.ID) async throws

    /// Marks or unmarks a chat as a favourite on this device. The change arrives
    /// through `chats(_:limit:)`.
    func setFavourite(_ isFavourite: Bool, for chatID: Chat.ID) async throws

    /// Marks or unmarks a space as a favourite on this device; favourites lead the
    /// tabs. The change arrives through `spaces()`.
    func setFavourite(_ isFavourite: Bool, space: Space.ID) async throws
}
