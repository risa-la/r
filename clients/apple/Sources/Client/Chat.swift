import Foundation

/// One conversation in the chat list: a room or a direct conversation, on any account.
nonisolated struct Chat: Identifiable, Hashable, Sendable {
    /// Library-provided identifier; opaque to the client. It identifies the account
    /// as well as the conversation, since one library session can hold several accounts.
    nonisolated struct ID: Hashable, Sendable {
        let rawValue: String
    }

    nonisolated enum Kind: Hashable, Sendable {
        case room
        case direct
    }

    /// The newest message, as the chat list shows it. Joins, parts, and settings
    /// never become the preview.
    nonisolated struct Preview: Hashable, Sendable {
        /// The author's display name; user content, shown as is.
        let author: String
        let isOwn: Bool
        /// The current text after edits; empty when deleted.
        let text: String
        let isDeleted: Bool
        let sentAt: Date
        let delivery: Message.Delivery
    }

    let id: ID
    let kind: Kind
    /// A room's name, or the other person's display name; user content, shown as is.
    let name: String
    /// In a direct conversation, the other person's uid when it must show apart from
    /// their name, never appended to it; `nil` when the name is enough.
    let uid: String?
    /// A room's topic; empty when it has none.
    let topic: String
    /// The space the conversation lives on.
    let space: Space.ID
    /// Which of the person's identities is in it.
    let identity: Identity.ID
    /// Whether the space is that identity's home. Rows name only other spaces.
    let isOnHomeServer: Bool
    /// When something last happened in it; the list is newest first.
    let lastActivity: Date
    /// The newest message, if there is one.
    let preview: Preview?
    /// Messages from others after the read marker.
    let unreadCount: Int
    /// Unread messages that mention the identity in it.
    let mentionCount: Int
    /// Display names of the people typing now, in the order they started.
    let typing: [String]
    /// In a direct conversation, whether the other person is connected; `nil` when
    /// not known, and for rooms.
    let isOnline: Bool?
    /// In a room, how many people are connected to it now; `nil` when not known,
    /// and for direct conversations.
    let presentCount: Int?
    var isFavourite: Bool

    init(
        id: ID,
        kind: Kind = .room,
        name: String,
        uid: String? = nil,
        topic: String = "",
        space: Space.ID,
        identity: Identity.ID,
        isOnHomeServer: Bool = true,
        lastActivity: Date,
        preview: Preview? = nil,
        unreadCount: Int = 0,
        mentionCount: Int = 0,
        typing: [String] = [],
        isOnline: Bool? = nil,
        presentCount: Int? = nil,
        isFavourite: Bool = false
    ) {
        self.id = id
        self.kind = kind
        self.name = name
        self.uid = uid
        self.topic = topic
        self.space = space
        self.identity = identity
        self.isOnHomeServer = isOnHomeServer
        self.lastActivity = lastActivity
        self.preview = preview
        self.unreadCount = unreadCount
        self.mentionCount = mentionCount
        self.typing = typing
        self.isOnline = isOnline
        self.presentCount = presentCount
        self.isFavourite = isFavourite
    }
}

/// One of the person's identities, or all their guest names together. Every
/// conversation and space belongs to one.
nonisolated struct Identity: Identifiable, Hashable, Sendable {
    nonisolated struct ID: Hashable, Sendable {
        let rawValue: String
    }

    let id: ID
    /// What chips and lists call it, chosen by the person on this device, such as
    /// `work`; by default the identity's own name, or `~layla` for guest names.
    let name: String
    /// The full identity, such as `layla@example.org`; empty for guest names.
    let address: String
    let isGuest: Bool
    /// The identity rows leave unmarked; there is one.
    let isMain: Bool
    /// Which palette tint the identity's chip uses, chosen on this device.
    let tint: Int
}

/// A server one of the person's identities is on: a group in the chat list.
nonisolated struct Space: Identifiable, Hashable, Sendable {
    /// The server's host name, such as `chat.example.org`.
    nonisolated struct ID: Hashable, Sendable {
        let rawValue: String
    }

    let id: ID
    let identity: Identity.ID
    /// Whether the identity is connected and signed in there. Cached chats stay
    /// readable either way.
    let isReachable: Bool
    /// Chats with unread messages.
    let unreadChats: Int
    /// Unread messages that mention the identity.
    let mentions: Int
    /// Favourite spaces come first in the tabs, in this device's order.
    let isFavourite: Bool

    /// The host name without a leading `chat.` or `www.`, then up to its first dot,
    /// for tabs: `chat.acme.work` is `acme`.
    var shortName: String {
        var labels = id.rawValue.split(separator: ".")
        if labels.count > 2, ["chat", "www"].contains(labels[0]) {
            labels.removeFirst()
        }
        return labels.first.map(String.init) ?? id.rawValue
    }
}

/// The person's identities and spaces, favourite spaces first in their order.
nonisolated struct Spaces: Hashable, Sendable {
    let identities: [Identity]
    let spaces: [Space]
    // Every row looks up its identity and space, so both are indexed once.
    private let identitiesByID: [Identity.ID: Identity]
    private let spacesByID: [Space.ID: Space]

    init(identities: [Identity], spaces: [Space]) {
        self.identities = identities
        self.spaces = spaces
        identitiesByID = Dictionary(identities.map { ($0.id, $0) }) { first, _ in first }
        spacesByID = Dictionary(spaces.map { ($0.id, $0) }) { first, _ in first }
    }

    static let empty = Spaces(identities: [], spaces: [])

    func identity(_ id: Identity.ID) -> Identity? {
        identitiesByID[id]
    }

    func space(_ id: Space.ID) -> Space? {
        spacesByID[id]
    }

    static func == (lhs: Spaces, rhs: Spaces) -> Bool {
        lhs.identities == rhs.identities && lhs.spaces == rhs.spaces
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(identities)
        hasher.combine(spaces)
    }
}

/// Which chats the list shows. The default shows every chat.
nonisolated struct ChatFilter: Hashable, Sendable {
    /// Only this space's chats: a tab.
    var space: Space.ID?
    var mentions = false
    var unread = false
    var favourites = false
    var rooms = false
}

/// Counts for the chat list, kept current with each batch.
nonisolated struct ChatCounts: Hashable, Sendable {
    /// Chats with unread messages in the current tab, for the unread toggle.
    let unreadChats: Int
    /// Unread mentions in the current tab, for the mentions toggle.
    let mentions: Int
    /// Chats that match the filter in all, shown or not yet loaded.
    let total: Int

    init(unreadChats: Int, mentions: Int = 0, total: Int) {
        self.unreadChats = unreadChats
        self.mentions = mentions
        self.total = total
    }

    static let zero = ChatCounts(unreadChats: 0, total: 0)
}

typealias ChatListChange = ListChange<Chat>

/// Changes the library made together; apply all of them, or none.
nonisolated struct ChatListBatch: Sendable {
    /// May be empty when only the counts changed.
    let changes: [ChatListChange]
    let counts: ChatCounts
}

/// A window on the chats that match a filter, newest activity first, and the
/// batches that change it.
nonisolated struct ChatListSubscription: Sendable {
    /// The first rows, read from the cache without waiting for a connection,
    /// followed by `batches` with no gap between them.
    let initial: [Chat]
    let counts: ChatCounts
    /// Cancelling the consuming task ends the subscription. A row that moves is a
    /// removal and an insertion; one that changes in place is an update.
    let batches: AsyncThrowingStream<ChatListBatch, any Error>
    /// Widens the window by up to `count` rows. Returns once requested; the rows
    /// arrive as `batches`.
    let loadMore: @Sendable (_ count: Int) async throws -> Void
}

/// The person's identities and spaces now, followed by each later state.
nonisolated struct SpacesSubscription: Sendable {
    let initial: Spaces
    /// Each element replaces the whole state. Cancelling the consuming task ends it.
    let updates: AsyncThrowingStream<Spaces, any Error>
}
