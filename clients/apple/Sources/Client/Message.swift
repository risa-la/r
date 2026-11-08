import Foundation

/// One item of a conversation's timeline: a message or another event, with edits,
/// deletion, and reactions already applied by the library.
nonisolated struct Message: Identifiable, Hashable, Sendable {
    /// Library-provided identifier; opaque to the client and never generated in Swift.
    /// Stable for the item's lifetime: a sent message keeps the ID it had while queued.
    nonisolated struct ID: Hashable, Sendable {
        let rawValue: String
    }

    nonisolated enum Kind: Hashable, Sendable {
        case message
        case join
        case part
        case invite
        case kick
        case ban
        case unban
        /// A room setting changed.
        case setting
        case role
        /// An event this client does not show in detail.
        case other
    }

    nonisolated struct Reaction: Hashable, Sendable {
        /// Usually an emoji; user content, shown as is.
        let reaction: String
        let count: Int
        /// Whether the account is one of those who reacted.
        let mine: Bool
    }

    /// Where an account's own message is on its way to the server.
    nonisolated enum Delivery: Hashable, Sendable {
        /// Stored by the server, or not the account's to send.
        case sent
        /// Queued or awaiting the server's answer.
        case sending
        /// It will not be sent unless retried. `possiblySent` when the connection
        /// dropped before the answer, so the server may have it after all.
        case failed(possiblySent: Bool)
    }

    let id: ID
    let author: String
    let kind: Kind
    /// A message's current text; empty when deleted. For other kinds, the library's
    /// text, such as a reason, if any.
    let text: String?
    /// The person an invite, kick, ban, unban, or role change acts on.
    let subject: String?
    let sentAt: Date
    /// Whether the account sent it.
    let isOwn: Bool
    let isEdited: Bool
    let isDeleted: Bool
    let reactions: [Reaction]
    let delivery: Delivery

    init(
        id: ID,
        author: String,
        kind: Kind = .message,
        text: String?,
        subject: String? = nil,
        sentAt: Date,
        isOwn: Bool = false,
        isEdited: Bool = false,
        isDeleted: Bool = false,
        reactions: [Reaction] = [],
        delivery: Delivery = .sent
    ) {
        self.id = id
        self.author = author
        self.kind = kind
        self.text = text
        self.subject = subject
        self.sentAt = sentAt
        self.isOwn = isOwn
        self.isEdited = isEdited
        self.isDeleted = isDeleted
        self.reactions = reactions
        self.delivery = delivery
    }
}
