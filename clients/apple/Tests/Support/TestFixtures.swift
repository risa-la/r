import Foundation

@testable import Risala

enum TestFixtures {
    static let space = Space.ID(rawValue: "risala.test")
    static let identity = Identity.ID(rawValue: "me@risala.test")

    static let chats = [
        chat("a", "General"),
        chat("b", "العربية"),
        chat("c", "Mixed عربي"),
    ]

    static func chat(_ id: String, _ name: String, unread: Int = 0) -> Chat {
        Chat(
            id: Chat.ID(rawValue: id), name: name, space: space, identity: identity,
            lastActivity: Date(timeIntervalSince1970: 0), unreadCount: unread)
    }
}
