@testable import Risala

enum TestFixtures {
    static let rooms = [
        Room(id: Room.ID(rawValue: "a"), name: "General", topic: ""),
        Room(id: Room.ID(rawValue: "b"), name: "العربية", topic: ""),
        Room(id: Room.ID(rawValue: "c"), name: "Mixed عربي", topic: ""),
    ]
}
