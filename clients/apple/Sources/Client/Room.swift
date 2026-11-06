import Foundation

nonisolated struct Room: Identifiable, Hashable, Sendable {
    /// Library-provided identifier; opaque to the client.
    nonisolated struct ID: Hashable, Sendable {
        let rawValue: String
    }

    let id: ID
    let name: String
    let topic: String
}
