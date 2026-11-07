import Foundation

nonisolated struct Message: Identifiable, Hashable, Sendable {
    /// Library-provided identifier; opaque to the client and never generated in Swift.
    nonisolated struct ID: Hashable, Sendable {
        let rawValue: String
    }

    let id: ID
    let author: String
    let text: String
    let sentAt: Date
}
