import Foundation

@MainActor
protocol ChatClient {
    func loadRooms() async throws -> [Room]
    func messages(in roomID: Room.ID) -> [Message]
    /// Returns when the client accepts responsibility for the message, not on delivery.
    func send(_ text: String, to roomID: Room.ID) async throws
}
