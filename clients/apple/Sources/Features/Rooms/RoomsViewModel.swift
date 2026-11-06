import Foundation
import OSLog
import Observation

@MainActor
@Observable
final class RoomsViewModel {
    private static let logger = Logger(subsystem: "la.risa.apple", category: "rooms")
    private let client: any ChatClient?
    enum State {
        case disconnected
        case loading
        case empty
        case loaded([Room])
        case failed
    }

    private(set) var state: State = .disconnected
    var rooms: [Room] {
        if case .loaded(let rooms) = state { rooms } else { [] }
    }
    init(client: any ChatClient? = nil) {
        self.client = client
    }

    func load() async {
        guard let client else { return }
        switch state {
        case .loading, .loaded, .empty: return
        case .disconnected, .failed: break
        }
        state = .loading
        do {
            let rooms = try await client.loadRooms()
            try Task.checkCancellation()
            state = rooms.isEmpty ? .empty : .loaded(rooms)
        } catch {
            if Task.isCancelled || error is CancellationError {
                state = .disconnected
            } else {
                Self.logger.error("loadRooms failed; code=\((error as NSError).code)")
                state = .failed
            }
        }
    }

}
