import Foundation
import OSLog
import Observation

@Observable
final class RoomsViewModel {
    enum State: Equatable {
        /// No library session is available.
        case disconnected
        /// Waiting for a load to start, including after a cancelled load.
        case idle
        case loading
        case empty
        case loaded([Room])
        case failed
    }

    private static let logger = Logger(subsystem: "la.risa.apple", category: "rooms")
    private let client: (any ChatClient)?
    private(set) var state: State

    var rooms: [Room] {
        if case .loaded(let rooms) = state { rooms } else { [] }
    }

    init(client: (any ChatClient)? = nil) {
        self.client = client
        state = client == nil ? .disconnected : .idle
    }

    func load() async {
        guard let client else { return }
        switch state {
        case .disconnected, .loading, .loaded, .empty: return
        case .idle, .failed: break
        }
        state = .loading
        do {
            let rooms = try await client.loadRooms()
            try Task.checkCancellation()
            state = rooms.isEmpty ? .empty : .loaded(rooms)
        } catch {
            if Task.isCancelled || error is CancellationError {
                state = .idle
            } else {
                Self.logger.error("loadRooms failed; code=\((error as NSError).code)")
                state = .failed
            }
        }
    }
}
