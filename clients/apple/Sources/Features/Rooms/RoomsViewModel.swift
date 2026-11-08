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
    /// Counts `observe()` calls; only the latest one changes the state.
    private var observation = 0
    private(set) var state: State

    var rooms: [Room] {
        if case .loaded(let rooms) = state { rooms } else { [] }
    }

    init(client: (any ChatClient)? = nil) {
        self.client = client
        state = client == nil ? .disconnected : .idle
    }

    /// Loads the cached rooms, then follows changes to them until cancelled; run it
    /// from a view-owned task. Rooms already shown stay while it subscribes again,
    /// and a later call takes over from an earlier one.
    func observe() async {
        guard let client else { return }
        observation += 1
        let current = observation
        if state == .idle || state == .failed {
            state = .loading
        }
        do {
            let subscription = try await client.rooms()
            guard observation == current else { return }
            try Task.checkCancellation()
            show(subscription.initial)
            for try await rooms in subscription.updates {
                guard observation == current else { return }
                try Task.checkCancellation()
                show(rooms)
            }
        } catch {
            guard observation == current else { return }
            let cancelled = Task.isCancelled || error is CancellationError
            if state == .loading {
                state = cancelled ? .idle : .failed
            }
            if !cancelled {
                // Rooms already shown stay readable; the next observe() follows again.
                Self.logger.error("rooms failed; code=\((error as NSError).code)")
            }
        }
    }

    private func show(_ rooms: [Room]) {
        state = rooms.isEmpty ? .empty : .loaded(rooms)
    }
}
