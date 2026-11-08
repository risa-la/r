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
        /// The last rooms shown, possibly none, no longer followed because their
        /// updates failed or ended. They stay until `observe()` replaces them.
        case stale([Room])
        /// The first load failed, so there are no rooms to show.
        case failed
    }

    private static let logger = Logger(subsystem: "la.risa.apple", category: "rooms")
    private let client: (any ChatClient)?
    /// Counts `observe()` calls; only the latest one changes the state.
    private var observation = 0
    private(set) var state: State

    var rooms: [Room] {
        switch state {
        case .loaded(let rooms), .stale(let rooms): rooms
        default: []
        }
    }

    /// Whether the rooms shown may be out of date.
    var isStale: Bool {
        if case .stale = state { true } else { false }
    }

    init(client: (any ChatClient)? = nil) {
        self.client = client
        state = client == nil ? .disconnected : .idle
    }

    /// Loads the cached rooms, then follows changes to them until cancelled; run it
    /// from a view-owned task. Rooms already shown stay while it subscribes again,
    /// and a later call takes over from an earlier one. If following fails or ends
    /// once rooms are shown, they stay, marked stale.
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
            // Cancelling also ends the stream without an error. Otherwise the
            // subscription should last as long as the task, so an end is a failure.
            guard observation == current else { return }
            try Task.checkCancellation()
            Self.logger.error("room updates ended")
            markStale()
        } catch {
            guard observation == current else { return }
            if Task.isCancelled || error is CancellationError {
                if state == .loading { state = .idle }
                return
            }
            Self.logger.error("rooms failed; code=\((error as NSError).code)")
            if state == .loading {
                state = .failed
            } else {
                markStale()
            }
        }
    }

    private func show(_ rooms: [Room]) {
        state = rooms.isEmpty ? .empty : .loaded(rooms)
    }

    /// Keeps the rooms shown, marked as no longer followed.
    private func markStale() {
        switch state {
        case .empty: state = .stale([])
        case .loaded(let rooms): state = .stale(rooms)
        default: break
        }
    }
}
