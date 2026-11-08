import Foundation
import OSLog
import Observation

@Observable
final class ChatsViewModel {
    nonisolated enum State: Equatable, Sendable {
        /// No library session is available.
        case disconnected
        /// Waiting for a load to start, including after a cancelled load.
        case idle
        case loading
        /// The rows in `chats` are the library's, possibly none.
        case loaded
        /// The first load failed; it is tried again after a while, or on `retry()`.
        case failed
    }

    /// Identifies one subscription; changes with the filter and on every retry.
    nonisolated struct ObservationID: Hashable, Sendable {
        let filter: ChatFilter
        fileprivate let attempt: Int
    }

    /// What looking a chat up by its ID found.
    nonisolated enum Lookup: Equatable, Sendable {
        case found(Chat)
        /// The library has no such chat, such as one the person left.
        case missing
        /// The library could not say, such as when the read failed.
        case unknown
    }

    static let pageSize = 50
    /// Batches that do not fit the rows in a row that subscribe again at once; after
    /// that, subscribing again waits as after a failure.
    static let maxResubscriptions = 3
    /// The waits before following the list again after failures in a row, the last
    /// repeating.
    static let retryDelays: [Duration] = [
        .seconds(1), .seconds(2), .seconds(4), .seconds(8), .seconds(16), .seconds(30),
    ]
    /// What the command line shows with nothing typed.
    static let recentCount = 5
    /// The chats one command line search reads; the library reads at most 200 at once.
    static let searchLimit = 200
    private static let logger = Logger(subsystem: "la.risa.apple", category: "chats")

    private let client: (any ChatClient)?
    /// Waits before subscribing again; tests replace it to control time.
    private let wait: (Duration) async throws -> Void
    /// Counts `observe()` calls; only the latest one changes the state.
    private var observation = 0
    private var attempt = 0
    private var loadMoreRows: (@Sendable (Int) async throws -> Void)?
    private(set) var state: State
    private(set) var chats: [Chat] = [] {
        didSet { if foundChats.isEmpty { updateCommandItems() } }
    }
    private(set) var counts = ChatCounts.zero
    private(set) var isLoadingMore = false
    /// Whether the list stopped following the library while rows show. The rows stay
    /// readable, and it subscribes again after a while, or at once on `retry()`.
    private(set) var isInterrupted = false
    /// The person's identities and spaces, for the tabs, chips, and offline marks.
    private(set) var spaces = Spaces.empty {
        didSet { updateCommandItems() }
    }
    /// The rows shown and those to subscribe to; changing it subscribes again.
    var filter = ChatFilter()

    /// What is typed into the command line.
    var command = "" {
        didSet { if command != oldValue { updateCommandItems() } }
    }
    /// What the command line offers for `command`, best first; kept current as the
    /// query, the chats found, and the spaces change.
    private(set) var commandItems: [CommandItem] = []
    /// The chats the latest command line search read, for `commandItems` to rank.
    private var foundChats: [Chat] = [] {
        didSet { updateCommandItems() }
    }

    var observationID: ObservationID {
        ObservationID(filter: filter, attempt: attempt)
    }

    /// Whether the account has no chats at all, as opposed to none that match.
    var hasNoChats: Bool {
        state == .loaded && chats.isEmpty && filter == ChatFilter()
    }

    var hasMore: Bool {
        loadMoreRows != nil && chats.count < counts.total
    }

    init(
        client: (any ChatClient)? = nil,
        wait: @escaping (Duration) async throws -> Void = { try await Task.sleep(for: $0) }
    ) {
        self.client = client
        self.wait = wait
        state = client == nil ? .disconnected : .idle
    }

    /// The wait before the next attempt after `failures` failures in a row.
    static func retryDelay(after failures: Int) -> Duration {
        retryDelays[min(max(failures, 1), retryDelays.count) - 1]
    }

    func isReachable(_ space: Space.ID) -> Bool {
        // A space not listed yet is not known to be down.
        spaces.space(space)?.isReachable ?? true
    }

    /// The chip a chat's row shows: its identity, unless that is the main one.
    func chip(for chat: Chat) -> Identity? {
        spaces.identity(chat.identity).flatMap { $0.isMain ? nil : $0 }
    }

    /// Subscribes again at once, keeping the rows shown.
    func retry() {
        attempt += 1
    }

    /// Loads the cached chats for the current filter, then follows changes to them
    /// until cancelled; run it from a view-owned task keyed by `observationID`. Rows
    /// already shown stay while it subscribes again, and a later call takes over from
    /// an earlier one. When following stops, it subscribes again after a wait that
    /// grows with each failure in a row.
    func observe() async {
        guard let client else { return }
        observation += 1
        let current = observation
        let filter = self.filter
        if state == .idle || state == .failed {
            state = .loading
        }
        var misfits = 0
        var failures = 0
        while true {
            do {
                let subscription = try await client.chats(filter, limit: Self.pageSize)
                guard observation == current else { return }
                try Task.checkCancellation()
                chats = subscription.initial
                counts = subscription.counts
                loadMoreRows = subscription.loadMore
                isLoadingMore = false
                state = .loaded
                isInterrupted = false
                var fits = true
                for try await batch in subscription.batches {
                    guard observation == current else { return }
                    try Task.checkCancellation()
                    guard let rows = chats.applying(batch.changes) else {
                        fits = false
                        break
                    }
                    chats = rows
                    counts = batch.counts
                    misfits = 0
                    failures = 0
                }
                guard observation == current else { return }
                try Task.checkCancellation()
                loadMoreRows = nil
                guard !fits else { throw SubscriptionEnded() }
                misfits += 1
                Self.logger.error("chat list batch did not fit; resubscribing")
                guard misfits <= Self.maxResubscriptions else { throw ResubscriptionLimit() }
            } catch {
                guard observation == current else { return }
                loadMoreRows = nil
                if Task.isCancelled || error is CancellationError {
                    if state == .loading { state = .idle }
                    return
                }
                Self.logger.error("chat list failed; code=\((error as NSError).code)")
                failures += 1
                switch state {
                case .loading: state = .failed
                case .loaded: isInterrupted = true
                default: break
                }
                do {
                    try await wait(Self.retryDelay(after: failures))
                } catch {
                    // Cancelled while waiting: the rows and the state stay as they are.
                    return
                }
                guard observation == current, !Task.isCancelled else { return }
            }
        }
    }

    /// Asks for the next page of rows; they arrive through `observe()`.
    func loadMore() async {
        guard let loadMoreRows, hasMore, !isLoadingMore else { return }
        let current = observation
        isLoadingMore = true
        defer { if observation == current { isLoadingMore = false } }
        do {
            try await loadMoreRows(Self.pageSize)
        } catch {
            guard observation == current, !(error is CancellationError) else { return }
            Self.logger.error("more chats failed; code=\((error as NSError).code)")
        }
    }

    /// The chat with `id`: from the rows shown, or else from the library, since a
    /// restored selection may be beyond the rows loaded so far.
    func lookUp(_ id: Chat.ID) async -> Lookup {
        if let row = chats.first(where: { $0.id == id }) {
            return .found(row)
        }
        guard let client else { return .unknown }
        do {
            return try await client.chat(id).map(Lookup.found) ?? .missing
        } catch {
            if !(error is CancellationError) {
                Self.logger.error("chat lookup failed; code=\((error as NSError).code)")
            }
            return .unknown
        }
    }

    /// Follows the person's identities and spaces until cancelled; run it from a
    /// view-owned task.
    func observeSpaces() async {
        guard let client else { return }
        do {
            let subscription = try await client.spaces()
            spaces = subscription.initial
            for try await state in subscription.updates {
                spaces = state
            }
        } catch {
            guard !(error is CancellationError), !Task.isCancelled else { return }
            // Without the list, rows show as reachable and only "all" is offered.
            Self.logger.error("spaces failed; code=\((error as NSError).code)")
        }
    }

    // MARK: Command line

    /// Reads the chats that match `command` from every space, whatever the filter;
    /// run it from a view-owned task keyed by `command` while the command line is open.
    func searchCommand() async {
        guard let client else { return }
        let query = command
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines)
        do {
            let found = try await client.chats(
                matching: needle, limit: needle.isEmpty ? Self.recentCount : Self.searchLimit)
            guard query == command, !Task.isCancelled else { return }
            foundChats = found
        } catch {
            guard !(error is CancellationError), !Task.isCancelled else { return }
            // The chats already found, or the rows shown, stay searchable.
            Self.logger.error("chat search failed; code=\((error as NSError).code)")
        }
    }

    /// Clears what was typed and found once the command line is put away.
    func endCommand() {
        command = ""
        foundChats = []
    }

    private func updateCommandItems() {
        // Until a search returns, the rows shown stand in for every chat.
        commandItems = CommandItem.matches(
            command, chats: foundChats.isEmpty ? chats : foundChats, spaces: spaces.spaces,
            recent: Self.recentCount)
    }

    // MARK: Favourites

    /// Adds the chat to the favourites, or removes it; the change arrives through
    /// `observe()`.
    func toggleFavourite(_ chat: Chat) {
        setFavourite { try await $0.setFavourite(!chat.isFavourite, for: chat.id) }
    }

    /// Adds the space to the favourites, or removes it; the change arrives through
    /// `observeSpaces()`.
    func toggleFavourite(_ space: Space) {
        setFavourite { try await $0.setFavourite(!space.isFavourite, space: space.id) }
    }

    private func setFavourite(_ change: @escaping @Sendable (any ChatClient) async throws -> Void) {
        guard let client else { return }
        Task {
            do {
                try await change(client)
            } catch {
                Self.logger.error("favourite failed; code=\((error as NSError).code)")
            }
        }
    }
}

private struct SubscriptionEnded: Error {}
private struct ResubscriptionLimit: Error {}
