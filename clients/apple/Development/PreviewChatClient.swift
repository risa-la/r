#if DEBUG
    import Foundation

    /// An in-memory library for SwiftUI previews, holding one of `PreviewChats`'
    /// scenarios. It filters, pages, and reports changes the way the library does, so
    /// previews exercise the same view model code as the app. Debug only.
    ///
    /// A Debug build launched with `-RisalaPreview <scenario>`, such as
    /// `-RisalaPreview worstCase`, runs on it instead of librisala.
    @MainActor
    final class PreviewChatClient: ChatClient {
        enum Scenario: String {
            case busy, worstCase, arabic, many, empty
            /// The first read never finishes.
            case loading
            /// The first read fails.
            case failed
        }

        /// One chat list subscription: a filter and how many rows it shows.
        private final class ListSubscription {
            let filter: ChatFilter
            var limit: Int
            var rows: [Chat] = []
            let continuation: AsyncThrowingStream<ChatListBatch, any Error>.Continuation

            init(
                filter: ChatFilter, limit: Int,
                continuation: AsyncThrowingStream<ChatListBatch, any Error>.Continuation
            ) {
                self.filter = filter
                self.limit = limit
                self.continuation = continuation
            }
        }

        /// The client the launch arguments ask for, if any.
        static func fromLaunchArguments() -> PreviewChatClient? {
            UserDefaults.standard.string(forKey: "RisalaPreview")
                .flatMap(Scenario.init(rawValue:))
                .map(PreviewChatClient.init)
        }

        private let scenario: Scenario
        private var all: [Chat]
        private var subscriptions: [ListSubscription] = []
        /// Each space's identity, reachability, and favourite flag; counts come from `all`.
        private var spaceList: [(Space.ID, Identity, reachable: Bool, favourite: Bool)]
        private var spaceListeners: [UUID: AsyncThrowingStream<Spaces, any Error>.Continuation] =
            [:]

        init(_ scenario: Scenario) {
            self.scenario = scenario
            all =
                switch scenario {
                case .busy: PreviewChats.busy
                case .worstCase: PreviewChats.worstCase
                case .arabic: PreviewChats.arabic
                case .many: PreviewChats.many
                case .empty, .loading, .failed: []
                }
            spaceList =
                switch scenario {
                case .many: PreviewChats.manySpaces
                case .worstCase: PreviewChats.worstCaseSpaces
                case .empty: [(PreviewChats.example, PreviewChats.layla, true, false)]
                default: PreviewChats.spaces
                }
        }

        // Witnesses default to the protocol's nonisolated requirements; keep them on MainActor.
        @MainActor func chats(_ filter: ChatFilter, limit: Int) async throws -> ChatListSubscription
        {
            try await waitForScenario()
            let (batches, continuation) = AsyncThrowingStream<ChatListBatch, any Error>.makeStream()
            let subscription = ListSubscription(
                filter: filter, limit: limit, continuation: continuation)
            subscription.rows = rows(for: subscription)
            subscriptions.append(subscription)
            let id = ObjectIdentifier(subscription)
            // Holding the client until the subscription ends, as the library would.
            continuation.onTermination = { _ in
                Task { @MainActor in self.subscriptions.removeAll { ObjectIdentifier($0) == id } }
            }
            return ChatListSubscription(
                initial: subscription.rows,
                counts: counts(for: filter),
                batches: batches,
                loadMore: { [self, subscription] count in
                    await self.loadMore(subscription, count: count)
                })
        }

        @MainActor func chats(matching query: String, limit: Int) async throws -> [Chat] {
            try await waitForScenario()
            let query = MatchQuery(query)
            return Array(
                matching(ChatFilter())
                    .filter { chat in query.map { chat.rank($0) != nil } ?? true }
                    .prefix(limit))
        }

        @MainActor func chat(_ id: Chat.ID) async throws -> Chat? {
            try await waitForScenario()
            return all.first { $0.id == id }
        }

        @MainActor func spaces() async throws -> SpacesSubscription {
            let (updates, continuation) = AsyncThrowingStream<Spaces, any Error>.makeStream()
            let id = UUID()
            spaceListeners[id] = continuation
            continuation.onTermination = { _ in
                Task { @MainActor in self.spaceListeners[id] = nil }
            }
            return SpacesSubscription(initial: currentSpaces(), updates: updates)
        }

        @MainActor func setFavourite(_ isFavourite: Bool, space: Space.ID) async throws {
            guard let index = spaceList.firstIndex(where: { $0.0 == space }) else { return }
            var entry = spaceList.remove(at: index)
            entry.favourite = isFavourite
            // A new favourite joins the end of the favourites; others keep their order.
            let end = spaceList.lastIndex(where: \.favourite).map { $0 + 1 } ?? 0
            spaceList.insert(entry, at: isFavourite ? end : spaceList.count)
            publishSpaces()
        }

        @MainActor func timeline(in chatID: Chat.ID, limit: Int) async throws
            -> TimelineSubscription
        {
            if let scripted = PreviewTimelines.timeline(for: chatID) {
                return TimelineSubscription(
                    initial: scripted.messages, isAtStart: true,
                    batches: AsyncThrowingStream { _ in }, loadOlder: { _ in },
                    firstUnread: scripted.firstUnread)
            }
            let preview = all.first { $0.id == chatID }?.preview
            let messages = preview.map { preview in
                [
                    Message(
                        id: Message.ID(rawValue: "preview"), author: preview.author,
                        text: preview.text, sentAt: preview.sentAt, isOwn: preview.isOwn,
                        isDeleted: preview.isDeleted, delivery: preview.delivery)
                ]
            }
            return TimelineSubscription(
                initial: messages ?? [], isAtStart: true,
                batches: AsyncThrowingStream { _ in }, loadOlder: { _ in })
        }

        @MainActor func send(_ text: String, to chatID: Chat.ID) async throws {}
        @MainActor func retry(_ messageID: Message.ID, in chatID: Chat.ID) async throws {}
        @MainActor func discard(_ messageID: Message.ID, in chatID: Chat.ID) async throws {}

        @MainActor func setFavourite(_ isFavourite: Bool, for chatID: Chat.ID) async throws {
            guard let index = all.firstIndex(where: { $0.id == chatID }) else { return }
            all[index].isFavourite = isFavourite
            publish()
        }

        // MARK: Lists

        private func loadMore(_ subscription: ListSubscription, count: Int) {
            subscription.limit += count
            publish(to: subscription)
        }

        /// Sends each subscription the changes from its rows to the current ones.
        private func publish() {
            for subscription in subscriptions {
                publish(to: subscription)
            }
        }

        /// As the library reports them: a row that moves is a removal and an insertion,
        /// and one that changes where it is, an update.
        private func publish(to subscription: ListSubscription) {
            let new = rows(for: subscription)
            let difference = new.map(\.id).difference(from: subscription.rows.map(\.id))
            // A collection difference lists removals from the lowest offset up and
            // insertions from the lowest up. Applied one by one, removals go from the
            // highest offset down, so each leaves the offsets before it as they were.
            var changes: [ChatListChange] = []
            var rows = subscription.rows
            for case .remove(let offset, _, _) in difference.removals.reversed() {
                changes.append(.remove(at: offset))
                rows.remove(at: offset)
            }
            for case .insert(let offset, _, _) in difference.insertions {
                changes.append(.insert(new[offset], at: offset))
                rows.insert(new[offset], at: offset)
            }
            for (offset, chat) in new.enumerated() where rows[offset] != chat {
                changes.append(.update(chat, at: offset))
            }
            subscription.rows = new
            subscription.continuation.yield(
                ChatListBatch(changes: changes, counts: counts(for: subscription.filter)))
        }

        /// Reads in the `loading` scenario never finish, and in `failed` they fail.
        private func waitForScenario() async throws {
            switch scenario {
            case .loading: try await Task.sleep(for: .seconds(365 * 86_400))
            case .failed: throw CocoaError(.fileReadUnknown)
            default: break
            }
        }

        private func rows(for subscription: ListSubscription) -> [Chat] {
            Array(matching(subscription.filter).prefix(subscription.limit))
        }

        private func matching(_ filter: ChatFilter) -> [Chat] {
            all
                .filter { chat in
                    (filter.space.map { chat.space == $0 } ?? true)
                        && (!filter.mentions || chat.mentionCount > 0)
                        && (!filter.unread || chat.unreadCount > 0)
                        && (!filter.favourites || chat.isFavourite)
                        && (!filter.rooms || chat.kind == .room)
                }
                .sorted { ($0.lastActivity, $0.id.rawValue) > ($1.lastActivity, $1.id.rawValue) }
        }

        private func counts(for filter: ChatFilter) -> ChatCounts {
            let group = ChatFilter(space: filter.space)
            return ChatCounts(
                unreadChats: matching(group).count { $0.unreadCount > 0 },
                mentions: matching(group).reduce(0) { $0 + $1.mentionCount },
                total: matching(filter).count)
        }

        // MARK: Spaces

        private func currentSpaces() -> Spaces {
            let identities = [
                PreviewChats.layla, PreviewChats.work, PreviewChats.northwind, PreviewChats.guest,
            ]
            .filter { identity in spaceList.contains { $0.1.id == identity.id } }
            let spaces = spaceList.map { id, identity, reachable, favourite in
                let chats = all.filter { $0.space == id }
                return Space(
                    id: id, identity: identity.id, isReachable: reachable,
                    unreadChats: chats.count { $0.unreadCount > 0 },
                    mentions: chats.reduce(0) { $0 + $1.mentionCount },
                    isFavourite: favourite)
            }
            // Favourites lead, in their order; the rest follow.
            return Spaces(
                identities: identities,
                spaces: spaces.filter(\.isFavourite) + spaces.filter { !$0.isFavourite })
        }

        private func publishSpaces() {
            let state = currentSpaces()
            for listener in spaceListeners.values {
                listener.yield(state)
            }
        }
    }
#endif
