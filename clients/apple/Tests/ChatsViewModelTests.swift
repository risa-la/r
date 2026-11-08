import Foundation
import Testing

@testable import Risala

@MainActor
struct ChatsViewModelTests {
    private let chats = TestFixtures.chats

    @Test func noClientStaysDisconnected() async {
        let model = ChatsViewModel()
        await model.observe()
        guard case .disconnected = model.state else {
            Issue.record("Missing client must not appear as an empty chat list")
            return
        }
        #expect(!model.hasNoChats)
    }

    /// Catches a chat added after the first load never appearing, or a removed one staying.
    @Test(.timeLimit(.minutes(1)))
    func chatsFollowUpdatesAfterLoading() async {
        let client = TestChatClient()
        let model = ChatsViewModel(client: client)
        let observing = await start(model, client, initial: [])
        #expect(model.hasNoChats)

        client.pushChats([chats[0]])
        #expect(await eventually { model.chats == [chats[0]] })
        client.pushChats([])
        #expect(await eventually { model.chats.isEmpty && model.hasNoChats })
        observing.cancel()
        await observing.value
    }

    /// Catches index changes applied out of order, such as a chat moving to the top
    /// as a removal then an insertion, or counts not following the batch.
    @Test(.timeLimit(.minutes(1)))
    func appliesIndexChangesInOrder() async {
        let client = TestChatClient()
        let model = ChatsViewModel(client: client)
        let observing = await start(model, client, initial: chats)

        let moved = TestFixtures.chat("c", "Mixed عربي", unread: 1)
        client.push(
            ChatListBatch(
                changes: [.remove(at: 2), .insert(moved, at: 0), .remove(at: 2)],
                counts: ChatCounts(unreadChats: 1, total: 2)))
        #expect(await eventually { model.chats == [moved, chats[0]] })
        #expect(model.counts == ChatCounts(unreadChats: 1, total: 2))
        observing.cancel()
        await observing.value
    }

    /// Catches a batch that does not fit being applied partly, or blanking the list,
    /// instead of keeping the rows and subscribing again.
    @Test(.timeLimit(.minutes(1)))
    func batchThatDoesNotFitSubscribesAgain() async {
        let client = TestChatClient()
        let model = ChatsViewModel(client: client)
        var loads = client.chatLoads.starts.makeAsyncIterator()
        let observing = Task { await model.observe() }
        _ = await loads.next()
        client.chatLoads.finish(.success(chats))
        #expect(await eventually { model.chats == chats })

        client.push(ChatListBatch(changes: [.remove(at: 7)], counts: .zero))
        _ = await loads.next()
        #expect(model.chats == chats)
        #expect(model.state == .loaded)
        client.chatLoads.finish(.success([chats[1]]))
        #expect(await eventually { model.chats == [chats[1]] })
        #expect(client.chatFilters.count == 2)
        observing.cancel()
        await observing.value
    }

    /// Catches a filter change that keeps following the old subscription.
    @Test(.timeLimit(.minutes(1)))
    func filterChangeSubscribesWithTheNewFilter() async {
        let client = TestChatClient()
        let model = ChatsViewModel(client: client)
        let before = model.observationID
        model.filter.unread = true
        #expect(model.observationID != before)
        #expect(!model.hasNoChats)

        let observing = await start(model, client, initial: [])
        #expect(client.chatFilters == [ChatFilter(unread: true)])
        // An empty filtered list is not the empty state.
        #expect(!model.hasNoChats)
        observing.cancel()
        await observing.value
    }

    /// Catches asking for more rows when every matching chat is shown already.
    @Test(.timeLimit(.minutes(1)))
    func loadsMoreOnlyWhileRowsRemain() async {
        let client = TestChatClient()
        let model = ChatsViewModel(client: client)
        let observing = await start(model, client, initial: chats)
        await model.loadMore()
        #expect(client.loadMoreRequests == 0)

        client.push(ChatListBatch(changes: [], counts: ChatCounts(unreadChats: 0, total: 9)))
        #expect(await eventually { model.hasMore })
        await model.loadMore()
        #expect(client.loadMoreRequests == 1)
        observing.cancel()
        await observing.value
    }

    /// Catches a list that freezes, or blanks, when its subscription ends after rows
    /// show, or that subscribes again without waiting.
    @Test(.timeLimit(.minutes(1)))
    func endedSubscriptionKeepsRowsAndSubscribesAgainAfterWaiting() async {
        let client = TestChatClient()
        let waits = PendingCalls<Void>()
        let model = ChatsViewModel(client: client, wait: { _ in try await waits.wait() })
        var waitStarts = waits.starts.makeAsyncIterator()
        var loads = client.chatLoads.starts.makeAsyncIterator()
        let observing = Task { await model.observe() }
        _ = await loads.next()
        client.chatLoads.finish(.success(chats))
        #expect(await eventually { model.chats == chats })

        client.endChats(throwing: CocoaError(.fileReadUnknown))
        _ = await waitStarts.next()
        #expect(model.chats == chats)
        #expect(model.state == .loaded)
        #expect(model.isInterrupted)
        #expect(client.chatFilters.count == 1)

        waits.finish(.success(()))
        _ = await loads.next()
        client.chatLoads.finish(.success([chats[1]]))
        #expect(await eventually { model.chats == [chats[1]] && !model.isInterrupted })
        observing.cancel()
        await observing.value
    }

    /// Catches a failed first load that stays failed until the person taps retry.
    @Test(.timeLimit(.minutes(1)))
    func failedFirstLoadTriesAgainAfterWaiting() async {
        let client = TestChatClient()
        let waits = PendingCalls<Void>()
        let model = ChatsViewModel(client: client, wait: { _ in try await waits.wait() })
        var waitStarts = waits.starts.makeAsyncIterator()
        var loads = client.chatLoads.starts.makeAsyncIterator()
        let observing = Task { await model.observe() }
        _ = await loads.next()
        client.chatLoads.finish(.failure(CocoaError(.fileReadUnknown)))
        _ = await waitStarts.next()
        #expect(model.state == .failed)
        #expect(!model.isInterrupted)

        waits.finish(.success(()))
        _ = await loads.next()
        // Trying again on its own keeps the failure on screen rather than flickering.
        #expect(model.state == .failed)
        client.chatLoads.finish(.success(chats))
        #expect(await eventually { model.state == .loaded && model.chats == chats })
        observing.cancel()
        await observing.value
    }

    /// Catches waits that keep growing, or that do not grow at all.
    @Test func retryDelaysDoubleThenHold() {
        let delays = (1...8).map(ChatsViewModel.retryDelay(after:))
        #expect(delays == [1, 2, 4, 8, 16, 30, 30, 30].map { Duration.seconds($0) })
    }

    /// Catches a restored selection beyond the loaded rows being dropped, or one the
    /// library no longer has being kept.
    @Test(.timeLimit(.minutes(1)))
    func looksChatsUpBeyondTheLoadedRows() async {
        let client = TestChatClient()
        client.library = [chats[2]]
        let model = ChatsViewModel(client: client)
        let observing = await start(model, client, initial: [chats[0]])

        #expect(await model.lookUp(chats[0].id) == .found(chats[0]))
        #expect(await model.lookUp(chats[2].id) == .found(chats[2]))
        #expect(await model.lookUp(Chat.ID(rawValue: "gone")) == .missing)
        client.lookupError = CocoaError(.fileReadUnknown)
        #expect(await model.lookUp(Chat.ID(rawValue: "gone")) == .unknown)
        observing.cancel()
        await observing.value
    }

    /// Catches the command line searching only the loaded, filtered rows.
    @Test(.timeLimit(.minutes(1)))
    func commandLineSearchesEveryChat() async {
        let client = TestChatClient()
        let genealogy = TestFixtures.chat("d", "Genealogy")
        client.library = chats + [genealogy]
        let model = ChatsViewModel(client: client)
        model.filter.unread = true
        let observing = await start(model, client, initial: [])

        model.command = " gen"
        await model.searchCommand()
        #expect(model.commandItems == [.chat(chats[0]), .chat(genealogy)])
        model.endCommand()
        #expect(model.command.isEmpty)
        #expect(model.commandItems.isEmpty)
        observing.cancel()
        await observing.value
    }

    private func start(_ model: ChatsViewModel, _ client: TestChatClient, initial: [Chat])
        async -> Task<Void, Never>
    {
        var loads = client.chatLoads.starts.makeAsyncIterator()
        let observing = Task { await model.observe() }
        _ = await loads.next()
        client.chatLoads.finish(.success(initial))
        _ = await eventually { model.state == .loaded }
        return observing
    }
}

@MainActor
struct ChatsIdentityTests {
    /// Catches every row of a one-identity person carrying a chip, or another identity's
    /// rows losing theirs.
    @Test(.timeLimit(.minutes(1)))
    func chipsMarkOnlyOtherIdentities() async {
        let main = Identity(
            id: TestFixtures.identity, name: "me", address: "me@risala.test", isGuest: false,
            isMain: true, tint: 0)
        let work = Identity(
            id: Identity.ID(rawValue: "w@acme.work"), name: "work", address: "w@acme.work",
            isGuest: false, isMain: false, tint: 1)
        let client = TestChatClient()
        client.spaceState = Spaces(identities: [main, work], spaces: [])
        let model = ChatsViewModel(client: client)
        let observing = Task { await model.observeSpaces() }
        #expect(await eventually { model.spaces.identities.count == 2 })

        let mine = TestFixtures.chats[0]
        let theirs = Chat(
            id: Chat.ID(rawValue: "w"), name: "standup", space: TestFixtures.space,
            identity: work.id, lastActivity: .now)
        #expect(model.chip(for: mine) == nil)
        #expect(model.chip(for: theirs) == work)
        observing.cancel()
        await observing.value
    }
}
