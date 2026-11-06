import Foundation
import Testing

@testable import Risala

@MainActor
struct ConversationTimelineTests {
    private let room = TestFixtures.rooms[0]
    private let otherRoom = TestFixtures.rooms[1]

    /// Catches gaps or misordering between the initial page and later changes.
    @Test(.timeLimit(.minutes(1)))
    func appliesSnapshotThenChanges() async {
        let client = TestChatClient()
        client.seed(["one", "two"], in: room.id)
        let model = ConversationViewModel(client: client)
        var subscriptions = client.subscriptions.makeAsyncIterator()
        model.select(room)
        let observing = Task { await model.observeTimeline() }
        _ = await subscriptions.next()
        client.receive("three", in: room.id)
        #expect(await eventually { texts(model) == ["one", "two", "three"] })

        let replacement = client.makeMessage("after reset")
        client.push(.reset(MessagePage(messages: [replacement], olderCursor: nil)), to: room.id)
        #expect(await eventually { texts(model) == ["after reset"] })
        observing.cancel()
        await observing.value
    }

    /// Catches a late change from the previous room's subscription leaking into the new room.
    @Test(.timeLimit(.minutes(1)))
    func discardsChangesAfterSwitchingRooms() async {
        let client = TestChatClient()
        client.seed(["first room"], in: room.id)
        let model = ConversationViewModel(client: client)
        var subscriptions = client.subscriptions.makeAsyncIterator()
        model.select(room)
        // Left running, as if cancellation had not reached it yet.
        let stale = Task { await model.observeTimeline() }
        _ = await subscriptions.next()
        #expect(await eventually { texts(model) == ["first room"] })
        model.select(otherRoom)
        client.receive("late", in: room.id)
        // The stale subscription stops at its first change after the switch.
        await stale.value
        #expect(model.room?.id == otherRoom.id)
        #expect(model.messages.isEmpty)
    }

    /// Catches older pages landing out of order or being requested past the start of history.
    @Test(.timeLimit(.minutes(1)))
    func loadsOlderPagesInOrder() async {
        let history = (1...120).map(String.init)
        let client = TestChatClient()
        client.seed(history, in: room.id)
        let model = ConversationViewModel(client: client)
        model.select(room)
        let observing = Task { await model.observeTimeline() }
        #expect(await eventually { texts(model) == Array(history.suffix(50)) })
        while model.canLoadOlder {
            await model.loadOlderMessages()
        }
        #expect(texts(model) == history)
        observing.cancel()
        await observing.value
    }

    /// Catches an older page from before a reset being merged into the replacement timeline.
    @Test(.timeLimit(.minutes(1)))
    func discardsOlderPageAfterReset() async {
        let client = TestChatClient(holdsOlderPages: true)
        client.seed((1...60).map(String.init), in: room.id)
        var pageRequests = client.olderPages.starts.makeAsyncIterator()
        let model = ConversationViewModel(client: client)
        model.select(room)
        let observing = Task { await model.observeTimeline() }
        #expect(await eventually { model.messages.count == 50 })
        let older = Task { await model.loadOlderMessages() }
        await pageRequests.next()
        #expect(!model.canLoadOlder)

        let replacement = client.makeMessage("after reset")
        client.push(.reset(MessagePage(messages: [replacement], olderCursor: nil)), to: room.id)
        #expect(await eventually { texts(model) == ["after reset"] })
        client.olderPages.finish(.success(()))
        await older.value
        #expect(texts(model) == ["after reset"])
        #expect(!model.canLoadOlder)
        observing.cancel()
        await observing.value
    }

    /// Catches a failed subscription blanking readable messages or offering no retry.
    @Test(.timeLimit(.minutes(1)))
    func failureKeepsMessagesUntilRetry() async {
        let client = TestChatClient()
        client.seed(["readable"], in: room.id)
        let model = ConversationViewModel(client: client)
        var subscriptions = client.subscriptions.makeAsyncIterator()
        model.select(room)
        let failing = Task { await model.observeTimeline() }
        _ = await subscriptions.next()
        client.failTimeline(in: room.id, with: CocoaError(.fileReadUnknown))
        await failing.value
        #expect(model.timelineFailed)
        #expect(texts(model) == ["readable"])

        let failedID = model.timelineID
        model.retryTimeline()
        #expect(model.timelineID != failedID)
        #expect(!model.timelineFailed)
        let retry = Task { await model.observeTimeline() }
        client.receive("recovered", in: room.id)
        #expect(await eventually { texts(model) == ["readable", "recovered"] })
        retry.cancel()
        await retry.value
    }

    private func texts(_ model: ConversationViewModel) -> [String] {
        model.messages.map(\.text)
    }
}
