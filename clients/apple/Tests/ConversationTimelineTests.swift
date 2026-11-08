import Foundation
import Testing

@testable import Risala

@MainActor
struct ConversationTimelineTests {
    private let room = TestFixtures.rooms[0]
    private let otherRoom = TestFixtures.rooms[1]

    /// Batches that cannot apply to the items they follow.
    nonisolated enum Misfit: CaseIterable {
        case removeOutOfRange
        case insertOutOfRange
        case updateOfAnotherItem
        case repeatedID
    }

    /// Catches gaps or misordering between the initial window and later changes.
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
        client.push(TimelineBatch(changes: [.reset([replacement])], isAtStart: true), to: room.id)
        #expect(await eventually { texts(model) == ["after reset"] })
        observing.cancel()
        await observing.value
    }

    /// Catches index changes applied at the wrong place, or an update that loses the item's ID.
    @Test(.timeLimit(.minutes(1)))
    func appliesInsertUpdateAndRemoveByIndex() async {
        let client = TestChatClient()
        client.seed(["one", "two", "three"], in: room.id)
        let model = ConversationViewModel(client: client)
        model.select(room)
        let observing = Task { await model.observeTimeline() }
        #expect(await eventually { texts(model) == ["one", "two", "three"] })

        let two = model.messages[1]
        let edited = Message(
            id: two.id, author: two.author, text: "two, edited", sentAt: two.sentAt,
            isEdited: true)
        let batch = TimelineBatch(
            changes: [
                .insert(client.makeMessage("inserted"), at: 1),
                .update(edited, at: 2),
                .remove(at: 0),
            ],
            isAtStart: true)
        client.push(batch, to: room.id)
        #expect(await eventually { texts(model) == ["inserted", "two, edited", "three"] })
        #expect(model.messages[1].id == two.id)
        #expect(model.messages[1].isEdited)
        #expect(model.isAtStart)
        observing.cancel()
        await observing.value
    }

    /// Catches a batch that does not fit crashing, corrupting, or blanking the timeline,
    /// instead of starting again from a fresh snapshot.
    @Test(.timeLimit(.minutes(1)), arguments: Misfit.allCases)
    func misfitBatchResubscribes(misfit: Misfit) async {
        let client = TestChatClient()
        client.seed(["one"], in: room.id)
        let model = ConversationViewModel(client: client)
        var subscriptions = client.subscriptions.makeAsyncIterator()
        model.select(room)
        let observing = Task { await model.observeTimeline() }
        _ = await subscriptions.next()
        #expect(await eventually { texts(model) == ["one"] })

        // The library moved on; the next snapshot shows it.
        client.seed(["two"], in: room.id)
        client.push(batch(for: misfit, in: model, client: client), to: room.id)
        _ = await subscriptions.next()
        #expect(await eventually { texts(model) == ["one", "two"] })
        #expect(!model.timelineFailed)
        observing.cancel()
        await observing.value
    }

    /// Catches endless resubscribing when every snapshot is followed by a batch that does not fit.
    @Test(.timeLimit(.minutes(1)))
    func repeatedMisfitsFailWithMessagesKept() async {
        let client = TestChatClient()
        client.seed(["readable"], in: room.id)
        let model = ConversationViewModel(client: client)
        var subscriptions = client.subscriptions.makeAsyncIterator()
        model.select(room)
        let observing = Task { await model.observeTimeline() }
        for _ in 0...ConversationViewModel.maxResubscriptions {
            _ = await subscriptions.next()
            client.push(TimelineBatch(changes: [.remove(at: 9)], isAtStart: true), to: room.id)
        }
        await observing.value
        #expect(model.timelineFailed)
        #expect(texts(model) == ["readable"])
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
        #expect(model.canLoadOlder)
        for count in [100, 120] {
            await model.loadOlderMessages()
            #expect(await eventually { model.messages.count == count })
        }
        #expect(texts(model) == history)
        #expect(model.isAtStart)
        #expect(!model.canLoadOlder)
        await model.loadOlderMessages()
        #expect(client.olderRequests == 2)
        observing.cancel()
        await observing.value
    }

    /// Catches an older page requested before a room switch landing in the new room,
    /// or leaving the new room stuck loading.
    @Test(.timeLimit(.minutes(1)))
    func olderPageStaysInItsRoom() async {
        let client = TestChatClient(holdsOlderPages: true)
        client.seed((1...60).map(String.init), in: room.id)
        client.seed(["other"], in: otherRoom.id)
        var pageRequests = client.olderPages.starts.makeAsyncIterator()
        let model = ConversationViewModel(client: client)
        model.select(room)
        let stale = Task { await model.observeTimeline() }
        #expect(await eventually { model.messages.count == 50 })
        let older = Task { await model.loadOlderMessages() }
        await pageRequests.next()
        #expect(model.isLoadingOlder)

        model.select(otherRoom)
        #expect(!model.isLoadingOlder)
        let observing = Task { await model.observeTimeline() }
        #expect(await eventually { texts(model) == ["other"] })
        client.olderPages.finish(.success(()))
        await older.value
        await stale.value
        #expect(texts(model) == ["other"])
        #expect(!model.isLoadingOlder)
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
        #expect(!model.canLoadOlder)

        let failedID = model.timelineID
        model.retryTimeline()
        #expect(model.timelineID != failedID)
        #expect(!model.timelineFailed)
        let retry = Task { await model.observeTimeline() }
        _ = await subscriptions.next()
        client.receive("recovered", in: room.id)
        #expect(await eventually { texts(model) == ["readable", "recovered"] })
        retry.cancel()
        await retry.value
    }

    private func batch(for misfit: Misfit, in model: ConversationViewModel, client: TestChatClient)
        -> TimelineBatch
    {
        let changes: [TimelineChange] =
            switch misfit {
            case .removeOutOfRange: [.remove(at: 1)]
            case .insertOutOfRange: [.insert(client.makeMessage("bad"), at: 2)]
            case .updateOfAnotherItem: [.update(client.makeMessage("bad"), at: 0)]
            case .repeatedID: [.insert(model.messages[0], at: 1)]
            }
        return TimelineBatch(changes: changes, isAtStart: true)
    }

    private func texts(_ model: ConversationViewModel) -> [String] {
        model.messages.compactMap(\.text)
    }
}
