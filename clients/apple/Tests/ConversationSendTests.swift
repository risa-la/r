import Foundation
import Testing

@testable import Risala

@MainActor
struct ConversationSendTests {
    private enum SendError: Error { case unavailable }
    private let rooms = TestFixtures.rooms

    @Test(.timeLimit(.minutes(1)))
    func failureKeepsDraftAndAllowsRetry() async {
        let client = TestChatClient(holdsSends: true)
        var starts = client.sends.starts.makeAsyncIterator()
        let model = ConversationViewModel(client: client)
        model.select(rooms[0])
        model.draft = "hello"
        let failed = Task { await model.sendMessage() }
        await starts.next()
        #expect(model.isSending)
        #expect(!model.canSend)
        await model.sendMessage()
        #expect(client.sends.count == 1)
        client.sends.finish(.failure(SendError.unavailable))
        await failed.value
        #expect(model.draft == "hello")
        #expect(model.sendFailed)
        #expect(model.canSend)

        let retry = Task { await model.sendMessage() }
        await starts.next()
        client.sends.finish(.success(()))
        await retry.value
        #expect(model.draft.isEmpty)
        #expect(!model.sendFailed)
        #expect(client.sent == [SentMessage(roomID: rooms[0].id, text: "hello")])
        #expect(model.sendRevision == 1)
    }

    @Test(.timeLimit(.minutes(1)), arguments: [false, true])
    func acceptancePreservesEditsAcrossRoomSwitches(edit: Bool) async {
        let client = TestChatClient(holdsSends: true)
        var starts = client.sends.starts.makeAsyncIterator()
        let model = ConversationViewModel(client: client)
        model.select(rooms[0])
        model.draft = "hello"
        let send = Task { await model.sendMessage() }
        await starts.next()
        if edit {
            model.draft = "new text"
            model.draft = "hello"
        }
        model.select(rooms[1])
        model.draft = "other room"
        // A send in progress elsewhere must not block this room's composer.
        #expect(model.canSend)
        client.sends.finish(.success(()))
        await send.value
        #expect(model.draft == "other room")
        #expect(model.sendRevision == 0)
        model.select(rooms[0])
        #expect(model.draft == (edit ? "hello" : ""))
        #expect(client.sent == [SentMessage(roomID: rooms[0].id, text: "hello")])
    }

    @Test(.timeLimit(.minutes(1)))
    func failureBelongsToSubmittedRoom() async {
        let client = TestChatClient(holdsSends: true)
        var starts = client.sends.starts.makeAsyncIterator()
        let model = ConversationViewModel(client: client)
        model.select(rooms[0])
        model.draft = "hello"
        let send = Task { await model.sendMessage() }
        await starts.next()
        model.select(rooms[1])
        client.sends.finish(.failure(SendError.unavailable))
        await send.value
        #expect(!model.sendFailed)
        model.select(rooms[0])
        #expect(model.sendFailed)
        #expect(model.draft == "hello")
    }

    /// Catches a failed message whose retry or removal goes to the wrong message or room,
    /// or that can be retried when it has not failed.
    @Test(.timeLimit(.minutes(1)))
    func failedMessagesCanBeRetriedOrRemoved() async {
        let client = TestChatClient()
        let roomID = rooms[0].id
        let first = client.addFailed("lost", in: roomID)
        let second = client.addFailed("lost too", in: roomID)
        let model = ConversationViewModel(client: client)
        model.select(rooms[0])
        let observing = Task { await model.observeTimeline() }
        #expect(await eventually { model.messages.map(\.id) == [first.id, second.id] })

        await model.retry(model.messages[0])
        #expect(await eventually { model.messages.first?.delivery == .sending })
        #expect(model.messages.first?.id == first.id)
        // Sending again, so there is nothing to retry or remove.
        await model.retry(model.messages[0])
        await model.discard(model.messages[0])

        await model.discard(model.messages[1])
        #expect(await eventually { model.messages.map(\.id) == [first.id] })
        #expect(
            client.outboxActions == [
                OutboxAction(kind: .retry, messageID: first.id, roomID: roomID),
                OutboxAction(kind: .discard, messageID: second.id, roomID: roomID),
            ])
        #expect(model.busyMessages.isEmpty)
        observing.cancel()
        await observing.value
    }

    @Test(.timeLimit(.minutes(1)))
    func cancellationKeepsDraftWithoutError() async {
        let client = TestChatClient(holdsSends: true)
        var starts = client.sends.starts.makeAsyncIterator()
        let model = ConversationViewModel(client: client)
        model.select(rooms[0])
        model.draft = "hello"
        let send = Task { await model.sendMessage() }
        await starts.next()
        send.cancel()
        client.sends.finish(.failure(CancellationError()))
        await send.value
        #expect(model.draft == "hello")
        #expect(!model.sendFailed)
        #expect(!model.isSending)
    }
}
