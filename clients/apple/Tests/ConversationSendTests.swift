import Foundation
import Testing

@MainActor
struct ConversationSendTests {
    private enum SendError: Error { case unavailable }

    @Test(.timeLimit(.minutes(1)))
    func failureKeepsDraftAndAllowsRetry() async {
        let client = SuspendedSendClient()
        var starts = client.starts.makeAsyncIterator()
        let model = ConversationViewModel(client: client)
        model.select(TestFixtures.rooms[0])
        model.draft = "hello"
        let failed = Task { await model.sendMessage() }
        await starts.next()
        #expect(model.isSending)
        #expect(!model.canSend)
        await model.sendMessage()
        #expect(client.calls == 1)
        client.finish(.failure(SendError.unavailable))
        await failed.value
        #expect(model.draft == "hello")
        #expect(model.sendFailed)
        #expect(model.canSend)

        let retry = Task { await model.sendMessage() }
        await starts.next()
        client.finish(.success(()))
        await retry.value
        #expect(model.draft.isEmpty)
        #expect(!model.sendFailed)
        #expect(model.messages.map(\.text) == ["hello"])
        #expect(model.sendRevision == 1)
    }

    @Test(.timeLimit(.minutes(1)), arguments: [false, true])
    func acceptancePreservesEditsAcrossRoomSwitches(edit: Bool) async {
        let client = SuspendedSendClient()
        var starts = client.starts.makeAsyncIterator()
        let model = ConversationViewModel(client: client)
        let first = TestFixtures.rooms[0]
        let second = TestFixtures.rooms[1]
        model.select(first)
        model.draft = "hello"
        let send = Task { await model.sendMessage() }
        await starts.next()
        if edit {
            model.draft = "new text"
            model.draft = "hello"
        }
        model.select(second)
        model.draft = "other room"
        client.finish(.success(()))
        await send.value
        #expect(model.draft == "other room")
        #expect(model.messages.isEmpty)
        #expect(model.sendRevision == 0)
        model.select(first)
        #expect(model.draft == (edit ? "hello" : ""))
        #expect(model.messages.map(\.text) == ["hello"])
    }

    @Test(.timeLimit(.minutes(1)))
    func failureBelongsToSubmittedRoom() async {
        let client = SuspendedSendClient()
        var starts = client.starts.makeAsyncIterator()
        let model = ConversationViewModel(client: client)
        model.select(TestFixtures.rooms[0])
        model.draft = "hello"
        let send = Task { await model.sendMessage() }
        await starts.next()
        model.select(TestFixtures.rooms[1])
        client.finish(.failure(SendError.unavailable))
        await send.value
        #expect(!model.sendFailed)
        model.select(TestFixtures.rooms[0])
        #expect(model.sendFailed)
        #expect(model.draft == "hello")
    }

    @Test(.timeLimit(.minutes(1)))
    func cancellationKeepsDraftWithoutError() async {
        let client = SuspendedSendClient()
        var starts = client.starts.makeAsyncIterator()
        let model = ConversationViewModel(client: client)
        model.select(TestFixtures.rooms[0])
        model.draft = "hello"
        let send = Task { await model.sendMessage() }
        await starts.next()
        send.cancel()
        client.finish(.failure(CancellationError()))
        await send.value
        #expect(model.draft == "hello")
        #expect(!model.sendFailed)
        #expect(!model.isSending)
    }
}
