import Foundation
import Testing

@testable import Risala

@MainActor
struct ConversationRandomizedTests {
    private let rooms = TestFixtures.rooms

    @Test(.timeLimit(.minutes(1)), arguments: RandomizedRun.seeds)
    func conversationActions(seed: UInt64) async {
        var run = RandomizedRun(seed: seed)
        let client = TestChatClient()
        // Shared library, separate windows; third window has no connection.
        let windows = [
            ConversationViewModel(client: client),
            ConversationViewModel(client: client),
            ConversationViewModel(),
        ]
        // Stand-ins for each window's view-owned timeline task.
        var observers: [Task<Void, Never>?] = [nil, nil, nil]
        var selections: [Int?] = [nil, nil, nil]
        var drafts = Array(repeating: [String](repeating: "", count: 3), count: 3)
        var expectedSends: [SentMessage] = []
        let inputs = [
            "", " \n\t", "hello", "مرحبًا", "Hello عالم 👋🏽", "line 1\nسطر ٢",
            String(repeating: "ع", count: 2048),
        ]
        defer {
            for observer in observers { observer?.cancel() }
        }

        for step in 0..<300 {
            let window = run.pick(windows.count)
            let model = windows[window]
            switch run.pick(3) {
            case 0:
                let choice = run.pick(4)
                let selected: Int? = choice == 3 ? nil : choice
                run.record("\(step): window \(window) select \(String(describing: selected))")
                if selections[window] != selected {
                    selections[window] = selected
                    model.select(selected.map { rooms[$0] })
                    observers[window]?.cancel()
                    observers[window] = Task { await model.observeTimeline() }
                }
            case 1:
                let input = run.pick(inputs.count)
                run.record("\(step): window \(window) edit input[\(input)]")
                // The UI only exposes the composer when a room is selected.
                if let selected = selections[window] {
                    drafts[window][selected] = inputs[input]
                    model.draft = inputs[input]
                }
            default:
                run.record("\(step): window \(window) send")
                if let selected = selections[window], window != 2 {
                    let text = drafts[window][selected].trimmingCharacters(
                        in: .whitespacesAndNewlines)
                    if !text.isEmpty {
                        expectedSends.append(SentMessage(roomID: rooms[selected].id, text: text))
                        drafts[window][selected] = ""
                    }
                }
                await model.sendMessage()
            }

            // Check every window after every action, not only the active one.
            for index in windows.indices {
                let selected = selections[index]
                let draft = selected.map { drafts[index][$0] } ?? ""
                let canSend =
                    index != 2 && selected != nil
                    && !draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                // Every connected window shows its room's accepted sends, whichever window sent them.
                let visible =
                    selected.map { room in
                        index == 2
                            ? [] : expectedSends.filter { $0.roomID == rooms[room].id }.map(\.text)
                    } ?? []
                let model = windows[index]
                guard model.room?.id == selected.map({ rooms[$0].id }),
                    model.draft == draft,
                    model.canSend == canSend,
                    client.sent == expectedSends,
                    await eventually({ model.messages.compactMap(\.text) == visible })
                else {
                    run.fail("Conversation invariant failed in window \(index)")
                    return
                }
            }
        }
    }
}
