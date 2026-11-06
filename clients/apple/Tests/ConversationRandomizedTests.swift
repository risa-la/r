import Foundation
import Testing

@MainActor
struct ConversationRandomizedTests {
    private let rooms = TestFixtures.rooms

    @Test(arguments: RandomizedRun.seeds)
    func conversationActions(seed: UInt64) async {
        var run = RandomizedRun(seed: seed)
        let client = RecordingChatClient()
        // Shared library, separate windows; third window has no connection.
        let windows = [
            ConversationViewModel(client: client),
            ConversationViewModel(client: client),
            ConversationViewModel(),
        ]
        var selections: [Int?] = [nil, nil, nil]
        var drafts = Array(repeating: [String](repeating: "", count: 3), count: 3)
        var visibleMessages = Array(repeating: [String](), count: 3)
        var expectedSends: [SentMessage] = []
        let inputs = [
            "", " \n\t", "hello", "مرحبًا", "Hello عالم 👋🏽", "line 1\nسطر ٢",
            String(repeating: "ع", count: 2048),
        ]

        for step in 0..<300 {
            let window = run.pick(windows.count)
            let model = windows[window]
            switch run.pick(3) {
            case 0:
                let choice = run.pick(4)
                let selected: Int? = choice == 3 ? nil : choice
                run.record("\(step): window \(window) select \(String(describing: selected))")
                if selections[window] != selected {
                    visibleMessages[window] =
                        selected.map { index in
                            window == 2
                                ? []
                                : expectedSends.filter { $0.roomID == rooms[index].id }.map(\.text)
                        } ?? []
                }
                selections[window] = selected
                model.select(selected.map { rooms[$0] })
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
                        visibleMessages[window] = expectedSends.filter {
                            $0.roomID == rooms[selected].id
                        }.map(\.text)
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
                guard windows[index].room?.id == selected.map({ rooms[$0].id }),
                    windows[index].draft == draft,
                    windows[index].canSend == canSend,
                    windows[index].messages.map(\.text) == visibleMessages[index],
                    client.sent == expectedSends
                else {
                    run.fail("Conversation invariant failed in window \(index)")
                    return
                }
            }
        }
    }

}
