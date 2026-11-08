import SwiftUI

/// What the menus can do in the focused window.
struct ChatCommandActions {
    /// Opens the chat list's command line, to find or start a chat.
    let findOrStart: () -> Void
    /// Hides or shows the chat list pane; `nil` in the phone layout.
    let toggleList: (() -> Void)?
    let isListHidden: Bool
    /// Closes the open chat; `nil` when none is open.
    let closeChat: (() -> Void)?
}

extension FocusedValues {
    @Entry var chatCommands: ChatCommandActions?
}

/// The Chats menu: its shortcuts work from anywhere in the window, and show in the
/// iPad's shortcut list.
struct ChatCommands: Commands {
    @FocusedValue(\.chatCommands) private var actions

    var body: some Commands {
        CommandMenu("Chats") {
            Button("Find or Start…") { actions?.findOrStart() }
                .keyboardShortcut("k")
                .disabled(actions == nil)
            Button {
                actions?.toggleList?()
            } label: {
                if actions?.isListHidden == true {
                    Text("Show Chat List")
                } else {
                    Text("Hide Chat List")
                }
            }
            .keyboardShortcut("s", modifiers: [.control, .command])
            .disabled(actions?.toggleList == nil)
            Divider()
            Button("Close Chat") { actions?.closeChat?() }
                .disabled(actions?.closeChat == nil)
        }
    }
}
