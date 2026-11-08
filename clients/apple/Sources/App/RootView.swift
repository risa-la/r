import SwiftUI

struct RootView: View {
    @SceneStorage("selectedChatID") private var storedChatID: String?
    @SceneStorage("isChatListHidden") private var isListHidden = false
    @State private var chats: ChatsViewModel
    @State private var conversation: ConversationViewModel
    /// The chat list's command line and spaces page, owned here so ⌘K reaches them
    /// and a change between the phone layout and panes keeps them.
    @State private var isCommanding = false
    @State private var showsSpaces = false
    #if os(iOS)
        @Environment(\.horizontalSizeClass) private var horizontalSizeClass
    #endif
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    init(client: (any ChatClient)? = nil) {
        self.chats = ChatsViewModel(client: client)
        self.conversation = ConversationViewModel(client: client)
    }

    var body: some View {
        // The models, their tasks, and the selection live here, above the layout, so
        // a change of width keeps them.
        Group {
            if usesPanes {
                PanesView(
                    chats: chats, conversation: conversation, selection: selection,
                    isCommanding: $isCommanding, showsSpaces: $showsSpaces,
                    isListHidden: $isListHidden)
            } else {
                splitView
            }
        }
        .focusedSceneValue(\.chatCommands, commands)
        .task(id: storedChatID) { await openStoredChat() }
        .onChange(of: chats.chats) {
            // The open chat follows its row; one that leaves the list, such as one read
            // under the unread filter, stays open until the selection changes.
            if let open = conversation.chat,
                let row = chats.chats.first(where: { $0.id == open.id })
            {
                conversation.select(row)
            }
        }
        .task(id: chats.observationID) { await chats.observe() }
        .task { await chats.observeSpaces() }
    }

    /// Panes on iPad and Mac; the phone's layout wherever the width is compact, such
    /// as on iPhone, in Slide Over, or in a narrow split. The Mac's window is never
    /// narrower than both panes.
    private var usesPanes: Bool {
        #if os(iOS)
            horizontalSizeClass == .regular
        #else
            true
        #endif
    }

    /// The phone's layout: one split view in every state, so the chat list keeps its
    /// state and tasks; loading, failure, and the empty state show in the list column.
    private var splitView: some View {
        NavigationSplitView {
            ChatsView(
                model: chats, selection: selection, isCommanding: $isCommanding,
                showsSpaces: $showsSpaces
            )
            .navigationSplitViewColumnWidth(min: 220, ideal: 300, max: 380)
        } detail: {
            if hasNothingToOpen {
                // Hudhud in the list column says it already.
                Color.surface.ignoresSafeArea()
            } else {
                ConversationView(
                    model: conversation,
                    placement: .screen(
                        identity: conversation.chat.flatMap { chats.spaces.identity($0.identity) })
                )
            }
        }
    }

    private var commands: ChatCommandActions {
        ChatCommandActions(
            findOrStart: {
                if usesPanes, isListHidden { isListHidden = false }
                withAnimation(motion) { isCommanding = true }
            },
            toggleList: usesPanes
                ? { withAnimation(reduceMotion ? nil : .snappy) { isListHidden.toggle() } } : nil,
            isListHidden: isListHidden,
            closeChat: storedChatID == nil ? nil : { storedChatID = nil }
        )
    }

    /// As the chat list's own command line opens.
    private var motion: Animation {
        reduceMotion ? .easeInOut(duration: 0.15) : .spring(response: 0.34, dampingFraction: 0.86)
    }

    private var selection: Binding<Chat.ID?> {
        Binding {
            storedChatID.map(Chat.ID.init(rawValue:))
        } set: {
            storedChatID = $0?.rawValue
        }
    }

    private var hasNothingToOpen: Bool {
        conversation.chat == nil && (chats.hasNoChats || chats.state == .disconnected)
    }

    /// Opens the selected chat, which may be beyond the rows loaded so far, such as one
    /// restored on launch or found by the command line. A chat that no longer exists
    /// clears the selection.
    private func openStoredChat() async {
        guard let id = storedChatID.map(Chat.ID.init(rawValue:)) else {
            conversation.select(nil)
            return
        }
        let lookup = await chats.lookUp(id)
        guard !Task.isCancelled else { return }
        switch lookup {
        case .found(let chat): conversation.select(chat)
        case .missing: storedChatID = nil
        // Kept, so a later launch can try again.
        case .unknown: break
        }
    }
}

#Preview("English") {
    RootView()
        .environment(\.locale, Locale(identifier: "en"))
        .environment(\.layoutDirection, .leftToRight)
}

#Preview("Arabic") {
    RootView()
        .environment(\.locale, Locale(identifier: "ar"))
        .environment(\.layoutDirection, .rightToLeft)
}

#Preview("Arabic · Accessibility text") {
    RootView()
        .environment(\.locale, Locale(identifier: "ar"))
        .environment(\.layoutDirection, .rightToLeft)
        .environment(\.dynamicTypeSize, .accessibility3)
}

#if DEBUG
    #Preview("Busy") {
        RootView(client: PreviewChatClient(.busy))
    }
#endif
