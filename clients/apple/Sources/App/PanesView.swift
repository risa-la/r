import SwiftUI

/// The large-screen layout, on iPad and Mac: a bar of identities and space tabs
/// across the window, then the chat list pane beside a chat pane. One pane has the
/// focus and shows the mode: the list while its command line is open or no chat is,
/// otherwise the chat.
struct PanesView: View {
    @Bindable var chats: ChatsViewModel
    @Bindable var conversation: ConversationViewModel
    @Binding var selection: Chat.ID?
    @Binding var isCommanding: Bool
    @Binding var showsSpaces: Bool
    @Binding var isListHidden: Bool

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private var isListFocused: Bool {
        isCommanding || conversation.chat == nil
    }

    /// The list shows unless hidden, and always while its command line is open or
    /// there is no chat to show instead.
    private var showsList: Bool {
        !isListHidden || isListFocused
    }

    var body: some View {
        VStack(spacing: 0) {
            TopBar(
                model: chats, showAll: { showsSpaces = true },
                leadingInset: Self.windowButtonsWidth, height: Self.barHeight)
            HStack(spacing: Layout.paneGap) {
                if showsList {
                    ChatsView(
                        model: chats, selection: $selection, isCommanding: $isCommanding,
                        showsSpaces: $showsSpaces, placement: .pane(isFocused: isListFocused)
                    )
                    .frame(width: Layout.listPaneWidth)
                    .pane(isFocused: isListFocused)
                    .transition(.move(edge: .leading).combined(with: .opacity))
                }
                ConversationView(
                    model: conversation,
                    placement: .pane(
                        ConversationView.Pane(
                            isFocused: !isListFocused,
                            identity: conversation.chat.flatMap {
                                chats.spaces.identity($0.identity)
                            },
                            isListHidden: !showsList,
                            toggleList: toggleList,
                            close: { selection = nil }
                        ))
                )
                .frame(minWidth: Layout.chatPaneMinWidth)
                .pane(isFocused: !isListFocused)
                // Using the chat pane takes the focus from the command line.
                .simultaneousGesture(
                    TapGesture().onEnded { if isCommanding { isCommanding = false } })
            }
            .padding(.horizontal, Layout.paneGap)
            .padding(.bottom, Layout.paneGap)
        }
        .background(.surface)
        #if os(macOS)
            // The bar sits in the title bar, beside the window buttons.
            .ignoresSafeArea(.container, edges: .top)
        #endif
    }

    private func toggleList() {
        withAnimation(reduceMotion ? nil : .snappy) { isListHidden.toggle() }
    }

    /// The Mac's close, minimise, and zoom buttons, which the bar makes room for.
    private static var windowButtonsWidth: CGFloat {
        #if os(macOS)
            58
        #else
            0
        #endif
    }

    /// On the Mac the bar's tabs center on the window buttons, in the title bar.
    private static var barHeight: CGFloat {
        #if os(macOS)
            32
        #else
            Layout.topBarHeight
        #endif
    }
}
