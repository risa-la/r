import SwiftUI

/// The open chat: the phone's pushed screen, or the chat pane beside the list on
/// large screens.
struct ConversationView: View {
    /// What a chat pane needs from the window around it.
    struct Pane {
        /// Whether the pane has the focus, so its composer shows the mode.
        var isFocused: Bool
        var isListHidden: Bool
        var toggleList: () -> Void
        var close: () -> Void
    }

    @Bindable var model: ConversationViewModel
    /// The identity you speak as, for the composer.
    var identity: Identity?
    /// Set in a pane; `nil` on the phone.
    var pane: Pane?

    var body: some View {
        Group {
            if let chat = model.chat {
                if let pane {
                    VStack(spacing: 0) {
                        PaneChatHeader(chat: chat, pane: pane)
                        timeline(for: chat, showsTopic: false)
                        bottom(for: chat, showsMode: pane.isFocused)
                    }
                    .id(chat.id)
                } else {
                    timeline(for: chat, showsTopic: true)
                        .safeAreaInset(edge: .bottom, spacing: 0) {
                            // The same bottom bar as the chat list: the mode, who you
                            // speak as, and the prompt.
                            bottom(for: chat, showsMode: true)
                                .background {
                                    LinearGradient(
                                        colors: [Color.surface.opacity(0), .surface],
                                        startPoint: .top, endPoint: .center
                                    )
                                    .ignoresSafeArea()
                                }
                        }
                        .background(Color.surface.ignoresSafeArea())
                        .id(chat.id)
                        .navigationTitle(chat.name)
                        .toolbarTitleDisplayMode(.inline)
                }
            } else {
                noChatOpen
            }
        }
        .task(id: model.timelineID) { await model.observeTimeline() }
    }

    /// The typing line, then the composer.
    private func bottom(for chat: Chat, showsMode: Bool) -> some View {
        VStack(spacing: 0) {
            if !chat.typing.isEmpty {
                typingLine(chat.typing)
            }
            MessageComposer(
                roomName: chat.kind == .room ? "#" + chat.name : chat.name,
                draft: $model.draft,
                canSend: model.canSend,
                sendFailed: model.sendFailed,
                identity: identity,
                showsMode: showsMode
            ) {
                // A submitted send survives the conversation view disappearing.
                Task { [model] in await model.sendMessage() }
            }
            .padding(.horizontal, pane == nil ? Layout.modeBarInset : 16)
            .padding(.bottom, pane == nil ? 4 : 14)
        }
    }

    /// A quiet line; Hudhud is kept for when there are no chats at all.
    private var noChatOpen: some View {
        Text("no chat open · ⌘K to find one")
            .font(Typography.terminal)
            .foregroundStyle(.textTertiary)
            .multilineTextAlignment(.center)
            .padding(24)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// `farah, karim +2 typing` under the timeline, lined up with it.
    private func typingLine(_ names: [String]) -> some View {
        HStack(spacing: 8) {
            TypingIndicator()
            ChatRow.typingText(names)
                .font(Typography.terminalSmall)
                .foregroundStyle(.textSecondary)
                .lineLimit(1)
        }
        .frame(maxWidth: Layout.timelineMaxWidth, alignment: .leading)
        .padding(.horizontal, 16)
        .padding(.bottom, 10)
        .frame(maxWidth: .infinity)
        .accessibilityElement(children: .combine)
    }

    // MARK: Timeline

    private func timeline(for chat: Chat, showsTopic: Bool) -> some View {
        VStack(spacing: 0) {
            if showsTopic, !chat.topic.isEmpty {
                Text(chat.topic)
                    .font(Typography.roomTopic)
                    .foregroundStyle(Colors.supportingContent)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
            }
            if model.timelineFailed {
                HStack(spacing: 4) {
                    Text("Unable to load messages.")
                        .foregroundStyle(.textSecondary)
                    TryAgainButton(action: model.retryTimeline)
                }
                .font(Typography.terminalSmall)
                .padding(.horizontal)
            }
            MessageTimeline(
                messages: model.messages,
                firstUnread: model.firstUnread,
                sendRevision: model.sendRevision,
                hasOlder: model.hasOlderMessages,
                isLoadingOlder: model.isLoadingOlder,
                busyMessages: model.busyMessages,
                loadOlder: model.loadOlderMessages,
                // Like sends, these survive the conversation view disappearing.
                retry: { message in _ = Task { [model] in await model.retry(message) } },
                discard: { message in _ = Task { [model] in await model.discard(message) } }
            )
        }
    }
}

/// `# general  48 here`, then the pane's controls: show or hide the list, and close.
private struct PaneChatHeader: View {
    let chat: Chat
    let pane: ConversationView.Pane

    var body: some View {
        HStack(spacing: 8) {
            Text(verbatim: chat.kind == .room ? "#" : "@")
                .font(Typography.paneMark)
                .foregroundStyle(.ink)
                .accessibilityHidden(true)
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                ChatName(chat: chat)
                    .foregroundStyle(.text)
                Group {
                    if let present = chat.presentCount {
                        Text("\(present) here").monospacedDigit()
                    } else if chat.isOnline == true {
                        Text("online")
                    }
                }
                .foregroundStyle(.textTertiary)
                .lineLimit(1)
                .fixedSize()
            }
            .font(Typography.paneTitle)
            .accessibilityElement(children: .combine)
            .accessibilityAddTraits(.isHeader)
            Spacer(minLength: 0)
            HStack(spacing: 2) {
                control(
                    pane.isListHidden
                        ? "arrow.down.right.and.arrow.up.left"
                        : "arrow.up.left.and.arrow.down.right",
                    label: pane.isListHidden ? Text("Show chat list") : Text("Hide chat list"),
                    action: pane.toggleList)
                control("xmark", label: Text("Close chat"), action: pane.close)
            }
        }
        .padding(.leading, 14)
        .padding(.trailing, 10)
        .frame(minHeight: Layout.paneHeaderHeight)
    }

    private func control(_ symbol: String, label: Text, action: @escaping () -> Void)
        -> some View
    {
        Button(action: action) {
            Image(systemName: symbol)
                .font(.footnote)
                .foregroundStyle(.textTertiary)
                .frame(width: 28, height: 28)
                .minimumTouchTarget()
        }
        .buttonStyle(.plain)
        .accessibilityLabel(label)
        #if os(macOS)
            .help(label)
        #endif
    }
}
