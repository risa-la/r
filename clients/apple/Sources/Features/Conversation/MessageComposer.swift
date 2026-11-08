import SwiftUI

struct MessageComposer: View {
    let roomName: String
    @Binding var draft: String
    let canSend: Bool
    let sendFailed: Bool
    /// The identity you speak as, shown before the prompt.
    let identity: Identity?
    /// The mode shows only where the focus is: always on the phone, and in the focused
    /// pane on a large screen.
    let showsMode: Bool
    let onSend: () -> Void
    @FocusState private var composerFocused: Bool

    /// `NOR L › message #general`, with Send once there is something to send. Typing
    /// is INS; the mode shows only in the focused pane.
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if sendFailed {
                HStack(spacing: 4) {
                    Text("Unable to send message.").foregroundStyle(.wax)
                    TryAgainButton(action: send).disabled(!canSend)
                }
                .font(Typography.terminalSmall)
                .padding(.horizontal, 12)
            }
            HStack(alignment: .center, spacing: 10) {
                if showsMode {
                    ModeBlock(
                        mode: composerFocused ? Text(verbatim: "INS") : Text(verbatim: "NOR"),
                        color: composerFocused ? .presence : .mode)
                }
                if let identity {
                    IdentityChip(identity: identity, isLarge: true)
                }
                ForwardChevron()
                    .font(Typography.prompt.weight(.bold))
                    .foregroundStyle(.ink)
                // The prompt is in JetBrains Mono like every prompt; what is typed is in
                // the system face, since the mono face's fallback breaks Arabic apart.
                // An empty prompt, or the Mac shows the label as one under the overlay.
                TextField(text: $draft, prompt: Text(verbatim: ""), axis: .vertical) {
                    Text("Message")
                }
                .overlay(alignment: .leading) {
                    if draft.isEmpty {
                        Text("message \(roomName)")
                            .font(Typography.prompt)
                            .foregroundStyle(.textTertiary)
                            .lineLimit(1)
                            .allowsHitTesting(false)
                            .accessibilityHidden(true)
                    }
                }
                .font(Typography.messageBody)
                .foregroundStyle(.text)
                .lineLimit(1...6)
                .textFieldStyle(.plain)
                .focused($composerFocused)
                .onKeyPress(.escape) {
                    guard composerFocused else { return .ignored }
                    composerFocused = false
                    return .handled
                }
                .frame(minHeight: Layout.minimumTouchTarget - 18)
                if canSend {
                    Button {
                        send()
                    } label: {
                        Image(systemName: "arrow.up")
                            .font(.footnote.weight(.bold))
                            .foregroundStyle(.onInk)
                            .frame(width: 26, height: 26)
                            .background(.ink, in: .rect(cornerRadius: 8))
                            .minimumTouchTarget()
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("Send message")
                    .transition(.opacity)
                }
            }
            .padding(.vertical, 9)
            .padding(.leading, 9)
            .padding(.trailing, 14)
            .frame(minHeight: Layout.minimumTouchTarget)
            .background(.panel, in: .rect(cornerRadius: Layout.panelCornerRadius))
            .overlay {
                RoundedRectangle(cornerRadius: Layout.panelCornerRadius)
                    .strokeBorder(composerFocused ? Color.ink.opacity(0.5) : Color.rule)
            }
            .contentShape(.rect)
            .onTapGesture { composerFocused = true }
            // ⌘↵ sends, whether or not Send shows.
            .background {
                Button("Send message", action: send)
                    .keyboardShortcut(.return, modifiers: .command)
                    .disabled(!canSend)
                    .hidden()
            }
        }
        .frame(maxWidth: Layout.composerMaxWidth)
        .frame(maxWidth: .infinity)
    }

    private func send() {
        composerFocused = true
        onSend()
    }
}
