import SwiftUI

struct MessageComposer: View {
    let roomName: String
    @Binding var draft: String
    let canSend: Bool
    let sendFailed: Bool
    let onSend: () -> Void
    @FocusState private var composerFocused: Bool

    var body: some View {
        VStack(spacing: Layout.relatedContentSpacing) {
            if sendFailed {
                HStack {
                    Text("Unable to send message.")
                    Button("Try again") { send() }
                        .disabled(!canSend)
                }
            }
            HStack(alignment: .bottom) {
                TextField("Message \(roomName)", text: $draft, axis: .vertical)
                    .font(Typography.composer)
                    .lineLimit(1...5)
                    .textFieldStyle(.plain)
                    .accessibilityLabel("Message")
                    .focused($composerFocused)
                Button {
                    send()
                } label: {
                    Image(systemName: "arrow.up.circle.fill")
                        .iconActionLabel()
                }
                .accessibilityLabel("Send message")
                .keyboardShortcut(.return, modifiers: .command)
                .disabled(!canSend)
            }
        }
        .padding()
        .modifier(ComposerSurface())
    }

    private func send() {
        composerFocused = true
        onSend()
    }
}

private struct ComposerSurface: ViewModifier {
    func body(content: Content) -> some View {
        if #available(iOS 26, macOS 26, *) {
            content.glassEffect(.regular, in: .rect(cornerRadius: 24))
        } else {
            content.background(.regularMaterial, in: .rect(cornerRadius: 24))
        }
    }
}
