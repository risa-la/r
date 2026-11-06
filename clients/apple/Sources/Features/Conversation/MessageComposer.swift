import SwiftUI

struct MessageComposer: View {
    let roomName: String
    @Binding var draft: String
    let canSend: Bool
    let sendFailed: Bool
    let onSend: () -> Void
    @FocusState private var composerFocused: Bool

    var body: some View {
        VStack(spacing: 0) {
            if sendFailed {
                HStack {
                    Text("Unable to send message.")
                    Button("Try again") { send() }
                        .disabled(!canSend)
                }
                .padding(.horizontal)
            }
            HStack(alignment: .bottom) {
                TextField("Message \(roomName)", text: $draft, axis: .vertical)
                    .font(Typography.composer)
                    .lineLimit(1...5).textFieldStyle(.roundedBorder)
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
            }.padding()
        }
    }

    private func send() {
        composerFocused = true
        onSend()
    }
}
