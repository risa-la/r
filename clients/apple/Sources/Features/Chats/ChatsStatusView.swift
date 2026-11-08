import SwiftUI

struct ChatsStatusView: View {
    enum Status {
        /// Nothing to list: no chats, or no library session.
        case noChats
        case loading
        case failed
    }

    let status: Status
    let retry: () -> Void
    /// Opens the command line, to find or start a chat.
    let start: () -> Void
    /// Opens the spaces page.
    let browseSpaces: () -> Void

    var body: some View {
        switch status {
        // Cached chats show whether or not a server is connected, so reaching
        // this state without a session still means there is nothing to show.
        case .noChats:
            HudhudMessage(
                title: Text("No chats yet"),
                message: Text("Hudhud is holding a letter with nowhere to take it.")
            ) {
                emptyActions
            }
        case .loading:
            ProgressView("Loading chats…")
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        case .failed:
            ContentUnavailableView {
                Label("Unable to load chats", systemImage: "exclamationmark.triangle")
            } description: {
                Text("Please try again.")
            } actions: {
                Button("Try again", action: retry)
            }
        }
    }

    // Pasting an invite joins these once invites can be accepted.
    private var emptyActions: some View {
        VStack(spacing: Layout.inlineSpacing) {
            Button(action: start) {
                Label("Give Hudhud a job", systemImage: "arrowtriangle.up.fill")
                    .terminalButtonLabel(primary: true)
                    .frame(maxWidth: .infinity)
            }
            .terminalPrimaryButton()
            Button(action: browseSpaces) {
                Text("Browse spaces").terminalButtonLabel().frame(maxWidth: .infinity)
            }
            .terminalSecondaryButton()
        }
    }
}
