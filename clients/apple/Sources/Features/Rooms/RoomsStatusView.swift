import SwiftUI

struct RoomsStatusView: View {
    let state: RoomsViewModel.State
    let retry: () -> Void
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize

    var body: some View {
        switch state {
        // Cached chats show whether or not a server is connected, so reaching
        // this state without a session still means there is nothing to show.
        case .disconnected, .empty:
            HudhudMessage(
                title: Text("No chats yet"),
                message: Text("Hudhud is holding a letter with nowhere to take it.")
            ) {
                emptyActions
            }
        case .idle, .loading:
            ProgressView("Loading rooms…")
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        case .failed:
            ContentUnavailableView {
                Label("Unable to load rooms", systemImage: "exclamationmark.triangle")
            } description: {
                Text("Please try again.")
            } actions: {
                Button("Try again", action: retry)
            }
        case .loaded:
            EmptyView()
        }
    }

    // The command line, invites, and spaces are not built yet; these actions
    // connect to them when they are.
    private var emptyActions: some View {
        VStack(spacing: Layout.inlineSpacing) {
            Button {
            } label: {
                Label("Give Hudhud a job", systemImage: "arrowtriangle.up.fill")
                    .frame(maxWidth: .infinity)
            }
            .terminalPrimaryButton()
            secondaryLayout {
                Button {
                } label: {
                    Text("Paste invite").frame(maxWidth: .infinity)
                }
                .terminalSecondaryButton()
                Button {
                } label: {
                    Text("Browse spaces").frame(maxWidth: .infinity)
                }
                .terminalSecondaryButton()
            }
        }
    }

    /// Side by side, or stacked when accessibility text sizes leave no room.
    private var secondaryLayout: AnyLayout {
        dynamicTypeSize.isAccessibilitySize
            ? AnyLayout(VStackLayout(spacing: Layout.inlineSpacing))
            : AnyLayout(HStackLayout(spacing: Layout.inlineSpacing))
    }
}
