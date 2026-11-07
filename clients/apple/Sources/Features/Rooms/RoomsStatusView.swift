import SwiftUI

struct RoomsStatusView: View {
    let state: RoomsViewModel.State
    let retry: () -> Void

    var body: some View {
        switch state {
        case .disconnected:
            ContentUnavailableView(
                "Not connected",
                systemImage: "network.slash",
                description: Text("Your rooms will appear when connected to a server.")
            )
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
        case .empty:
            ContentUnavailableView(
                "No rooms",
                systemImage: "bubble.left.and.bubble.right",
                description: Text("Your rooms will appear here.")
            )
        case .loaded:
            EmptyView()
        }
    }
}
