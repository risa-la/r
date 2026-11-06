import SwiftUI

struct RootView: View {
    @State private var rooms: RoomsViewModel
    @State private var conversation: ConversationViewModel
    @State private var selectedRoomID: Room.ID?
    @State private var reloadID = 0

    init(client: any ChatClient? = nil) {
        self.rooms = RoomsViewModel(client: client)
        self.conversation = ConversationViewModel(client: client)
    }

    var body: some View {
        NavigationSplitView {
            RoomsView(model: rooms, selection: $selectedRoomID)
                .navigationSplitViewColumnWidth(min: 180, ideal: 220, max: 320)
        } detail: {
            detail
        }
        .onChange(of: selectedRoomID) {
            conversation.select(rooms.rooms.first { $0.id == selectedRoomID })
        }
        .task(id: reloadID) { await rooms.load() }
    }

    @ContentBuilder
    private var detail: some View {
        switch rooms.state {
        case .disconnected:
            ContentUnavailableView(
                "Not connected",
                systemImage: "network.slash",
                description: Text("Your rooms will appear when connected to a server.")
            )
        case .loading:
            ProgressView("Loading rooms…")
        case .failed:
            ContentUnavailableView {
                Label("Unable to load rooms", systemImage: "exclamationmark.triangle")
            } description: {
                Text("Please try again.")
            } actions: {
                Button("Try again") { reloadID += 1 }
            }
        case .empty:
            ContentUnavailableView(
                "No rooms",
                systemImage: "bubble.left.and.bubble.right",
                description: Text("Your rooms will appear here.")
            )
        case .loaded:
            ConversationView(model: conversation)
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
