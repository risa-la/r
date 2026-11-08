import SwiftUI

struct RootView: View {
    #if os(iOS)
        @Environment(\.horizontalSizeClass) private var horizontalSizeClass
    #endif
    @SceneStorage("selectedRoomID") private var storedRoomID: String?
    @State private var rooms: RoomsViewModel
    @State private var conversation: ConversationViewModel
    @State private var roomsLoadAttempt = 0

    init(client: (any ChatClient)? = nil) {
        self.rooms = RoomsViewModel(client: client)
        self.conversation = ConversationViewModel(client: client)
    }

    var body: some View {
        Group {
            // With nothing to list, one pane holds the state; an empty sidebar
            // beside it would only look broken.
            if rooms.rooms.isEmpty {
                RoomsView(model: rooms, selection: selection, showsStatus: true, retry: retry)
            } else {
                NavigationSplitView {
                    RoomsView(
                        model: rooms, selection: selection, showsStatus: isCompact, retry: retry
                    )
                    .navigationSplitViewColumnWidth(min: 180, ideal: 220, max: 320)
                } detail: {
                    ConversationView(model: conversation)
                }
            }
        }
        .onChange(of: selectedRoom, initial: true) {
            conversation.select(selectedRoom)
        }
        .onChange(of: rooms.state) {
            // Forget a restored selection once loaded rooms no longer include it.
            switch rooms.state {
            case .loaded, .empty: if selectedRoom == nil { storedRoomID = nil }
            default: break
            }
        }
        .task(id: roomsLoadAttempt) { await rooms.observe() }
    }

    private var selection: Binding<Room.ID?> {
        Binding {
            storedRoomID.map(Room.ID.init(rawValue:))
        } set: {
            storedRoomID = $0?.rawValue
        }
    }

    private var selectedRoom: Room? {
        guard let storedRoomID else { return nil }
        return rooms.rooms.first { $0.id.rawValue == storedRoomID }
    }

    private var isCompact: Bool {
        #if os(iOS)
            horizontalSizeClass == .compact
        #else
            false
        #endif
    }

    private func retry() {
        roomsLoadAttempt += 1
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
