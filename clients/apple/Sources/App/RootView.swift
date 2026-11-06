import SwiftUI

struct RootView: View {
    #if os(iOS)
        @Environment(\.horizontalSizeClass) private var horizontalSizeClass
    #endif
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
            RoomsView(model: rooms, selection: $selectedRoomID, showsStatus: isCompact) {
                reloadID += 1
            }
            .navigationSplitViewColumnWidth(min: 180, ideal: 220, max: 320)
        } detail: {
            detail
        }
        .onChange(of: selectedRoomID) {
            conversation.select(rooms.rooms.first { $0.id == selectedRoomID })
        }
        .task(id: reloadID) { await rooms.load() }
    }

    private var isCompact: Bool {
        #if os(iOS)
            horizontalSizeClass == .compact
        #else
            false
        #endif
    }

    @ContentBuilder
    private var detail: some View {
        switch rooms.state {
        case .loaded:
            ConversationView(model: conversation)
        default:
            RoomsStatusView(state: rooms.state) { reloadID += 1 }
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
