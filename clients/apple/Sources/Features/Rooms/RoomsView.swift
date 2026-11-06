import SwiftUI

struct RoomsView: View {
    let model: RoomsViewModel
    @Binding var selection: Room.ID?
    let showsStatus: Bool
    let retry: () -> Void

    var body: some View {
        Group {
            if showsStatus && model.rooms.isEmpty {
                RoomsStatusView(state: model.state, retry: retry)
            } else {
                List(selection: $selection) {
                    ForEach(model.rooms) { room in
                        Label(room.name, systemImage: "number")
                            .font(Typography.roomName)
                            .tag(room.id)
                    }
                }
            }
        }
        .navigationTitle("Rooms")
        .toolbarTitleDisplayMode(.inline)
    }

}
