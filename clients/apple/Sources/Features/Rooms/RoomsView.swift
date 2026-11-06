import SwiftUI

struct RoomsView: View {
    let model: RoomsViewModel
    @Binding var selection: Room.ID?

    var body: some View {
        List(selection: $selection) {
            Section("Rooms") {
                ForEach(model.rooms) { room in
                    Label(room.name, systemImage: "number")
                        .font(Typography.roomName)
                        .tag(room.id)
                }
            }
        }
        .navigationTitle("Risala")
    }
}
