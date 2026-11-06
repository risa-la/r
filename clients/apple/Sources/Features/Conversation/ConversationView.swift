import SwiftUI

struct ConversationView: View {
    @Bindable var model: ConversationViewModel

    var body: some View {
        if let room = model.room {
            VStack(spacing: 0) {
                Text(room.topic).font(Typography.roomTopic).foregroundStyle(
                    Colors.supportingContent
                )
                .frame(maxWidth: .infinity, alignment: .leading).padding()
                Divider()
                MessageTimeline(messages: model.messages, sendRevision: model.sendRevision)
                Divider()
                MessageComposer(
                    roomName: room.name,
                    draft: $model.draft,
                    canSend: model.canSend,
                    sendFailed: model.sendFailed
                ) {
                    // A submitted send survives the room view disappearing.
                    Task { [model] in await model.sendMessage() }
                }
            }
            .id(room.id)
            .navigationTitle(room.name)
        } else {
            ContentUnavailableView(
                "Choose a room",
                systemImage: "bubble.left.and.bubble.right",
                description: Text("Select a room to view its messages.")
            )
        }
    }
}
