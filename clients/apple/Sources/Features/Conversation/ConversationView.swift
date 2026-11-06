import SwiftUI

struct ConversationView: View {
    @Bindable var model: ConversationViewModel

    var body: some View {
        if let room = model.room {
            conversation(for: room)
                .id(room.id)
                .navigationTitle(room.name)
                .toolbarTitleDisplayMode(.inline)
        } else {
            ContentUnavailableView(
                "Choose a room",
                systemImage: "bubble.left.and.bubble.right",
                description: Text("Select a room to view its messages.")
            )
        }
    }

    @ContentBuilder
    private func conversation(for room: Room) -> some View {
        if #available(iOS 26, macOS 26, *) {
            timeline(for: room)
                .safeAreaBar(edge: .bottom) { composer(for: room) }
        } else {
            timeline(for: room)
                .safeAreaInset(edge: .bottom, spacing: 0) { composer(for: room) }
        }
    }

    private func timeline(for room: Room) -> some View {
        VStack(spacing: 0) {
            if !room.topic.isEmpty {
                Text(room.topic)
                    .font(Typography.roomTopic)
                    .foregroundStyle(Colors.supportingContent)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
            }
            MessageTimeline(messages: model.messages, sendRevision: model.sendRevision)
        }
    }

    private func composer(for room: Room) -> some View {
        MessageComposer(
            roomName: room.name,
            draft: $model.draft,
            canSend: model.canSend,
            sendFailed: model.sendFailed
        ) {
            // A submitted send survives the room view disappearing.
            Task { [model] in await model.sendMessage() }
        }
        .padding(.horizontal)
        .padding(.vertical, 8)
    }
}
