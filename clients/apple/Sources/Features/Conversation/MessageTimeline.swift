import SwiftUI

struct MessageTimeline: View {
    let messages: [Message]
    let sendRevision: Int
    @State private var visibleMessageID: Message.ID?
    @State private var isNearBottom = true
    @State private var hasNewMessages = false

    var body: some View {
        GeometryReader { viewport in
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: Layout.timelineItemSpacing) {
                        ForEach(messages) { message in
                            MessageRow(message: message)
                                .id(message.id)
                        }
                    }
                    .scrollTargetLayout()
                    .padding()
                    .background {
                        GeometryReader { content in
                            Color.clear.preference(
                                key: TimelineBottomKey.self,
                                value: content.frame(in: .named("timeline")).maxY)
                        }
                    }
                }
                .coordinateSpace(name: "timeline")
                .scrollPosition(id: $visibleMessageID, anchor: .top)
                .onPreferenceChange(TimelineBottomKey.self) { bottom in
                    isNearBottom = bottom <= viewport.size.height + 44
                    if isNearBottom { hasNewMessages = false }
                }
                .onAppear { scrollToLatest(proxy) }
                .onChange(of: messages.map(\.id)) { previous, current in
                    guard let latest = current.last, latest != previous.last else { return }
                    // Prepending history leaves the latest ID unchanged.
                    if previous.isEmpty || isNearBottom {
                        scrollToLatest(proxy)
                    } else {
                        hasNewMessages = true
                    }
                }
                .onChange(of: sendRevision) { scrollToLatest(proxy) }
                .overlay(alignment: .bottomTrailing) {
                    if hasNewMessages {
                        Button("New messages", systemImage: "arrow.down") {
                            scrollToLatest(proxy)
                        }
                        .buttonStyle(.borderedProminent)
                        .padding()
                    }
                }
            }
        }
    }

    private func scrollToLatest(_ proxy: ScrollViewProxy) {
        guard let latest = messages.last?.id else { return }
        proxy.scrollTo(latest, anchor: .bottom)
        hasNewMessages = false
    }
}

private struct TimelineBottomKey: PreferenceKey {
    static let defaultValue: CGFloat = 0

    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) {
        value = nextValue()
    }
}
