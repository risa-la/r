import SwiftUI

struct MessageTimeline: View {
    let messages: [Message]
    let sendRevision: Int
    /// Whether older messages may exist, whether or not a request is in flight.
    let hasOlder: Bool
    let isLoadingOlder: Bool
    let busyMessages: Set<Message.ID>
    let loadOlder: () async -> Void
    let retry: (Message) -> Void
    let discard: (Message) -> Void
    @State private var position = ScrollPosition(edge: .bottom)
    @State private var edges = ScrollEdges()
    @State private var hasNewMessages = false
    @State private var olderRequest = 0
    /// Older messages landed; check the top again once they are laid out.
    @State private var olderLanded = false
    /// The top was reached while a request was in flight; check again when it ends.
    @State private var olderAgain = false

    var body: some View {
        let tolerance = Layout.timelineEdgeTolerance
        ScrollView {
            LazyVStack(alignment: .leading, spacing: Layout.timelineItemSpacing) {
                if isLoadingOlder {
                    ProgressView()
                        .frame(maxWidth: .infinity)
                }
                ForEach(messages) { message in
                    MessageRow(
                        message: message,
                        isBusy: busyMessages.contains(message.id),
                        retry: { retry(message) },
                        discard: { discard(message) }
                    )
                }
            }
            .scrollTargetLayout()
            .padding()
        }
        .scrollPosition($position)
        .onScrollGeometryChange(for: ScrollEdges.self) { geometry in
            ScrollEdges(geometry, tolerance: tolerance)
        } action: { previous, current in
            edges = current
            if current.nearBottom { hasNewMessages = false }
            let grew = current.contentHeight > previous.contentHeight
            // Reaching the top asks for more; so does still being there once a page lands.
            if current.nearTop, !previous.nearTop || (olderLanded && grew) {
                requestOlder()
            }
            if grew { olderLanded = false }
        }
        .onChange(of: messages.first?.id) { olderLanded = true }
        .onChange(of: isLoadingOlder) {
            guard !isLoadingOlder, olderAgain else { return }
            olderAgain = false
            if edges.nearTop { requestOlder() }
        }
        .onChange(of: messages.last?.id) { previous, latest in
            // Older history and replaced outbox items keep the latest ID.
            guard latest != nil, latest != previous else { return }
            if previous == nil || edges.nearBottom {
                scrollToLatest()
            } else if messages.contains(where: { $0.id == previous }) {
                // The previous latest is still there, so this one arrived after it.
                hasNewMessages = true
            }
        }
        .onChange(of: sendRevision) { scrollToLatest() }
        .task(id: olderRequest) {
            guard olderRequest > 0 else { return }
            await loadOlder()
        }
        .overlay(alignment: .bottomTrailing) {
            if hasNewMessages {
                Button("New messages", systemImage: "arrow.down") { scrollToLatest() }
                    .buttonStyle(.borderedProminent)
                    .padding()
            }
        }
    }

    private func requestOlder() {
        guard hasOlder else { return }
        if isLoadingOlder {
            olderAgain = true
        } else {
            olderRequest += 1
        }
    }

    private func scrollToLatest() {
        position.scrollTo(edge: .bottom)
        hasNewMessages = false
    }
}

private nonisolated struct ScrollEdges: Equatable {
    var nearTop = false
    var nearBottom = true
    var contentHeight: CGFloat = 0

    init() {}

    init(_ geometry: ScrollGeometry, tolerance: CGFloat) {
        let offset = geometry.contentOffset.y
        let visibleBottom = offset + geometry.containerSize.height - geometry.contentInsets.bottom
        nearTop = offset + geometry.contentInsets.top <= tolerance
        nearBottom = geometry.contentSize.height - visibleBottom <= tolerance
        contentHeight = geometry.contentSize.height
    }
}
