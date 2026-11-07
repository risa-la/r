import SwiftUI

struct MessageTimeline: View {
    let messages: [Message]
    let sendRevision: Int
    let canLoadOlder: Bool
    let isLoadingOlder: Bool
    let loadOlder: () async -> Void
    @State private var position = ScrollPosition(edge: .bottom)
    @State private var edges = ScrollEdges()
    @State private var hasNewMessages = false
    @State private var olderRequest = 0

    var body: some View {
        let tolerance = Layout.timelineEdgeTolerance
        ScrollView {
            LazyVStack(alignment: .leading, spacing: Layout.timelineItemSpacing) {
                if isLoadingOlder {
                    ProgressView()
                        .frame(maxWidth: .infinity)
                }
                ForEach(messages) { message in
                    MessageRow(message: message)
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
            if current.nearTop, !previous.nearTop, canLoadOlder { olderRequest += 1 }
        }
        .onChange(of: messages.last?.id) { previous, latest in
            // Prepending history leaves the latest ID unchanged.
            guard latest != nil, latest != previous else { return }
            if previous == nil || edges.nearBottom {
                scrollToLatest()
            } else {
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

    private func scrollToLatest() {
        position.scrollTo(edge: .bottom)
        hasNewMessages = false
    }
}

private nonisolated struct ScrollEdges: Equatable {
    var nearTop = false
    var nearBottom = true

    init() {}

    init(_ geometry: ScrollGeometry, tolerance: CGFloat) {
        let offset = geometry.contentOffset.y
        let visibleBottom = offset + geometry.containerSize.height - geometry.contentInsets.bottom
        nearTop = offset + geometry.contentInsets.top <= tolerance
        nearBottom = geometry.contentSize.height - visibleBottom <= tolerance
    }
}
