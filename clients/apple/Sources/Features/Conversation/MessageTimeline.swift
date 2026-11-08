import SwiftUI

/// A chat's messages as a terminal timeline, newest at the bottom: day lines, a
/// "new" line where the unread messages start, and messages grouped by author. It
/// follows new messages while at the bottom and loads older ones at the top.
struct MessageTimeline: View {
    let messages: [Message]
    /// Where the "new" line goes.
    var firstUnread: Message.ID? = nil
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
            LazyVStack(alignment: .leading, spacing: 0) {
                if isLoadingOlder {
                    ProgressView()
                        .frame(maxWidth: .infinity)
                        .padding(.bottom, Layout.timelineEntrySpacing)
                }
                let entries = TimelineEntry.entries(for: messages, firstUnread: firstUnread)
                ForEach(Array(entries.enumerated()), id: \.element.id) { index, entry in
                    self.entry(entry)
                        .padding(.top, index == 0 ? 0 : spacing(before: entry))
                }
            }
            .scrollTargetLayout()
            .frame(maxWidth: Layout.timelineMaxWidth)
            .padding(.horizontal, 16)
            .padding(.top, 12)
            .padding(.bottom, 14)
            .frame(maxWidth: .infinity)
        }
        // The top edge fades rather than cutting a line in half.
        .mask {
            VStack(spacing: 0) {
                LinearGradient(colors: [.clear, .black], startPoint: .top, endPoint: .bottom)
                    .frame(height: 28)
                Color.black
            }
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
                Button(action: scrollToLatest) {
                    HStack(spacing: 6) {
                        Text(verbatim: "↓").accessibilityHidden(true)
                        Text("New messages")
                    }
                    .font(Typography.terminalSmall.weight(.bold))
                    .foregroundStyle(.ink)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(.panel, in: .rect(cornerRadius: 8))
                    .overlay { RoundedRectangle(cornerRadius: 8).strokeBorder(.rule) }
                    .minimumTouchTarget()
                }
                .buttonStyle(.plain)
                .padding()
            }
        }
    }

    @ViewBuilder
    private func entry(_ entry: TimelineEntry) -> some View {
        switch entry {
        case .day(let date):
            TimelineDivider(label: DayLabel(date: date), isNew: false)
        case .new:
            TimelineDivider(label: Text("new"), isNew: true)
        case .message(let message, let continuesGroup):
            MessageRow(
                message: message,
                continuesGroup: continuesGroup,
                isBusy: busyMessages.contains(message.id),
                retry: { retry(message) },
                discard: { discard(message) }
            )
        }
    }

    /// Lines in a group sit close; everything else has room around it.
    private func spacing(before entry: TimelineEntry) -> CGFloat {
        if case .message(_, true) = entry { return 2 }
        return Layout.timelineEntrySpacing
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

/// A line across the timeline with a label at its trailing end: `──── today`, or the
/// "new" line in ink.
private struct TimelineDivider<Label: View>: View {
    let label: Label
    let isNew: Bool

    var body: some View {
        HStack(spacing: 6) {
            Rectangle()
                .fill(isNew ? Color.ink.opacity(0.35) : Color.rule)
                .frame(height: 1)
                .accessibilityHidden(true)
            label
                .font(Typography.timelineDivider)
                .foregroundStyle(isNew ? .ink : .textTertiary)
                .lineLimit(1)
                .fixedSize()
        }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isHeader)
    }
}

/// `today`, `yesterday`, or the date, in lowercase like the rest of the terminal.
private struct DayLabel: View {
    let date: Date

    var body: some View {
        Group {
            if Calendar.current.isDateInToday(date) {
                Text("today")
            } else if Calendar.current.isDateInYesterday(date) {
                Text("yesterday")
            } else {
                Text(date, format: .dateTime.weekday(.wide).day().month(.wide))
            }
        }
        .textCase(.lowercase)
    }
}
