import SwiftUI

/// Something the command line can open: a chat, or a space to show in the list.
enum CommandItem: Identifiable, Hashable {
    case chat(Chat)
    case space(Space)

    var id: String {
        switch self {
        case .chat(let chat): "chat:" + chat.id.rawValue
        case .space(let space): "space:" + space.id.rawValue
        }
    }

    /// What the command line finds for `query`, best first, as `MatchQuery` ranks
    /// names; a space comes just after the chats that match as well. With no query,
    /// the `recent` newest chats, so the bar also works as a quick switcher.
    static func matches(
        _ query: String, chats: [Chat], spaces: [Space], recent: Int = 5, limit: Int = 8
    ) -> [CommandItem] {
        guard let query = MatchQuery(query) else {
            return chats.prefix(recent).map(CommandItem.chat)
        }
        let items = chats.map(CommandItem.chat) + spaces.map(CommandItem.space)
        return Array(query.ranked(items) { $0.rank(query) }.prefix(limit))
    }

    private func rank(_ query: MatchQuery) -> MatchRank? {
        switch self {
        case .chat(let chat): chat.rank(query)
        case .space(let space): space.rank(query)
        }
    }
}

/// The command line's results, growing up out of the mode bar: the best match last,
/// next to the prompt, marked `↵`.
struct CommandResults: View {
    let items: [CommandItem]
    let spaces: Spaces
    /// What was typed, as typed.
    let query: String
    let choose: (CommandItem) -> Void

    @ScaledMetric(relativeTo: .body) private var maxHeight: CGFloat = 300

    private var trimmedQuery: String {
        query.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if items.isEmpty {
                noMatches
                    .font(Typography.terminal)
                    .foregroundStyle(.textTertiary)
                    .lineLimit(2)
                    .padding(.horizontal, Layout.chatRowHorizontalPadding - Layout.modeBarInset)
                    .padding(.vertical, 14)
                    // The panel spans the bar, as it does with results.
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else {
                if trimmedQuery.isEmpty {
                    SectionLine(title: Text("recent"), fill: .panel)
                }
                ScrollView {
                    VStack(spacing: 0) {
                        ForEach(Array(items.reversed().enumerated()), id: \.element.id) {
                            index, item in
                            row(item, isBest: index == items.count - 1)
                                .transition(.opacity.combined(with: .offset(y: 6)))
                        }
                    }
                }
                .defaultScrollAnchor(.bottom)
                .scrollBounceBehavior(.basedOnSize)
                .frame(maxHeight: maxHeight)
                .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.vertical, 4)
        .background(.panel, in: .rect(cornerRadius: Layout.panelCornerRadius))
        .overlay {
            RoundedRectangle(cornerRadius: Layout.panelCornerRadius).strokeBorder(.rule)
        }
        .padding(.horizontal, Layout.modeBarInset)
        .padding(.bottom, 6)
    }

    /// Says what was searched for, so a typo shows.
    private var noMatches: Text {
        trimmedQuery.isEmpty
            ? Text("Nothing matches.")
            : Text("Nothing matches “\(trimmedQuery.isolated)”.")
    }

    private func row(_ item: CommandItem, isBest: Bool) -> some View {
        ResultRow(
            isBest: isBest,
            horizontalPadding: Layout.chatRowHorizontalPadding - Layout.modeBarInset
        ) {
            choose(item)
        } label: {
            switch item {
            case .chat(let chat):
                ChatMark(chat: chat, isSmall: true)
                HStack(spacing: 7) {
                    ChatName(chat: chat)
                        .font(Typography.chatPreview)
                        .foregroundStyle(.text)
                    if let identity = spaces.identity(chat.identity), !identity.isMain {
                        IdentityChip(identity: identity)
                            .layoutPriority(1)
                    }
                }
                Spacer(minLength: 0)
                UnreadMark(
                    mentions: chat.mentionCount, unread: chat.unreadCount,
                    unreadLabel: Text("\(chat.unreadCount) unread"))
            case .space(let space):
                if let identity = spaces.identity(space.identity) {
                    IdentityChip(identity: identity, isLarge: true)
                }
                SpaceName(space: space)
                Spacer(minLength: 0)
                Text("space").foregroundStyle(.textTertiary)
            }
        }
    }
}

/// A result of the command line or the spaces search. The best match, nearest the
/// prompt, is tinted and marked `↵`, for Return.
struct ResultRow<Label: View>: View {
    let isBest: Bool
    var horizontalPadding = Layout.chatRowHorizontalPadding
    let action: () -> Void
    @ViewBuilder let label: Label

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                label
                if isBest {
                    Text(verbatim: "↵").foregroundStyle(.ink).accessibilityHidden(true)
                }
            }
            .font(Typography.terminal)
            .padding(.horizontal, horizontalPadding)
            .frame(minHeight: Layout.minimumTouchTarget)
            .background(isBest ? Color.location.opacity(0.12) : .clear)
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
    }
}

/// A space's full host, read left to right whatever its script, cut in the middle.
struct SpaceName: View {
    let space: Space

    var body: some View {
        Text(terminal: space.id.rawValue.leftToRightIsolated)
            .foregroundStyle(.text)
            .lineLimit(1)
            .truncationMode(.middle)
    }
}
