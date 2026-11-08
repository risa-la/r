import SwiftUI

/// One chat in the list: its mark, then the name and time, then the newest message
/// with a count or mention block. Unread chats are bold with ink metadata; read ones
/// step down to regular weight and tertiary color.
struct ChatRow: View {
    let chat: Chat
    /// Which of the person's identities is in the chat, when it is not the main one;
    /// it shows as a chip after the name.
    var identity: Identity?
    /// Whether the identity is connected to the chat's space.
    var isReachable = true
    /// The time the row's age is measured to; the list passes one for every row.
    var now = Date.now

    @Environment(\.layoutDirection) private var layoutDirection

    private var isUnread: Bool { chat.unreadCount > 0 }
    private var isMentioned: Bool { chat.mentionCount > 0 }

    var body: some View {
        HStack(alignment: .center, spacing: Layout.chatRowMarkSpacing) {
            ChatMark(chat: chat, isReachable: isReachable)
            VStack(alignment: .leading, spacing: 3) {
                HStack(alignment: .firstTextBaseline, spacing: 10) {
                    title
                    Spacer(minLength: 0)
                    time
                }
                HStack(alignment: .center, spacing: 10) {
                    secondLine
                    Spacer(minLength: 0)
                    block
                }
            }
        }
        .padding(.horizontal, Layout.chatRowHorizontalPadding)
        .padding(.vertical, Layout.chatRowVerticalPadding)
        .contentShape(.rect)
        // Each part reads as it shows, with its own spoken form where the text is terse.
        .accessibilityElement(children: .combine)
        .accessibilityValue(accessibilityStatus)
    }

    // MARK: First line

    private var title: some View {
        NameLine(spacing: 7) {
            ChatName(chat: chat)
                .font(Typography.chatName)
                .fontWeight(isUnread ? .semibold : .regular)
                .foregroundStyle(isUnread ? .text : .textSecondary)
            if let identity {
                IdentityChip(identity: identity)
            }
            if !chat.isOnHomeServer {
                Text(terminal: "@" + chat.space.rawValue.leftToRightIsolated)
                    .font(Typography.terminalSmall)
                    .foregroundStyle(.textTertiary)
                    .lineLimit(1)
                    // Hosts differ at the end, such as `…-retro-25` and `…-retro-26`.
                    .truncationMode(.middle)
                    .layoutValue(key: NameLine.IsSuffix.self, value: true)
            }
        }
    }

    /// The time, or `◷` while the newest message is still sending.
    private var time: some View {
        Group {
            if chat.preview?.delivery == .sending {
                Text(verbatim: "◷")
                    .accessibilityLabel(Text("Sending…"))
            } else {
                Text(ChatTime.short(from: chat.lastActivity, to: now))
                    .accessibilityLabel(
                        Text(chat.lastActivity, format: .relative(presentation: .named)))
            }
        }
        .font(Typography.terminalSmall)
        .foregroundStyle(isMentioned ? .mention : isUnread ? .ink : .textTertiary)
        .monospacedDigit()
        .lineLimit(1)
        .fixedSize()
    }

    // MARK: Second line

    @ViewBuilder
    private var secondLine: some View {
        if !chat.typing.isEmpty {
            HStack(spacing: 8) {
                TypingIndicator()
                typingText
                    .font(Typography.chatPreview)
                    .foregroundStyle(.ink)
                    .lineLimit(1)
            }
        } else if !isReachable {
            offlineLine
        } else if let preview = chat.preview {
            previewText(preview)
                .font(Typography.chatPreview)
                .foregroundStyle(isUnread ? .textSecondary : .textTertiary)
                .lineLimit(1)
                .frame(maxWidth: .infinity, alignment: previewAlignment(preview))
        }
    }

    private var typingText: Text {
        guard chat.kind == .room else { return Text("typing") }
        return Self.typingText(chat.typing)
    }

    /// Who is typing, by name: `farah, karim +2 typing`. Empty when no one is.
    static func typingText(_ names: [String]) -> Text {
        switch names.count {
        case 0: return Text(verbatim: "")
        case 1: return Text("\(names[0].isolated) is typing")
        case 2: return Text("\(names[0].isolated) and \(names[1].isolated) are typing")
        default:
            return Text("\(names[0].isolated), \(names[1].isolated) +\(names.count - 2) typing")
        }
    }

    /// The space is unreachable: said on the row itself, where it matters.
    private var offlineLine: some View {
        HStack(spacing: 0) {
            Text("offline")
                .foregroundStyle(.wax)
            if let preview = chat.preview {
                Text(verbatim: " · ")
                    .foregroundStyle(.textTertiary)
                previewText(preview)
                    .foregroundStyle(.textTertiary)
            }
        }
        .font(Typography.chatPreview)
        .lineLimit(1)
    }

    private func previewText(_ preview: Chat.Preview) -> Text {
        // One line: later lines of a message never show in the list.
        let body =
            preview.isDeleted
            ? Text("message deleted")
            : Text(verbatim: oneLine(preview.text).isolated)
        if case .failed = preview.delivery {
            return Text("\(Text("not sent").foregroundStyle(.wax)): \(body)")
        }
        if preview.isOwn {
            return Text("you: \(body)")
        }
        if chat.kind == .direct {
            // The other person's name is the row's title already.
            return body
        }
        return Text("\(Text(verbatim: preview.author.isolated)): \(body)")
    }

    /// A preview with no prefix runs in its own direction, so an Arabic message in
    /// an English list sits on the right; one with a prefix follows the interface.
    private func previewAlignment(_ preview: Chat.Preview) -> Alignment {
        let hasPrefix = preview.isOwn || chat.kind == .room
        guard !hasPrefix, !preview.isDeleted,
            let direction = preview.text.firstStrongDirection, direction != layoutDirection
        else { return .leading }
        return .trailing
    }

    private func oneLine(_ text: String) -> String {
        text.split(whereSeparator: \.isNewline).joined(separator: " ")
    }

    // MARK: Block

    /// A mention outranks a count: one block, `@` on mention, else the unread count.
    @ViewBuilder
    private var block: some View {
        if isMentioned {
            CountBlock(text: Text(verbatim: "@"), fill: .mention)
                .accessibilityLabel(Text("\(chat.mentionCount) mentions"))
        } else if isUnread {
            CountBlock(text: Text(count: chat.unreadCount), fill: .ink)
                .accessibilityLabel(Text("\(chat.unreadCount) unread"))
        }
    }

    private var accessibilityStatus: Text {
        switch (isReachable, identity) {
        case (false, let identity?): Text("Server offline, as \(identity.name)")
        case (false, nil): Text("Server offline")
        case (true, let identity?): Text("as \(identity.name)")
        case (true, nil): Text(verbatim: "")
        }
    }
}

/// A count in inverse colors, so it never runs into the time beside it.
struct CountBlock: View {
    let text: Text
    let fill: Color

    var body: some View {
        text
            .font(Typography.countBlock)
            .foregroundStyle(.onInk)
            .monospacedDigit()
            .padding(.horizontal, 6)
            .padding(.vertical, 1)
            .background(fill, in: RoundedRectangle(cornerRadius: 4))
            .fixedSize()
    }
}

/// `@` in bold when something mentions you, else the unread count; nothing when
/// neither. A lighter mark than `CountBlock`, for results and tabs.
struct UnreadMark: View {
    let mentions: Int
    let unread: Int
    /// What VoiceOver says for the count, such as "3 unread chats".
    let unreadLabel: Text

    var body: some View {
        if mentions > 0 {
            Text(verbatim: "@").fontWeight(.bold).foregroundStyle(.mention)
                .accessibilityLabel(Text("\(mentions) mentions"))
        } else if unread > 0 {
            Text(count: unread)
                .fontWeight(.bold).foregroundStyle(.ink)
                .monospacedDigit()
                .fixedSize()
                .accessibilityLabel(unreadLabel)
        }
    }
}

/// The context menu item that adds a chat or a space to the favourites, or removes it.
struct FavouriteButton: View {
    let isFavourite: Bool
    let toggle: () -> Void

    var body: some View {
        Button(action: toggle) {
            if isFavourite {
                Label("Remove from favourites", systemImage: "star.slash")
            } else {
                Label("Add to favourites", systemImage: "star")
            }
        }
    }
}

/// How long ago something happened, in a row's time column: `now`, `2m`, `1h`, `4d`,
/// `1w`, `11mo`, `2y`, in the person's language.
enum ChatTime {
    private static let formatter: DateComponentsFormatter = {
        let formatter = DateComponentsFormatter()
        formatter.unitsStyle = .abbreviated
        formatter.maximumUnitCount = 1
        formatter.allowedUnits = [.year, .month, .weekOfMonth, .day, .hour, .minute]
        return formatter
    }()

    static func short(from date: Date, to now: Date, calendar: Calendar = .autoupdatingCurrent)
        -> String
    {
        guard now.timeIntervalSince(date) >= 60 else {
            return String(
                localized: "now", comment: "A chat's time when it was active this minute")
        }
        if formatter.calendar != calendar {
            formatter.calendar = calendar
        }
        return formatter.string(from: date, to: now) ?? ""
    }
}

/// The time section a chat falls in, for the list's section lines.
enum ChatSection: Hashable {
    case today, thisWeek, earlier

    init(_ date: Date, now: Date, calendar: Calendar = .current) {
        if calendar.isDate(date, inSameDayAs: now) {
            self = .today
        } else if now.timeIntervalSince(date) < 7 * 86_400 {
            self = .thisWeek
        } else {
            self = .earlier
        }
    }

    var title: Text {
        switch self {
        case .today: Text("today")
        case .thisWeek: Text("this week")
        case .earlier: Text("earlier")
        }
    }
}

/// A chat's name on one line. A person's name is cut at the end; a room's in the
/// middle, since room names often differ only at the end.
struct ChatName: View {
    let chat: Chat

    var body: some View {
        Text(verbatim: chat.name.isolated)
            .lineLimit(1)
            .truncationMode(chat.kind == .room ? .middle : .tail)
    }
}

/// A name, an identity chip, and a host on one line. The name comes first: the host
/// gives way before it, cut in the middle, yet keeps up to `suffixShare` of the line so
/// both of its ends stay readable. The chip never shrinks and stays beside the name.
struct NameLine: SwiftUI.Layout {
    /// Marks the host, the part that gives way first.
    struct IsSuffix: LayoutValueKey {
        static let defaultValue = false
    }

    var spacing: CGFloat
    /// The share of the line the host keeps when the name would take it all.
    var suffixShare: CGFloat = 0.4

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let widths = self.widths(for: proposal.width, subviews: subviews)
        let height = zip(subviews, widths).map { subview, width in
            subview.sizeThatFits(ProposedViewSize(width: width, height: proposal.height)).height
        }
        return CGSize(
            width: widths.reduce(0, +) + spacing * CGFloat(max(subviews.count - 1, 0)),
            height: height.max() ?? 0)
    }

    func placeSubviews(
        in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()
    ) {
        var x = bounds.minX
        for (subview, width) in zip(subviews, widths(for: bounds.width, subviews: subviews)) {
            let size = ProposedViewSize(width: width, height: bounds.height)
            subview.place(at: CGPoint(x: x, y: bounds.midY), anchor: .leading, proposal: size)
            x += width + spacing
        }
    }

    /// The name's baselines, so the time beside the line sits on them.
    func explicitAlignment(
        of guide: VerticalAlignment, in bounds: CGRect, proposal: ProposedViewSize,
        subviews: Subviews, cache: inout ()
    ) -> CGFloat? {
        guard guide == .firstTextBaseline || guide == .lastTextBaseline, let name = subviews.first
        else { return nil }
        let width = widths(for: bounds.width, subviews: subviews)[0]
        let dimensions = name.dimensions(in: ProposedViewSize(width: width, height: bounds.height))
        return bounds.midY - dimensions.height / 2 + dimensions[guide]
    }

    /// Each part's width: the chip as it is, then the name and host as they fit.
    private func widths(for available: CGFloat?, subviews: Subviews) -> [CGFloat] {
        let ideal = subviews.map { $0.sizeThatFits(.unspecified).width }
        guard let available else { return ideal }
        let suffix = subviews.firstIndex { $0[IsSuffix.self] }
        let fixed = subviews.indices.dropFirst().filter { $0 != suffix }
        let room =
            available - fixed.reduce(0) { $0 + ideal[$1] }
            - spacing * CGFloat(max(subviews.count - 1, 0))
        var widths = ideal
        guard let suffix else {
            widths[0] = max(0, min(ideal[0], room))
            return widths
        }
        let left = room - ideal[0]
        let kept = min(ideal[suffix], max(left, room * suffixShare))
        widths[suffix] = max(0, kept)
        widths[0] = max(0, min(ideal[0], room - widths[suffix]))
        return widths
    }
}
