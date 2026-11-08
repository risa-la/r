import SwiftUI

/// One message on the terminal timeline: the time in a gutter, then the author in
/// their color, the text, and what hangs off it: the message it answers, a file,
/// a thread summary, and reactions. A message that continues its author's group
/// leaves out the name and time.
struct MessageRow: View {
    let message: Message
    /// Whether it follows the same author's message closely; see `TimelineEntry`.
    var continuesGroup = false
    var isBusy = false
    var retry: () -> Void = {}
    var discard: () -> Void = {}

    @Environment(\.layoutDirection) private var layoutDirection

    var body: some View {
        if message.kind == .message {
            HStack(alignment: .firstTextBaseline, spacing: Layout.gutterSpacing) {
                TimeGutter(message: message, showsTime: !continuesGroup)
                VStack(alignment: .leading, spacing: 0) {
                    content
                        .accessibilityElement(children: .combine)
                    if case .failed(let possiblySent) = message.delivery {
                        failure(possiblySent: possiblySent)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            HStack(alignment: .firstTextBaseline, spacing: Layout.gutterSpacing) {
                TimeGutter(message: message, showsTime: true)
                EventLine(message: message)
            }
        }
    }

    private var content: some View {
        VStack(alignment: .leading, spacing: 0) {
            if let reply = message.reply {
                replyLine(reply)
            }
            if continuesGroup {
                // The name shows on the group's first message; VoiceOver still says it.
                Text(verbatim: message.author.isolated)
                    .font(Typography.messageAuthor)
                    .frame(width: 0, height: 0)
                    .clipped()
                    .accessibilityHidden(false)
            } else {
                authorLine
            }
            messageText
            if let attachment = message.attachment {
                AttachmentCard(attachment: attachment)
                    .padding(.top, 6)
            }
            if let thread = message.thread {
                threadLine(thread)
            }
            if !message.reactions.isEmpty {
                ReactionsRow(reactions: message.reactions)
                    .padding(.top, 6)
            }
        }
    }

    // MARK: Lines

    private var authorLine: some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Text(verbatim: message.author.isolated)
                .font(Typography.messageAuthor)
                .foregroundStyle(authorColor)
                .lineLimit(1)
            if message.isGuestAuthor {
                Text("guest")
                    .font(Typography.terminalSmall)
                    .foregroundStyle(.textTertiary)
                    .fixedSize()
            }
        }
    }

    @ViewBuilder
    private var messageText: some View {
        if message.isDeleted {
            Text("This message was deleted.")
                .font(Typography.messageBody.italic())
                .foregroundStyle(.textTertiary)
        } else if let text = message.text, !text.isEmpty {
            // Text that runs against the interface, such as Arabic in an English
            // timeline, sits on its own side.
            let isAgainst = text.firstStrongDirection.map { $0 != layoutDirection } ?? false
            Text(bodyText(text))
                .font(Typography.messageBody)
                .foregroundStyle(message.delivery == .sending ? .textSecondary : .text)
                .multilineTextAlignment(isAgainst ? .trailing : .leading)
                .frame(maxWidth: .infinity, alignment: isAgainst ? .trailing : .leading)
                .textSelection(.enabled)
        }
    }

    /// The text, isolated so its direction can't move the `(edited)` after it.
    private func bodyText(_ text: String) -> AttributedString {
        var body = AttributedString(text.isolated)
        if message.isEdited {
            var edited = AttributedString(
                " " + String(localized: "(edited)", comment: "After a message that was edited"))
            edited.foregroundColor = .textTertiary
            body.append(edited)
        }
        return body
    }

    /// `┌ ~sam: is anyone coming?` on one line above the author.
    private func replyLine(_ reply: Message.Reply) -> some View {
        let quoted =
            reply.text.isEmpty
            ? Text("message deleted")
            : Text(terminal: reply.text.split(whereSeparator: \.isNewline).joined(separator: " "))
        return HStack(alignment: .firstTextBaseline, spacing: 6) {
            Text(verbatim: layoutDirection == .rightToLeft ? "┐" : "┌")
                .accessibilityHidden(true)
            Text("\(Text(terminal: reply.author.isolated)): \(quoted)")
                .lineLimit(1)
                .accessibilityLabel(Text("In reply to \(reply.author.isolated)"))
        }
        .font(Typography.terminalSmall)
        .foregroundStyle(.textTertiary)
    }

    /// `└─ 3 replies · last 15:45`
    private func threadLine(_ thread: Message.Thread) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Text(verbatim: layoutDirection == .rightToLeft ? "─┘" : "└─")
                .accessibilityHidden(true)
            Text(
                "\(thread.replyCount) replies · last \(Text(thread.lastReplyAt, format: .dateTime.hour().minute()))"
            )
            .monospacedDigit()
            .lineLimit(1)
        }
        .font(Typography.terminalSmall)
        .foregroundStyle(.ink)
        .padding(.top, 2)
    }

    private var authorColor: Color {
        if message.isGuestAuthor { return .textSecondary }
        return IdentityChip.tints[authorTintIndex(message.author, count: IdentityChip.tints.count)]
    }

    // MARK: Failure

    /// Said once, on one line, with the two ways out.
    private func failure(possiblySent: Bool) -> some View {
        HStack(spacing: 4) {
            Group {
                if possiblySent {
                    Text("May not have been sent.")
                } else {
                    Text("Not sent.")
                }
            }
            .foregroundStyle(.wax)
            Button(action: retry) {
                Text("Try again").fontWeight(.bold).foregroundStyle(.ink).minimumTouchTarget()
            }
            Button(role: .destructive, action: discard) {
                Text("Remove").foregroundStyle(.textSecondary).minimumTouchTarget()
            }
        }
        .buttonStyle(.plain)
        .font(Typography.terminalSmall)
        .lineLimit(1)
        .disabled(isBusy)
    }
}

/// The time a message was sent, in a column of its own, or `◷` while it is sending.
/// Every gutter is as wide as the widest time, so messages line up.
private struct TimeGutter: View {
    let message: Message
    let showsTime: Bool

    /// A late time in the person's format, as wide as any.
    private static let template = Date(timeIntervalSinceReferenceDate: 22 * 3_600 + 58 * 60)

    var body: some View {
        ZStack(alignment: .leading) {
            Text(Self.template, format: .dateTime.hour().minute())
                .hidden()
            if message.delivery == .sending {
                Text(verbatim: "◷")
                    .accessibilityLabel(Text("Sending…"))
            } else if showsTime {
                Text(message.sentAt, format: .dateTime.hour().minute())
            }
        }
        .font(Typography.timelineTime)
        .foregroundStyle(.textTertiary)
        .monospacedDigit()
        .lineLimit(1)
        .fixedSize()
    }
}

/// An image as a card with its file name and size along the bottom, or another file
/// as one line. The name is cut in the middle, so its extension stays.
private struct AttachmentCard: View {
    let attachment: Message.Attachment

    var body: some View {
        if attachment.isImage {
            image
                .overlay(alignment: .bottom) {
                    caption
                        .foregroundStyle(.white)
                        .padding(.horizontal, 10)
                        .padding(.top, 16)
                        .padding(.bottom, 7)
                        // A shade over the photo, whatever the appearance.
                        .background(
                            LinearGradient(
                                colors: [.black.opacity(0), .black.opacity(0.65)],
                                startPoint: .top, endPoint: .bottom))
                }
                .clipShape(.rect(cornerRadius: Layout.attachmentCornerRadius))
                .overlay {
                    RoundedRectangle(cornerRadius: Layout.attachmentCornerRadius)
                        .strokeBorder(.rule)
                }
                .accessibilityElement(children: .combine)
                .accessibilityAddTraits(.isImage)
        } else {
            caption
                .foregroundStyle(.text)
                .padding(.horizontal, 10)
                .padding(.vertical, 7)
                .frame(maxWidth: Layout.attachmentSize.width)
                .overlay {
                    RoundedRectangle(cornerRadius: Layout.rowCornerRadius).strokeBorder(.rule)
                }
                .accessibilityElement(children: .combine)
        }
    }

    private var image: some View {
        AsyncImage(url: attachment.thumbnail) { image in
            image.resizable().scaledToFill()
        } placeholder: {
            Color.rule
        }
        .frame(width: Layout.attachmentSize.width, height: Layout.attachmentSize.height)
        .clipped()
    }

    private var caption: some View {
        HStack(spacing: 8) {
            Text(terminal: attachment.name)
                .lineLimit(1)
                .truncationMode(.middle)
                .frame(maxWidth: .infinity, alignment: .leading)
            Text(attachment.byteCount, format: .byteCount(style: .file))
                .opacity(0.75)
                .fixedSize()
        }
        .font(Typography.timelineDivider)
    }
}

/// Reactions as chips that wrap; your own are filled with ink and said as selected.
private struct ReactionsRow: View {
    let reactions: [Message.Reaction]

    var body: some View {
        WrappingStack(spacing: 6) {
            ForEach(reactions, id: \.reaction) { reaction in
                HStack(spacing: 6) {
                    Text(terminal: reaction.reaction, bold: true)
                        .fontWeight(.bold)
                        .foregroundStyle(.text)
                    Text(count: reaction.count)
                        .fontWeight(reaction.mine ? .bold : .regular)
                        .foregroundStyle(reaction.mine ? .ink : .textTertiary)
                        .monospacedDigit()
                }
                .font(Typography.terminalSmall)
                .lineLimit(1)
                .padding(.horizontal, 8)
                .frame(minHeight: Layout.reactionHeight)
                .background(
                    reaction.mine ? Color.ink.opacity(0.18) : Color.rule.opacity(0.45),
                    in: .rect(cornerRadius: 8)
                )
                .overlay {
                    RoundedRectangle(cornerRadius: 8)
                        .strokeBorder(reaction.mine ? Color.ink.opacity(0.4) : Color.rule)
                }
                .fixedSize()
                .accessibilityElement(children: .ignore)
                .accessibilityLabel(Text("\(reaction.count) people reacted \(reaction.reaction)"))
                .accessibilityAddTraits(reaction.mine ? .isSelected : [])
            }
        }
    }
}

/// Lays its views out in rows, starting a new row when one would overflow.
private struct WrappingStack: SwiftUI.Layout {
    var spacing: CGFloat

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let rows = rows(for: proposal.width ?? .infinity, subviews: subviews)
        let width = rows.map(\.width).max() ?? 0
        let height =
            rows.map(\.height).reduce(0, +) + spacing * CGFloat(max(rows.count - 1, 0))
        return CGSize(width: width, height: height)
    }

    func placeSubviews(
        in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()
    ) {
        var y = bounds.minY
        for row in rows(for: bounds.width, subviews: subviews) {
            var x = bounds.minX
            for index in row.indices {
                let size = subviews[index].sizeThatFits(.unspecified)
                subviews[index].place(
                    at: CGPoint(x: x, y: y + (row.height - size.height) / 2), anchor: .topLeading,
                    proposal: ProposedViewSize(size))
                x += size.width + spacing
            }
            y += row.height + spacing
        }
    }

    private struct Row {
        var indices: [Int] = []
        var width: CGFloat = 0
        var height: CGFloat = 0
    }

    private func rows(for available: CGFloat, subviews: Subviews) -> [Row] {
        var rows: [Row] = []
        var current = Row()
        for index in subviews.indices {
            let size = subviews[index].sizeThatFits(.unspecified)
            let needed = current.indices.isEmpty ? size.width : current.width + spacing + size.width
            if needed > available, !current.indices.isEmpty {
                rows.append(current)
                current = Row()
            }
            current.width =
                current.indices.isEmpty ? size.width : current.width + spacing + size.width
            current.height = max(current.height, size.height)
            current.indices.append(index)
        }
        if !current.indices.isEmpty { rows.append(current) }
        return rows
    }
}

/// A join, part, or other event that is not a message: one muted line.
private struct EventLine: View {
    let message: Message

    var body: some View {
        description
            .font(Typography.terminalSmall)
            .foregroundStyle(.textTertiary)
            .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var description: Text {
        let author = message.author.isolated
        let subject = (message.subject ?? "").isolated
        switch message.kind {
        case .join: return Text("\(author) joined")
        case .part: return Text("\(author) left")
        case .invite: return Text("\(author) invited \(subject)")
        case .kick: return Text("\(author) removed \(subject)")
        case .ban: return Text("\(author) banned \(subject)")
        case .unban: return Text("\(author) unbanned \(subject)")
        case .setting: return Text("\(author) changed the room settings")
        case .role: return Text("\(author) changed the role of \(subject)")
        case .message, .other: return Text("\(author) did something this app cannot show yet")
        }
    }
}
