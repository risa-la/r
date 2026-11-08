import SwiftUI

struct MessageRow: View {
    let message: Message
    var isBusy = false
    var retry: () -> Void = {}
    var discard: () -> Void = {}

    var body: some View {
        if message.kind == .message {
            VStack(alignment: .leading, spacing: Layout.relatedContentSpacing) {
                content
                    .accessibilityElement(children: .combine)
                if case .failed(let possiblySent) = message.delivery {
                    failure(possiblySent: possiblySent)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        } else {
            EventLine(message: message)
        }
    }

    private var content: some View {
        VStack(alignment: .leading, spacing: Layout.relatedContentSpacing) {
            ViewThatFits(in: .horizontal) {
                HStack { header }
                VStack(alignment: .leading) { header }
            }
            if message.isDeleted {
                Text("This message was deleted.")
                    .font(Typography.messageBody.italic())
                    .foregroundStyle(Colors.supportingContent)
            } else {
                Text(message.text ?? "")
                    .font(Typography.messageBody)
                    .foregroundStyle(Colors.content)
                    .textSelection(.enabled)
            }
            if !message.reactions.isEmpty {
                ReactionsRow(reactions: message.reactions)
            }
            if message.delivery == .sending {
                Label("Sending…", systemImage: "clock")
                    .font(Typography.messageMetadata)
                    .foregroundStyle(Colors.supportingContent)
            }
        }
    }

    @ViewBuilder
    private var header: some View {
        Text(message.author).font(Typography.messageAuthor)
        Text(message.sentAt, style: .time).font(Typography.messageMetadata)
            .foregroundStyle(Colors.supportingContent)
        if message.isEdited && !message.isDeleted {
            Text("edited").font(Typography.messageMetadata)
                .foregroundStyle(Colors.supportingContent)
        }
    }

    private func failure(possiblySent: Bool) -> some View {
        ViewThatFits(in: .horizontal) {
            HStack { failureContent(possiblySent: possiblySent) }
            VStack(alignment: .leading) { failureContent(possiblySent: possiblySent) }
        }
        .font(Typography.messageMetadata)
        .disabled(isBusy)
    }

    @ViewBuilder
    private func failureContent(possiblySent: Bool) -> some View {
        Label {
            if possiblySent {
                Text("May not have been sent.")
            } else {
                Text("Not sent.")
            }
        } icon: {
            Image(systemName: "exclamationmark.circle")
        }
        .foregroundStyle(Colors.failure)
        Button("Try again", action: retry)
        Button("Remove", role: .destructive, action: discard)
    }
}

private struct ReactionsRow: View {
    let reactions: [Message.Reaction]

    var body: some View {
        HStack(spacing: Layout.relatedContentSpacing) {
            ForEach(reactions, id: \.reaction) { reaction in
                HStack(spacing: 2) {
                    Text(verbatim: reaction.reaction)
                    Text(reaction.count, format: .number)
                }
                .font(Typography.messageMetadata)
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(.quaternary, in: .capsule)
                .overlay {
                    // The account's own reaction is outlined, not only tinted.
                    if reaction.mine {
                        Capsule().strokeBorder(.tint)
                    }
                }
                .accessibilityElement(children: .ignore)
                .accessibilityLabel(Text("\(reaction.count) people reacted \(reaction.reaction)"))
                .accessibilityAddTraits(reaction.mine ? .isSelected : [])
            }
        }
    }
}

/// A join, part, or other event that is not a message: one muted line.
private struct EventLine: View {
    let message: Message

    var body: some View {
        description
            .font(Typography.messageMetadata)
            .foregroundStyle(Colors.supportingContent)
            .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var description: Text {
        let author = message.author
        let subject = message.subject ?? ""
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
