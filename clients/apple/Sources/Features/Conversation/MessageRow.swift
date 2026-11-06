import SwiftUI

struct MessageRow: View {
    let message: Message

    var body: some View {
        VStack(alignment: .leading, spacing: Layout.relatedContentSpacing) {
            ViewThatFits(in: .horizontal) {
                HStack {
                    Text(message.author).font(Typography.messageAuthor)
                    Text(message.sentAt, style: .time).font(Typography.messageMetadata)
                        .foregroundStyle(Colors.supportingContent)
                }
                VStack(alignment: .leading) {
                    Text(message.author).font(Typography.messageAuthor)
                    Text(message.sentAt, style: .time).font(Typography.messageMetadata)
                        .foregroundStyle(Colors.supportingContent)
                }
            }
            Text(message.text)
                .font(Typography.messageBody)
                .foregroundStyle(Colors.content)
                .textSelection(.enabled)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
    }
}
