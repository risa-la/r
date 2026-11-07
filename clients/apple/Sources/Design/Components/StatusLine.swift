import SwiftUI

/// The line along the bottom of a terminal panel: the current mode, what you are
/// looking at, and one count that matters, like a vim status line.
struct StatusLine<Context: View, Trailing: View>: View {
    let mode: Text
    @ViewBuilder let context: Context
    @ViewBuilder let trailing: Trailing

    @ScaledMetric(relativeTo: .caption) private var height = Layout.statusLineHeight

    var body: some View {
        VStack(spacing: 0) {
            Divider().overlay(.rule)
            HStack(spacing: 0) {
                mode
                    .font(Typography.modeBadge)
                    .textCase(.uppercase)
                    .foregroundStyle(.onMode)
                    .padding(.horizontal, Layout.modeBadgePadding)
                    .padding(.vertical, 2)
                    .background(
                        .mode, in: RoundedRectangle(cornerRadius: Layout.modeBadgeCornerRadius))
                context
                    .font(Typography.statusLine)
                    .foregroundStyle(.textTertiary)
                    .lineLimit(1)
                    .padding(.horizontal, Layout.modeBadgePadding)
                    .frame(maxWidth: .infinity, alignment: .leading)
                trailing
                    .font(Typography.statusLine.weight(.bold))
                    .foregroundStyle(.ink)
                    .lineLimit(1)
                    .padding(.horizontal, Layout.modeBadgePadding)
            }
            .padding(.leading, Layout.inlineSpacing)
            .padding(.trailing, Layout.relatedContentSpacing)
            .frame(minHeight: height)
        }
        .accessibilityElement(children: .combine)
    }
}

extension StatusLine where Trailing == EmptyView {
    init(mode: Text, @ViewBuilder context: () -> Context) {
        self.init(mode: mode, context: context, trailing: { EmptyView() })
    }
}

#Preview {
    VStack {
        Spacer()
        StatusLine(mode: Text(verbatim: "normal")) {
            Text(verbatim: "~layla · 8 rooms")
        } trailing: {
            Text(verbatim: "3 unread")
        }
    }
    .terminalPanel()
}
