import SwiftUI

/// Hudhud with a short title and message, centered on the panel, and optional
/// actions below. Use only for empty, first-run, and other rare states; banners
/// and errors stay plain text.
struct HudhudMessage<Actions: View>: View {
    let title: Text
    let message: Text
    @ViewBuilder let actions: Actions

    @ScaledMetric(relativeTo: .body) private var illustrationHeight = Layout.hudhudHeight

    var body: some View {
        VStack(spacing: 0) {
            Image(.hudhud)
                // Pixel art: keep the edges hard when scaling.
                .interpolation(.none)
                .resizable()
                .scaledToFit()
                .frame(height: illustrationHeight)
                .padding(.bottom, Layout.hudhudSpacing)
                .accessibilityHidden(true)
            VStack(spacing: Layout.relatedContentSpacing) {
                title
                    .font(Typography.terminalTitle)
                    .foregroundStyle(.text)
                message
                    .font(Typography.terminal)
                    .foregroundStyle(.textTertiary)
            }
            .textCase(.lowercase)
            .multilineTextAlignment(.center)
            .accessibilityElement(children: .combine)
            actions
                .padding(.top, Layout.hudhudActionsSpacing)
        }
        // A narrow column, so a wide window doesn't stretch the actions.
        .frame(maxWidth: Layout.hudhudColumnWidth)
        .padding(.horizontal, Layout.hudhudMargin)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

extension HudhudMessage where Actions == EmptyView {
    init(title: Text, message: Text) {
        self.init(title: title, message: message, actions: { EmptyView() })
    }
}

#Preview {
    HudhudMessage(
        title: Text("No chats yet"),
        message: Text("Hudhud is holding a letter with nowhere to take it.")
    )
    .terminalPanel()
}
