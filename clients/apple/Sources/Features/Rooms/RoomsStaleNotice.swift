import SwiftUI

/// Says the rooms shown may be out of date and offers to follow them again. Plain
/// text that leaves the rooms usable; it wraps under narrow widths and large text.
struct RoomsStaleNotice: View {
    let retry: () -> Void

    var body: some View {
        ViewThatFits(in: .horizontal) {
            HStack(alignment: .firstTextBaseline, spacing: Layout.inlineSpacing) {
                message
                tryAgain
            }
            VStack(alignment: .leading, spacing: Layout.relatedContentSpacing) {
                message
                tryAgain
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .contain)
    }

    private var message: some View {
        Label {
            Text("Rooms may be out of date.")
                .fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: "exclamationmark.triangle")
        }
        .font(Typography.terminal)
        .foregroundStyle(.textSecondary)
    }

    // Underlined as well as bold, so it reads as an action without relying on color.
    private var tryAgain: some View {
        Button(action: retry) {
            Text("Try again")
                .font(Typography.terminalEmphasis)
                .underline()
                .foregroundStyle(.text)
                #if os(iOS)
                    .frame(minHeight: Layout.minimumTouchTarget)
                #endif
                .contentShape(.rect)
        }
        .buttonStyle(.borderless)
        .tint(.text)
    }
}

#Preview("English") {
    RoomsStaleNotice {}
        .padding()
        .terminalPanel()
}

#Preview("Arabic · Accessibility text") {
    RoomsStaleNotice {}
        .padding()
        .terminalPanel()
        .environment(\.locale, Locale(identifier: "ar"))
        .environment(\.layoutDirection, .rightToLeft)
        .environment(\.dynamicTypeSize, .accessibility3)
}
