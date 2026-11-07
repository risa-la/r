import SwiftUI

/// The heading of a terminal panel: the app name, then where you are.
struct Breadcrumb: View {
    let location: Text

    var body: some View {
        HStack(spacing: Layout.inlineSpacing) {
            Text("Risala")
                .font(Typography.terminalEmphasis)
                .foregroundStyle(.mode)
            Text(verbatim: "/")
                .font(Typography.terminal)
                .foregroundStyle(.rule)
                .accessibilityHidden(true)
            location
                .font(Typography.terminalEmphasis)
                .foregroundStyle(.location)
                .lineLimit(1)
        }
        .textCase(.lowercase)
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isHeader)
    }
}

#Preview {
    Breadcrumb(location: Text("Chats"))
        .padding()
        .terminalPanel()
}
