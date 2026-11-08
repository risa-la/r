import SwiftUI

struct RoomRow: View {
    let room: Room

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: Layout.rowGlyphSpacing) {
            Glyph(symbol: "#")
            VStack(alignment: .leading, spacing: 0) {
                Text(room.name)
                    .font(Typography.terminalEmphasis)
                    .foregroundStyle(.text)
                if !room.topic.isEmpty {
                    Text(room.topic)
                        .font(Typography.terminal)
                        .foregroundStyle(.textTertiary)
                }
            }
            .lineLimit(1)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(Layout.rowPadding)
        .contentShape(.rect)
        .accessibilityElement(children: .combine)
    }
}
