import SwiftUI

/// The small mark at the start of a row: a symbol for rooms, an initial for people.
/// It is decorative; the row's text names the room or person.
struct Glyph: View {
    enum Kind {
        /// A rounded square.
        case room
        /// A circle.
        case person
    }

    enum Status {
        case normal
        /// The server is unreachable; drawn dashed in wax.
        case offline
        /// A guest without an identity; drawn dashed and unfilled.
        case guest
    }

    let symbol: String
    var kind: Kind = .room
    var status: Status = .normal
    var tint: Color = .ink

    @ScaledMetric(relativeTo: .caption2) private var size = Layout.glyphSize

    var body: some View {
        switch kind {
        case .room: mark(in: RoundedRectangle(cornerRadius: Layout.glyphCornerRadius))
        case .person: mark(in: Circle())
        }
    }

    private func mark(in shape: some InsettableShape) -> some View {
        Text(verbatim: symbol)
            .font(Typography.glyph)
            .foregroundStyle(foreground)
            .lineLimit(1)
            .minimumScaleFactor(0.5)
            .frame(width: size, height: size)
            .background(fill, in: shape)
            .overlay {
                if status != .normal {
                    shape.strokeBorder(foreground.opacity(0.6), style: StrokeStyle(dash: [2, 2]))
                }
            }
            .accessibilityHidden(true)
    }

    private var foreground: Color {
        switch status {
        case .normal: tint
        case .offline: .wax
        case .guest: .textTertiary
        }
    }

    private var fill: Color {
        switch status {
        case .normal: tint.opacity(0.18)
        case .offline: .wax.opacity(0.1)
        case .guest: .clear
        }
    }
}

#Preview {
    HStack {
        Glyph(symbol: "#")
        Glyph(symbol: "#", status: .offline)
        Glyph(symbol: "O", kind: .person)
        Glyph(symbol: "S", kind: .person, status: .guest)
    }
    .padding()
    .terminalPanel()
}
