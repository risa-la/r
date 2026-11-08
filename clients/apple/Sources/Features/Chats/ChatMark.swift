import SwiftUI

/// A chat's mark at the start of its row: a rounded square with `#` for rooms, a circle
/// with an initial for people. A dashed outline in wax means the space is offline; a
/// dot means the person is connected. It is decorative; the row's text says the same.
struct ChatMark: View {
    let chat: Chat
    var isReachable = true
    /// The size of a large identity chip, for command line results, rather than a row's.
    var isSmall = false

    @ScaledMetric(relativeTo: .body) private var largeSize = Layout.markSize
    @ScaledMetric(relativeTo: .body) private var largeCornerRadius = Layout.markCornerRadius
    @ScaledMetric(relativeTo: .caption2) private var smallSize = Layout.chipSizeLarge
    @ScaledMetric(relativeTo: .caption2) private var smallCornerRadius =
        Layout.markCornerRadiusSmall

    private var size: CGFloat { isSmall ? smallSize : largeSize }

    var body: some View {
        Group {
            switch chat.kind {
            case .room:
                mark(
                    in: RoundedRectangle(
                        cornerRadius: isSmall ? smallCornerRadius : largeCornerRadius))
            case .direct: mark(in: Circle())
            }
        }
        .overlay(alignment: .bottomTrailing) {
            if chat.isOnline == true, !isSmall {
                Circle()
                    .fill(.presence)
                    .frame(width: size / 4, height: size / 4)
                    .overlay { Circle().strokeBorder(.surface, lineWidth: 2) }
                    .offset(x: 1, y: 1)
            }
        }
        .accessibilityHidden(true)
    }

    private func mark(in shape: some InsettableShape) -> some View {
        Text(verbatim: Self.symbol(for: chat))
            .font(isSmall ? Typography.countBlock : Typography.markLarge)
            .foregroundStyle(isReachable ? tint : .wax)
            .lineLimit(1)
            .minimumScaleFactor(0.5)
            .frame(width: size, height: size)
            .background(isReachable ? tint.opacity(0.18) : .clear, in: shape)
            .overlay {
                if !isReachable {
                    shape.strokeBorder(Color.wax.opacity(0.6), style: StrokeStyle(dash: [3, 3]))
                }
            }
    }

    /// `#` for a room; for a person, the first letter of their name, else its first
    /// emoji, else `?`.
    nonisolated static func symbol(for chat: Chat) -> String {
        switch chat.kind {
        case .room: "#"
        case .direct: chat.name.initial ?? "?"
        }
    }

    /// Rooms are ink; each person has a tint that is the same on every launch.
    private var tint: Color {
        guard chat.kind == .direct else { return .ink }
        let tints: [Color] = [.ink, .wax, .location, .presence, .mode, .mention]
        // FNV-1a: Hasher is seeded per launch.
        var hash: UInt64 = 0xcbf2_9ce4_8422_2325
        for byte in chat.id.rawValue.utf8 {
            hash = (hash ^ UInt64(byte)) &* 0x100_0000_01b3
        }
        return tints[Int(hash % UInt64(tints.count))]
    }
}
