import SwiftUI

/// One of the person's identities: its initial in the identity's tint, or a dashed `~`
/// for guest names. The same chip marks rows, tabs, the spaces page, and the mode bar,
/// so "which of you" always looks the same. It is decorative; text around it says the
/// same for VoiceOver.
struct IdentityChip: View {
    enum Size {
        /// In rows and tabs.
        case small
        /// In the mode bar and the composer.
        case large
        /// In a large window's top bar.
        case window
    }

    let identity: Identity
    var size = Size.small

    @ScaledMetric(relativeTo: .caption2) private var smallSize = Layout.chipSize
    @ScaledMetric(relativeTo: .caption2) private var largeSize = Layout.chipSizeLarge
    @ScaledMetric(relativeTo: .caption2) private var windowSize = Layout.chipSizeTopBar

    init(identity: Identity, isLarge: Bool = false) {
        self.identity = identity
        self.size = isLarge ? .large : .small
    }

    init(identity: Identity, size: Size) {
        self.identity = identity
        self.size = size
    }

    /// Identity tints, by `Identity.tint`; each pairs with its own text in the chip.
    static let tints: [Color] = [.wax, .mode, .location, .presence, .mention, .ink]

    var body: some View {
        let side =
            switch size {
            case .small: smallSize
            case .large: largeSize
            // A guest chip is a little smaller, so the solid chips lead.
            case .window: identity.isGuest ? windowSize - 4 : windowSize
            }
        Text(verbatim: symbol)
            .font(size == .small ? Typography.chip : Typography.countBlock)
            .foregroundStyle(identity.isGuest ? Color.textSecondary : tint)
            .lineLimit(1)
            .minimumScaleFactor(0.5)
            .frame(width: side, height: side)
            .background {
                if !identity.isGuest {
                    Circle().fill(tint.opacity(0.2))
                }
            }
            .overlay {
                if identity.isGuest {
                    Circle().strokeBorder(Color.textTertiary, style: StrokeStyle(dash: [2, 2]))
                }
            }
            .accessibilityHidden(true)
    }

    private var symbol: String {
        if identity.isGuest { return "~" }
        return identity.name.initial ?? "?"
    }

    private var tint: Color {
        Self.tints[Self.tintIndex(for: identity.tint)]
    }

    /// The palette index for any `Identity.tint`; `magnitude`, since `abs` traps on
    /// `Int.min`.
    static func tintIndex(for tint: Int) -> Int {
        Int(tint.magnitude % UInt(tints.count))
    }
}

/// The person's identities, overlapping in the order given, the first in front, each
/// ringed in `ring` so the edges read.
struct IdentityStack: View {
    let identities: [Identity]
    let size: IdentityChip.Size
    let ring: Color

    var body: some View {
        HStack(spacing: size == .window ? -8 : -7) {
            ForEach(Array(identities.enumerated()), id: \.element.id) { index, identity in
                IdentityChip(identity: identity, size: size)
                    .background(Circle().fill(ring).padding(-2))
                    .zIndex(Double(identities.count - index))
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(identities.map(\.name).formatted(.list(type: .and))))
    }
}
