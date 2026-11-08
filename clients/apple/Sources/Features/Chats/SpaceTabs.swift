import SwiftUI

/// The chat list's tabs: `all`, then favourite spaces, a divider, the other spaces,
/// and a last tab that opens every space. The strip scrolls sideways; when spaces
/// with mentions are scrolled out of view, a pinned `@ n ›` brings the next one in.
struct SpaceTabs: View {
    let spaces: Spaces
    @Binding var selection: Space.ID?
    let showAll: () -> Void
    let toggleFavourite: (Space) -> Void
    /// Room above and below the strip; by default, what the platform's tabs need.
    var verticalPadding: CGFloat? = nil
    /// Keeps the tab that opens every space at the trailing end instead of after the
    /// last tab, where a wide window has room for it.
    var pinsEverySpaceTab = false

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    /// The tabs at least mostly in view. Empty until the strip first reports, which
    /// `isMeasured` tells apart from every tab being out of view.
    @State private var visible: Set<Space.ID> = []
    @State private var isMeasured = false
    /// Which ends of the strip have tabs beyond them, to fade only those.
    @State private var overflow = Overflow()

    private struct Overflow: Equatable {
        var leading = false
        var trailing = false
    }

    private var favourites: [Space] { spaces.spaces.filter(\.isFavourite) }
    private var others: [Space] { spaces.spaces.filter { !$0.isFavourite } }

    /// Spaces with mentions that are scrolled out of view, in tab order.
    private var hiddenMentions: [Space] {
        guard isMeasured else { return [] }
        return (favourites + others).filter { $0.mentions > 0 && !visible.contains($0.id) }
    }

    /// Fades in and out of the strip's ends, so a cut-off tab reads as more to scroll.
    private static let fadeWidth: CGFloat = 28

    var body: some View {
        ScrollViewReader { proxy in
            HStack(spacing: 4) {
                ScrollView(.horizontal) {
                    HStack(spacing: 2) {
                        allTab
                        ForEach(favourites) { tab($0) }
                        if !favourites.isEmpty && !others.isEmpty {
                            Rectangle()
                                .fill(.rule)
                                .frame(width: 1, height: 18)
                                .padding(.horizontal, 6)
                                .accessibilityHidden(true)
                        }
                        ForEach(others) { tab($0) }
                        if !pinsEverySpaceTab { everySpaceTab }
                    }
                    .padding(.horizontal, 12)
                }
                .scrollIndicators(.hidden)
                .onScrollGeometryChange(for: Overflow.self) { geometry in
                    let offset = geometry.contentOffset.x + geometry.contentInsets.leading
                    let end =
                        geometry.contentSize.width + geometry.contentInsets.leading
                        + geometry.contentInsets.trailing - geometry.containerSize.width
                    return Overflow(leading: offset > 1, trailing: offset < end - 1)
                } action: { _, new in
                    overflow = new
                }
                .mask { fadeMask }
                if let next = hiddenMentions.first {
                    Button {
                        withAnimation(scrollAnimation) { proxy.scrollTo(next.id, anchor: .center) }
                    } label: {
                        HStack(spacing: 4) {
                            Text("@ \(Text(count: hiddenMentions.count))")
                                .fontWeight(.bold)
                                .monospacedDigit()
                            ForwardChevron()
                        }
                        .font(Typography.terminal)
                        .foregroundStyle(.mention)
                        .padding(.horizontal, 9)
                        .padding(.vertical, 6)
                        .background(Color.mention.opacity(0.18), in: .rect(cornerRadius: 8))
                        .minimumTouchTarget()
                    }
                    .buttonStyle(.plain)
                    .padding(.trailing, 12)
                    .accessibilityLabel(Text("\(hiddenMentions.count) more spaces mention you"))
                }
                if pinsEverySpaceTab {
                    everySpaceTab.fixedSize().padding(.trailing, 8)
                }
            }
            .padding(.vertical, verticalPadding ?? Self.stripPadding)
            // A space chosen from the spaces page may be scrolled out of view.
            .onChange(of: selection) {
                if let selection {
                    withAnimation(scrollAnimation) { proxy.scrollTo(selection, anchor: .center) }
                }
            }
        }
    }

    /// Opaque where the strip ends, clear at an end with more tabs beyond it. Leading
    /// and trailing follow the layout direction.
    private var fadeMask: some View {
        HStack(spacing: 0) {
            LinearGradient(
                colors: [overflow.leading ? .clear : .black, .black], startPoint: .leading,
                endPoint: .trailing
            )
            .frame(width: Self.fadeWidth)
            Color.black
            LinearGradient(
                colors: [.black, overflow.trailing ? .clear : .black], startPoint: .leading,
                endPoint: .trailing
            )
            .frame(width: Self.fadeWidth)
        }
    }

    /// Scrolling the strip jumps under Reduce Motion.
    private var scrollAnimation: Animation? {
        reduceMotion ? nil : .default
    }

    /// The tabs grow to the touch target on iOS, so the strip needs less padding there.
    private static var stripPadding: CGFloat {
        #if os(iOS)
            0
        #else
            8
        #endif
    }

    private var allTab: some View {
        let unreadChats = spaces.spaces.reduce(0) { $0 + $1.unreadChats }
        let mentions = spaces.spaces.reduce(0) { $0 + $1.mentions }
        return tabButton(isSelected: selection == nil) {
            selection = nil
        } label: {
            HStack(spacing: 6) {
                Text("all")
                counts(unreadChats: unreadChats, mentions: mentions)
            }
        }
        .accessibilityValue(countsValue(unreadChats: unreadChats, mentions: mentions))
    }

    private func tab(_ space: Space) -> some View {
        tabButton(isSelected: selection == space.id) {
            selection = space.id
        } label: {
            HStack(spacing: 6) {
                if let identity = spaces.identity(space.identity) {
                    IdentityChip(identity: identity)
                }
                Text(terminal: space.shortName)
                    .lineLimit(1)
                    .foregroundStyle(
                        !space.isReachable ? .wax : space.isFavourite ? .text : .textTertiary)
                counts(unreadChats: space.unreadChats, mentions: space.mentions)
            }
        }
        .id(space.id)
        .onScrollVisibilityChange(threshold: 0.8) { isVisible in
            isMeasured = true
            if isVisible { visible.insert(space.id) } else { visible.remove(space.id) }
        }
        .contextMenu {
            FavouriteButton(isFavourite: space.isFavourite) { toggleFavourite(space) }
        }
        .accessibilityValue(tabValue(space))
    }

    /// Hidden from VoiceOver, which reads `countsValue` instead.
    private func counts(unreadChats: Int, mentions: Int) -> some View {
        UnreadMark(mentions: mentions, unread: unreadChats, unreadLabel: Text(verbatim: ""))
            .accessibilityHidden(true)
    }

    /// What `counts` shows, in words: VoiceOver reads a bare `@` as "at".
    private func countsValue(unreadChats: Int, mentions: Int) -> Text {
        if mentions > 0 { return Text("\(mentions) mentions") }
        if unreadChats > 0 { return Text("\(unreadChats) unread chats") }
        return Text(verbatim: "")
    }

    private func tabValue(_ space: Space) -> Text {
        let counts = countsValue(unreadChats: space.unreadChats, mentions: space.mentions)
        guard !space.isReachable else { return counts }
        return space.mentions > 0 || space.unreadChats > 0
            ? Text("Server offline, \(counts)") : Text("Server offline")
    }

    private var everySpaceTab: some View {
        Button(action: showAll) {
            HStack(spacing: 6) {
                Text("\(spaces.spaces.count) spaces")
                    .monospacedDigit()
                ForwardChevron().foregroundStyle(.textTertiary)
            }
            .font(Typography.terminal)
            .foregroundStyle(.ink)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .overlay { RoundedRectangle(cornerRadius: 8).strokeBorder(.rule) }
            .minimumTouchTarget()
            .padding(.leading, 4)
        }
        .buttonStyle(.plain)
    }

    private func tabButton(
        isSelected: Bool, action: @escaping () -> Void,
        @ViewBuilder label: () -> some View
    ) -> some View {
        Button(action: action) {
            label()
                .font(Typography.terminal)
                .fontWeight(isSelected ? .bold : .regular)
                .foregroundStyle(isSelected ? .location : .textSecondary)
                .padding(.horizontal, 10)
                .padding(.vertical, 6)
                .background(
                    isSelected ? Color.location.opacity(0.18) : .clear, in: .rect(cornerRadius: 8)
                )
                .minimumTouchTarget()
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(isSelected ? .isSelected : [])
    }
}
