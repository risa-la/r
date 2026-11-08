import SwiftUI

/// The bar across a large window: the person's identities, then the space tabs as
/// on the phone. On the Mac it shares the title bar with the window buttons.
struct TopBar: View {
    @Bindable var model: ChatsViewModel
    /// Opens the spaces page.
    let showAll: () -> Void
    /// Room at the leading end for the Mac's window buttons.
    var leadingInset: CGFloat = 0
    var height = Layout.topBarHeight

    var body: some View {
        HStack(spacing: 12) {
            IdentityStack(identities: model.spaces.identities.sorted { $0.isMain && !$1.isMain })
            // Empty states show no tabs.
            if !model.hasNoChats, model.state != .disconnected {
                SpaceTabs(
                    spaces: model.spaces,
                    selection: $model.filter.space,
                    allUnread: model.spaces.spaces.reduce(0) { $0 + $1.unreadChats },
                    allMentions: model.spaces.spaces.reduce(0) { $0 + $1.mentions },
                    showAll: showAll,
                    toggleFavourite: { space in
                        Task { await model.setFavourite(!space.isFavourite, space: space) }
                    },
                    // The bar sets its own height.
                    verticalPadding: 0,
                    pinsEverySpaceTab: true
                )
            } else {
                Spacer(minLength: 0)
            }
        }
        .padding(.leading, 32 + leadingInset)
        .padding(.trailing, 4)
        .frame(minHeight: height)
    }
}

/// The person's identities, overlapping, the main identity in front, each ringed in
/// the window's surface so the edges read.
private struct IdentityStack: View {
    let identities: [Identity]

    var body: some View {
        HStack(spacing: -8) {
            ForEach(Array(identities.enumerated()), id: \.element.id) { index, identity in
                IdentityChip(identity: identity, size: .window)
                    .background(Circle().fill(.surface).padding(-2))
                    .zIndex(Double(identities.count - index))
            }
        }
        .fixedSize()
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(identities.map(\.name).formatted(.list(type: .and))))
    }
}
