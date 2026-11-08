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
            // Each ringed in the window's surface so the edges read.
            IdentityStack(
                identities: model.spaces.identities.sorted { $0.isMain && !$1.isMain },
                size: .window, ring: .surface
            )
            .fixedSize()
            // Empty states show no tabs.
            if !model.hasNoChats, model.state != .disconnected {
                SpaceTabs(
                    spaces: model.spaces, selection: $model.filter.space, showAll: showAll,
                    toggleFavourite: model.toggleFavourite,
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
