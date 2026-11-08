import SwiftUI

struct RoomsView: View {
    #if os(iOS)
        @Environment(\.horizontalSizeClass) private var horizontalSizeClass
    #endif
    let model: RoomsViewModel
    @Binding var selection: Room.ID?
    let showsStatus: Bool
    let retry: () -> Void

    var body: some View {
        withBreadcrumb {
            if showsStatus && model.rooms.isEmpty {
                RoomsStatusView(state: model.state, retry: retry)
            } else {
                List(selection: $selection) {
                    ForEach(model.rooms) { room in
                        RoomRow(room: room)
                            .tag(room.id)
                            .listRowInsets(
                                EdgeInsets(
                                    top: 1, leading: Layout.panelInset,
                                    bottom: 1, trailing: Layout.panelInset)
                            )
                            .listRowSeparator(.hidden)
                            .listRowBackground(Color.clear)
                    }
                }
                .listStyle(.plain)
                .scrollContentBackground(.hidden)
            }
        }
        .terminalPanel()
        .navigationTitle("Chats")
        .toolbarTitleDisplayMode(.inline)
        #if os(iOS)
            // The breadcrumb names the screen on iPhone; iPad keeps its sidebar controls.
            .toolbarVisibility(
                horizontalSizeClass == .compact ? .hidden : .automatic, for: .navigationBar)
        #endif
    }

    @ContentBuilder
    private func withBreadcrumb(@ContentBuilder _ content: () -> some View) -> some View {
        if #available(iOS 26, macOS 26, *) {
            content().safeAreaBar(edge: .top, spacing: 0) { breadcrumb }
        } else {
            content().safeAreaInset(edge: .top, spacing: 0) {
                breadcrumb.background(.panel)
            }
        }
    }

    private var breadcrumb: some View {
        Breadcrumb(location: Text("Chats"))
            .padding(.horizontal, Layout.panelContentPadding)
            .padding(.top, Layout.panelContentPadding)
            .padding(.bottom, Layout.inlineSpacing)
    }
}
