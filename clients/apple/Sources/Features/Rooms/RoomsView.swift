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
        withHeader {
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
    private func withHeader(@ContentBuilder _ content: () -> some View) -> some View {
        if #available(iOS 26, macOS 26, *) {
            content().safeAreaBar(edge: .top, spacing: 0) { header }
        } else {
            content().safeAreaInset(edge: .top, spacing: 0) {
                header.background(.panel)
            }
        }
    }

    /// The breadcrumb, then a notice while the rooms may be out of date.
    private var header: some View {
        VStack(alignment: .leading, spacing: 0) {
            Breadcrumb(location: Text("Chats"))
                .padding(.top, Layout.panelContentPadding)
                .padding(.bottom, Layout.inlineSpacing)
            if model.isStale {
                RoomsStaleNotice(retry: retry)
                    .padding(.bottom, Layout.inlineSpacing)
            }
        }
        .padding(.horizontal, Layout.panelContentPadding)
    }
}
