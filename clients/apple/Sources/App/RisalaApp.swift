import SwiftUI

@main
struct RisalaApp: App {
    /// The one library session, shared by every window; `nil` until librisala is integrated.
    private let client: (any ChatClient)? = nil
    @AppStorage(Appearance.storageKey) private var appearance: Appearance = .system

    var body: some Scene {
        WindowGroup {
            RootView(client: client)
                .preferredColorScheme(appearance.colorScheme)
                #if os(macOS)
                    .frame(minWidth: 640, minHeight: 420)
                    // The title bar blends into the window surface, as in the
                    // mockups; panes carry their own breadcrumb headings.
                    .toolbar(removing: .title)
                    .toolbarBackgroundVisibility(.hidden, for: .windowToolbar)
                    .containerBackground(.surface, for: .window)
                #endif
        }
        .defaultSize(width: 900, height: 600)
        .commands { SidebarCommands() }

        #if os(macOS)
            Settings {
                SettingsView()
                    .preferredColorScheme(appearance.colorScheme)
            }
        #endif
    }
}
