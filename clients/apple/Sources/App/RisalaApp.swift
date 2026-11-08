import SwiftUI

@main
struct RisalaApp: App {
    /// The one library session, shared by every window; `nil` until librisala is integrated.
    private let client: (any ChatClient)?
    @AppStorage(Appearance.storageKey) private var appearance: Appearance = .system

    init() {
        #if DEBUG
            client = PreviewChatClient.fromLaunchArguments()
        #else
            client = nil
        #endif
    }

    var body: some Scene {
        WindowGroup {
            RootView(client: client)
                .preferredColorScheme(appearance.colorScheme)
                #if os(macOS)
                    // Wide enough for the chat list pane beside a chat pane.
                    .frame(
                        minWidth: Layout.listPaneWidth + Layout.chatPaneMinWidth
                            + Layout.paneGap * 3,
                        minHeight: 480
                    )
                    .containerBackground(.surface, for: .window)
                #endif
        }
        #if os(macOS)
            // The space tabs share the title bar with the window buttons.
            .windowStyle(.hiddenTitleBar)
        #endif
        .defaultSize(width: 1280, height: 800)
        .commands { ChatCommands() }

        #if os(macOS)
            Settings {
                SettingsView()
                    .preferredColorScheme(appearance.colorScheme)
            }
        #endif
    }
}
