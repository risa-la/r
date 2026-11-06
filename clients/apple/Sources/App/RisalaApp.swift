import SwiftUI

@main
struct RisalaApp: App {
    var body: some Scene {
        WindowGroup {
            RootView()
                #if os(macOS)
                    .frame(minWidth: 640, minHeight: 420)
                #endif
        }
        .defaultSize(width: 900, height: 600)
        .commands { SidebarCommands() }
    }
}
