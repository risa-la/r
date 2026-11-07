import SwiftUI

/// The macOS Settings window. On iOS the same preferences live in the system
/// Settings app, through `Resources/Settings.bundle`.
struct SettingsView: View {
    @AppStorage(Appearance.storageKey) private var appearance: Appearance = .system

    var body: some View {
        Form {
            Picker("Appearance", selection: $appearance) {
                Text("System").tag(Appearance.system)
                Text("Light").tag(Appearance.light)
                Text("Dark").tag(Appearance.dark)
            }
        }
        .formStyle(.grouped)
        .frame(width: 420)
        .fixedSize(horizontal: false, vertical: true)
    }
}
