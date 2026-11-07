import SwiftUI

/// The person's appearance choice. Stored in user defaults under `storageKey`,
/// which the iOS Settings bundle writes too, so keep the raw values in sync with
/// `Resources/Settings.bundle/Root.plist`.
enum Appearance: String, CaseIterable, Identifiable {
    case system
    case light
    case dark

    static let storageKey = "appearance"

    var id: Self { self }

    /// `nil` follows the system.
    var colorScheme: ColorScheme? {
        switch self {
        case .system: nil
        case .light: .light
        case .dark: .dark
        }
    }
}
