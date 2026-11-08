import SwiftUI

/// The person's appearance choice. Stored in user defaults under `storageKey`,
/// which the iOS Settings bundle writes too, so keep the raw values in sync with
/// `Resources/Settings.bundle/Root.plist`.
enum Appearance: String {
    case system
    case light
    case dark

    static let storageKey = "appearance"

    /// `nil` follows the system.
    var colorScheme: ColorScheme? {
        switch self {
        case .system: nil
        case .light: .light
        case .dark: .dark
        }
    }
}
