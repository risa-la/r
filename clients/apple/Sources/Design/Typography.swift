import SwiftUI

// Product roles stay backed by system text styles for Dynamic Type and Arabic.
enum Typography {
    static let roomName: Font = .body
    static let roomTopic: Font = .subheadline
    static let messageBody: Font = .body
    static let messageAuthor: Font = .body.weight(.semibold)
    static let messageMetadata: Font = .caption
    static let composer: Font = .body
    #if os(macOS)
        static let actionSymbol: Font = .body
    #else
        static let actionSymbol: Font = .title2
    #endif
}

// The terminal surface sets everything in JetBrains Mono (bundled in
// Resources/Fonts, declared in Info.plist), so columns line up. Sizes
// scale with Dynamic Type from their text style. Arabic falls back to the system
// Arabic face. Bundled weights: regular, semibold, bold, extra bold.
extension Typography {
    private static let monoFamily = "JetBrains Mono"

    /// The title of an empty or first-run state.
    static let terminalTitle: Font = .custom(monoFamily, size: 16, relativeTo: .callout)
        .weight(.bold)
    /// List rows, breadcrumbs, and filters.
    static let terminal: Font = .custom(monoFamily, size: 13, relativeTo: .footnote)
    /// Names and other row titles that need weight.
    static let terminalEmphasis: Font = terminal.weight(.bold)
    /// A primary button on a terminal panel.
    static let buttonProminent: Font = terminal.weight(.heavy)
    /// A secondary button on a terminal panel.
    static let button: Font = .custom(monoFamily, size: 12, relativeTo: .caption)
    /// The letter or symbol inside a room or person glyph.
    static let glyph: Font = .custom(monoFamily, size: 11, relativeTo: .caption2).weight(.bold)
}
