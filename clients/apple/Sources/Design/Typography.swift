import SwiftUI

// Product roles stay backed by system text styles for Dynamic Type and Arabic.
enum Typography {
    static let roomTopic: Font = .subheadline
}

// The terminal surface sets everything in JetBrains Mono (bundled in
// Resources/Fonts, declared in Info.plist), so columns line up. Sizes
// scale with Dynamic Type from their text style. JetBrains Mono has no Arabic, and
// the system's fallback for it is a monospaced Arabic face that stretches words, so
// user content goes through `Text(terminal:)`, which sets right-to-left runs in
// `terminalArabic`. In a right-to-left interface the copy itself is Arabic, so the
// terminal roles use the system face there instead. Bundled weights: regular,
// semibold, bold, extra bold.
extension Typography {
    private static let monoFamily = "JetBrains Mono"

    /// Whether the app runs in a right-to-left language, read once: changing the
    /// language relaunches the app.
    private static let isRightToLeftInterface =
        Locale.Language(identifier: Bundle.main.preferredLocalizations.first ?? "en")
        .characterDirection == .rightToLeft

    /// JetBrains Mono at `size`, scaled like `style`; the system face at `style` in a
    /// right-to-left interface.
    private static func mono(_ size: CGFloat, relativeTo style: Font.TextStyle) -> Font {
        isRightToLeftInterface ? .system(style) : .custom(monoFamily, size: size, relativeTo: style)
    }

    /// The title of an empty or first-run state.
    static let terminalTitle: Font = mono(16, relativeTo: .callout)
        .weight(.bold)
    /// List rows, breadcrumbs, and filters.
    static let terminal: Font = mono(13, relativeTo: .footnote)
    /// A primary button on a terminal panel.
    static let buttonProminent: Font = terminal.weight(.heavy)
    /// A secondary button on a terminal panel.
    static let button: Font = mono(12, relativeTo: .caption)
    /// Right-to-left runs in terminal text: the system face, a step up so that
    /// Arabic reads at the same size as the mono text around it.
    static func terminalArabic(bold: Bool = false) -> Font {
        .system(.subheadline, weight: bold ? .bold : .regular)
    }
}

// The chat list reads like a messenger: names and messages in the system face, which
// also sets Arabic properly, and everything structural in JetBrains Mono: times,
// counts, server names, tabs, filters, and the mode bar.
extension Typography {
    /// A chat's name; bold while it has unread messages.
    static let chatName: Font = .body
    /// The newest message under a chat's name.
    static let chatPreview: Font = .subheadline
    /// Times, server names, section lines, and filters.
    static let terminalSmall: Font = button
    /// The number in a count or mention block.
    static let countBlock: Font = button.weight(.heavy)
    /// The letter or symbol inside a chat's 44-point mark.
    static let markLarge: Font = mono(18, relativeTo: .title3).weight(.bold)
    /// The letter inside an identity chip.
    static let chip: Font = mono(10, relativeTo: .caption2).weight(.heavy)
    /// The mode name at the start of the mode bar.
    static let mode: Font = .custom(monoFamily, size: 11, relativeTo: .caption2).weight(.heavy)
    /// The prompt in the mode bar and the spaces search.
    static let prompt: Font = mono(15, relativeTo: .subheadline)
}

// The timeline follows the chat list's rule: names and messages in the system face,
// and its structure in JetBrains Mono: the time gutter, day lines, replies, threads,
// reactions, and file names.
extension Typography {
    /// A message's text.
    static let messageBody: Font = .subheadline
    /// The author line above a message.
    static let messageAuthor: Font = .subheadline.weight(.semibold)
    /// The time in the gutter beside a message.
    static let timelineTime: Font = terminal
    /// A day or "new" line across the timeline.
    static let timelineDivider: Font = mono(11, relativeTo: .caption2)
    /// A pane's header: the chat's or the list's name.
    static let paneTitle: Font = .footnote
    /// The mark before a chat's name in a pane header, such as `#`.
    static let paneMark: Font = terminal.weight(.bold)
    /// A keyboard shortcut hint, such as `⌘K`.
    static let shortcutHint: Font = terminalSmall
}
