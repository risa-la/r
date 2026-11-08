import Foundation

extension String {
    /// The symbol a chat mark or identity chip shows for a name: the first letter, as
    /// a whole grapheme and uppercased where the script has case; else the first
    /// emoji; else `nil`. `🦊 Noor` gives `N`, `نور الهدى` gives `ن`, and `🌻` gives `🌻`.
    nonisolated var initial: String? {
        if let letter = first(where: \.isLetter) {
            return String(letter).uppercased()
        }
        return first(where: \.isEmoji).map(String.init)
    }
}

extension Character {
    /// Whether the character shows as an emoji. Digits, `#`, and `*` have emoji forms
    /// but show as text unless a variation selector or keycap follows them.
    nonisolated var isEmoji: Bool {
        guard let first = unicodeScalars.first else { return false }
        return first.properties.isEmojiPresentation
            || (first.properties.isEmoji && unicodeScalars.count > 1)
    }
}
