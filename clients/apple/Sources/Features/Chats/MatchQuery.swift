import Foundation

/// How well a name matches what was typed into a search, best first.
nonisolated enum MatchRank: Int, Comparable, Sendable {
    /// The name starts with the query.
    case prefix
    /// A later word, or a part after a hyphen, dot, or underscore, starts with it.
    case wordPrefix
    /// The query is somewhere in the name.
    case contains

    static func < (lhs: MatchRank, rhs: MatchRank) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

/// Text typed into the command line or the spaces search, ready to rank names
/// against. Matching ignores case and diacritics, so `olafur` finds `Ólafur` and
/// Arabic marks never stand in the way, and surrounding whitespace does not count.
nonisolated struct MatchQuery: Sendable {
    private let needle: String

    /// `nil` when nothing but whitespace was typed.
    init?(_ text: String) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        needle = Self.fold(trimmed)
    }

    /// How well `name` matches, or `nil` when it does not.
    func rank(_ name: String) -> MatchRank? {
        let name = Self.fold(name)
        if name.hasPrefix(needle) { return .prefix }
        var previous: Character?
        for index in name.indices {
            defer { previous = name[index] }
            guard let previous, Self.isSeparator(previous), !Self.isSeparator(name[index])
            else { continue }
            if name[index...].hasPrefix(needle) { return .wordPrefix }
        }
        return name.contains(needle) ? .contains : nil
    }

    /// The items that match, best first; items that match equally keep their order.
    func ranked<Item>(_ items: [Item], by rank: (Item) -> MatchRank?) -> [Item] {
        items.enumerated()
            .compactMap { offset, item in rank(item).map { (item, $0, offset) } }
            .sorted { ($0.1, $0.2) < ($1.1, $1.2) }
            .map(\.0)
    }

    /// Lowercased, without accents, and without combining marks such as Arabic
    /// harakat, which diacritic folding leaves in place.
    private static func fold(_ text: String) -> String {
        let folded = text.folding(
            options: [.caseInsensitive, .diacriticInsensitive, .widthInsensitive], locale: nil)
        var scalars = String.UnicodeScalarView()
        scalars.append(
            contentsOf: folded.unicodeScalars.filter {
                $0.properties.generalCategory != .nonspacingMark
            })
        return String(scalars)
    }

    private static func isSeparator(_ character: Character) -> Bool {
        character.isWhitespace || character == "-" || character == "." || character == "_"
    }
}

extension Chat {
    nonisolated func rank(_ query: MatchQuery) -> MatchRank? {
        query.rank(name)
    }
}

extension Space {
    /// The short name's start counts as the name's; any other match on the host, such
    /// as `acme.work` for `work`, ranks at best as a later part.
    nonisolated func rank(_ query: MatchQuery) -> MatchRank? {
        if query.rank(shortName) == .prefix { return .prefix }
        return query.rank(id.rawValue).map { max($0, .wordPrefix) }
    }
}
