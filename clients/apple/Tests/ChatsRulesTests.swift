import Foundation
import SwiftUI
import Testing

@testable import Risala

/// The chat list's pure rules: matching, names, directions, time, list changes, and
/// what counts and marks show.
@MainActor
struct ChatsRulesTests {
    // MARK: Matching

    /// Catches a ranking that puts a contained match before a start, or misses a
    /// later word, a hyphen- or dot-separated part, or a name led by an emoji.
    @Test func matchRanksStartsThenPartsThenContents() throws {
        let query = try #require(MatchQuery("no"))
        #expect(query.rank("Noor") == .prefix)
        #expect(query.rank("🦊 Noor") == .wordPrefix)
        #expect(query.rank("weekly-notes") == .wordPrefix)
        #expect(query.rank("chat.nordic.example") == .wordPrefix)
        #expect(query.rank("laser_notes") == .wordPrefix)
        #expect(query.rank("Bruno") == .contains)
        #expect(query.rank("Sam") == nil)

        let gen = try #require(MatchQuery("gen"))
        let names = ["Agenda", "Big gen", "General", "Sam", "Genealogy"]
        #expect(
            gen.ranked(names) { gen.rank($0) } == ["General", "Genealogy", "Big gen", "Agenda"])
    }

    /// Catches a query that fails on accents, case, or Arabic marks on either side.
    @Test func matchIgnoresCaseAndDiacritics() throws {
        #expect(try #require(MatchQuery("olafur")).rank("Ólafur Arnalds") == .prefix)
        #expect(try #require(MatchQuery("ÓLAF")).rank("olafur") == .prefix)
        #expect(try #require(MatchQuery("شكرا")).rank("شكرًا جزيلًا") == .prefix)
        #expect(try #require(MatchQuery("مُحَمَّد")).rank("محمد علي") == .prefix)
        #expect(try #require(MatchQuery("الهدى")).rank("نور الهدى عبد الرحمن") == .wordPrefix)
    }

    /// Catches whitespace counting toward the query, or a blank query matching.
    @Test func matchTrimsWhitespace() throws {
        #expect(MatchQuery("   \n") == nil)
        #expect(try #require(MatchQuery("  gen \n")).rank("General") == .prefix)
        #expect(try #require(MatchQuery("noor al")).rank("Noor al-Huda") == .prefix)
    }

    /// Catches a space outranking a chat that matches as well, or the chat list's
    /// order being lost among equal matches.
    @Test func commandSpacesFollowChatsThatMatchAsWell() {
        let general = TestFixtures.chat("a", "general")
        let agenda = TestFixtures.chat("b", "agenda")
        let space = Space(
            id: Space.ID(rawValue: "chat.gentoo.org"), identity: TestFixtures.identity,
            isReachable: true, unreadChats: 0, mentions: 0, isFavourite: false)
        let items = CommandItem.matches("gen", chats: [agenda, general], spaces: [space])
        #expect(items == [.chat(general), .space(space), .chat(agenda)])
        #expect(
            CommandItem.matches(" ", chats: [agenda, general], spaces: [space], recent: 1) == [
                .chat(agenda)
            ])
    }

    /// Catches tabs named after `chat.` or `www.`, or a host cut too far.
    @Test(arguments: [
        ("chat.acme.work", "acme"),
        ("www.example.org", "example"),
        ("example.chat", "example"),
        ("chat.example", "chat"),
        ("localhost", "localhost"),
        (
            "nordic-woodworkers-and-furniture-restorers.example.co.uk",
            "nordic-woodworkers-and-furniture-restorers"
        ),
    ])
    func spaceShortName(host: String, short: String) {
        let space = Space(
            id: Space.ID(rawValue: host), identity: TestFixtures.identity, isReachable: true,
            unreadChats: 0, mentions: 0, isFavourite: false)
        #expect(space.shortName == short)
    }

    // MARK: Text

    /// Catches neutral characters deciding the direction, or emoji counting as a letter.
    @Test func firstStrongDirection() {
        #expect("hello".firstStrongDirection == .leftToRight)
        #expect("مرحبا".firstStrongDirection == .rightToLeft)
        #expect("שלום".firstStrongDirection == .rightToLeft)
        #expect("123, مرحبا".firstStrongDirection == .rightToLeft)
        #expect("🦊 Noor".firstStrongDirection == .leftToRight)
        #expect("📷 12:30!".firstStrongDirection == nil)
        #expect("".firstStrongDirection == nil)
    }

    /// Catches an Arabic phrase split into runs at its spaces or punctuation, or a
    /// run boundary in the wrong place.
    @Test func terminalRunsSplitAtScriptChanges() {
        #expect("".terminalRuns.isEmpty)
        #expect(
            "example.org".terminalRuns == [TerminalRun(text: "example.org", isRightToLeft: false)])
        #expect(
            "@مجتمع-القراءة.example".terminalRuns == [
                TerminalRun(text: "@", isRightToLeft: false),
                TerminalRun(text: "مجتمع-القراءة.", isRightToLeft: true),
                TerminalRun(text: "example", isRightToLeft: false),
            ])
        #expect(
            "see you at 11 ولا تنسَ القهوة".terminalRuns == [
                TerminalRun(text: "see you at 11 ", isRightToLeft: false),
                TerminalRun(text: "ولا تنسَ القهوة", isRightToLeft: true),
            ])
    }

    // MARK: Time

    private static let calendar: Calendar = {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        calendar.locale = Locale(identifier: "en_US_POSIX")
        return calendar
    }()

    private static func date(_ day: Int, _ hour: Int, _ minute: Int) -> Date {
        calendar.date(
            from: DateComponents(year: 2026, month: 11, day: day, hour: hour, minute: minute))!
    }

    /// Catches a chat staying under "today" after midnight, or a week ending early.
    @Test func sectionsTurnOverAtMidnight() {
        let now = Self.date(8, 0, 1)
        let calendar = Self.calendar
        #expect(ChatSection(Self.date(8, 0, 0), now: now, calendar: calendar) == .today)
        #expect(ChatSection(Self.date(7, 23, 59), now: now, calendar: calendar) == .thisWeek)
        #expect(ChatSection(Self.date(1, 0, 2), now: now, calendar: calendar) == .thisWeek)
        #expect(ChatSection(Self.date(1, 0, 0), now: now, calendar: calendar) == .earlier)
    }

    /// Catches a time column that rounds two minutes across midnight up to a day.
    @Test func timesCountAcrossMidnight() {
        let now = Self.date(8, 0, 1)
        let calendar = Self.calendar
        #expect(ChatTime.short(from: Self.date(7, 23, 59), to: now, calendar: calendar) == "2m")
        #expect(ChatTime.short(from: Self.date(7, 22, 0), to: now, calendar: calendar) == "2h")
        #expect(ChatTime.short(from: Self.date(6, 23, 0), to: now, calendar: calendar) == "1d")
        #expect(
            ChatTime.short(from: now.addingTimeInterval(-30), to: now, calendar: calendar)
                == String(localized: "now"))
    }

    // MARK: List changes

    /// Catches a batch applied although it repeats a row or updates the wrong one.
    @Test func listChangesThatDoNotFit() {
        let rows = TestFixtures.chats
        #expect(rows.applying([.insert(rows[0], at: 3)]) == nil)
        #expect(rows.applying([.reset([rows[0], rows[0]])]) == nil)
        #expect(rows.applying([.update(rows[1], at: 0)]) == nil)
        #expect(rows.applying([.remove(at: 3)]) == nil)
        let renamed = TestFixtures.chat("a", "General chat")
        #expect(rows.applying([.update(renamed, at: 0)]) == [renamed, rows[1], rows[2]])
    }

    // MARK: Counts and marks

    /// Catches a count block wider than four digits, or 999 shown as capped.
    @Test func countsCapAt999() {
        #expect(CountLabel(0) == .exact(0))
        #expect(CountLabel(999) == .exact(999))
        #expect(CountLabel(1_000) == .capped)
        #expect(CountLabel(1_284) == .capped)
    }

    /// Catches a mark showing half a grapheme, an emoji where a letter follows it, or
    /// nothing for a name with neither.
    @Test(arguments: [
        ("🦊 Noor", "N"),
        ("نور الهدى عبد الرحمن", "ن"),
        ("jo", "J"),
        ("ólafur", "Ó"),
        ("e\u{301}mile", "E\u{301}"),
        ("🌻", "🌻"),
        ("👩‍👩‍👧", "👩‍👩‍👧"),
        ("123", "?"),
        ("", "?"),
    ])
    func markSymbol(name: String, symbol: String) {
        let person = Chat(
            id: Chat.ID(rawValue: name), kind: .direct, name: name, space: TestFixtures.space,
            identity: TestFixtures.identity, lastActivity: .now)
        #expect(ChatMark.symbol(for: person) == symbol)
        let room = Chat(
            id: Chat.ID(rawValue: name), name: name, space: TestFixtures.space,
            identity: TestFixtures.identity, lastActivity: .now)
        #expect(ChatMark.symbol(for: room) == "#")
    }

    /// Catches a tint chosen on another device crashing the chip.
    @Test func identityTintsWrap() {
        let count = IdentityChip.tints.count
        #expect(IdentityChip.tintIndex(for: .min) < count)
        #expect(IdentityChip.tintIndex(for: -1) == 1)
        #expect(IdentityChip.tintIndex(for: count) == 0)
    }
}
