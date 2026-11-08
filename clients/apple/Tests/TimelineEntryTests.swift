import Foundation
import Testing

@testable import Risala

/// How the timeline lays out its lines: day lines, the "new" line, and author groups.
struct TimelineEntryTests {
    private let calendar: Calendar = {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        return calendar
    }()

    /// 2026-11-07 21:00 UTC.
    private let evening = Date(timeIntervalSince1970: 1_794_085_200)

    private func message(
        _ id: String, _ author: String, at minutes: Double, kind: Message.Kind = .message,
        reply: Message.Reply? = nil, delivery: Message.Delivery = .sent
    ) -> Message {
        Message(
            id: Message.ID(rawValue: id), author: author, kind: kind, text: id,
            sentAt: evening.addingTimeInterval(minutes * 60), delivery: delivery, reply: reply)
    }

    private func shape(_ entries: [TimelineEntry]) -> [String] {
        entries.map { entry in
            switch entry {
            case .day: "day"
            case .new: "new"
            case .message(let message, let continues):
                continues ? "+" + message.id.rawValue : message.id.rawValue
            }
        }
    }

    /// Catches a missing day line at midnight, a "new" line in the wrong place, or a
    /// group that runs across either line.
    @Test func daysAndNewLineBreakGroups() {
        let messages = [
            message("a", "farah", at: 0),
            message("b", "farah", at: 1),
            // After midnight, from the same author.
            message("c", "farah", at: 180),
            message("d", "farah", at: 181),
            message("e", "farah", at: 182),
        ]
        let entries = TimelineEntry.entries(
            for: messages, firstUnread: Message.ID(rawValue: "e"), calendar: calendar)
        #expect(shape(entries) == ["day", "a", "+b", "day", "c", "+d", "new", "e"])
    }

    /// Catches grouping across authors, long pauses, replies, events, or failures,
    /// which each need their own name and time.
    @Test func groupsOnlyCloseMessagesFromOneAuthor() {
        let messages = [
            message("a", "karim", at: 0),
            message("b", "omar", at: 1),
            message("c", "omar", at: 7),
            message("d", "omar", at: 8, reply: Message.Reply(author: "karim", text: "a")),
            message("e", "omar", at: 9, kind: .join),
            message("f", "omar", at: 10),
            message("g", "omar", at: 11, delivery: .failed(possiblySent: false)),
            message("h", "omar", at: 12),
        ]
        let entries = TimelineEntry.entries(for: messages, firstUnread: nil, calendar: calendar)
        #expect(shape(entries) == ["day", "a", "b", "c", "d", "e", "f", "g", "h"])
    }

    /// Catches an author whose color changes between launches, as `hashValue` would.
    @Test func authorTintIsStable() {
        #expect(authorTintIndex("layla", count: 6) == authorTintIndex("layla", count: 6))
        #expect((0..<6).contains(authorTintIndex("نور", count: 6)))
        // FNV-1a of "a" is 0xaf63dc4c8601ec8c.
        #expect(authorTintIndex("a", count: 6) == Int(UInt64(0xaf63_dc4c_8601_ec8c) % 6))
    }
}
