import Foundation

/// One line of the timeline as it shows: a message, or a line across the timeline
/// where the day changes or the unread messages start.
nonisolated enum TimelineEntry: Identifiable, Hashable, Sendable {
    /// The start of the day the messages below it were sent on.
    case day(Date)
    /// The unread messages start below it.
    case new
    /// A message; `continuesGroup` when it follows the same author's message closely
    /// enough to leave out their name and time.
    case message(Message, continuesGroup: Bool)

    var id: String {
        switch self {
        case .day(let date): "day:\(date.timeIntervalSinceReferenceDate)"
        case .new: "new"
        case .message(let message, _): "message:" + message.id.rawValue
        }
    }

    /// How close a message must follow the one before it, from the same author, to
    /// continue its group.
    static let groupInterval: TimeInterval = 5 * 60

    /// The timeline's lines for `messages`, oldest first: a day line before each
    /// day's first message, a "new" line before `firstUnread`, and messages grouped
    /// by author. A line between two messages always breaks their group, as do
    /// replies, events, and failed messages.
    static func entries(
        for messages: [Message], firstUnread: Message.ID?, calendar: Calendar = .current
    ) -> [TimelineEntry] {
        var entries: [TimelineEntry] = []
        entries.reserveCapacity(messages.count + 4)
        var previous: Message?
        var currentDay: Date?
        for message in messages {
            let day = calendar.startOfDay(for: message.sentAt)
            var broken = false
            if day != currentDay {
                entries.append(.day(day))
                currentDay = day
                broken = true
            }
            if message.id == firstUnread {
                entries.append(.new)
                broken = true
            }
            let continues =
                !broken && previous.map { continuesGroup(message, after: $0) } ?? false
            entries.append(.message(message, continuesGroup: continues))
            previous = message
        }
        return entries
    }

    private static func continuesGroup(_ message: Message, after previous: Message) -> Bool {
        message.kind == .message && previous.kind == .message
            && message.author == previous.author && message.isOwn == previous.isOwn
            && message.reply == nil && !isFailed(message) && !isFailed(previous)
            && message.sentAt.timeIntervalSince(previous.sentAt) < groupInterval
            && message.sentAt >= previous.sentAt
    }

    private static func isFailed(_ message: Message) -> Bool {
        if case .failed = message.delivery { return true }
        return false
    }
}

/// Which palette tint an author's name shows in, the same for a name every time:
/// FNV-1a over its scalars, since `hashValue` changes between launches.
nonisolated func authorTintIndex(_ name: String, count: Int) -> Int {
    var hash: UInt64 = 0xcbf2_9ce4_8422_2325
    for scalar in name.unicodeScalars {
        hash ^= UInt64(scalar.value)
        hash &*= 0x100_0000_01b3
    }
    return Int(hash % UInt64(max(count, 1)))
}
