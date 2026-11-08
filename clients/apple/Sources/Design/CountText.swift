import SwiftUI

/// How a count shows in the chat list, its tabs, and the spaces page: exact up to 999,
/// then `999+`, so a block never grows wider than four digits.
nonisolated enum CountLabel: Equatable, Sendable {
    case exact(Int)
    /// More than `CountLabel.cap`.
    case capped

    static let cap = 999

    init(_ count: Int) {
        self = count > Self.cap ? .capped : .exact(count)
    }
}

extension Text {
    /// A count in the person's locale, `999+` beyond 999. Set it with
    /// `.monospacedDigit()` so that counts line up.
    init(count: Int) {
        switch CountLabel(count) {
        case .exact(let count): self.init(count, format: .number)
        case .capped: self.init("\(CountLabel.cap, format: .number)+")
        }
    }
}
