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
