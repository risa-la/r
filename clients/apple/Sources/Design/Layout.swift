import SwiftUI

enum Layout {
    static let relatedContentSpacing: CGFloat = 4
    /// Distance from a timeline edge that still counts as being at it.
    static let timelineEdgeTolerance: CGFloat = 44
    static let minimumTouchTarget: CGFloat = 44
}

// Terminal surface metrics, from the TUI mockups.
extension Layout {
    /// Space between the screen edge and a panel.
    static let panelInset: CGFloat = 8
    static let panelCornerRadius: CGFloat = 14
    static let rowCornerRadius: CGFloat = 10
    /// Gap between items on one line, such as stacked buttons.
    static let inlineSpacing: CGFloat = 8
    /// Space above the actions in an empty or first-run state.
    static let hudhudActionsSpacing: CGFloat = 24
    /// A chat row's mark: rooms a rounded square, people a circle.
    static let markSize: CGFloat = 44
    static let markCornerRadius: CGFloat = 9
    /// A chat's mark at the size of a large identity chip, in command line results.
    static let markCornerRadiusSmall: CGFloat = 5
    /// A chat row's horizontal and vertical padding, and the gap after its mark.
    static let chatRowHorizontalPadding: CGFloat = 20
    static let chatRowVerticalPadding: CGFloat = 12
    static let chatRowMarkSpacing: CGFloat = 14
    /// An identity chip inside a row or tab, and in the mode bar.
    static let chipSize: CGFloat = 16
    static let chipSizeLarge: CGFloat = 22
    /// How far the mode bar is inset from the screen edges.
    static let modeBarInset: CGFloat = 8
    /// Hudhud's height in empty and first-run states.
    static let hudhudHeight: CGFloat = 170
    /// Space between Hudhud and the text below.
    static let hudhudSpacing: CGFloat = 28
    /// The widest Hudhud's text and actions get, from the large-screen mockups.
    static let hudhudColumnWidth: CGFloat = 300
    /// Horizontal margin that keeps Hudhud's message to a readable measure.
    static let hudhudMargin: CGFloat = 36
}

// Large screens: the chat list pane beside a chat pane, under one bar of space tabs.
extension Layout {
    /// The chat list pane's width.
    static let listPaneWidth: CGFloat = 320
    /// The narrowest a chat pane gets, which with the list pane sets the Mac window's
    /// minimum width.
    static let chatPaneMinWidth: CGFloat = 420
    /// Space between panes, and between the panes and the window edge.
    static let paneGap: CGFloat = 8
    /// A pane's header line.
    static let paneHeaderHeight: CGFloat = 38
    /// The bar of identity chips and space tabs across the window.
    static let topBarHeight: CGFloat = 52
    /// The widest the timeline and composer get, for a readable measure.
    static let timelineMaxWidth: CGFloat = 720
    static let composerMaxWidth: CGFloat = 688
    /// Space between the time gutter and a message.
    static let gutterSpacing: CGFloat = 8
    /// Space between messages and dividers in the timeline.
    static let timelineEntrySpacing: CGFloat = 16
    /// An image attachment's card.
    static let attachmentSize = CGSize(width: 236, height: 128)
    static let attachmentCornerRadius: CGFloat = 12
    /// The height of a reaction chip.
    static let reactionHeight: CGFloat = 24
    /// The window's identity chips in the top bar.
    static let chipSizeTopBar: CGFloat = 28
}
