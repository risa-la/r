import SwiftUI

enum Layout {
    static let relatedContentSpacing: CGFloat = 4
    static let timelineItemSpacing: CGFloat = 20
    /// Distance from a timeline edge that still counts as being at it.
    static let timelineEdgeTolerance: CGFloat = 44
    static let minimumTouchTarget: CGFloat = 44
}

// Terminal surface metrics, from the TUI mockups.
extension Layout {
    /// Space between the screen edge and a panel.
    static let panelInset: CGFloat = 8
    static let panelCornerRadius: CGFloat = 14
    /// Horizontal padding for text set directly on a panel.
    static let panelContentPadding: CGFloat = 16
    static let rowCornerRadius: CGFloat = 10
    static let rowPadding: CGFloat = 10
    /// Space between a row's glyph and its text.
    static let rowGlyphSpacing: CGFloat = 10
    /// Gap between items on one line, such as breadcrumb parts and filters.
    static let inlineSpacing: CGFloat = 8
    static let glyphSize: CGFloat = 20
    /// Rooms use a rounded square and people a circle.
    static let glyphCornerRadius: CGFloat = 6
    /// Space above the actions in an empty or first-run state.
    static let hudhudActionsSpacing: CGFloat = 24
    /// Hudhud's height in empty and first-run states.
    static let hudhudHeight: CGFloat = 170
    /// Space between Hudhud and the text below.
    static let hudhudSpacing: CGFloat = 28
    /// The widest Hudhud's text and actions get, from the large-screen mockups.
    static let hudhudColumnWidth: CGFloat = 300
    /// Horizontal margin that keeps Hudhud's message to a readable measure.
    static let hudhudMargin: CGFloat = 36
}
