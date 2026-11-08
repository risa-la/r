import SwiftUI

/// The `›` of a prompt or a link onward, pointing in the reading direction: a text
/// glyph does not mirror in a right-to-left layout as an SF Symbol does.
struct ForwardChevron: View {
    @Environment(\.layoutDirection) private var layoutDirection

    var body: some View {
        Text(verbatim: layoutDirection == .rightToLeft ? "‹" : "›")
            .accessibilityHidden(true)
    }
}
