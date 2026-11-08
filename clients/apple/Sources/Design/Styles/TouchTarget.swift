import SwiftUI

extension View {
    /// Makes the view tappable across at least 44×44 points on iOS without changing
    /// how it looks: apply it after the view's background, inside the button's label.
    func minimumTouchTarget() -> some View {
        #if os(iOS)
            frame(minWidth: Layout.minimumTouchTarget, minHeight: Layout.minimumTouchTarget)
                .contentShape(.rect)
        #else
            contentShape(.rect)
        #endif
    }
}
