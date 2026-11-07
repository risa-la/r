import SwiftUI

// Style the label while retaining the platform's native Button behavior.
private struct IconActionLabelStyle: ViewModifier {
    func body(content: Content) -> some View {
        content
            .font(Typography.actionSymbol)
            #if os(iOS)
                .frame(minWidth: Layout.minimumTouchTarget, minHeight: Layout.minimumTouchTarget)
            #endif
    }
}

extension View {
    func iconActionLabel() -> some View {
        modifier(IconActionLabelStyle())
    }
}
