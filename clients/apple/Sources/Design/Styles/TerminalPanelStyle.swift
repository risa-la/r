import SwiftUI

// Sets content on a terminal panel: a framed card inset from the window or
// screen surface, on every platform.
private struct TerminalPanelStyle: ViewModifier {
    private let shape = RoundedRectangle(cornerRadius: Layout.panelCornerRadius)

    func body(content: Content) -> some View {
        content
            .background(.panel)
            .clipShape(shape)
            .overlay { shape.strokeBorder(.rule) }
            .padding(.horizontal, Layout.panelInset)
            .padding(.bottom, Layout.panelInset)
            .background(.surface)
    }
}

extension View {
    func terminalPanel() -> some View {
        modifier(TerminalPanelStyle())
    }
}
