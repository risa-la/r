import SwiftUI

// Sets content on a terminal panel. On iPhone and iPad the panel is a framed card
// inset from the screen; on macOS the window already frames it, so it only fills.
private struct TerminalPanelStyle: ViewModifier {
    private let shape = RoundedRectangle(cornerRadius: Layout.panelCornerRadius)

    func body(content: Content) -> some View {
        #if os(macOS)
            content
                .background(.panel)
        #else
            content
                .background(.panel)
                .clipShape(shape)
                .overlay { shape.strokeBorder(.rule) }
                .padding(.horizontal, Layout.panelInset)
                .padding(.bottom, Layout.panelInset)
                .background(.surface)
        #endif
    }
}

extension View {
    func terminalPanel() -> some View {
        modifier(TerminalPanelStyle())
    }
}
