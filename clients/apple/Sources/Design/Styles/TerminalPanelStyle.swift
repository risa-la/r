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

// A pane on a large screen: a framed panel on the window's surface. The focused
// pane's frame is a step brighter; its prompt also shows the mode.
private struct PaneStyle: ViewModifier {
    let isFocused: Bool
    private let shape = RoundedRectangle(cornerRadius: Layout.panelCornerRadius)

    func body(content: Content) -> some View {
        content
            .background(.panel)
            .clipShape(shape)
            .overlay {
                shape.strokeBorder(isFocused ? Color.textTertiary.opacity(0.45) : Color.rule)
            }
    }
}

extension View {
    func pane(isFocused: Bool) -> some View {
        modifier(PaneStyle(isFocused: isFocused))
    }
}
