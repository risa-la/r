import SwiftUI

// Dresses a native bordered button for a terminal panel: ink fill for the primary
// action, a quiet tinted fill for secondary ones, and lowercase monospaced labels.
// The system styles keep focus rings, hover effects, and accessibility shapes.
private struct TerminalButtonStyle: ViewModifier {
    let isPrimary: Bool

    func body(content: Content) -> some View {
        styled(content)
            .font(isPrimary ? Typography.buttonProminent : Typography.button)
            .textCase(.lowercase)
            .buttonBorderShape(.roundedRectangle(radius: Layout.rowCornerRadius))
            .controlSize(.large)
    }

    @ViewBuilder
    private func styled(_ content: Content) -> some View {
        if isPrimary {
            content
                .buttonStyle(.borderedProminent)
                .tint(.ink)
                .foregroundStyle(.onInk)
        } else {
            content
                .buttonStyle(.bordered)
                .tint(.text)
        }
    }
}

extension View {
    /// Styles a button as the main action on a terminal panel.
    func terminalPrimaryButton() -> some View {
        modifier(TerminalButtonStyle(isPrimary: true))
    }

    /// Styles a button as a secondary action on a terminal panel.
    func terminalSecondaryButton() -> some View {
        modifier(TerminalButtonStyle(isPrimary: false))
    }
}
