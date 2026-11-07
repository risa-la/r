import SwiftUI

// Dresses a native bordered button for a terminal panel: ink fill for the primary
// action and a quiet tinted fill for secondary ones. The system styles keep focus
// rings, hover effects, and accessibility shapes.
private struct TerminalButtonStyle: ViewModifier {
    let isPrimary: Bool

    func body(content: Content) -> some View {
        styled(content)
            .buttonBorderShape(.roundedRectangle(radius: Layout.rowCornerRadius))
            .controlSize(.large)
    }

    @ViewBuilder
    private func styled(_ content: Content) -> some View {
        if isPrimary {
            content.buttonStyle(.borderedProminent).tint(.ink)
        } else {
            content.buttonStyle(.bordered).tint(.text)
        }
    }
}

// The label's type. Applied to the label itself, because the macOS bordered
// styles replace the font and color set on the button.
private struct TerminalButtonLabelStyle: ViewModifier {
    let isPrimary: Bool

    func body(content: Content) -> some View {
        content
            .font(isPrimary ? Typography.buttonProminent : Typography.button)
            .foregroundStyle(isPrimary ? Color.onInk : Color.text)
            .textCase(.lowercase)
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

    /// Sets a terminal button's label type. Use inside the button's label.
    func terminalButtonLabel(primary: Bool = false) -> some View {
        modifier(TerminalButtonLabelStyle(isPrimary: primary))
    }
}
