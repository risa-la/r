import SwiftUI

/// The bar at the bottom of the screen, as in vim: the mode, then a prompt, then which
/// of you is here. Tapping the prompt turns the bar itself into the command line, so
/// nothing leaves the screen: the mode changes, the prompt takes the cursor, and the
/// keyboard lifts the bar. It holds only the mode and things to use; connection and
/// other status stay on the rows they concern.
struct ModeBar: View {
    /// Shown in reverse video at the start, such as `NOR`; `nil` in a pane that
    /// does not have the focus.
    let mode: Text?
    let modeColor: Color
    /// The prompt's placeholder, such as `find or start`.
    let prompt: Text
    @Binding var text: String
    let isEditing: Bool
    var isFocused: FocusState<Bool>.Binding
    /// The identities to show at the end; the main identity in front.
    let identities: [Identity]
    let activate: () -> Void
    let submit: () -> Void
    let cancel: () -> Void
    /// A keyboard shortcut for the prompt, such as `⌘K`, shown at the end instead
    /// of the chips.
    var shortcut: Text? = nil
    /// The panel's corner radius and its inset from the edges.
    var cornerRadius = Layout.panelCornerRadius
    var inset = Layout.modeBarInset

    var body: some View {
        HStack(spacing: 10) {
            if let mode {
                ModeBlock(mode: mode, color: modeColor)
            }
            ForwardChevron()
                .font(Typography.prompt.weight(.bold))
                .foregroundStyle(.ink)
            field
            if !isEditing {
                if let shortcut {
                    ShortcutHint(text: shortcut)
                        .transition(.opacity)
                } else {
                    IdentityStack(identities: identities, size: .large, ring: .panel)
                        .transition(.opacity)
                }
            }
        }
        .frame(minHeight: Layout.minimumTouchTarget)
        .padding(.leading, mode == nil ? 12 : 9)
        .padding(.trailing, 12)
        .background(.panel, in: .rect(cornerRadius: cornerRadius))
        .overlay {
            RoundedRectangle(cornerRadius: cornerRadius)
                .strokeBorder(isEditing ? Color.ink.opacity(0.5) : Color.rule)
        }
        .padding(.horizontal, inset)
        .padding(.bottom, 4)
        // Pulling the bar down puts the command line away.
        .gesture(
            DragGesture(minimumDistance: 12).onEnded { drag in
                if isEditing, drag.translation.height > 30 { cancel() }
            })
    }

    @ViewBuilder
    private var field: some View {
        if isEditing {
            TextField(text: $text, prompt: prompt.foregroundStyle(.textTertiary)) {
                prompt
            }
            .font(Typography.prompt)
            .foregroundStyle(.text)
            .textFieldStyle(.plain)
            .focused(isFocused)
            .autocorrectionDisabled()
            #if os(iOS)
                .textInputAutocapitalization(.never)
                .submitLabel(.go)
            #endif
            .onSubmit(submit)
            #if os(macOS)
                // The Mac's field can take the first Return for itself; the command
                // line acts on it at once.
                .onKeyPress(.return) {
                    submit()
                    return .handled
                }
            #endif
            .onKeyPress(.escape) {
                cancel()
                return .handled
            }
            // VoiceOver's two-finger scrub puts the command line away, as Escape does.
            .accessibilityAction(.escape, cancel)
            // The field joins the bar as the bar turns into the command line; focusing
            // it once it is there, rather than in the same update, keeps the focus.
            .onAppear { isFocused.wrappedValue = true }
        } else {
            Button(action: activate) {
                prompt
                    .font(Typography.prompt)
                    .foregroundStyle(.textTertiary)
                    .lineLimit(1)
                    .frame(
                        maxWidth: .infinity, minHeight: Layout.minimumTouchTarget,
                        alignment: .leading
                    )
                    .contentShape(.rect)
            }
            .buttonStyle(.plain)
        }
    }
}

/// The mode in reverse video, such as `NOR` or `INS`. Never translated, and always in
/// JetBrains Mono, even in an Arabic interface.
struct ModeBlock: View {
    let mode: Text
    let color: Color

    var body: some View {
        mode
            .font(Typography.mode)
            .tracking(0.6)
            .foregroundStyle(.onInk)
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .background(color, in: .rect(cornerRadius: 6))
            .contentTransition(.opacity)
            .fixedSize()
            .accessibilityHidden(true)
    }
}

/// A keyboard shortcut in a small outlined chip, such as `⌘K`. Decorative: the
/// shortcut is in the menus, where VoiceOver and the shortcut list find it.
struct ShortcutHint: View {
    let text: Text

    var body: some View {
        text
            .font(Typography.shortcutHint)
            .foregroundStyle(.textTertiary)
            .padding(.horizontal, 6)
            .padding(.vertical, 1)
            .overlay { RoundedRectangle(cornerRadius: 5).strokeBorder(.rule) }
            .fixedSize()
            .accessibilityHidden(true)
    }
}
