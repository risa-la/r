import SwiftUI

extension String {
    /// The direction of the first strong letter, or `nil` when there is none, such as
    /// for digits, punctuation, or emoji alone. Used to place user content that runs
    /// against the interface, such as an Arabic preview in an English list.
    nonisolated var firstStrongDirection: LayoutDirection? {
        for scalar in unicodeScalars {
            if scalar.isRightToLeft { return .rightToLeft }
            if scalar.properties.isAlphabetic { return .leftToRight }
        }
        return nil
    }

    /// The text wrapped in a first-strong isolate, so its direction cannot reorder
    /// the text around it, such as a name before a colon.
    nonisolated var isolated: String {
        "\u{2068}\(self)\u{2069}"
    }

    /// The text wrapped in a left-to-right isolate. A host name reads from its first
    /// label to its last whatever its script, so `مجتمع-القراءة.example` keeps its
    /// labels in order and a leading `@` stays in front of it.
    nonisolated var leftToRightIsolated: String {
        "\u{2066}\(self)\u{2069}"
    }
}

extension Unicode.Scalar {
    /// Whether the scalar is in a right-to-left script's block: Hebrew, Arabic,
    /// Syriac, Thaana, NKo and their extensions and presentation forms.
    nonisolated var isRightToLeft: Bool {
        switch value {
        case 0x0590...0x08FF, 0xFB1D...0xFDFF, 0xFE70...0xFEFF, 0x10800...0x10FFF,
            0x1E800...0x1EFFF:
            properties.isAlphabetic
        default:
            false
        }
    }
}

/// A stretch of user content set in one font on the terminal surface.
nonisolated struct TerminalRun: Equatable, Sendable {
    let text: Substring
    /// Whether the run is in a right-to-left script, set in `Typography.terminalArabic`.
    let isRightToLeft: Bool
}

extension String {
    /// The text split where letters change between right-to-left scripts and the
    /// rest. Spaces, digits, and punctuation join the run before them, so an Arabic
    /// phrase stays one run.
    nonisolated var terminalRuns: [TerminalRun] {
        var runs: [TerminalRun] = []
        var start = startIndex
        var isRightToLeft = false
        for index in indices {
            guard let scalar = self[index].unicodeScalars.first, scalar.properties.isAlphabetic
            else { continue }
            guard scalar.isRightToLeft != isRightToLeft else { continue }
            if index > start {
                runs.append(TerminalRun(text: self[start..<index], isRightToLeft: isRightToLeft))
            }
            start = index
            isRightToLeft = scalar.isRightToLeft
        }
        if start < endIndex {
            runs.append(TerminalRun(text: self[start...], isRightToLeft: isRightToLeft))
        }
        return runs
    }
}

extension Text {
    /// User content on the terminal surface. Runs in right-to-left scripts use
    /// `Typography.terminalArabic`; the rest takes the font set around it.
    init(terminal string: String, bold: Bool = false) {
        var text = AttributedString()
        for run in string.terminalRuns {
            var part = AttributedString(String(run.text))
            if run.isRightToLeft {
                part.font = Typography.terminalArabic(bold: bold)
            }
            text.append(part)
        }
        self.init(text)
    }
}
