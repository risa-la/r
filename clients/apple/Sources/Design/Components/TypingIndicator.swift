import SwiftUI

/// Someone is typing: a 4×2 cell of dots, as tall as a lowercase letter, that flickers
/// like a computer working. Each tick lights two or three dots at random, and the
/// previous tick's dots stay dimly lit for one more. Reduce Motion holds one frame.
/// It is decorative; the text beside it says who is typing.
struct TypingIndicator: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @ScaledMetric(relativeTo: .footnote) private var dot: CGFloat = 3

    /// How long each frame shows.
    static let tick: TimeInterval = 0.2

    var body: some View {
        let gap = dot / 2
        // Paused under Reduce Motion, so the held frame is not redrawn every tick.
        TimelineView(.animation(minimumInterval: Self.tick, paused: reduceMotion)) { context in
            let index =
                reduceMotion
                ? 3 : Int(context.date.timeIntervalSinceReferenceDate / Self.tick)
            Canvas { canvas, _ in
                let frame = Self.frames[index % Self.frames.count]
                let previous = Self.frames[(index + Self.frames.count - 1) % Self.frames.count]
                for cell in 0..<8 {
                    let x = CGFloat(cell % 4) * (dot + gap)
                    let y = CGFloat(cell / 4) * (dot + gap)
                    let shading: Color =
                        frame.contains(cell)
                        ? .ink
                        : previous.contains(cell) && !reduceMotion
                            ? .ink.opacity(0.45) : .textTertiary.opacity(0.3)
                    canvas.fill(
                        Path(ellipseIn: CGRect(x: x, y: y, width: dot, height: dot)),
                        with: .color(shading))
                }
            }
        }
        .frame(width: dot * 4 + gap * 3, height: dot * 2 + gap)
        .accessibilityHidden(true)
    }

    /// A fixed loop of frames, each a set of lit cells (0–7, row by row). No set
    /// repeats within four frames, so the loop never shows a pattern.
    private static let frames: [Set<Int>] = {
        var generator = SplitMix(state: 11)
        var frames: [Set<Int>] = []
        var previous: Set<Int> = []
        while frames.count < 24 {
            let count = generator.next() % 3 == 0 ? 3 : 2
            var lit: Set<Int> = []
            while lit.count < count {
                let cell = Int(generator.next() % 8)
                if !previous.contains(cell) { lit.insert(cell) }
            }
            guard !frames.suffix(4).contains(lit) else { continue }
            frames.append(lit)
            previous = lit
        }
        return frames
    }()
}

/// SplitMix64: a small, fixed generator, so the loop is the same on every launch.
private struct SplitMix {
    var state: UInt64

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var value = state
        value = (value ^ (value >> 30)) &* 0xBF58_476D_1CE4_E5B9
        value = (value ^ (value >> 27)) &* 0x94D0_49BB_1331_11EB
        return value ^ (value >> 31)
    }
}

#Preview {
    HStack(spacing: 8) {
        TypingIndicator()
        Text("typing").font(Typography.chatPreview).foregroundStyle(.ink)
    }
    .padding()
    .background(.surface)
}
