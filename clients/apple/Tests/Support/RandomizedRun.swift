import Testing

// Shared mechanics only: generators, actions, and invariants belong to each feature suite.
struct RandomizedRun {
    static let seeds: [UInt64] = Array(0..<16) + [42, 2026, UInt64.max]
    let seed: UInt64
    private var random: SeededRandom
    private var trace: [String] = []

    init(seed: UInt64) {
        self.seed = seed
        random = SeededRandom(state: seed)
    }

    mutating func pick(_ count: Int) -> Int {
        precondition(count > 0)
        return random.pick(count)
    }

    mutating func record(_ action: String) {
        trace.append(action)
    }

    func fail(_ reason: String, sourceLocation: SourceLocation = #_sourceLocation) {
        Issue.record(
            Comment(rawValue: "\(reason)\nReplay seed: \(seed)\n\(trace.joined(separator: "\n"))"),
            sourceLocation: sourceLocation
        )
    }
}

// SplitMix64: keep the algorithm and action ordering stable for seed replay.
private struct SeededRandom {
    var state: UInt64

    mutating func pick(_ count: Int) -> Int {
        state &+= 0x9E37_79B9_7F4A_7C15
        var value = state
        value = (value ^ (value >> 30)) &* 0xBF58_476D_1CE4_E5B9
        value = (value ^ (value >> 27)) &* 0x94D0_49BB_1331_11EB
        return Int((value ^ (value >> 31)) % UInt64(count))
    }
}
