import Observation

/// Waits until `condition` holds, re-checking only when observable state it reads changes.
/// Returns `false` after `timeout` so callers can report a seed and trace.
@MainActor
func eventually(timeout: Duration = .seconds(5), _ condition: () -> Bool) async -> Bool {
    let deadline = ContinuousClock.now.advanced(by: timeout)
    while !condition() {
        guard ContinuousClock.now < deadline else { return false }
        await withCheckedContinuation { continuation in
            let wakeup = Wakeup(continuation)
            withObservationTracking {
                _ = condition()
            } onChange: {
                Task { @MainActor in wakeup.resume() }
            }
            wakeup.timeout = Task { @MainActor in
                try? await Task.sleep(until: deadline)
                wakeup.resume()
            }
        }
    }
    return true
}

@MainActor
private final class Wakeup {
    private var continuation: CheckedContinuation<Void, Never>?
    var timeout: Task<Void, Never>?

    init(_ continuation: CheckedContinuation<Void, Never>) {
        self.continuation = continuation
    }

    func resume() {
        timeout?.cancel()
        continuation?.resume()
        continuation = nil
    }
}
