import Foundation
import Testing

@MainActor
struct RoomsRandomizedTests {
    private let rooms = TestFixtures.rooms

    @Test(.timeLimit(.minutes(1)), arguments: RandomizedRun.seeds)
    func loadingActions(seed: UInt64) async {
        var run = RandomizedRun(seed: seed)
        let client = SuspendedChatClient()
        var model = RoomsViewModel(client: client)
        var events = client.starts.makeAsyncIterator()

        for step in 0..<50 {
            // Completed loads are stable until the window is recreated.
            switch model.state {
            case .loaded, .empty:
                let previousCalls = client.calls
                await model.load()
                guard client.calls == previousCalls else {
                    run.fail("Repeated load refetched")
                    return
                }
                model = RoomsViewModel(client: client)
            default: break
            }
            let current = model
            let load = Task { await current.load() }
            _ = await events.next()
            let outcome = run.pick(4)
            run.record("\(step): load outcome \(outcome) (0=empty, 1=rooms, 2=error, 3=cancel)")
            guard case .loading = model.state else {
                client.finish(.success([]))
                await load.value
                run.fail("Missing loading state")
                return
            }
            let calls = client.calls
            await model.load()
            if client.calls != calls {
                run.fail("Concurrent load duplicated a request")
            }
            switch outcome {
            case 0: client.finish(.success([]))
            case 1: client.finish(.success(rooms))
            case 2: client.finish(.failure(CocoaError(.fileReadUnknown)))
            default:
                load.cancel()
                // Even a successful late response must not override cancellation.
                client.finish(.success(rooms))
            }
            await load.value
            let valid: Bool
            switch model.state {
            case .empty: valid = outcome == 0 && model.rooms.isEmpty
            case .loaded(let values): valid = outcome == 1 && values == rooms
            case .failed: valid = outcome == 2 && model.rooms.isEmpty
            case .disconnected: valid = outcome == 3 && model.rooms.isEmpty
            case .loading: valid = false
            }
            guard valid else {
                run.fail("Load invariant failed")
                return
            }
        }
    }
}
