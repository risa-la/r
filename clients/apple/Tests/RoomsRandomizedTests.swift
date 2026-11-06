import Foundation
import Testing

@testable import Risala

@MainActor
struct RoomsRandomizedTests {
    private let rooms = TestFixtures.rooms

    @Test(.timeLimit(.minutes(1)), arguments: RandomizedRun.seeds)
    func loadingActions(seed: UInt64) async {
        var run = RandomizedRun(seed: seed)
        let client = TestChatClient()
        var model = RoomsViewModel(client: client)
        var events = client.roomLoads.starts.makeAsyncIterator()

        for step in 0..<50 {
            // Completed loads are stable until the window is recreated.
            switch model.state {
            case .loaded, .empty:
                let previousCalls = client.roomLoads.count
                await model.load()
                guard client.roomLoads.count == previousCalls else {
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
                client.roomLoads.finish(.success([]))
                await load.value
                run.fail("Missing loading state")
                return
            }
            let calls = client.roomLoads.count
            await model.load()
            if client.roomLoads.count != calls {
                run.fail("Concurrent load duplicated a request")
            }
            switch outcome {
            case 0: client.roomLoads.finish(.success([]))
            case 1: client.roomLoads.finish(.success(rooms))
            case 2: client.roomLoads.finish(.failure(CocoaError(.fileReadUnknown)))
            default:
                load.cancel()
                // Even a successful late response must not override cancellation.
                client.roomLoads.finish(.success(rooms))
            }
            await load.value
            let valid: Bool
            switch model.state {
            case .empty: valid = outcome == 0 && model.rooms.isEmpty
            case .loaded(let values): valid = outcome == 1 && values == rooms
            case .failed: valid = outcome == 2 && model.rooms.isEmpty
            case .idle: valid = outcome == 3 && model.rooms.isEmpty
            case .loading, .disconnected: valid = false
            }
            guard valid else {
                run.fail("Load invariant failed")
                return
            }
        }
    }
}
