import Foundation
import Testing

@testable import Risala

@MainActor
struct RoomsRandomizedTests {
    private let rooms = TestFixtures.rooms

    @Test(.timeLimit(.minutes(1)), arguments: RandomizedRun.seeds)
    func observingActions(seed: UInt64) async {
        var run = RandomizedRun(seed: seed)
        let client = TestChatClient()
        let model = RoomsViewModel(client: client)
        var loads = client.roomLoads.starts.makeAsyncIterator()
        // The observer following updates, once its first load succeeded.
        var follower: Task<Void, Never>?
        defer { follower?.cancel() }

        for step in 0..<50 {
            if let current = follower {
                switch run.pick(3) {
                case 0:
                    let list = pickRooms(&run)
                    run.record("\(step): update to \(list.count) rooms")
                    client.pushRooms(list)
                    guard await eventually({ model.state == expected(list) }) else {
                        run.fail("Update did not reach the room list")
                        return
                    }
                    continue
                case 1:
                    run.record("\(step): cancel the follower")
                    let before = model.state
                    current.cancel()
                    await current.value
                    follower = nil
                    guard model.state == before else {
                        run.fail("Cancelling hid the rooms")
                        return
                    }
                    continue
                default:
                    // A restarted view task takes over from the follower.
                    run.record("\(step): observe again")
                }
            }

            let before = model.state
            let observer = Task { await model.observe() }
            _ = await loads.next()
            let reloading = before != .idle && before != .failed
            guard model.state == (reloading ? before : .loading) else {
                client.roomLoads.finish(.success([]))
                run.fail(reloading ? "Subscribing again hid the rooms" : "Missing loading state")
                return
            }
            let outcome = run.pick(4)
            let list = pickRooms(&run)
            run.record("\(step): load outcome \(outcome) (0=empty, 1=rooms, 2=error, 3=cancel)")
            switch outcome {
            case 0, 1:
                let loaded = outcome == 0 ? [] : list
                client.roomLoads.finish(.success(loaded))
                guard await eventually({ model.state == expected(loaded) }) else {
                    run.fail("Load did not show its rooms")
                    return
                }
            case 2:
                client.roomLoads.finish(.failure(CocoaError(.fileReadUnknown)))
                await observer.value
            default:
                observer.cancel()
                // Even a successful late response must not override cancellation.
                client.roomLoads.finish(.success(list))
                await observer.value
            }
            let settled = model.state
            // A superseded follower leaves the state to the latest observer.
            follower?.cancel()
            await follower?.value
            follower = outcome < 2 ? observer : nil
            let valid: Bool
            switch outcome {
            case 0, 1: valid = settled == expected(outcome == 0 ? [] : list)
            // Rooms already shown stay readable when subscribing again fails or stops.
            case 2: valid = settled == (reloading ? before : .failed)
            default: valid = settled == (reloading ? before : .idle)
            }
            guard valid, model.state == settled else {
                run.fail("Load invariant failed")
                return
            }
        }
    }

    private func pickRooms(_ run: inout RandomizedRun) -> [Room] {
        Array(rooms.prefix(run.pick(rooms.count + 1)))
    }

    private func expected(_ rooms: [Room]) -> RoomsViewModel.State {
        rooms.isEmpty ? .empty : .loaded(rooms)
    }
}
