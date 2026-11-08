import Foundation
import Testing

@testable import Risala

@MainActor
struct RoomsViewModelTests {
    @Test func noClientStaysDisconnected() async {
        let model = RoomsViewModel()
        await model.observe()
        guard case .disconnected = model.state else {
            Issue.record("Missing client must not appear as an empty room list")
            return
        }
    }

    /// Catches a room joined after the first load never appearing, or a parted one staying.
    @Test(.timeLimit(.minutes(1)))
    func roomsFollowUpdatesAfterLoading() async {
        let rooms = TestFixtures.rooms
        let client = TestChatClient()
        let model = RoomsViewModel(client: client)
        var loads = client.roomLoads.starts.makeAsyncIterator()
        let observing = Task { await model.observe() }
        _ = await loads.next()
        client.roomLoads.finish(.success([]))
        #expect(await eventually { model.state == .empty })

        client.pushRooms([rooms[0]])
        #expect(await eventually { model.state == .loaded([rooms[0]]) })
        client.pushRooms([])
        #expect(await eventually { model.state == .empty })
        observing.cancel()
        await observing.value
    }

    /// Catches failed room updates leaving the list silently frozen, blanking it, or
    /// a retry that does not follow updates again.
    @Test(.timeLimit(.minutes(1)))
    func updateFailureKeepsRoomsUntilRetry() async {
        let rooms = TestFixtures.rooms
        let client = TestChatClient()
        let model = RoomsViewModel(client: client)
        var loads = client.roomLoads.starts.makeAsyncIterator()
        let failing = Task { await model.observe() }
        _ = await loads.next()
        client.roomLoads.finish(.success([rooms[0]]))
        #expect(await eventually { model.state == .loaded([rooms[0]]) })
        client.endRooms(throwing: CocoaError(.fileReadUnknown))
        await failing.value
        #expect(model.state == .stale([rooms[0]]))
        #expect(model.rooms == [rooms[0]])

        let retry = Task { await model.observe() }
        _ = await loads.next()
        #expect(model.state == .stale([rooms[0]]), "Retrying hid the rooms")
        client.roomLoads.finish(.success(rooms))
        #expect(await eventually { model.state == .loaded(rooms) })
        client.pushRooms([rooms[1]])
        #expect(await eventually { model.state == .loaded([rooms[1]]) })
        retry.cancel()
        await retry.value
        #expect(model.state == .loaded([rooms[1]]), "Cancelling marked the rooms stale")
    }
}
