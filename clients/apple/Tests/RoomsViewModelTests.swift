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
}
