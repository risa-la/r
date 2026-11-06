import Foundation
import Testing

@MainActor
struct RoomsViewModelTests {
    @Test func noClientStaysDisconnected() async {
        let model = RoomsViewModel()
        await model.load()
        guard case .disconnected = model.state else {
            Issue.record("Missing client must not appear as an empty room list")
            return
        }
    }

}
