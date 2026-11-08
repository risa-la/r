import Foundation
import Testing

@testable import Risala

@MainActor
struct ChatsRandomizedTests {
    private let chats = TestFixtures.chats

    /// The chat list's load invariants under any order of loads, failures, ended
    /// subscriptions, cancellations, updates, and restarted view tasks.
    @Test(.timeLimit(.minutes(1)), arguments: RandomizedRun.seeds)
    func observingActions(seed: UInt64) async {
        var run = RandomizedRun(seed: seed)
        let client = TestChatClient()
        let waits = PendingCalls<Void>()
        let model = ChatsViewModel(client: client, wait: { _ in try await waits.wait() })
        var loads = client.chatLoads.starts.makeAsyncIterator()
        var subscribed = client.chatSubscriptions.makeAsyncIterator()
        var waitStarts = waits.starts.makeAsyncIterator()
        // The observer following updates, once its first load succeeded.
        var follower: Task<Void, Never>?
        defer { follower?.cancel() }

        for step in 0..<50 {
            var resumed: Task<Void, Never>?
            if let current = follower {
                switch run.pick(4) {
                case 0:
                    let list = pickChats(&run)
                    run.record("\(step): update to \(list.count) chats")
                    client.pushChats(list)
                    guard await eventually({ shows(model, list) }) else {
                        run.fail("Update did not reach the chat list")
                        return
                    }
                    continue
                case 1:
                    run.record("\(step): cancel the follower")
                    let before = snapshot(model)
                    current.cancel()
                    await current.value
                    follower = nil
                    guard snapshot(model) == before else {
                        run.fail("Cancelling hid the chats")
                        return
                    }
                    continue
                case 2:
                    let failing = run.pick(2) == 0
                    run.record("\(step): the subscription ends\(failing ? " with an error" : "")")
                    let shown = model.chats
                    let subscriptions = client.chatFilters.count
                    client.endChats(throwing: failing ? CocoaError(.fileReadUnknown) : nil)
                    _ = await waitStarts.next()
                    guard snapshot(model) == Snapshot(.loaded, shown, isInterrupted: true) else {
                        run.fail("An ended subscription hid the chats or did not say so")
                        return
                    }
                    guard client.chatFilters.count == subscriptions else {
                        run.fail("Subscribed again before the wait")
                        return
                    }
                    // After the wait, the follower subscribes again itself.
                    follower = nil
                    resumed = current
                default:
                    // A restarted view task takes over from the follower.
                    run.record("\(step): observe again")
                }
            }

            let before = snapshot(model)
            let observer: Task<Void, Never>
            if let resumed {
                observer = resumed
                waits.finish(.success(()))
            } else {
                observer = Task { await model.observe() }
            }
            _ = await loads.next()
            let reloading = before.state != .idle && before.state != .failed
            let loading = Snapshot(.loading, before.chats, isInterrupted: before.isInterrupted)
            guard snapshot(model) == (reloading ? before : loading) else {
                client.chatLoads.finish(.success([]))
                run.fail(reloading ? "Subscribing again hid the chats" : "Missing loading state")
                return
            }
            let outcome = run.pick(4)
            let list = pickChats(&run)
            run.record("\(step): load outcome \(outcome) (0=empty, 1=chats, 2=error, 3=cancel)")
            switch outcome {
            case 0, 1:
                let loaded = outcome == 0 ? [] : list
                client.chatLoads.finish(.success(loaded))
                // The rows may already show, so wait for the subscription itself.
                _ = await subscribed.next()
                guard await eventually({ shows(model, loaded) && !model.isInterrupted }) else {
                    run.fail("Load did not show its chats")
                    return
                }
            case 2:
                client.chatLoads.finish(.failure(CocoaError(.fileReadUnknown)))
                // It waits before trying again; leave it there.
                _ = await waitStarts.next()
            default:
                observer.cancel()
                // Even a successful late response must not override cancellation.
                client.chatLoads.finish(.success(list))
                _ = await subscribed.next()
                await observer.value
            }
            let settled = snapshot(model)
            if outcome == 2 {
                observer.cancel()
                waits.finish(.failure(CancellationError()))
                await observer.value
            }
            // A superseded follower leaves the state to the latest observer.
            follower?.cancel()
            await follower?.value
            follower = outcome < 2 ? observer : nil
            let valid: Bool
            switch outcome {
            case 0, 1: valid = settled == Snapshot(.loaded, outcome == 0 ? [] : list)
            // Chats already shown stay readable when subscribing again fails, with a
            // line saying so; with none shown, the list has failed.
            case 2:
                valid =
                    settled
                    == (reloading
                        ? Snapshot(.loaded, before.chats, isInterrupted: true)
                        : Snapshot(.failed, before.chats))
            default:
                let idle = Snapshot(.idle, loading.chats, isInterrupted: loading.isInterrupted)
                valid = settled == (reloading ? before : idle)
            }
            guard valid, snapshot(model) == settled else {
                run.fail("Load invariant failed")
                return
            }
        }
    }

    private struct Snapshot: Equatable {
        let state: ChatsViewModel.State
        let chats: [Chat]
        let isInterrupted: Bool

        init(_ state: ChatsViewModel.State, _ chats: [Chat], isInterrupted: Bool = false) {
            self.state = state
            self.chats = chats
            self.isInterrupted = isInterrupted
        }
    }

    private func snapshot(_ model: ChatsViewModel) -> Snapshot {
        Snapshot(model.state, model.chats, isInterrupted: model.isInterrupted)
    }

    private func shows(_ model: ChatsViewModel, _ chats: [Chat]) -> Bool {
        model.state == .loaded && model.chats == chats
    }

    private func pickChats(_ run: inout RandomizedRun) -> [Chat] {
        Array(chats.prefix(run.pick(chats.count + 1)))
    }
}
