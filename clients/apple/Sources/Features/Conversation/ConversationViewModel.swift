import Foundation
import OSLog
import Observation

@MainActor
@Observable
final class ConversationViewModel {
    private static let logger = Logger(subsystem: "la.risa.apple", category: "conversation")
    private let client: any ChatClient?
    private struct ComposerState {
        var draft = ""
        var revision = 0
        var sendFailed = false
    }

    private var composers: [Room.ID: ComposerState] = [:]
    private(set) var room: Room?
    private(set) var messages: [Message] = []
    private(set) var isSending = false
    private(set) var sendRevision = 0
    var draft: String {
        get { room.map { composers[$0.id]?.draft ?? "" } ?? "" }
        set {
            guard let room else { return }
            composers[room.id, default: ComposerState()].draft = newValue
            composers[room.id, default: ComposerState()].revision += 1
        }
    }

    var sendFailed: Bool {
        room.map { composers[$0.id]?.sendFailed ?? false } ?? false
    }

    var canSend: Bool {
        !isSending && client != nil && room != nil
            && !draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    init(client: any ChatClient? = nil) {
        self.client = client
    }

    func select(_ room: Room?) {
        guard room?.id != self.room?.id else { return }
        self.room = room
        messages = room.map { client?.messages(in: $0.id) ?? [] } ?? []
    }

    func sendMessage() async {
        guard canSend, let client, let room else { return }
        let submittedDraft = draft
        let revision = composers[room.id, default: ComposerState()].revision
        isSending = true
        composers[room.id, default: ComposerState()].sendFailed = false
        defer { isSending = false }

        do {
            try await client.send(
                submittedDraft.trimmingCharacters(in: .whitespacesAndNewlines), to: room.id)
            if composers[room.id]?.revision == revision {
                composers[room.id]?.draft = ""
            }
            if self.room?.id == room.id {
                messages = client.messages(in: room.id)
                sendRevision += 1
            }
        } catch {
            guard !Task.isCancelled, !(error is CancellationError) else { return }
            composers[room.id, default: ComposerState()].sendFailed = true
            Self.logger.error("send failed; code=\((error as NSError).code)")
        }
    }
}
