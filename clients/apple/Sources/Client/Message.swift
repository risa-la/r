import Foundation

struct Message: Identifiable {
    let id: UUID
    let author: String
    let text: String
    let sentAt: Date
}
