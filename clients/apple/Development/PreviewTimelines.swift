#if DEBUG
    import SwiftUI
    import ImageIO
    import UniformTypeIdentifiers

    /// Fixed timelines for previews, after the Paper file's large-screen boards (L1,
    /// L2): `#general` in the busy scenario has day lines, a group, a thread, a guest
    /// with reactions, the "new" line, a reply with a picture, and Arabic. Times are
    /// relative to launch, so "today" stays today. Debug only.
    @MainActor
    enum PreviewTimelines {
        static func timeline(for chatID: Chat.ID) -> (
            messages: [Message], firstUnread: Message.ID?
        )? {
            guard chatID.rawValue == "\(PreviewChats.example.rawValue)/#general" else {
                return nil
            }
            return (general, Message.ID(rawValue: "general-7"))
        }

        private static var general: [Message] {
            let yesterday = Calendar.current.date(
                byAdding: .day, value: -1, to: Calendar.current.startOfDay(for: .now))!
            func evening(_ hour: Int, _ minute: Int) -> Date {
                yesterday.addingTimeInterval(TimeInterval(hour * 3_600 + minute * 60))
            }
            func ago(_ minutes: Double) -> Date {
                max(
                    Date.now.addingTimeInterval(-minutes * 60),
                    Calendar.current.startOfDay(for: .now))
            }
            return [
                message(1, "farah", "weather says sunny all weekend. picnic?", at: evening(21, 4)),
                message(
                    2, "karim", "yes please. the spot by the lake, not the one with the geese",
                    at: evening(21, 6)),
                message(3, "karim", "i can bring the speaker", at: evening(21, 6)),
                message(
                    4, "layla", "i'll check who's free and post a time tomorrow",
                    at: evening(21, 11), isOwn: true),
                message(
                    5, "layla",
                    "picnic is saturday at 11 in the park by the lake. bring something to share!",
                    at: ago(9), isOwn: true,
                    thread: Message.Thread(replyCount: 3, lastReplyAt: ago(5))),
                message(
                    6, "~sam", "is anyone coming on saturday? i can bring drinks.", at: ago(7),
                    reactions: [
                        Message.Reaction(reaction: ":)", count: 4, mine: true),
                        Message.Reaction(reaction: "XD", count: 2, mine: false),
                        Message.Reaction(reaction: ":'(", count: 1, mine: false),
                    ]),
                message(
                    7, "omar", "count me in — i'll bring a blanket and cake.", at: ago(6),
                    isEdited: true,
                    reply: Message.Reply(author: "~sam", text: "is anyone coming on saturday?"),
                    attachment: Message.Attachment(
                        name: "picnic-spot.jpg", byteCount: 1_200_000, isImage: true,
                        thumbnail: picnicPicture)),
                message(8, "nour", "سأكون هناك! سأحضر القهوة ☕", at: ago(2)),
            ]
        }

        private static func message(
            _ index: Int, _ author: String, _ text: String, at date: Date, isOwn: Bool = false,
            isEdited: Bool = false, reactions: [Message.Reaction] = [],
            reply: Message.Reply? = nil, thread: Message.Thread? = nil,
            attachment: Message.Attachment? = nil
        ) -> Message {
            Message(
                id: Message.ID(rawValue: "general-\(index)"), author: author, text: text,
                sentAt: date, isOwn: isOwn, isEdited: isEdited, reactions: reactions,
                reply: reply, thread: thread, attachment: attachment)
        }

        /// Sky over a lawn, drawn once and written to a temporary file, so no picture
        /// ships with the app.
        private static var picnicPicture: URL? {
            if let drawnPicture { return drawnPicture }
            let view = LinearGradient(
                stops: [
                    .init(color: Color(red: 0.50, green: 0.66, blue: 0.84), location: 0),
                    .init(color: Color(red: 0.73, green: 0.83, blue: 0.92), location: 0.38),
                    .init(color: Color(red: 0.90, green: 0.93, blue: 0.94), location: 0.47),
                    .init(color: Color(red: 0.50, green: 0.69, blue: 0.49), location: 0.49),
                    .init(color: Color(red: 0.37, green: 0.56, blue: 0.35), location: 0.70),
                    .init(color: Color(red: 0.27, green: 0.44, blue: 0.25), location: 1),
                ], startPoint: .top, endPoint: .bottom
            )
            .frame(width: 236, height: 128)
            let renderer = ImageRenderer(content: view)
            renderer.scale = 2
            guard let image = renderer.cgImage else { return nil }
            let url = FileManager.default.temporaryDirectory.appending(path: "picnic-spot.png")
            guard
                let destination = CGImageDestinationCreateWithURL(
                    url as CFURL, UTType.png.identifier as CFString, 1, nil)
            else { return nil }
            CGImageDestinationAddImage(destination, image, nil)
            drawnPicture = CGImageDestinationFinalize(destination) ? url : nil
            return drawnPicture
        }

        private static var drawnPicture: URL?
    }
#endif
