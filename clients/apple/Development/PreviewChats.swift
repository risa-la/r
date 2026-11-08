#if DEBUG
    import Foundation

    /// Fixed chats for previews, after the Paper file's final chat list (F1, N1, N2).
    /// Debug only: no demo data ships in Release builds. Only what the protocol allows:
    /// room names are ASCII (3.5), and direct conversations are between identities
    /// (5.1), so Arabic shows in people's names and messages, and guests appear only as
    /// the person's own guest names.
    enum PreviewChats {
        // MARK: Identities and spaces

        static let layla = Identity(
            id: Identity.ID(rawValue: "layla@example.org"), name: "layla",
            address: "layla@example.org", isGuest: false, isMain: true, tint: 0)
        static let work = Identity(
            id: Identity.ID(rawValue: "l.haddad@acme.work"), name: "work",
            address: "l.haddad@acme.work", isGuest: false, isMain: false, tint: 1)
        /// A long label, and a tint far outside the palette, for the worst case.
        static let northwind = Identity(
            id: Identity.ID(rawValue: "counsel@northwind-holdings.example"),
            name: "northwind-holdings-legal", address: "counsel@northwind-holdings.example",
            isGuest: false, isMain: false, tint: .min)
        static let guest = Identity(
            id: Identity.ID(rawValue: "guest"), name: "~layla", address: "", isGuest: true,
            isMain: false, tint: 2)

        static let example = Space.ID(rawValue: "example.chat")
        static let acme = Space.ID(rawValue: "chat.acme.work")
        static let nightly = Space.ID(rawValue: "nightly-builds.acme.work")
        static let hackspace = Space.ID(rawValue: "hackspace.example.net")
        static let nixos = Space.ID(rawValue: "nixos-users.org")
        static let hiking = Space.ID(rawValue: "weekend-hiking-and-photography.example.net")
        static let bookLovers = Space.ID(rawValue: "book-lovers.berlin")
        /// An internationalised host, to check Arabic in the monospaced places.
        static let readers = Space.ID(rawValue: "مجتمع-القراءة.example")
        static let nordic = Space.ID(
            rawValue: "nordic-woodworkers-and-furniture-restorers.example.co.uk")

        /// Each space's identity, whether it is reachable, and whether it is a favourite.
        static let spaces: [(Space.ID, Identity, reachable: Bool, favourite: Bool)] = [
            (example, layla, true, true),
            (acme, work, true, true),
            (bookLovers, guest, true, false),
            (hackspace, layla, false, false),
            (nixos, layla, true, false),
            (hiking, layla, true, false),
            (nightly, work, true, false),
            (readers, layla, true, false),
        ]

        /// The usual spaces and a long host on a long-named identity.
        static let worstCaseSpaces: [(Space.ID, Identity, reachable: Bool, favourite: Bool)] =
            spaces + [(nordic, northwind, true, false)]

        /// Ninety-two more spaces, for a hundred in all.
        static let manySpaces: [(Space.ID, Identity, reachable: Bool, favourite: Bool)] =
            spaces
            + (1...92).map { index in
                (
                    Space.ID(rawValue: "space-\(index).example.org"),
                    index % 9 == 0 ? work : layla, index % 31 != 0, false
                )
            }

        // MARK: Scenarios

        /// The "N1 · Mentions on many servers" board.
        static var busy: [Chat] {
            [
                room(
                    "general", in: example, as: layla, ago: .minutes(2), unread: 12,
                    preview: message("sam", "is anyone coming on saturday?"),
                    topic: "General chat. Be kind.", present: 48),
                person(
                    "omar", in: example, as: layla, ago: .minutes(31), unread: 2,
                    preview: message("omar", "on my way, save me a seat"), typing: true,
                    online: true),
                room(
                    "standup", in: acme, as: work, ago: .hours(1), unread: 1, mentions: 1,
                    preview: message("dana", "@l.haddad is the deploy green?"), favourite: true),
                room(
                    "trips", in: hiking, as: layla, ago: .hours(3), unread: 4, mentions: 1,
                    preview: message("aleks", "@layla do you still have the car keys?")),
                room(
                    "help", in: nixos, as: layla, ago: .hours(5), unread: 2, mentions: 1,
                    preview: message("sam", "thanks @layla, that flake fixed it")),
                room(
                    "workshop", in: hackspace, as: layla, ago: .days(4),
                    preview: message("karim", "the laser cutter is fixed")),
                person(
                    "farah", in: example, as: layla, ago: .days(5),
                    preview: own("see you there!"), online: true, favourite: true),
                person(
                    "nour", in: example, as: layla, ago: .days(6),
                    preview: message("nour", "شكراً، نلتقي يوم السبت")),
                room(
                    "book-swap", in: bookLovers, as: guest, ago: .weeks(2),
                    preview: message("mira", "anyone have volume two?")),
                person(
                    "Dana Okafor", in: acme, as: work, ago: .weeks(3),
                    preview: message("Dana Okafor", "can you look at the release notes?")),
            ]
        }

        /// Long names, huge counts, a message sending and one failed, a deleted one. Two
        /// 63-character room names differ only at the end; a long name sits beside a
        /// long identity and a long host; names start with an emoji or are Arabic.
        static var worstCase: [Chat] {
            [
                room(
                    "northwind-holdings-legal-and-compliance-quarterly-retro-2025-q3",
                    in: nordic, as: northwind, ago: .minutes(1), unread: 7, mentions: 2,
                    preview: message("Christopher", "agenda attached; please read before 9")),
                room(
                    "northwind-holdings-legal-and-compliance-quarterly-retro-2025-q4",
                    in: nordic, as: northwind, ago: .minutes(9),
                    preview: message("Aleksandra", "moved to thursday")),
                person(
                    "Christopher Alexander Montgomery III", in: nordic, as: northwind,
                    ago: .minutes(14), unread: 2,
                    preview: message("Christopher", "can you countersign by friday?"),
                    online: true),
                person(
                    "🦊 Noor", in: example, as: layla, ago: .minutes(48), unread: 1,
                    preview: message("Noor", "🦊🦊🦊")),
                room(
                    "weekend-hiking-and-photography-club-of-greater-berlin", in: hiking,
                    as: layla, ago: .minutes(2), unread: 1_284,
                    preview: message(
                        "aleksandra", "has anyone seen bartholomew's tripod? he left it at the lake"
                    )
                ),
                person(
                    "Aleksandra Wiśniewska-Kowalczyk", in: example, as: layla, ago: .minutes(31),
                    unread: 1, preview: message("Aleksandra", "ok")),
                room(
                    "x", in: nightly, as: work, ago: .hours(1), unread: 3,
                    typing: ["farah", "karim", "omar", "sam"], preview: message("jo", "k")),
                room(
                    "workshop", in: hackspace, as: layla, ago: .weeks(3),
                    preview: message("karim", "the laser cutter is fixed")),
                person("Jo", in: example, as: layla, ago: .days(5)),
                person(
                    "نور الهدى عبد الرحمن", in: example, as: layla, ago: .weeks(1),
                    preview: message("نور الهدى", "شكرًا :) see you at 11 ولا تنسَ القهوة والبطاطس")),
                person(
                    "Bartholomew Fitzgerald-Montgomery the Third", in: example, as: layla,
                    ago: .weeks(2), preview: own("welcome! ask me anything.")),
                person("🌻 Sunny", in: example, as: layla, ago: .days(330), preview: own("📷 photo")),
                room(
                    "deleted-things", in: example, as: layla, ago: .days(340),
                    preview: message("moderator", "", deleted: true)),
                room(
                    "drafts", in: example, as: layla, ago: .seconds(20),
                    preview: own("this one is still on its way", delivery: .sending)),
                room(
                    "outbox", in: example, as: layla, ago: .days(2),
                    preview: own(
                        "this one could not be sent\nand had a second line",
                        delivery: .failed(possiblySent: false))),
            ]
        }

        /// Arabic people and messages, for an Arabic interface.
        static var arabic: [Chat] {
            [
                room(
                    "general", in: example, as: layla, ago: .minutes(4), unread: 5,
                    preview: message("سارة", "من سيأتي يوم السبت؟")),
                person(
                    "عمر", in: example, as: layla, ago: .minutes(40), unread: 1,
                    preview: message("عمر", "في الطريق"), typing: true, online: true),
                room(
                    "book-club", in: readers, as: layla, ago: .hours(3), unread: 5,
                    preview: message("نور", "which chapter are we on?")),
                person("ليلى", in: example, as: layla, ago: .days(2), preview: own("أراكِ هناك!")),
                room(
                    "workshop", in: hackspace, as: layla, ago: .days(6),
                    preview: message("كريم", "تم إصلاح القاطع بالليزر")),
            ]
        }

        /// Enough rooms to page through: three pages and a bit, over a hundred spaces.
        static var many: [Chat] {
            busy
                + (1...160).map { index in
                    room(
                        "room-\(index)",
                        in: manySpaces[index % manySpaces.count].0,
                        as: manySpaces[index % manySpaces.count].1,
                        ago: .hours(Double(index) * 5),
                        unread: index % 7 == 0 ? index : 0,
                        preview: message("someone", "message number \(index)"))
                }
        }

        // MARK: Builders

        private static func room(
            _ name: String, in space: Space.ID, as identity: Identity, ago: Duration,
            unread: Int = 0, mentions: Int = 0, typing: [String] = [],
            preview: Chat.Preview? = nil, topic: String = "", favourite: Bool = false,
            present: Int? = nil
        ) -> Chat {
            Chat(
                id: Chat.ID(rawValue: "\(space.rawValue)/#\(name)"), kind: .room, name: name,
                topic: topic, space: space, identity: identity.id,
                isOnHomeServer: isHome(space, for: identity), lastActivity: date(ago),
                preview: preview.map { at($0, ago) }, unreadCount: unread,
                mentionCount: mentions, typing: typing, presentCount: present,
                isFavourite: favourite)
        }

        private static func person(
            _ name: String, in space: Space.ID, as identity: Identity, ago: Duration,
            unread: Int = 0, preview: Chat.Preview? = nil, typing: Bool = false,
            online: Bool = false, favourite: Bool = false
        ) -> Chat {
            Chat(
                id: Chat.ID(rawValue: "\(space.rawValue)/@\(name)"), kind: .direct, name: name,
                space: space, identity: identity.id,
                isOnHomeServer: isHome(space, for: identity), lastActivity: date(ago),
                preview: preview.map { at($0, ago) }, unreadCount: unread,
                typing: typing ? [name] : [], isOnline: online, isFavourite: favourite)
        }

        /// As the library decides it: guests are always at home; an identity is at home
        /// on its own domain and under it. layla's identity is hosted by example.chat.
        private static func isHome(_ space: Space.ID, for identity: Identity) -> Bool {
            guard !identity.isGuest,
                let domain = identity.address.split(separator: "@").last.map(String.init)
            else { return true }
            return space.rawValue == domain || space.rawValue.hasSuffix(".\(domain)")
                || (identity.isMain && space == example)
        }

        private static func message(_ author: String, _ text: String, deleted: Bool = false)
            -> Chat.Preview
        {
            Chat.Preview(
                author: author, isOwn: false, text: text, isDeleted: deleted, sentAt: .now,
                delivery: .sent)
        }

        private static func own(_ text: String, delivery: Message.Delivery = .sent)
            -> Chat.Preview
        {
            Chat.Preview(
                author: "layla", isOwn: true, text: text, isDeleted: false, sentAt: .now,
                delivery: delivery)
        }

        private static func at(_ preview: Chat.Preview, _ ago: Duration) -> Chat.Preview {
            Chat.Preview(
                author: preview.author, isOwn: preview.isOwn, text: preview.text,
                isDeleted: preview.isDeleted, sentAt: date(ago), delivery: preview.delivery)
        }

        private static func date(_ ago: Duration) -> Date {
            Date.now.addingTimeInterval(-Double(ago.components.seconds))
        }
    }

    extension Duration {
        fileprivate static func minutes(_ n: Double) -> Duration { .seconds(n * 60) }
        fileprivate static func hours(_ n: Double) -> Duration { .seconds(n * 3_600) }
        fileprivate static func days(_ n: Double) -> Duration { .seconds(n * 86_400) }
        fileprivate static func weeks(_ n: Double) -> Duration { .seconds(n * 604_800) }
    }
#endif
