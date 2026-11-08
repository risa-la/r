import SwiftUI

/// Every space, opened from the end of the tabs. Without a query: favourites in tab
/// order, spaces with unread messages, then every space under the identity that is
/// there. With a query, matches stack up from the prompt, ranked as `MatchQuery`
/// ranks them, the best one nearest, so it is under the thumb and Return opens it.
struct SpacesView: View {
    let spaces: Spaces
    let select: (Space.ID) -> Void
    let toggleFavourite: (Space) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var query = ""
    @FocusState private var isSearching: Bool

    var body: some View {
        // Ranked once per update, for the results, their count, and Return.
        let matchQuery = MatchQuery(query)
        let found = matchQuery.map { query in spaces.spaces.ranked(by: query) } ?? []
        VStack(spacing: 0) {
            if matchQuery == nil {
                browse
            } else {
                results(found)
            }
            searchLine(found: matchQuery == nil ? nil : found)
        }
        .background(.panel)
    }

    // MARK: Browse

    private var browse: some View {
        List {
            let favourites = spaces.spaces.filter(\.isFavourite)
            if !favourites.isEmpty {
                section(Text("favourites"), favourites)
            }
            let unread = spaces.spaces.filter {
                !$0.isFavourite && ($0.unreadChats > 0 || $0.mentions > 0)
            }
            if !unread.isEmpty {
                section(Text("unread"), unread)
            }
            ForEach(spaces.identities) { identity in
                let theirs = spaces.spaces
                    .filter { $0.identity == identity.id }
                    .sorted { $0.id.rawValue < $1.id.rawValue }
                if !theirs.isEmpty {
                    Section {
                        ForEach(theirs) { row($0) }
                    } header: {
                        identityHeader(identity, count: theirs.count)
                    }
                }
            }
        }
        .listStyle(.plain)
        #if os(iOS)
            .listSectionSpacing(0)
        #endif
        .contentMargins(.top, 0, for: .scrollContent)
        .scrollContentBackground(.hidden)
        .environment(\.defaultMinListRowHeight, 0)
        .environment(\.defaultMinListHeaderHeight, 0)
    }

    private func section(_ title: Text, _ list: [Space]) -> some View {
        Section {
            ForEach(list) { row($0) }
        } header: {
            SectionLine(title: title, fill: .panel)
        }
    }

    private func identityHeader(_ identity: Identity, count: Int) -> some View {
        HStack(spacing: 10) {
            IdentityChip(identity: identity, isLarge: true)
            if identity.isGuest {
                Text("guest names")
                    .foregroundStyle(.textSecondary)
            } else {
                Text(verbatim: identity.address)
                    .foregroundStyle(.textTertiary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer(minLength: 0)
            Text(count, format: .number)
                .foregroundStyle(.textTertiary)
                .monospacedDigit()
                .accessibilityLabel(Text("\(count) spaces"))
        }
        .font(Typography.terminal)
        .padding(.horizontal, Layout.chatRowHorizontalPadding)
        .padding(.top, 14)
        .padding(.bottom, 6)
        .frame(maxWidth: .infinity)
        .background(.panel)
        .listRowInsets(EdgeInsets())
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isHeader)
    }

    // MARK: Results

    /// Matches stack up from the prompt, even when there are only a few; the best
    /// match is last, next to the prompt.
    private func results(_ found: [Space]) -> some View {
        GeometryReader { geometry in
            ScrollView {
                VStack(spacing: 0) {
                    Spacer(minLength: 0)
                    ForEach(Array(found.reversed().enumerated()), id: \.element.id) {
                        index, space in
                        row(space, isBest: index == found.count - 1)
                    }
                }
                .frame(minHeight: geometry.size.height, alignment: .bottom)
            }
            .defaultScrollAnchor(.bottom)
        }
    }

    // MARK: Rows and search

    private func row(_ space: Space, isBest: Bool = false) -> some View {
        ResultRow(isBest: isBest) {
            choose(space.id)
        } label: {
            if let identity = spaces.identity(space.identity) {
                IdentityChip(identity: identity)
                    .frame(width: Layout.chipSizeLarge)
            }
            SpaceName(space: space)
            Spacer(minLength: 0)
            if !space.isReachable {
                Text("offline").font(Typography.terminalSmall).foregroundStyle(.wax)
            } else {
                UnreadMark(
                    mentions: space.mentions, unread: space.unreadChats,
                    unreadLabel: Text("\(space.unreadChats) unread chats"))
            }
        }
        .listRowInsets(EdgeInsets())
        .listRowSeparator(.hidden)
        .listRowBackground(Color.clear)
        .contextMenu {
            FavouriteButton(isFavourite: space.isFavourite) { toggleFavourite(space) }
        }
    }

    /// The search field, with the count of spaces, or of `found` while searching.
    private func searchLine(found: [Space]?) -> some View {
        HStack(spacing: 10) {
            ForwardChevron()
                .font(Typography.prompt.weight(.bold))
                .foregroundStyle(.ink)
            TextField("find a space", text: $query)
                .font(Typography.prompt)
                .focused($isSearching)
                .autocorrectionDisabled()
                #if os(iOS)
                    .textInputAutocapitalization(.never)
                #endif
                .onSubmit {
                    if let best = found?.first { choose(best.id) }
                }
            Group {
                if let found {
                    Text("\(found.count) of \(spaces.spaces.count)")
                } else {
                    Text(spaces.spaces.count, format: .number)
                        .accessibilityLabel(Text("\(spaces.spaces.count) spaces"))
                }
            }
            .font(Typography.terminalSmall)
            .foregroundStyle(.textTertiary)
            .monospacedDigit()
            Button {
                dismiss()
            } label: {
                Text("Done")
                    .font(Typography.terminal)
                    .foregroundStyle(.textSecondary)
                    .minimumTouchTarget()
            }
            .buttonStyle(.plain)
        }
        .padding(.horizontal, Layout.chatRowHorizontalPadding)
        .frame(minHeight: Layout.minimumTouchTarget + 8)
        .background(.panel)
        .overlay(alignment: .top) { Rectangle().fill(.rule).frame(height: 1) }
    }

    private func choose(_ id: Space.ID) {
        select(id)
        dismiss()
    }
}

/// A section line in the chat list and the spaces page: a word, a rule to the edge,
/// then anything trailing, such as the filters.
struct SectionLine<Trailing: View>: View {
    let title: Text
    /// The line sticks to the top while its section scrolls, so it needs a fill.
    var fill: Color = .surface
    /// Whether `trailing` holds controls, which are full touch targets on iOS and so
    /// bring their own room above and below.
    var holdsControls = false
    @ViewBuilder var trailing: Trailing

    var body: some View {
        HStack(spacing: 10) {
            // A title never wraps or shrinks; the rule gives way first.
            title
                .foregroundStyle(.textTertiary)
                .lineLimit(1)
                .fixedSize()
                .accessibilityAddTraits(.isHeader)
            Rectangle()
                .fill(.rule)
                .frame(height: 1)
                .accessibilityHidden(true)
            trailing
        }
        .font(Typography.terminalSmall)
        .padding(.horizontal, Layout.chatRowHorizontalPadding)
        .padding(.top, holdsTouchTargets ? 3 : 12)
        .padding(.bottom, holdsTouchTargets ? 0 : 6)
        .frame(maxWidth: .infinity)
        .background(fill)
        .listRowInsets(EdgeInsets())
    }

    private var holdsTouchTargets: Bool {
        #if os(iOS)
            holdsControls
        #else
            false
        #endif
    }
}

extension SectionLine where Trailing == EmptyView {
    init(title: Text, fill: Color = .surface) {
        self.init(title: title, fill: fill) { EmptyView() }
    }
}

extension [Space] {
    /// The spaces that match `query`, best first; equal matches keep their order.
    func ranked(by query: MatchQuery) -> [Space] {
        query.ranked(self) { $0.rank(query) }
    }
}
