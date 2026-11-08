import SwiftUI

/// Every chat on every identity and space, newest activity first. On the phone,
/// space tabs run across the top and the mode bar waits at the bottom; in a pane,
/// the window's top bar holds the tabs, and the pane has a header and its own prompt.
/// The filters sit on the first section line, which sticks while the list scrolls.
/// Loading, failure, and the empty state show here too, in place of the rows.
struct ChatsView: View {
    /// The whole screen on the phone, or the list pane beside a chat on large screens.
    enum Placement {
        case screen
        case pane(isFocused: Bool)
    }

    #if os(iOS)
        @Environment(\.horizontalSizeClass) private var horizontalSizeClass
    #endif
    @Bindable var model: ChatsViewModel
    @Binding var selection: Chat.ID?
    /// Whether the mode bar is the command line; what is typed is `model.command`.
    /// The window owns it, so ⌘K reaches it and a layout change keeps it.
    @Binding var isCommanding: Bool
    /// Whether the spaces page shows; the window owns it, for the top bar's link.
    @Binding var showsSpaces: Bool
    var placement = Placement.screen

    @FocusState private var isCommandFocused: Bool
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        Group {
            if let status {
                ChatsStatusView(
                    status: status, retry: model.retry, start: beginCommand,
                    browseSpaces: { showsSpaces = true })
            } else {
                list
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(fill)
        // Behind the command line, the list is out of reach for VoiceOver as for touch.
        .accessibilityHidden(isCommanding)
        .safeAreaInset(edge: .top, spacing: 0) {
            VStack(spacing: 0) {
                if isPane {
                    PaneHeader()
                }
                // Empty states show neither tabs nor filters.
                if !isPane, !model.hasNoChats, model.state != .disconnected {
                    SpaceTabs(
                        spaces: model.spaces, selection: $model.filter.space,
                        showAll: { showsSpaces = true }, toggleFavourite: model.toggleFavourite)
                }
                if model.isInterrupted {
                    interruptedLine
                }
            }
            .background(fill)
        }
        // The list stays put behind the command line, dimmed; tapping it, or VoiceOver's
        // escape, puts the command line away.
        .overlay {
            if isCommanding {
                Color.scrim
                    .ignoresSafeArea()
                    .onTapGesture { endCommand() }
                    .transition(.opacity)
                    .accessibilityElement()
                    .accessibilityLabel(Text("Close the command line"))
                    .accessibilityAddTraits(.isButton)
                    .accessibilityAction { endCommand() }
                    .accessibilityAction(.escape) { endCommand() }
            }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            VStack(spacing: 0) {
                // With nothing typed and nothing recent, there is nothing to show yet.
                if isCommanding,
                    !model.commandItems.isEmpty
                        || !model.command.trimmingCharacters(in: .whitespaces).isEmpty
                {
                    CommandResults(
                        items: model.commandItems, spaces: model.spaces, query: model.command,
                        choose: choose
                    )
                    .accessibilityAction(.escape) { endCommand() }
                    .transition(
                        reduceMotion
                            ? .opacity
                            : .asymmetric(
                                insertion: .move(edge: .bottom).combined(with: .opacity),
                                removal: .opacity))
                }
                modeBar
            }
            .animation(motion, value: isCommanding ? model.commandItems : [])
        }
        // The window can put the command line away too, such as when the chat pane
        // takes the focus.
        .onChange(of: isCommanding) {
            if !isCommanding, isCommandFocused || !model.command.isEmpty { endCommand() }
        }
        // Every chat, not only the rows loaded, for what is typed.
        .task(id: isCommanding ? model.command : nil) {
            if isCommanding { await model.searchCommand() }
        }
        .navigationTitle("Chats")
        .toolbarTitleDisplayMode(.inline)
        #if os(iOS)
            // The tabs name where you are on iPhone; iPad keeps its sidebar controls.
            .toolbarVisibility(
                horizontalSizeClass == .compact ? .hidden : .automatic, for: .navigationBar
            )
            .fullScreenCover(isPresented: isPane ? .constant(false) : $showsSpaces) { spacesPage }
            .sheet(isPresented: isPane ? $showsSpaces : .constant(false)) { spacesPage }
        #else
            .sheet(isPresented: $showsSpaces) { spacesPage.frame(minWidth: 420, minHeight: 560) }
        #endif
    }

    private var isPane: Bool {
        if case .pane = placement { return true }
        return false
    }

    /// The list sits on the window's surface on the phone, and on a panel in a pane.
    private var fill: Color {
        isPane ? .panel : .surface
    }

    /// The mode shows in the pane that has the focus, and always on the phone.
    private var showsMode: Bool {
        switch placement {
        case .screen: true
        case .pane(let isFocused): isFocused || isCommanding
        }
    }

    /// The mode bar on a surface that reaches the bottom edge, with the list fading
    /// out above it.
    private var modeBar: some View {
        ModeBar(
            mode: !showsMode
                ? nil : isCommanding ? Text(verbatim: "INS") : Text(verbatim: "NOR"),
            modeColor: isCommanding ? .presence : .mode,
            prompt: Text("find or start"),
            text: $model.command,
            isEditing: isCommanding,
            isFocused: $isCommandFocused,
            identities: model.spaces.identities.sorted { $0.isMain && !$1.isMain },
            activate: beginCommand,
            submit: { model.commandItems.first.map(choose) },
            cancel: endCommand,
            // In a pane the window's top bar shows the identities; ⌘K finds the prompt.
            shortcut: isPane ? Text(verbatim: "⌘K") : nil,
            cornerRadius: isPane ? 12 : Layout.panelCornerRadius
        )
        .padding(.top, 6)
        .padding(.bottom, isPane ? 4 : 0)
        .background {
            fill
                .overlay(alignment: .top) {
                    LinearGradient(
                        colors: [fill.opacity(0), fill], startPoint: .top,
                        endPoint: .bottom
                    )
                    .frame(height: 24)
                    .offset(y: -24)
                }
                .ignoresSafeArea(edges: .bottom)
        }
    }

    /// Following the list stopped: said once, small, with the rows still readable.
    private var interruptedLine: some View {
        HStack(spacing: 10) {
            Text("Chats aren’t updating.")
                .foregroundStyle(.textSecondary)
            Spacer(minLength: 0)
            TryAgainButton(action: model.retry)
        }
        .font(Typography.terminalSmall)
        .lineLimit(2)
        .padding(.horizontal, Layout.chatRowHorizontalPadding)
    }

    // MARK: Command line

    /// Springy where motion is welcome; a short crossfade under Reduce Motion.
    static func commandLineMotion(reduceMotion: Bool) -> Animation {
        reduceMotion ? .easeInOut(duration: 0.15) : .spring(response: 0.34, dampingFraction: 0.86)
    }

    private var motion: Animation { Self.commandLineMotion(reduceMotion: reduceMotion) }

    /// The field takes focus as it appears in the mode bar.
    private func beginCommand() {
        withAnimation(motion) { isCommanding = true }
    }

    private func endCommand() {
        isCommandFocused = false
        withAnimation(motion) {
            isCommanding = false
            model.endCommand()
        }
    }

    private func choose(_ item: CommandItem) {
        switch item {
        case .chat(let chat): selection = chat.id
        case .space(let space): model.filter.space = space.id
        }
        endCommand()
    }

    private var spacesPage: some View {
        SpacesView(
            spaces: model.spaces, select: { model.filter.space = $0 },
            toggleFavourite: model.toggleFavourite)
    }

    /// What to show instead of rows, if anything.
    private var status: ChatsStatusView.Status? {
        switch model.state {
        case .disconnected: .noChats
        case .loaded: model.hasNoChats ? .noChats : nil
        case .idle, .loading: model.chats.isEmpty ? .loading : nil
        case .failed: model.chats.isEmpty ? .failed : nil
        }
    }

    // MARK: List

    /// The chats in time sections, in list order.
    private func sections(now: Date) -> [(ChatSection, [Chat])] {
        var result: [(ChatSection, [Chat])] = []
        for chat in model.chats {
            let section = ChatSection(chat.lastActivity, now: now)
            if result.last?.0 == section {
                result[result.count - 1].1.append(chat)
            } else {
                result.append((section, [chat]))
            }
        }
        return result
    }

    /// One clock for every row's time and the sections, so a chat moves out of
    /// "today" at midnight.
    private var list: some View {
        TimelineView(.everyMinute) { context in
            // In a pane, rows are buttons: the Mac's list selection would paint the
            // open chat in the system accent rather than the pane's own tint.
            List(selection: isPane ? .constant(nil) : $selection) {
                let sections = sections(now: context.date)
                if sections.isEmpty {
                    // The filters leave nothing; keep them in reach to turn off.
                    Section {
                        noMatches
                    } header: {
                        sectionLine(Text("today"), holdsFilters: true)
                    }
                }
                ForEach(Array(sections.enumerated()), id: \.element.0) { index, entry in
                    Section {
                        ForEach(entry.1) { chat in
                            row(chat, now: context.date)
                        }
                    } header: {
                        sectionLine(entry.0.title, holdsFilters: index == 0)
                    }
                }
            }
            .listStyle(.plain)
            #if os(iOS)
                .listSectionSpacing(0)
            #endif
            // The section line is the only rule; the Mac would add one under it.
            .listSectionSeparator(isPane ? .hidden : .automatic)
            .contentMargins(.top, 0, for: .scrollContent)
            .scrollContentBackground(.hidden)
            .environment(\.defaultMinListHeaderHeight, 0)
        }
    }

    private func row(_ chat: Chat, now: Date) -> some View {
        Group {
            if isPane {
                Button {
                    selection = chat.id
                } label: {
                    chatRow(chat, now: now)
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(selection == chat.id ? .isSelected : [])
            } else {
                chatRow(chat, now: now)
            }
        }
        .tag(chat.id)
        .listRowInsets(EdgeInsets())
        .listRowSeparator(.hidden)
        .listRowBackground(rowBackground(isSelected: selection == chat.id))
        .contextMenu {
            FavouriteButton(isFavourite: chat.isFavourite) { model.toggleFavourite(chat) }
        }
        .onAppear {
            if chat.id == model.chats.last?.id {
                Task { await model.loadMore() }
            }
        }
    }

    /// A section line; the first one holds the filters.
    private func sectionLine(_ title: Text, holdsFilters: Bool) -> some View {
        SectionLine(title: title, fill: fill, holdsControls: holdsFilters) {
            if holdsFilters {
                ChatFilterSwitches(filter: $model.filter, counts: model.counts)
            }
        }
    }

    private func chatRow(_ chat: Chat, now: Date) -> ChatRow {
        ChatRow(
            chat: chat, identity: model.chip(for: chat),
            isReachable: model.isReachable(chat.space), now: now
        )
    }

    /// The open chat's row: a panel on the phone's surface; in a pane, which is a
    /// panel already, a rounded ink tint.
    @ViewBuilder
    private func rowBackground(isSelected: Bool) -> some View {
        if !isSelected {
            Color.clear
        } else if isPane {
            RoundedRectangle(cornerRadius: Layout.rowCornerRadius)
                .fill(Color.ink.opacity(0.14))
                .padding(.horizontal, 8)
        } else {
            Color.panel
        }
    }

    /// The filters leave nothing to show; the chats themselves are fine.
    private var noMatches: some View {
        Text("No chats match these filters.")
            .font(Typography.terminal)
            .foregroundStyle(.textTertiary)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, Layout.chatRowHorizontalPadding)
            .padding(.vertical, 16)
            .listRowInsets(EdgeInsets())
            .listRowSeparator(.hidden)
            .listRowBackground(Color.clear)
    }
}

/// The list pane's header: `≡ chats`.
private struct PaneHeader: View {
    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "line.3.horizontal")
                .font(.footnote)
                .foregroundStyle(.textSecondary)
                .accessibilityHidden(true)
            Text("chats")
                .font(Typography.paneTitle)
                .foregroundStyle(.text)
                .lineLimit(1)
                .accessibilityAddTraits(.isHeader)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 14)
        .frame(height: Layout.paneHeaderHeight)
    }
}

/// The switches on the first section line: mentions, unread, favourites, rooms. With
/// none on, the list shows everything in the tab. An "on" switch is in reverse video.
struct ChatFilterSwitches: View {
    @Binding var filter: ChatFilter
    let counts: ChatCounts

    var body: some View {
        HStack(spacing: Self.spacing) {
            if counts.mentions > 0 || filter.mentions {
                toggle(isOn: $filter.mentions, fill: .mention, offStyle: .mention) {
                    Text("@ \(Text(count: counts.mentions))")
                }
                .accessibilityLabel(Text("Mentions"))
                .accessibilityValue(Text("\(counts.mentions) unread"))
            }
            toggle(isOn: $filter.unread) { unreadLabel }
                .accessibilityLabel(Text("Unread"))
                .accessibilityValue(Text("\(counts.unreadChats) chats"))
            toggle(isOn: $filter.favourites) { Text("favs") }
                .accessibilityLabel(Text("Favourites"))
            toggle(isOn: $filter.rooms) { Text("rooms") }
                .accessibilityLabel(Text("Rooms"))
        }
        .lineLimit(1)
        .fixedSize()
    }

    /// Each switch is a full touch target on iOS, which leaves room between them.
    private static var spacing: CGFloat {
        #if os(iOS)
            4
        #else
            12
        #endif
    }

    private var unreadLabel: Text {
        guard counts.unreadChats > 0, !filter.unread else { return Text("unread") }
        let count = Text(count: counts.unreadChats).foregroundStyle(.ink)
        return Text("unread \(count)")
    }

    /// A switch: `label` in `offStyle` while off, in reverse video on `fill` while on.
    private func toggle(
        isOn: Binding<Bool>, fill: Color = .ink, offStyle: Color = .textSecondary,
        label: () -> Text
    ) -> some View {
        Button {
            isOn.wrappedValue.toggle()
        } label: {
            Group {
                if isOn.wrappedValue {
                    label()
                        .fontWeight(.heavy)
                        .foregroundStyle(.onInk)
                        .padding(.horizontal, 5)
                        .background(fill, in: .rect(cornerRadius: 4))
                } else {
                    label()
                        .foregroundStyle(offStyle)
                }
            }
            .monospacedDigit()
            .padding(.vertical, 6)
            .minimumTouchTarget()
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(isOn.wrappedValue ? .isSelected : [])
    }
}

#if DEBUG
    /// The chat list alone, observing as `RootView` does in the app.
    private struct ChatsPreview: View {
        @State private var model: ChatsViewModel
        @State private var selection: Chat.ID?
        @State private var isCommanding = false
        @State private var showsSpaces = false

        init(_ scenario: PreviewChatClient.Scenario) {
            _model = State(initialValue: ChatsViewModel(client: PreviewChatClient(scenario)))
        }

        var body: some View {
            ChatsView(
                model: model, selection: $selection, isCommanding: $isCommanding,
                showsSpaces: $showsSpaces
            )
            .task(id: model.observationID) { await model.observe() }
            .task { await model.observeSpaces() }
        }
    }

    #Preview("Busy") { ChatsPreview(.busy) }
    #Preview("Worst case") { ChatsPreview(.worstCase) }
    #Preview("Arabic") {
        ChatsPreview(.arabic)
            .environment(\.locale, Locale(identifier: "ar"))
            .environment(\.layoutDirection, .rightToLeft)
    }
    #Preview("Accessibility text") {
        ChatsPreview(.busy)
            .environment(\.dynamicTypeSize, .accessibility3)
    }
    #Preview("Empty") { ChatsPreview(.empty) }
    #Preview("Loading") { ChatsPreview(.loading) }
    #Preview("Failed") { ChatsPreview(.failed) }
#endif
