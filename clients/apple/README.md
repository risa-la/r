# Risala for Apple platforms

Risala’s iOS and macOS client, built with SwiftUI.

## Build

```sh
xcodebuild -project clients/apple/Risala.xcodeproj -scheme Risala \
  -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO build
xcodebuild -project clients/apple/Risala.xcodeproj -scheme Risala \
  -destination 'generic/platform=iOS Simulator' CODE_SIGNING_ALLOWED=NO build
```

Run these from the repository root.

## Pull requests

Use the [Apple client PR template](../../.github/PULL_REQUEST_TEMPLATE/apple-client.md).

## Formatting

```sh
cd clients/apple
xcrun swift-format format --in-place --recursive Sources Tests
xcrun swift-format lint --strict --recursive Sources Tests
```

## Manual UI checks

Set the scheme's Run > Options > App Language to English or Arabic. Check RTL
navigation, mixed-language content, accessibility text sizes, keyboard navigation,
and VoiceOver labels and reading order on both platforms. Previews help review
layout but do not replace runtime checks.

## Model tests

```sh
xcodebuild -project clients/apple/Risala.xcodeproj -scheme Risala \
  -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO test
```

For iOS, choose an installed simulator as the test destination.

## Testing strategy

Use the cheapest test that catches the failure; test behavior, not implementation.

- **Unit tests:** isolated rules and boundaries.
- **Seeded model tests:** state transitions and interacting action sequences.
- **Integration tests:** the library adapter contract.
- **UI tests:** a few critical journeys to verify view wiring; bounded exploration
  for crashes under unexpected interaction.
- **Screenshots and accessibility checks:** layout, locales, text sizes, keyboard,
  and VoiceOver. Use pixel assertions only when exact appearance is a requirement.

Each test should catch a distinct failure. Extend existing coverage instead of
repeating the same cases across layers. Keep focused regressions when they add
coverage or a clearer reproduction; skip trivial getters and system behavior.

Keep reusable test support in `Tests/Support` and feature invariants in their
suites. Randomized failures must include a seed and action trace for replay.
Replay the seed's case in Xcode or narrow `RandomizedRun.seeds`; reduce failing
sequences when useful. Synchronize async tests on events, avoid sleeps and polling,
and use timeouts. Keep generated data and helpers in the test target.

## Startup integration contract

Client requirements to coordinate with the librisala lane; these do not specify
binding signatures.

| Capability | Required behavior at the Apple adapter boundary |
| --- | --- |
| Initial rooms | Return local room summaries without waiting for connection/authentication/sync. Distinguish no cached rooms from unavailable or failed storage. Paginate large room collections. |
| Initial timeline | Read a bounded recent page for the selected room. Start with a requested limit of 50; the library enforces a maximum and returns an opaque older-page cursor. |
| Older messages | Fetch only when requested. Preserve library-provided ordering and stable identifiers; do not rebuild history or generate replacement IDs in Swift. |
| Live updates | Provide an ordered snapshot plus subsequent changes without a subscription gap. Define revision/reset behavior so reconnects cannot silently miss or duplicate updates. Bound buffering and provide a resnapshot path if a consumer falls behind. |
| Connection status | Report connection/sync progress separately from cached content. Reconnecting or refresh failure must not blank an already-readable timeline. |
| Cancellation | Cancel obsolete page reads/subscriptions when changing rooms or closing windows. Discard late results from previous selections. Cancelling one window must not tear down the shared session. |
| Execution | No blocking storage/FFI work on MainActor. Async APIs must actually suspend or execute work on the library executor; async syntax alone is insufficient. |
| Shared lifetime | One library session per account/server context, shared across windows. Each window owns its navigation, presentation, and subscriptions. |

Startup order: show native navigation, obtain cached room summaries, restore a
valid selection and load its recent page, then apply synchronization updates.
Network connection may start concurrently but must never gate cached content.
An empty cache should still leave the shell responsive. If migrations or storage
recovery prevent a read, show that local loading/error state without blocking UI.
Defer older history, attachments, indexing, and unrelated rooms' timelines.

### Performance validation

Measure Release builds without a debugger on iOS devices and Macs. Track launch
responsiveness and time to useful cached content separately.

Establish baselines from repeated samples, recording device, OS, and build. Cover
fresh and repeat launches, offline use, large caches, migrations, and additional
Mac windows before setting regression thresholds.
