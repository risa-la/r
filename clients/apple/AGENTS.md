# Apple client

- Shared SwiftUI app for iOS 18+ and macOS 15+, built with Xcode 27.2 / Swift
  6.4.2 in Swift 6 mode. Use modern Swift where it helps; check API availability.
- The committed `Risala.xcodeproj` owns targets, settings, and schemes. Sources,
  Resources, and Tests use synchronized folders; no project generation step.
  Use the Nix-pinned SweetPad CLI for builds and tests (see `README.md`).
  Tests run hosted in the app through `@testable import Risala`.
- Keep protocol logic, persistence, and history caching in librisala. The client
  owns presentation and a thin library adapter. No demo data in Release builds:
  preview data lives in `Development/` (`DEVELOPMENT_ASSET_PATHS`), behind `#if DEBUG`.
- Use lightweight MVVM by feature: views own layout and temporary UI state;
  observable feature models (`*ViewModel`) own presentation, actions, and
  subscription lifetimes. Plain data types keep domain names (`Chat`, `Message`).
  Keep features under `Sources/Features`, the adapter under `Sources/Client`,
  and composition under `Sources/App`. Navigation and feature models belong to
  each window; share only the library session. Preserve drafts across chat switches.
- Use `@Observable`, `@State`, and `@Bindable`. The app target defaults to
  MainActor isolation with approachable concurrency, so omit `@MainActor` there.
  Mark adapter-boundary types `nonisolated` and `Sendable`; run blocking FFI or
  storage work in `@concurrent` functions. Prefer value types and checked
  `Sendable` boundaries over unsafe workarounds.
- Prefer structured async/await, view-owned `.task` work, and cancellation-aware
  cleanup. Model distinct UI states with enums.
- Prefer Swift Testing for unit tests and XCUITest for UI automation.

## Startup

Keep initializers and view bodies cheap. Follow the startup integration contract
in `README.md`: render before network work, read bounded library-cache snapshots,
retain content during sync, and keep blocking FFI/storage work off MainActor.
Measure responsive launch and useful cached content separately in Release builds.

## Localization

- Maintain English and Arabic in `Resources/Localizable.xcstrings`, including
  accessibility labels. App names belong in `Resources/InfoPlist.xcstrings`.
- Pass literals directly to SwiftUI views, without explicit `LocalizedStringKey`
  wrappers. Branch between literal views for conditional copy; interpolate whole
  sentences and use plural forms for counts. Leave user/server content unchanged.
- Follow system language and native RTL layout with leading/trailing alignment.
  Check both languages, mixed-direction text, Dynamic Type, and VoiceOver.

## Design

Keep typography, color, and layout roles in `Sources/Design`, reusable
view styling in `Sources/Design/Styles`, and views shared across features
(identity chip, mode bar, Hudhud) in `Sources/Design/Components`. Use these roles
in feature views; keep feature-specific components with their feature. Preserve
native controls and semantic fonts/colors. Avoid fixed RGB values in views.

The app is moving to the terminal look in the Paper file's TUI mockups: framed
panels, JetBrains Mono, and a breadcrumb heading. The mode shows in the mode bar
at the bottom (`ModeBar`): the mode, a prompt, and the person's identity chips. It
never carries connection or other status, which stays on the rows it concerns. The
chat list sets names and messages in the system face and everything structural
(times, counts, servers, tabs, filters) in JetBrains Mono. JetBrains Mono has no
Arabic, and its fallback breaks Arabic letters apart: Arabic user content goes
through `Text(terminal:)`, and an Arabic interface uses the system face for the
terminal roles (`Typography`). Its colors live
in `Resources/Assets.xcassets/Palette` with light and dark variants; dark values
come from the mockups. Name colorsets by role and use Xcode's generated symbols
(`.foregroundStyle(.textTertiary)`) rather than wrapping them; avoid names
SwiftUI already uses, such as `selection`. Text colors must reach 4.5:1 on `Panel` in both
appearances, so adjust a value rather than ship low-contrast text. JetBrains Mono is bundled in
`Resources/Fonts` under OFL-1.1 (see `REUSE.toml`) and declared in `Info.plist`
(`UIAppFonts` for iOS); to use another weight, add its file to both. Screens move to
the terminal roles one at a time; until then they keep the hierarchical roles.

## Settings

Appearance follows the system unless the person picks light or dark. Preferences
live in user defaults and are read with `@AppStorage`. macOS shows them in the
`Settings` scene; iOS shows them in the system Settings app through
`Resources/Settings.bundle` (iOS only, by a platform filter in the project).
Keep the two in step: same keys, values, and English/Arabic titles.

## Accessibility and formatting

- Use semantic fonts, flexible layouts, and native controls. Give icon-only
  actions accessible labels and touch targets of at least 44×44 points on iOS.
  Support keyboard navigation, visible focus, and VoiceOver reading order.
  Check accessibility text sizes; never communicate status by color alone.
- Use the Xcode toolchain's swift-format with the committed `.swift-format`.
  See `README.md` for formatting commands; no separate linter.

## Tests

Follow the testing strategy in `README.md`. Use focused tests for isolated
boundaries, seeded model tests for state sequences, integration tests for the
library contract, and a few UI flows for wiring. Reuse `Tests/Support`; keep
feature invariants in feature suites. Name the distinct failure each new test
catches, extend existing coverage where possible, and remove redundant examples.
Keep regression tests only when they add a clear reproduction or coverage gap.

## Documentation

Document decisions, constraints, and workflows. Code owns implementation details
and current behavior; avoid duplicating them or recording temporary integration status.

## Pull requests

Use `.github/PULL_REQUEST_TEMPLATE/apple-client.md` and follow its screenshot
requirements. Build both platforms and report any validation not performed.
