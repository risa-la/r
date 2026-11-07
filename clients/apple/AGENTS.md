# Apple client

- Shared SwiftUI app for iOS 18+ and macOS 15+, built with Xcode 27.2 / Swift
  6.4.2 in Swift 6 mode. Use modern Swift where it helps; check API availability.
- Xcode folders are synchronized: files under `Sources`, `Resources`, and `Tests`
  join their target without project edits. Tests run hosted in the app through
  `@testable import Risala`.
- Keep protocol logic, persistence, and history caching in librisala. The client
  owns presentation and a thin library adapter. No demo data.
- Use lightweight MVVM by feature: views own layout and temporary UI state;
  observable feature models (`*ViewModel`) own presentation, actions, and
  subscription lifetimes. Plain data types keep domain names (`Room`, `Message`).
  Keep features under `Sources/Features`, the adapter under `Sources/Client`,
  and composition under `Sources/App`. Navigation and feature models belong to
  each window; share only the library session. Preserve drafts across room switches.
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

Keep typography, color, and layout roles in `Sources/Design` and reusable
view styling in `Sources/Design/Styles`. Use these roles in feature views; keep
feature components with their feature. Preserve native controls and semantic
fonts/colors. Add asset-catalog colors with appearance variants when branding
requires them; avoid fixed RGB values in views.

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
