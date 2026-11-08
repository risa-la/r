## Changes

<!-- Describe the Apple client problem and resulting behavior in clients/apple.
     Persistence, history caching, and protocol logic remain library-owned. -->

## Validation

<!-- Record results, including device/OS versions. Mark checks not run explicitly. -->

- iOS build (minimum deployment target: iOS 18):
- macOS build:
- Runtime checks:

## Screenshots

<!-- Capture and inspect the running app's final UI on iPhone and macOS.
     Use real app state; do not add seeded data for screenshots.
     Recapture affected screens after further UI edits.
     Attach PNGs with `gh pr create/edit --attach` or the GitHub editor.
     Verify they render inline; keep PNGs out of tracked source.
     If upload or a runtime is unavailable, explicitly report what is pending.
     Label each image with device, OS version, and screen/state.
     Include before/after for existing screens when practical.
     Show dark and light appearance for each affected screen.
     Add iPad captures when its layout is affected.
     For localization changes, include English and Arabic RTL coverage.
     For non-UI changes, replace this section with "Not applicable: <reason>".

     Always lay screenshots out in a table, never one under another: a column
     per appearance or state (dark/light, before/after, English/Arabic) and a
     row per screen. Give each image a fixed width with
     <img src="…" width="…" alt="…"> so the columns line up: about 200 for
     iPhone, 300 for macOS, 420 for iPad. Put the device and OS version under
     the heading, and the screen and state in the column headers.
     -->

### iPhone

<!-- Device, OS version. -->

| Screen, dark | Screen, light |
| --- | --- |
| <!-- img --> | <!-- img --> |

### macOS

<!-- macOS version. -->

| Screen, dark | Screen, light |
| --- | --- |
| <!-- img --> | <!-- img --> |

## Library integration

<!-- Note any required librisala API or binding changes, or write "None".
     Identify unavailable integration behavior without implementing library
     responsibilities in the client. -->
