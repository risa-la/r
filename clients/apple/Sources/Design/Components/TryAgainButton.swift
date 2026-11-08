import SwiftUI

/// `Try again` in bold ink, after a short line that says what failed.
struct TryAgainButton: View {
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text("Try again").fontWeight(.bold).foregroundStyle(.ink).minimumTouchTarget()
        }
        .buttonStyle(.plain)
    }
}
