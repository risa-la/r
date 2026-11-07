import SwiftUI

// Hierarchical styles adapt to the surrounding native control and appearance.
// Screens not yet on the terminal surface keep using them.
//
// Terminal surface colors are the asset catalog's Palette folder, named by role
// and used through Xcode's generated symbols, e.g. `.foregroundStyle(.textTertiary)`.
// Each has light and dark variants; text roles meet 4.5:1 on `panel`. Pair
// status colors (`wax`, `presence`, `mention`) with a word or symbol.
enum Colors {
    static let content: HierarchicalShapeStyle = .primary
    static let supportingContent: HierarchicalShapeStyle = .secondary
}
