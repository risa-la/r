import Foundation

/// One change to a list the library keeps, to apply in order. Indices refer to the
/// items as they are after the changes before it.
nonisolated enum ListChange<Element: Hashable & Sendable>: Hashable, Sendable {
    /// Replaces every item, such as after a reconnect or when the consumer fell behind.
    case reset([Element])
    /// Inserts an item; later items move up.
    case insert(Element, at: Int)
    /// Replaces the item at an index with a newer state of the same item; the ID stays.
    case update(Element, at: Int)
    /// Removes the item at an index; later items move down.
    case remove(at: Int)
}

extension Array where Element: Identifiable & Hashable & Sendable {
    /// The items after `changes`, or `nil` when a change does not fit them. Rows are
    /// keyed by ID, so a repeated ID also counts as not fitting.
    nonisolated func applying(_ changes: [ListChange<Element>]) -> [Element]? {
        var items = self
        for change in changes {
            switch change {
            case .reset(let all):
                items = all
            case .insert(let item, let index):
                guard (0...items.count).contains(index) else { return nil }
                items.insert(item, at: index)
            case .update(let item, let index):
                guard items.indices.contains(index), items[index].id == item.id else {
                    return nil
                }
                items[index] = item
            case .remove(let index):
                guard items.indices.contains(index) else { return nil }
                items.remove(at: index)
            }
        }
        guard Set(items.map(\.id)).count == items.count else { return nil }
        return items
    }
}
