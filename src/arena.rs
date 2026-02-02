//! Arena allocation for FastGraph nodes.
//!
//! Provides `ArenaNodeId` (a dense, total-orderable identifier) and `NodeArena`
//! (contiguous storage with free-list reuse). The arena stores node data of a
//! generic type `T`.
//!
//! # Determinism
//! - `ArenaNodeId` ordering is by its inner `u32`.
//! - Iteration order over slots is by index (0..capacity).
//! - Free-list reuse may affect allocation order across runs, but NodeId
//!   generation is stable if the same sequence of allocations/deallocations
//!   occurs.

use std::fmt;
use std::hash::Hash;

/// Dense node identifier for arena-allocated graphs.
///
/// `ArenaNodeId(u32)` is `Copy`, `Eq`, `Ord`, `Hash`. The inner value is an
/// index into the arena's slot array. The value `0` and `1` are reserved for
/// extern pseudo-nodes (see `EXTERN_INPUTS_NODE`, `EXTERN_OUTPUTS_NODE`).
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArenaNodeId(u32);

impl ArenaNodeId {
    /// Creates a new `ArenaNodeId` from a raw `u32`.
    ///
    /// # Safety
    /// The caller must ensure the index is within bounds of the arena that will
    /// hold this node.
    #[inline]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw `u32` index.
    #[inline]
    pub const fn as_u32(&self) -> u32 {
        self.0
    }

    /// Maximum possible `ArenaNodeId` (for sentinel use).
    pub const MAX: ArenaNodeId = ArenaNodeId(u32::MAX);
}

impl fmt::Display for ArenaNodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ArenaNodeId({})", self.0)
    }
}

/// Reserved pseudo-node for external inputs.
///
/// This node acts as the source of all graph inputs. Its outgoing "ports"
/// (represented as edges in FastGraph) feed into internal nodes.
pub const EXTERN_INPUTS_NODE: ArenaNodeId = ArenaNodeId(0);

/// Reserved pseudo-node for external outputs.
///
/// This node acts as the sink of all graph outputs. Its incoming "ports"
/// (represented as edges in FastGraph) are fed by internal nodes.
pub const EXTERN_OUTPUTS_NODE: ArenaNodeId = ArenaNodeId(1);

/// Slot in the node arena.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct NodeSlot<T> {
    data: Option<T>,
    next_free: Option<u32>, // index of next free slot, if any
}

/// Contiguous storage for node data with free-list reuse.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct NodeArena<T> {
    slots: Vec<NodeSlot<T>>,
    free_list_head: Option<u32>,
    /// Number of live nodes (slots with `data.is_some()`).
    live_count: usize,
}

impl<T> NodeArena<T> {
    /// Creates a new empty arena.
    ///
    /// The arena initially contains the two reserved pseudo-nodes at indices
    /// 0 and 1, both initialized with `None` (no user data).
    pub fn new() -> Self {
        // Create slots for reserved indices 0 and 1.
        let mut slots = Vec::with_capacity(2);
        slots.push(NodeSlot { data: None, next_free: None });
        slots.push(NodeSlot { data: None, next_free: None });
        Self {
            slots,
            free_list_head: None,
            live_count: 0,
        }
    }

    /// Allocates a new slot and returns its `ArenaNodeId`.
    ///
    /// If a free slot is available, reuses it; otherwise pushes a new slot.
    /// The slot is initialized with `data`.
    ///
    /// # Determinism
    /// Free-list reuse order is deterministic: the first free slot in the list
    /// (which is the most recently freed) is used.
    pub fn allocate(&mut self, data: T) -> ArenaNodeId {
        if let Some(idx) = self.free_list_head {
            // Reuse free slot
            let slot = &mut self.slots[idx as usize];
            debug_assert!(slot.data.is_none(), "free slot should have no data");
            self.free_list_head = slot.next_free;
            slot.data = Some(data);
            slot.next_free = None;
            self.live_count += 1;
            ArenaNodeId(idx)
        } else {
            // Allocate new slot at the end
            let idx = self.slots.len() as u32;
            self.slots.push(NodeSlot {
                data: Some(data),
                next_free: None,
            });
            self.live_count += 1;
            ArenaNodeId(idx)
        }
    }

    /// Deallocates the slot identified by `id`.
    ///
    /// Returns `true` if the slot existed and was deallocated.
    /// The slot is added to the free list for future reuse.
    ///
    /// # Panics
    /// Panics if `id` is `EXTERN_INPUTS_NODE` or `EXTERN_OUTPUTS_NODE` (those
    /// slots must never be deallocated).
    pub fn deallocate(&mut self, id: ArenaNodeId) -> bool {
        assert!(
            id != EXTERN_INPUTS_NODE && id != EXTERN_OUTPUTS_NODE,
            "cannot deallocate reserved pseudo-nodes"
        );
        let idx = id.as_u32() as usize;
        if idx >= self.slots.len() {
            return false;
        }
        let slot = &mut self.slots[idx];
        if slot.data.is_none() {
            return false; // already free
        }
        slot.data = None;
        slot.next_free = self.free_list_head;
        self.free_list_head = Some(idx as u32);
        self.live_count -= 1;
        true
    }

    /// Returns a reference to the data stored at `id`, if present.
    pub fn get(&self, id: ArenaNodeId) -> Option<&T> {
        self.slots
            .get(id.as_u32() as usize)
            .and_then(|slot| slot.data.as_ref())
    }

    /// Returns a mutable reference to the data stored at `id`, if present.
    pub fn get_mut(&mut self, id: ArenaNodeId) -> Option<&mut T> {
        self.slots
            .get_mut(id.as_u32() as usize)
            .and_then(|slot| slot.data.as_mut())
    }

    /// Returns the number of live nodes (slots with data).
    pub fn live_count(&self) -> usize {
        self.live_count
    }

    /// Returns the total capacity (number of slots, including free ones).
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    /// Iterates over all live nodes in deterministic order (by index).
    ///
    /// Yields `(ArenaNodeId, &T)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (ArenaNodeId, &T)> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(idx, slot)| slot.data.as_ref().map(|data| (ArenaNodeId(idx as u32), data)))
    }

    /// Iterates over all live nodes mutably in deterministic order.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (ArenaNodeId, &mut T)> {
        self.slots
            .iter_mut()
            .enumerate()
            .filter_map(|(idx, slot)| slot.data.as_mut().map(|data| (ArenaNodeId(idx as u32), data)))
    }
}

impl<T> Default for NodeArena<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arena_basic() {
        let mut arena: NodeArena<&'static str> = NodeArena::new();
        assert_eq!(arena.live_count(), 0);
        assert_eq!(arena.capacity(), 2); // reserved slots

        let id1 = arena.allocate("hello");
        assert_eq!(id1.as_u32(), 2);
        assert_eq!(arena.live_count(), 1);
        assert_eq!(arena.get(id1), Some(&"hello"));

        let id2 = arena.allocate("world");
        assert_eq!(id2.as_u32(), 3);
        assert_eq!(arena.live_count(), 2);

        arena.deallocate(id1);
        assert_eq!(arena.live_count(), 1);
        assert_eq!(arena.get(id1), None);

        let id3 = arena.allocate("reused");
        assert_eq!(id3.as_u32(), 2); // reused freed slot
        assert_eq!(arena.live_count(), 2);
        assert_eq!(arena.get(id3), Some(&"reused"));
    }

    #[test]
    fn deterministic_iteration() {
        let mut arena: NodeArena<i32> = NodeArena::new();
        let ids: Vec<_> = (0..5).map(|i| arena.allocate(i)).collect();
        // Deallocate some to create free list
        arena.deallocate(ids[1]);
        arena.deallocate(ids[3]);
        // Reallocate, which will reuse free slots in LIFO order
        let _id_new1 = arena.allocate(100);
        let _id_new2 = arena.allocate(200);
        // Iteration order should be by index regardless of allocation order
        let collected: Vec<_> = arena.iter().map(|(id, &val)| (id.as_u32(), val)).collect();
        let expected = vec![(2, 0), (3, 200), (4, 2), (5, 100), (6, 4)];
        assert_eq!(collected, expected);
    }

    #[test]
    #[should_panic(expected = "cannot deallocate reserved pseudo-nodes")]
    fn cannot_deallocate_reserved() {
        let mut arena: NodeArena<()> = NodeArena::new();
        arena.deallocate(EXTERN_INPUTS_NODE);
    }
}