//! Deterministic worklist normalizer.
//!
//! The normalizer processes nodes in deterministic order, checking local
//! patterns and applying validated rewrites. It guarantees that the same
//! graph and doctrine produce the same sequence of rewrite steps across runs.

use crate::arena::ArenaNodeId;
use crate::doctrine::ext::ExtendedDoctrine;
use crate::graph::fast::FastGraph;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashSet};

/// Kind of rewrite rule.
///
/// This is a placeholder for PR1; actual rewrite kinds will be defined when
/// rewrite patterns are implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RewriteKind {
    /// No‑operation rewrite (benchmark placeholder).
    NoOp,
    // Future kinds: ComposeAssoc, TensorUnit, etc.
}

/// A candidate rewrite localized to a specific node.
#[derive(Debug, Clone)]
pub struct LocalCandidate {
    /// Kind of rewrite.
    pub rewrite_kind: RewriteKind,
    /// Primary node where the rewrite is focused.
    pub focus_node: ArenaNodeId,
    /// Secondary node involved (if any).
    pub secondary_node: Option<ArenaNodeId>,
    /// Port index involved (if any).
    pub port_idx: Option<u16>,
    /// Hash of the pattern matched (used as final tie‑breaker).
    pub pattern_hash: u64,
}

impl LocalCandidate {
    /// Creates a new candidate with minimal fields.
    pub fn new(rewrite_kind: RewriteKind, focus_node: ArenaNodeId) -> Self {
        Self {
            rewrite_kind,
            focus_node,
            secondary_node: None,
            port_idx: None,
            pattern_hash: 0,
        }
    }
}

/// Total ordering as required by spec (§6.2).
///
/// Order key:
/// 1. `rewrite_kind`
/// 2. `focus_node`
/// 3. `secondary_node` with `None := MAX`
/// 4. `port_idx` with `None := MAX`
/// 5. `pattern_hash`
impl Ord for LocalCandidate {
    fn cmp(&self, other: &Self) -> Ordering {
        (
            self.rewrite_kind,
            self.focus_node,
            self.secondary_node.unwrap_or(ArenaNodeId::MAX),
            self.port_idx.unwrap_or(u16::MAX),
            self.pattern_hash,
        )
            .cmp(&(
                other.rewrite_kind,
                other.focus_node,
                other.secondary_node.unwrap_or(ArenaNodeId::MAX),
                other.port_idx.unwrap_or(u16::MAX),
                other.pattern_hash,
            ))
    }
}

impl PartialOrd for LocalCandidate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for LocalCandidate {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for LocalCandidate {}

/// Deterministic worklist normalizer.
pub struct WorklistNormalizer {
    /// Nodes to process, ordered by ascending `ArenaNodeId`.
    worklist: BinaryHeap<std::cmp::Reverse<ArenaNodeId>>,
    /// Nodes that have been modified since last processed.
    dirty: HashSet<ArenaNodeId>,
    /// Local candidate buffer reused per step.
    local_buf: Vec<LocalCandidate>,
}

impl WorklistNormalizer {
    /// Creates a new empty normalizer.
    pub fn new() -> Self {
        Self {
            worklist: BinaryHeap::new(),
            dirty: HashSet::new(),
            local_buf: Vec::with_capacity(4),
        }
    }

    /// Adds a node to the worklist (marks it dirty).
    ///
    /// If the node is already dirty, nothing changes.
    /// Nodes are added in deterministic order (the worklist is a min‑heap).
    pub fn mark_dirty(&mut self, node: ArenaNodeId) {
        if self.dirty.insert(node) {
            self.worklist.push(std::cmp::Reverse(node));
        }
    }

    /// Marks all given nodes as dirty (deterministic order).
    pub fn mark_dirty_all<I>(&mut self, nodes: I)
    where
        I: IntoIterator<Item = ArenaNodeId>,
    {
        let mut sorted: Vec<ArenaNodeId> = nodes.into_iter().collect();
        sorted.sort();
        for node in sorted {
            self.mark_dirty(node);
        }
    }

    /// Performs a single normalization step.
    ///
    /// Returns `true` if a rewrite was applied, `false` if the worklist is
    /// empty or no valid rewrite was found.
    ///
    /// # Determinism
    /// - The smallest `ArenaNodeId` is popped from the worklist.
    /// - Neighbors are retrieved in sorted order (inputs then outputs).
    /// - Local candidates are sorted by the total order defined for
    ///   `LocalCandidate`.
    /// - The first valid candidate is applied (if any).
    /// - Neighbors of the rewritten node are marked dirty in sorted order.
    pub fn normalize_step<P, D>(
        &mut self,
        graph: &mut FastGraph<P>,
        doctrine: &D,
    ) -> bool
    where
        D: ExtendedDoctrine,
        P: Clone,
    {
        // Pop the smallest node from the worklist
        let Some(std::cmp::Reverse(focus)) = self.worklist.pop() else {
            return false;
        };
        self.dirty.remove(&focus);

        // Retrieve neighbors in deterministic order (inputs then outputs)
        let _neighbors = graph.stable_neighbors(focus);

        // Generate local candidates (PR1: none)
        self.local_buf.clear();
        // In PR1 we generate no candidates, but we still call validation
        // to measure overhead. For benchmarking we can skip validation
        // when there are no candidates, but we need to simulate the check.
        // We'll call `validate_fast_local` to include its cost in benchmarks.
        let _validation_result = doctrine.validate_fast_local(graph, focus);
        // If validation fails, we could still continue, but PR1's NoOpDoctrine
        // always succeeds.

        // If we had candidates, we would sort them:
        // self.local_buf.sort();

        // PR1 has no rewrites, so we never apply anything.
        // However, we still mark neighbors as dirty to simulate the propagation
        // that would occur after a rewrite.
        // This is optional; we'll skip for now to keep the benchmark pure.

        false
    }

    /// Runs normalization until the worklist is empty or a step limit is reached.
    ///
    /// Returns the number of rewrite steps applied.
    pub fn normalize<P, D>(
        &mut self,
        graph: &mut FastGraph<P>,
        doctrine: &D,
        step_limit: Option<usize>,
    ) -> usize
    where
        D: ExtendedDoctrine,
        P: Clone,
    {
        let mut steps = 0;
        let limit = step_limit.unwrap_or(usize::MAX);
        while steps < limit && self.normalize_step(graph, doctrine) {
            steps += 1;
        }
        steps
    }

    /// Clears the worklist and dirty set.
    pub fn clear(&mut self) {
        self.worklist.clear();
        self.dirty.clear();
        self.local_buf.clear();
    }
}

impl Default for WorklistNormalizer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NoOpDoctrine;

    #[test]
    fn candidate_ordering() {
        let a = ArenaNodeId::new(1);
        let b = ArenaNodeId::new(2);
        let c = ArenaNodeId::new(3);
        let cand1 = LocalCandidate::new(RewriteKind::NoOp, a);
        let cand2 = LocalCandidate::new(RewriteKind::NoOp, b);
        assert!(cand1 < cand2);
        let cand3 = LocalCandidate {
            rewrite_kind: RewriteKind::NoOp,
            focus_node: a,
            secondary_node: Some(c),
            port_idx: None,
            pattern_hash: 0,
        };
        let cand4 = LocalCandidate {
            rewrite_kind: RewriteKind::NoOp,
            focus_node: a,
            secondary_node: None,
            port_idx: None,
            pattern_hash: 0,
        };
        // cand3 has secondary_node Some(c), cand4 has None (= MAX)
        // Therefore cand3 < cand4
        assert!(cand3 < cand4);
    }

    #[test]
    fn worklist_deterministic_order() {
        let mut norm = WorklistNormalizer::new();
        norm.mark_dirty_all([ArenaNodeId::new(5), ArenaNodeId::new(2), ArenaNodeId::new(8)]);
        let mut popped = Vec::new();
        while let Some(std::cmp::Reverse(id)) = norm.worklist.pop() {
            popped.push(id);
        }
        assert_eq!(popped, vec![
            ArenaNodeId::new(2),
            ArenaNodeId::new(5),
            ArenaNodeId::new(8),
        ]);
    }

    #[test]
    fn normalize_step_no_rewrites() {
        let mut graph = FastGraph::<()>::new();
        let chain = graph.make_deterministic_chain(10, ());
        let mut norm = WorklistNormalizer::new();
        norm.mark_dirty_all(chain);
        let doctrine = NoOpDoctrine;
        // Each step will pop a node, validate, and return false.
        // Since there are no rewrites, after 10 steps the worklist empties.
        let mut steps = 0;
        while !norm.worklist.is_empty() {
            let applied = norm.normalize_step(&mut graph, &doctrine);
            if applied {
                steps += 1;
            }
        }
        assert_eq!(steps, 0);
        assert!(norm.worklist.is_empty());
    }
}