//! Fast‑path intermediate representation.
//!
//! `FastGraph` is a restricted IR that forbids identities, multi‑arity ports,
//! and arbitrary hyperedges. It is designed for deterministic, allocation‑lean
//! normalization using a worklist.
//!
//! # Invariants
//! - No node has more than one output edge (max_out_arity ≤ 1).
//! - No node has more than one input edge (max_in_arity ≤ 1) unless sharing is
//!   explicitly allowed by the doctrine.
//! - No identity nodes exist (they are erased before lowering).
//! - Extern interface is represented via pseudo‑nodes `EXTERN_INPUTS_NODE` and
//!   `EXTERN_OUTPUTS_NODE`.

use crate::arena::{ArenaNodeId, NodeArena, EXTERN_INPUTS_NODE, EXTERN_OUTPUTS_NODE};
use std::collections::HashSet;

/// Kind of a fast‑graph node.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FastNodeKind {
    /// Binary composition `left ∘ right`.
    Compose,
    /// Binary tensor product `left ⊗ right`.
    Tensor,
    /// Atomic term with user‑defined payload.
    Primitive,
    // No Identity variant.
}

/// Data stored for each node in the fast graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodeData<P> {
    /// Kind of the node.
    pub kind: FastNodeKind,
    /// User‑defined payload (may be unused for Compose/Tensor).
    pub payload: P,
    /// Nodes that feed into this node (inputs).
    ///
    /// For Compose/Tensor, these are the left/right children.
    /// For Primitive nodes, inputs are the sources of incoming edges.
    /// Deterministic order: sorted by `ArenaNodeId`.
    pub inputs: Vec<ArenaNodeId>,
    /// Nodes that this node feeds into (outputs).
    ///
    /// Deterministic order: sorted by `ArenaNodeId`.
    pub outputs: Vec<ArenaNodeId>,
}

impl<P> NodeData<P> {
    /// Creates a new primitive node with empty adjacency.
    pub fn primitive(payload: P) -> Self {
        Self {
            kind: FastNodeKind::Primitive,
            payload,
            inputs: Vec::new(),
            outputs: Vec::new(),
        }
    }

    /// Creates a new compose node with the given children.
    ///
    /// The children are added as inputs; the node itself has no outputs yet.
    pub fn compose(left: ArenaNodeId, right: ArenaNodeId, payload: P) -> Self {
        let mut inputs = Vec::with_capacity(2);
        inputs.push(left);
        inputs.push(right);
        // Keep deterministic order
        inputs.sort();
        Self {
            kind: FastNodeKind::Compose,
            payload,
            inputs,
            outputs: Vec::new(),
        }
    }

    /// Creates a new tensor node with the given children.
    pub fn tensor(left: ArenaNodeId, right: ArenaNodeId, payload: P) -> Self {
        let mut inputs = Vec::with_capacity(2);
        inputs.push(left);
        inputs.push(right);
        inputs.sort();
        Self {
            kind: FastNodeKind::Tensor,
            payload,
            inputs,
            outputs: Vec::new(),
        }
    }
}

/// Fast‑path graph representation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FastGraph<P> {
    /// Arena storing node data.
    arena: NodeArena<NodeData<P>>,
    /// Maximum output arity among all nodes.
    max_out_arity: u8,
    /// Maximum input arity among all nodes.
    max_in_arity: u8,
    /// Whether any node has more than one incoming edge (non‑tree sharing).
    has_sharing: bool,
    /// Total number of directed edges (input→node and node→output).
    total_wires: u32,
}

impl<P> FastGraph<P> {
    /// Creates a new empty `FastGraph`.
    ///
    /// The arena is initialized with the two reserved pseudo‑nodes.
    pub fn new() -> Self {
        let arena = NodeArena::new();
        // Ensure reserved slots exist (they are created by NodeArena::new).
        debug_assert!(arena.capacity() >= 2);
        Self {
            arena,
            max_out_arity: 0,
            max_in_arity: 0,
            has_sharing: false,
            total_wires: 0,
        }
    }

    /// Adds a primitive node with the given payload.
    ///
    /// Returns the new node's `ArenaNodeId`.
    pub fn add_primitive(&mut self, payload: P) -> ArenaNodeId {
        let data = NodeData::primitive(payload);
        self.arena.allocate(data)
    }

    /// Adds a compose node with the given children.
    ///
    /// Also updates adjacency of the children (adds this node as an output).
    /// Returns the new node's `ArenaNodeId`.
    pub fn add_compose(&mut self, left: ArenaNodeId, right: ArenaNodeId, payload: P) -> ArenaNodeId {
        let id = self.arena.allocate(NodeData::compose(left, right, payload));
        self.link_child(left, id);
        self.link_child(right, id);
        id
    }

    /// Adds a tensor node with the given children.
    pub fn add_tensor(&mut self, left: ArenaNodeId, right: ArenaNodeId, payload: P) -> ArenaNodeId {
        let id = self.arena.allocate(NodeData::tensor(left, right, payload));
        self.link_child(left, id);
        self.link_child(right, id);
        id
    }

    /// Helper to link a child node to its new parent.
    fn link_child(&mut self, child: ArenaNodeId, parent: ArenaNodeId) {
        if let Some(child_data) = self.arena.get_mut(child) {
            child_data.outputs.push(parent);
            child_data.outputs.sort();
            self.update_arity_after_add(child, false); // child's output arity changed
        }
        if let Some(_parent_data) = self.arena.get_mut(parent) {
            // inputs already sorted in NodeData constructor
            self.update_arity_after_add(parent, true); // parent's input arity changed
        }
        self.total_wires += 1;
    }

    /// Updates arity and sharing flags after adding an edge.
    fn update_arity_after_add(&mut self, node: ArenaNodeId, is_input: bool) {
        let data = self.arena.get(node).expect("node must exist");
        let arity = if is_input {
            data.inputs.len() as u8
        } else {
            data.outputs.len() as u8
        };
        if is_input {
            self.max_in_arity = self.max_in_arity.max(arity);
            if arity > 1 {
                self.has_sharing = true;
            }
        } else {
            self.max_out_arity = self.max_out_arity.max(arity);
        }
    }

    /// Returns the maximum output arity across all nodes.
    pub fn max_out_arity(&self) -> u8 {
        self.max_out_arity
    }

    /// Returns the maximum input arity across all nodes.
    pub fn max_in_arity(&self) -> u8 {
        self.max_in_arity
    }

    /// Returns `true` if any node has more than one incoming edge (non‑tree sharing).
    pub fn has_non_tree_sharing(&self) -> bool {
        self.has_sharing
    }

    /// Returns the total number of directed edges.
    pub fn total_wires(&self) -> u32 {
        self.total_wires
    }

    /// Returns a reference to the node's data, if it exists.
    pub fn node_data(&self, id: ArenaNodeId) -> Option<&NodeData<P>> {
        self.arena.get(id)
    }

    /// Returns a mutable reference to the node's data, if it exists.
    pub fn node_data_mut(&mut self, id: ArenaNodeId) -> Option<&mut NodeData<P>> {
        self.arena.get_mut(id)
    }

    /// Returns the neighbors of a node in deterministic order.
    ///
    /// The order is: inputs (sorted), then outputs (sorted).
    pub fn stable_neighbors(&self, id: ArenaNodeId) -> Vec<ArenaNodeId> {
        let mut neighbors = Vec::new();
        if let Some(data) = self.arena.get(id) {
            neighbors.extend(data.inputs.iter().copied());
            neighbors.extend(data.outputs.iter().copied());
        }
        neighbors
    }

    /// Returns the set of nodes that have no incoming edges (sources).
    pub fn sources(&self) -> HashSet<ArenaNodeId> {
        self.arena
            .iter()
            .filter(|(_, data)| data.inputs.is_empty())
            .map(|(id, _)| id)
            .collect()
    }

    /// Returns the set of nodes that have no outgoing edges (sinks).
    pub fn sinks(&self) -> HashSet<ArenaNodeId> {
        self.arena
            .iter()
            .filter(|(_, data)| data.outputs.is_empty())
            .map(|(id, _)| id)
            .collect()
    }

    /// Creates a deterministic chain of `n` primitive nodes.
    ///
    /// Useful for benchmarking the worklist overhead.
    /// The chain is: extern_inputs → node0 → node1 → … → node_{n-1} → extern_outputs.
    /// Returns the vector of internal node IDs in order.
    pub fn make_deterministic_chain(&mut self, n: usize, payload: P) -> Vec<ArenaNodeId>
    where
        P: Clone,
    {
        let mut ids = Vec::with_capacity(n);
        let mut prev = EXTERN_INPUTS_NODE;
        for _ in 0..n {
            let id = self.add_primitive(payload.clone());
            // Link prev → id
            if let Some(prev_data) = self.arena.get_mut(prev) {
                prev_data.outputs.push(id);
                prev_data.outputs.sort();
                self.update_arity_after_add(prev, false);
            }
            if let Some(id_data) = self.arena.get_mut(id) {
                id_data.inputs.push(prev);
                id_data.inputs.sort();
                self.update_arity_after_add(id, true);
            }
            self.total_wires += 1;
            ids.push(id);
            prev = id;
        }
        // Link last node → extern_outputs
        if let Some(last_data) = self.arena.get_mut(prev) {
            last_data.outputs.push(EXTERN_OUTPUTS_NODE);
            last_data.outputs.sort();
            self.update_arity_after_add(prev, false);
            self.total_wires += 1;
        }
        // Extern outputs node already exists; we don't need to modify it.
        ids
    }
}

impl<P> Default for FastGraph<P> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_graph_basic() {
        let mut graph: FastGraph<&'static str> = FastGraph::new();
        let a = graph.add_primitive("a");
        let b = graph.add_primitive("b");
        let c = graph.add_compose(a, b, "compose");
        assert_eq!(graph.max_out_arity(), 1); // a and b each have one output (c)
        assert_eq!(graph.max_in_arity(), 2); // c has two inputs
        assert!(graph.has_non_tree_sharing()); // c shares inputs from a and b
        assert_eq!(graph.total_wires(), 2); // a→c, b→c

        let data_c = graph.node_data(c).unwrap();
        assert!(matches!(data_c.kind, FastNodeKind::Compose));
        assert_eq!(data_c.inputs, vec![a, b]);
        assert_eq!(data_c.outputs, vec![]);
    }

    #[test]
    fn deterministic_chain() {
        let mut graph: FastGraph<()> = FastGraph::new();
        let chain = graph.make_deterministic_chain(5, ());
        assert_eq!(chain.len(), 5);
        assert_eq!(graph.total_wires(), 6); // extern_inputs→node0, node0→node1, …, node4→extern_outputs
        assert_eq!(graph.max_out_arity(), 1);
        assert_eq!(graph.max_in_arity(), 1);
        assert!(!graph.has_non_tree_sharing());
    }
}