//! Core data structures for ω-hypergraphs.
//!
//! Implements the mathematical definition of ω-hypergraphs as per Miyoshi and Tsujishita (2003),
//! with nodes as atomic terms and hyperedges as multi-source/multi-target relations.
//!
//! # Citations
//! - Miyoshi & Tsujishita, "ω-hypergraphs and weak ω-categories", Journal of Pure and Applied Algebra (2003)
//! - Street, "The algebra of oriented simplexes", Journal of Pure and Applied Algebra (1987)
//! - Burroni, "Higher-dimensional word problems with applications to higher-dimensional rewriting", (1991)

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::{Hash, Hasher};

/// Unique identifier for a node in the hypergraph.
///
/// Uses a transparent `u64` wrapper for efficient comparison and hashing.
/// The uniqueness invariant is maintained by the hypergraph builder.
///
/// # Invariant
/// - `NodeId`s are unique within a given `Codeswitch` instance.
/// - Equality and hash are based solely on the inner `u64`.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeId(u64);

impl NodeId {
    /// Creates a new `NodeId` from a raw `u64`.
    ///
    /// # Safety
    /// The caller must ensure uniqueness across the hypergraph.
    /// Prefer using the hypergraph's node creation methods.
    #[inline]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the raw `u64` representation.
    #[inline]
    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

impl Hash for NodeId {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", self.0)
    }
}

/// Attributes attached to a node.
///
/// Placeholder for span, type, or other metadata.
/// Can be extended as needed.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct NodeAttributes {
    // Currently empty; extend with fields like `span: Option<Span>`, `ty: Option<Type>`, etc.
    /// Dimension of the cell (0 for objects, 1 for morphisms, 2 for 2-cells, etc.).
    /// For ω-hypergraphs, each node represents a k-cell.
    pub dim: usize,
}

/// A node in the ω-hypergraph.
///
/// Each node carries a generic payload `P` and optional attributes.
/// Nodes are immutable once created; the hypergraph grows monotonically.
///
/// # Citations
/// - Category theory: objects as 0-cells in a higher category (Leinster, "Higher Operads, Higher Categories", 2004)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node<P> {
    /// Unique identifier.
    pub id: NodeId,
    /// User-defined payload.
    pub payload: P,
    /// Optional metadata.
    pub attributes: NodeAttributes,
}

impl<P> Node<P> {
    /// Creates a new node with the given ID, payload, and dimension.
    ///
    /// Attributes are set to default with the given dimension.
    #[inline]
    pub fn new(id: NodeId, payload: P, dim: usize) -> Self {
        Self {
            id,
            payload,
            attributes: NodeAttributes { dim },
        }
    }

    /// Creates a new node with custom attributes.
    #[inline]
    pub fn with_attributes(id: NodeId, payload: P, attributes: NodeAttributes) -> Self {
        Self {
            id,
            payload,
            attributes,
        }
    }

    /// Returns the dimension of this cell.
    #[inline]
    pub fn dim(&self) -> usize {
        self.attributes.dim
    }
}

/// Attributes attached to a hyperedge.
///
/// Placeholder for labels, weights, or higher-dimensional metadata.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct EdgeAttributes {
    // Extend as needed.
}

/// A hyperedge connecting multiple source nodes to multiple target nodes.
///
/// Mathematically, a hyperedge is a pair `(S, T)` where `S ⊆ V`, `T ⊆ V`, and `|S| + |T| > 0`.
/// The hypergraph is directed and acyclic.
///
/// # Invariants
/// - `sources` and `targets` are disjoint? Not required by definition, but typical.
/// - All node IDs refer to existing nodes in the hypergraph.
///
/// # Citations
/// - Hypergraph theory: Berge, "Graphs and Hypergraphs" (1973)
/// - ω-hypergraphs: Miyoshi & Tsujishita (2003)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HyperEdge {
    /// Set of source nodes.
    pub sources: HashSet<NodeId>,
    /// Set of target nodes.
    pub targets: HashSet<NodeId>,
    /// Optional metadata.
    pub attributes: EdgeAttributes,
}

impl HyperEdge {
    /// Creates a new hyperedge from given source and target sets.
    ///
    /// # Panics
    /// If both `sources` and `targets` are empty (violates `|S| + |T| > 0`).
    #[inline]
    pub fn new(sources: HashSet<NodeId>, targets: HashSet<NodeId>) -> Self {
        assert!(
            !sources.is_empty() || !targets.is_empty(),
            "HyperEdge must have at least one source or target"
        );
        Self {
            sources,
            targets,
            attributes: EdgeAttributes::default(),
        }
    }

    /// Creates a new hyperedge with custom attributes.
    #[inline]
    pub fn with_attributes(
        sources: HashSet<NodeId>,
        targets: HashSet<NodeId>,
        attributes: EdgeAttributes,
    ) -> Self {
        assert!(
            !sources.is_empty() || !targets.is_empty(),
            "HyperEdge must have at least one source or target"
        );
        Self {
            sources,
            targets,
            attributes,
        }
    }

    /// Returns the total number of incident nodes.
    #[inline]
    pub fn arity(&self) -> usize {
        self.sources.len() + self.targets.len()
    }

    /// Checks whether this hyperedge is a standard directed edge (single source, single target).
    #[inline]
    pub fn is_standard_edge(&self) -> bool {
        self.sources.len() == 1 && self.targets.len() == 1
    }
}

impl std::hash::Hash for HyperEdge {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Hash sources in deterministic order
        let mut sources: Vec<_> = self.sources.iter().collect();
        sources.sort();
        for &id in sources {
            id.hash(state);
        }
        // Hash targets in deterministic order
        let mut targets: Vec<_> = self.targets.iter().collect();
        targets.sort();
        for &id in targets {
            id.hash(state);
        }
        // Hash attributes
        self.attributes.hash(state);
    }
}

/// The core ω-hypergraph data structure.
///
/// Maintains a set of nodes and hyperedges, guaranteeing acyclicity and uniqueness.
/// The frontier represents the current "active" nodes (e.g., commit heads).
///
/// # Invariants
/// - Node IDs are unique.
/// - All hyperedges refer to existing nodes.
/// - The hypergraph is acyclic (directed, no cycles in the closure of edges).
/// - Frontier nodes are present in the node set and mutually independent (no directed paths between them).
///
/// # Citations
/// - ω-hypergraph model: Miyoshi & Tsujishita (2003)
/// - Polygraph/computad: Street (1987), Burroni (1991)
/// - DAG persistence: Git-like commit graphs (Chacon & Straub, "Pro Git", 2014)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Codeswitch<P> {
    /// Mapping from node ID to node data.
    nodes: HashMap<NodeId, Node<P>>,
    /// Set of hyperedges.
    edges: HashSet<HyperEdge>,
    /// Current frontier nodes.
    frontier: HashSet<NodeId>,
    /// Next available node ID.
    next_id: u64,
}

impl<P> Codeswitch<P> {
    /// Creates a new, empty ω-hypergraph.
    ///
    /// The initial frontier is empty.
    #[inline]
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: HashSet::new(),
            frontier: HashSet::new(),
            next_id: 0,
        }
    }

    /// Returns an iterator over all nodes.
    #[inline]
    pub fn nodes(&self) -> impl Iterator<Item = &Node<P>> {
        self.nodes.values()
    }

    /// Returns an iterator over all hyperedges.
    #[inline]
    pub fn edges(&self) -> impl Iterator<Item = &HyperEdge> {
        self.edges.iter()
    }

    /// Returns all nodes sorted by NodeId (deterministic iteration order).
    ///
    /// This is guaranteed to produce the same sequence across multiple runs
    /// for the same graph, as long as NodeId allocation order is consistent.
    pub fn nodes_sorted(&self) -> Vec<(NodeId, &Node<P>)> {
        let mut items: Vec<_> = self.nodes.iter().map(|(&id, node)| (id, node)).collect();
        items.sort_by_key(|&(id, _)| id);
        items
    }

    /// Returns all hyperedges sorted deterministically.
    ///
    /// Sorting is by (sources_sorted, targets_sorted) where sources and targets
    /// are sorted lists of NodeIds. This ensures deterministic order across runs.
    pub fn edges_sorted(&self) -> Vec<&HyperEdge> {
        let mut edges: Vec<_> = self.edges.iter().collect();
        edges.sort_by_key(|edge| {
            let mut sources: Vec<_> = edge.sources.iter().copied().collect();
            sources.sort();
            let mut targets: Vec<_> = edge.targets.iter().copied().collect();
            targets.sort();
            (sources, targets)
        });
        edges
    }

    /// Returns a reference to the current frontier set.
    #[inline]
    pub fn frontier(&self) -> &HashSet<NodeId> {
        &self.frontier
    }

    /// Returns the number of nodes.
    #[inline]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Returns the number of hyperedges.
    #[inline]
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Looks up a node by ID.
    #[inline]
    pub fn get_node(&self, id: NodeId) -> Option<&Node<P>> {
        self.nodes.get(&id)
    }

    /// Checks whether a node with the given ID exists.
    #[inline]
    pub fn contains_node(&self, id: NodeId) -> bool {
        self.nodes.contains_key(&id)
    }

    /// Internal method to generate a fresh node ID.
    pub(crate) fn fresh_id(&mut self) -> NodeId {
        let id = NodeId::new(self.next_id);
        self.next_id += 1;
        id
    }

    /// Internal method to add a node without validation.
    /// Used by operations after doctrine validation.
    pub(crate) fn add_node_raw(&mut self, node: Node<P>) {
        let id = node.id;
        self.nodes.insert(id, node);
    }

    /// Internal method to remove a node without validation.
    /// Used for rollback of temporary additions.
    pub(crate) fn remove_node_raw(&mut self, id: NodeId) -> bool {
        self.nodes.remove(&id).is_some()
    }

    /// Internal method to add a hyperedge without validation.
    pub(crate) fn add_edge_raw(&mut self, edge: HyperEdge) {
        self.edges.insert(edge);
    }

    /// Internal method to remove a hyperedge without validation.
    /// Used for rollback of temporary additions.
    pub(crate) fn remove_edge_raw(&mut self, edge: &HyperEdge) -> bool {
        self.edges.remove(edge)
    }

    /// Internal method to set the frontier without validation.
    pub(crate) fn set_frontier_raw(&mut self, frontier: HashSet<NodeId>) {
        self.frontier = frontier;
    }
}

impl<P> Default for Codeswitch<P> {
    fn default() -> Self {
        Self::new()
    }
}
