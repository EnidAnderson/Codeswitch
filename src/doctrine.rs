//! Doctrine system for enforcing operational invariants.
//!
//! A doctrine is a set of constraints that define a particular mode of operation:
//! - Globular: single source, single target (like globular higher categories)
//! - Linear: singleton frontier, linear history (like Git linear history)
//! - DAG: arbitrary edges, acyclic closure (like Git DAG)
//! - Full ω‑hypergraph: arbitrary multi‑source/multi‑target edges
//!
//! # Citations
//! - Lawvere, "Functorial semantics of algebraic theories" (1963) – doctrine concept
//! - Leinster, "Higher Operads, Higher Categories" (2004) – globular higher categories
//! - Git: Chacon & Straub, "Pro Git" (2014) – DAG and linear history models

use crate::core::{HyperEdge, Node, NodeId, Codeswitch};
use std::collections::{HashSet, VecDeque};

/// Error type for doctrine validation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DoctrineError {
    /// Hyperedge violates arity constraints.
    InvalidArity,
    /// Hyperedge creates a cycle.
    CycleDetected,
    /// Frontier is not a singleton (required by linear doctrine).
    FrontierNotSingleton,
    /// Frontier nodes are not mutually independent.
    FrontierNotIndependent,
    /// Node already exists with same ID.
    DuplicateNode,
    /// Referenced node does not exist.
    MissingNode,
    /// Other validation failure.
    Other(String),
}

impl std::fmt::Display for DoctrineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DoctrineError::InvalidArity => write!(f, "invalid hyperedge arity"),
            DoctrineError::CycleDetected => write!(f, "cycle detected"),
            DoctrineError::FrontierNotSingleton => write!(f, "frontier must be a singleton"),
            DoctrineError::FrontierNotIndependent => {
                write!(f, "frontier nodes are not independent")
            }
            DoctrineError::DuplicateNode => write!(f, "duplicate node ID"),
            DoctrineError::MissingNode => write!(f, "referenced node does not exist"),
            DoctrineError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for DoctrineError {}

/// A doctrine defines invariants for hypergraph operations.
///
/// Each doctrine provides validation methods for nodes, edges, and whole graphs.
/// Operations consult the doctrine to ensure invariants are preserved.
///
/// # Citations
/// - Lawvere theories: doctrines as categorical specifications of algebraic structures.
pub trait Doctrine {
    /// Validates a hyperedge before insertion.
    fn validate_edge<P>(
        &self,
        edge: &HyperEdge,
        graph: &Codeswitch<P>,
    ) -> Result<(), DoctrineError>;

    /// Validates a node before insertion.
    /// Typically checks ID uniqueness.
    fn validate_node<P>(
        &self,
        node: &Node<P>,
        graph: &Codeswitch<P>,
    ) -> Result<(), DoctrineError>;

    /// Validates the entire hypergraph structure.
    /// Includes acyclicity, frontier validity, etc.
    fn validate_graph<P>(&self, graph: &Codeswitch<P>) -> Result<(), DoctrineError>;

    /// Validates a frontier set (for rollback operations).
    fn validate_frontier<P>(
        &self,
        frontier: &HashSet<NodeId>,
        graph: &Codeswitch<P>,
    ) -> Result<(), DoctrineError>;
}

/// Globular doctrine: single source, single target per hyperedge.
///
/// Corresponds to globular higher categories where each k‑cell has one source and one target.
/// This is the "fast‑path" for opetopic composition.
///
/// # Citations
/// - Leinster, "Higher Operads, Higher Categories" (2004), Chapter 1: globular sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Globular;

impl Doctrine for Globular {
    fn validate_edge<P>(
        &self,
        edge: &HyperEdge,
        _graph: &Codeswitch<P>,
    ) -> Result<(), DoctrineError> {
        if edge.sources.len() == 1 && edge.targets.len() == 1 {
            Ok(())
        } else {
            Err(DoctrineError::InvalidArity)
        }
    }

    fn validate_node<P>(
        &self,
        node: &Node<P>,
        graph: &Codeswitch<P>,
    ) -> Result<(), DoctrineError> {
        if graph.contains_node(node.id) {
            Err(DoctrineError::DuplicateNode)
        } else {
            Ok(())
        }
    }

    fn validate_graph<P>(&self, graph: &Codeswitch<P>) -> Result<(), DoctrineError> {
        // Check acyclicity
        if !is_acyclic(graph) {
            return Err(DoctrineError::CycleDetected);
        }
        // Check that all edges are globular (deterministic order)
        for edge in graph.edges_sorted() {
            self.validate_edge(edge, graph)?;
        }
        Ok(())
    }

    fn validate_frontier<P>(
        &self,
        frontier: &HashSet<NodeId>,
        graph: &Codeswitch<P>,
    ) -> Result<(), DoctrineError> {
        // Globular doctrine doesn't impose frontier constraints beyond independence.
        validate_frontier_independence(frontier, graph)
    }
}

impl self::ext::ExtendedDoctrine for Globular {}

/// Linear doctrine: singleton frontier, linear history.
///
/// Ensures the hypergraph forms a linear chain (each node has at most one predecessor
/// and at most one successor). This is the strictest fast‑path, analogous to a linear Git history.
///
/// # Citations
/// - Git linear history: Chacon & Straub, "Pro Git", Section 3.1 "Git Branching" (2014)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Linear;

impl Doctrine for Linear {
    fn validate_edge<P>(
        &self,
        edge: &HyperEdge,
        graph: &Codeswitch<P>,
    ) -> Result<(), DoctrineError> {
        // Must be a standard edge (single source, single target)
        if edge.sources.len() != 1 || edge.targets.len() != 1 {
            return Err(DoctrineError::InvalidArity);
        }
        let src = *edge.sources.iter().next().unwrap();
        let tgt = *edge.targets.iter().next().unwrap();
        // Check that src has no other outgoing edges (deterministic order)
        for e in graph.edges_sorted() {
            if e.sources.contains(&src) {
                return Err(DoctrineError::Other(
                    "source already has outgoing edge".to_string(),
                ));
            }
            if e.targets.contains(&tgt) {
                return Err(DoctrineError::Other(
                    "target already has incoming edge".to_string(),
                ));
            }
        }
        Ok(())
    }

    fn validate_node<P>(
        &self,
        node: &Node<P>,
        graph: &Codeswitch<P>,
    ) -> Result<(), DoctrineError> {
        if graph.contains_node(node.id) {
            Err(DoctrineError::DuplicateNode)
        } else {
            Ok(())
        }
    }

    fn validate_graph<P>(&self, graph: &Codeswitch<P>) -> Result<(), DoctrineError> {
        // Acyclicity
        if !is_acyclic(graph) {
            return Err(DoctrineError::CycleDetected);
        }
        // Linearity: each node has at most one incoming and one outgoing edge.
        let mut incoming_count = std::collections::HashMap::new();
        let mut outgoing_count = std::collections::HashMap::new();
        for edge in graph.edges_sorted() {
            if edge.sources.len() != 1 || edge.targets.len() != 1 {
                return Err(DoctrineError::InvalidArity);
            }
            let src = *edge.sources.iter().next().unwrap();
            let tgt = *edge.targets.iter().next().unwrap();
            *outgoing_count.entry(src).or_insert(0) += 1;
            *incoming_count.entry(tgt).or_insert(0) += 1;
        }
        for &count in incoming_count.values().chain(outgoing_count.values()) {
            if count > 1 {
                return Err(DoctrineError::Other(
                    "node has multiple incoming/outgoing edges, violating linearity".to_string(),
                ));
            }
        }
        // Frontier must be singleton if there are nodes
        if graph.node_count() > 0 && graph.frontier().len() != 1 {
            return Err(DoctrineError::FrontierNotSingleton);
        }
        Ok(())
    }

    fn validate_frontier<P>(
        &self,
        frontier: &HashSet<NodeId>,
        graph: &Codeswitch<P>,
    ) -> Result<(), DoctrineError> {
        if graph.node_count() == 0 {
            if !frontier.is_empty() {
                return Err(DoctrineError::FrontierNotSingleton);
            }
        } else if frontier.len() != 1 {
            return Err(DoctrineError::FrontierNotSingleton);
        }
        validate_frontier_independence(frontier, graph)
    }
}

impl self::ext::ExtendedDoctrine for Linear {}

/// DAG doctrine: arbitrary edges, acyclic closure.
///
/// Allows multiple predecessors and successors, but forbids cycles.
/// This corresponds to Git's default DAG history.
///
/// # Citations
/// - Git DAG: Chacon & Straub, "Pro Git", Section 3.1 "Git Branching" (2014)
/// - Directed acyclic graphs: Cormen et al., "Introduction to Algorithms" (2009)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Dag;

impl Doctrine for Dag {
    fn validate_edge<P>(
        &self,
        edge: &HyperEdge,
        graph: &Codeswitch<P>,
    ) -> Result<(), DoctrineError> {
        // All nodes must exist
        for &id in edge.sources.iter().chain(edge.targets.iter()) {
            if !graph.contains_node(id) {
                return Err(DoctrineError::MissingNode);
            }
        }
        Ok(())
    }

    fn validate_node<P>(
        &self,
        node: &Node<P>,
        graph: &Codeswitch<P>,
    ) -> Result<(), DoctrineError> {
        if graph.contains_node(node.id) {
            Err(DoctrineError::DuplicateNode)
        } else {
            Ok(())
        }
    }

    fn validate_graph<P>(&self, graph: &Codeswitch<P>) -> Result<(), DoctrineError> {
        if !is_acyclic(graph) {
            return Err(DoctrineError::CycleDetected);
        }
        // All edges refer to existing nodes (checked in validate_edge)
        Ok(())
    }

    fn validate_frontier<P>(
        &self,
        frontier: &HashSet<NodeId>,
        graph: &Codeswitch<P>,
    ) -> Result<(), DoctrineError> {
        validate_frontier_independence(frontier, graph)
    }
}

impl self::ext::ExtendedDoctrine for Dag {}

/// Full ω‑hypergraph doctrine: arbitrary multi‑source/multi‑target edges.
///
/// The most general doctrine, allowing any hyperedge shape as long as the hypergraph remains acyclic.
///
/// # Citations
/// - Miyoshi & Tsujishita, "ω-hypergraphs and weak ω-categories" (2003)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FullOmegaHypergraph;

impl Doctrine for FullOmegaHypergraph {
    fn validate_edge<P>(
        &self,
        edge: &HyperEdge,
        graph: &Codeswitch<P>,
    ) -> Result<(), DoctrineError> {
        // All nodes must exist
        for &id in edge.sources.iter().chain(edge.targets.iter()) {
            if !graph.contains_node(id) {
                return Err(DoctrineError::MissingNode);
            }
        }
        Ok(())
    }

    fn validate_node<P>(
        &self,
        node: &Node<P>,
        graph: &Codeswitch<P>,
    ) -> Result<(), DoctrineError> {
        if graph.contains_node(node.id) {
            Err(DoctrineError::DuplicateNode)
        } else {
            Ok(())
        }
    }

    fn validate_graph<P>(&self, graph: &Codeswitch<P>) -> Result<(), DoctrineError> {
        if !is_acyclic(graph) {
            return Err(DoctrineError::CycleDetected);
        }
        Ok(())
    }

    fn validate_frontier<P>(
        &self,
        frontier: &HashSet<NodeId>,
        graph: &Codeswitch<P>,
    ) -> Result<(), DoctrineError> {
        validate_frontier_independence(frontier, graph)
    }
}

impl self::ext::ExtendedDoctrine for FullOmegaHypergraph {}

/// Checks whether the hypergraph is acyclic.
///
/// Uses Kahn's algorithm for topological sorting on the hypergraph.
/// Treats each hyperedge as directed edges from each source to each target.
///
/// # Citations
/// - Kahn, "Topological sorting of large networks" (1962)
/// - Cormen et al., "Introduction to Algorithms", Section 22.4 (2009)
pub(crate) fn is_acyclic<P>(graph: &Codeswitch<P>) -> bool {
    // Build adjacency list: node -> vec of successors (sorted, may contain duplicates)
    let mut successors: std::collections::HashMap<NodeId, Vec<NodeId>> =
        std::collections::HashMap::new();
    let mut indegree: std::collections::HashMap<NodeId, usize> = std::collections::HashMap::new();

    // Initialize indegree for all nodes
    for id in graph.nodes().map(|n| n.id) {
        indegree.insert(id, 0);
    }

    // Process each hyperedge in deterministic order
    for edge in graph.edges_sorted() {
        for &src in &edge.sources {
            for &tgt in &edge.targets {
                successors.entry(src).or_default().push(tgt);
                *indegree.entry(tgt).or_insert(0) += 1;
            }
        }
    }
    // Sort successor lists for deterministic iteration
    for succs in successors.values_mut() {
        succs.sort();
    }

    // Kahn's algorithm
    let mut queue: VecDeque<NodeId> = indegree
        .iter()
        .filter(|(_, d)| **d == 0)
        .map(|(&id, _)| id)
        .collect();
    let mut visited = 0;

    while let Some(v) = queue.pop_front() {
        visited += 1;
        if let Some(succs) = successors.get(&v) {
            for &u in succs {
                let deg = indegree.get_mut(&u).unwrap();
                *deg -= 1;
                if *deg == 0 {
                    queue.push_back(u);
                }
            }
        }
    }

    visited == graph.node_count()
}

/// Validates that frontier nodes are mutually independent (no directed path between them).
fn validate_frontier_independence<P>(
    frontier: &HashSet<NodeId>,
    graph: &Codeswitch<P>,
) -> Result<(), DoctrineError> {
    // For each pair (a, b) in frontier, ensure there is no directed path from a to b.
    // Naïve O(|frontier|² * (|V|+|E|)) implementation; can be optimized with transitive closure if needed.
    let nodes_set: HashSet<NodeId> = graph.nodes().map(|n| n.id).collect();
    for &a in frontier {
        if !nodes_set.contains(&a) {
            return Err(DoctrineError::MissingNode);
        }
        for &b in frontier {
            if a == b {
                continue;
            }
            if reachable(graph, a, b) {
                return Err(DoctrineError::FrontierNotIndependent);
            }
        }
    }
    Ok(())
}

/// Checks whether there is a directed path from `src` to `dst` in the hypergraph.
fn reachable<P>(graph: &Codeswitch<P>, src: NodeId, dst: NodeId) -> bool {
    use std::collections::VecDeque;
    // Build adjacency list (successors) with deterministic iteration order
    let mut adj_set: std::collections::HashMap<NodeId, HashSet<NodeId>> =
        std::collections::HashMap::new();
    for edge in graph.edges_sorted() {
        for &s in &edge.sources {
            for &t in &edge.targets {
                adj_set.entry(s).or_default().insert(t);
            }
        }
    }
    // Convert to sorted vectors for deterministic BFS order
    let mut adj: std::collections::HashMap<NodeId, Vec<NodeId>> = std::collections::HashMap::new();
    for (node, succs_set) in adj_set {
        let mut succs_vec: Vec<_> = succs_set.into_iter().collect();
        succs_vec.sort();
        adj.insert(node, succs_vec);
    }

    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(src);
    visited.insert(src);

    while let Some(v) = queue.pop_front() {
        if v == dst {
            return true;
        }
        if let Some(succs) = adj.get(&v) {
            for &u in succs {
                if !visited.contains(&u) {
                    visited.insert(u);
                    queue.push_back(u);
                }
            }
        }
    }
    false
}

pub mod ext;
pub mod adapter;
pub mod noop;

pub use ext::ExtendedDoctrine;
pub use noop::NoOpDoctrine;
