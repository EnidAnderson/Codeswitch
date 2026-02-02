//! Core operations on ω-hypergraphs with doctrine enforcement.
//!
//! Implements the primary API for building and manipulating Codeswitch hypergraphs.
//! Each operation validates invariants via the provided doctrine before making changes.
//!
//! # Citations
//! - Git operations: Chacon & Straub, "Pro Git" (2014) – commit, rollback, frontier
//! - Hypergraph rewriting: Burroni, "Higher-dimensional word problems" (1991)
//! - Monotonic persistent data structures: Okasaki, "Purely Functional Data Structures" (1999)

use crate::core::{HyperEdge, Node, NodeId, Codeswitch};
use crate::doctrine::{Doctrine, DoctrineError, is_acyclic};
use std::collections::{HashSet, VecDeque};

/// Adds a new node to the hypergraph with the given payload.
///
/// The node receives a fresh unique ID. The node is not connected to any edges.
/// The frontier remains unchanged.
///
/// # Citations
/// - Persistent data structures: Okasaki, "Purely Functional Data Structures", Chapter 2 (1999)
/// - Unique ID generation: UUID specification (RFC 4122, 2005)
pub fn add_node<P>(
    graph: &mut Codeswitch<P>,
    payload: P,
    dim: usize,
    doctrine: &impl Doctrine,
) -> Result<NodeId, DoctrineError> {
    let id = graph.fresh_id();
    let node = Node::new(id, payload, dim);
    doctrine.validate_node(&node, graph)?;
    graph.add_node_raw(node);
    Ok(id)
}

/// Adds a hyperedge connecting the given source and target nodes.
///
/// Validates that all referenced nodes exist and that the edge satisfies doctrine constraints.
/// The hypergraph must remain acyclic.
///
/// # Citations
/// - Hyperedge insertion: Berge, "Graphs and Hypergraphs", Chapter 1 (1973)
/// - Acyclicity maintenance: Cormen et al., "Introduction to Algorithms", Section 22.4 (2009)
pub fn add_edge<P>(
    graph: &mut Codeswitch<P>,
    sources: HashSet<NodeId>,
    targets: HashSet<NodeId>,
    doctrine: &impl Doctrine,
) -> Result<(), DoctrineError> {
    if sources.is_empty() && targets.is_empty() {
        return Err(DoctrineError::InvalidArity);
    }
    let edge = HyperEdge::new(sources, targets);
    doctrine.validate_edge(&edge, graph)?;
    // Temporary add edge to check acyclicity
    graph.add_edge_raw(edge.clone());
    if !is_acyclic(graph) {
        // Remove the edge we just added
        graph.remove_edge_raw(&edge);
        return Err(DoctrineError::CycleDetected);
    }
    Ok(())
}

/// Commits a new node connected to the current frontier.
///
/// Creates a new node with the given payload, adds hyperedges from each frontier node
/// to the new node (unless frontier is empty), and updates the frontier to the singleton {new_node}.
///
/// # Citations
/// - Git commit: Chacon & Straub, "Pro Git", Section 2.2 "Recording Changes" (2014)
/// - DAG frontier advancement: Lamport, "Time, Clocks, and the Ordering of Events" (1978)
pub fn commit<P>(
    graph: &mut Codeswitch<P>,
    payload: P,
    dim: usize,
    doctrine: &impl Doctrine,
) -> Result<NodeId, DoctrineError> {
    let new_id = graph.fresh_id();
    let new_node = Node::new(new_id, payload, dim);
    doctrine.validate_node(&new_node, graph)?;

    // Create edges from each frontier node to the new node
    let sources: HashSet<NodeId> = graph.frontier().clone();
    let targets = HashSet::from([new_id]);
    if !sources.is_empty() {
        let edge = HyperEdge::new(sources, targets.clone());
        doctrine.validate_edge(&edge, graph)?;
        // Temporarily add edge and node to check acyclicity
        graph.add_node_raw(new_node);
        graph.add_edge_raw(edge.clone());
        if !is_acyclic(graph) {
            // Rollback temporary additions
            graph.remove_node_raw(new_id);
            graph.remove_edge_raw(&edge);
            return Err(DoctrineError::CycleDetected);
        }
        // Edge already added, keep it
    } else {
        // No frontier: just add the node
        graph.add_node_raw(new_node);
    }

    // Update frontier to the new node
    graph.set_frontier_raw(HashSet::from([new_id]));
    Ok(new_id)
}

/// Rolls back the frontier to a given set of nodes.
///
/// Validates that the new frontier nodes exist, are mutually independent,
/// and satisfy doctrine constraints (e.g., singleton for linear doctrine).
///
/// # Citations
/// - Git reset/checkout: Chacon & Straub, "Pro Git", Section 7.7 "Reset Demystified" (2014)
/// - Rollback in persistent data structures: Okasaki, Chapter 3 (1999)
pub fn rollback<P>(
    graph: &mut Codeswitch<P>,
    target_frontier: &HashSet<NodeId>,
    doctrine: &impl Doctrine,
) -> Result<(), DoctrineError> {
    doctrine.validate_frontier(target_frontier, graph)?;
    graph.set_frontier_raw(target_frontier.clone());
    Ok(())
}

/// Evaluates the hypergraph by folding over the downward closure of a frontier.
///
/// Computes the set of all nodes reachable from the given frontier (including frontier nodes),
/// topologically sorts them, and applies the folding function sequentially.
///
/// # Citations
/// - Topological sort: Kahn, "Topological sorting of large networks" (1962)
/// - Fold/reduce operation: Bird & Wadler, "Introduction to Functional Programming" (1988)
pub fn evaluate<P, S>(
    graph: &Codeswitch<P>,
    frontier: &HashSet<NodeId>,
    init_state: S,
    apply: impl Fn(S, &P) -> S,
) -> S {
    // Compute downward closure: all nodes that are ancestors of frontier nodes.
    let closure = downward_closure(graph, frontier);
    // Topological sort of closure
    let sorted = topological_sort_subgraph(graph, &closure);
    // Apply folding
    let mut state = init_state;
    for id in sorted {
        if let Some(node) = graph.get_node(id) {
            state = apply(state, &node.payload);
        }
    }
    state
}

/// Checks whether the hypergraph satisfies all doctrine invariants.
///
/// Runs full validation including acyclicity, edge arity, frontier validity, etc.
///
/// # Citations
/// - Graph validation: Cormen et al., "Introduction to Algorithms", Chapter 22 (2009)
/// - Invariant preservation: Lamport, "Specifying Systems" (2002)
pub fn is_well_formed<P>(graph: &Codeswitch<P>, doctrine: &impl Doctrine) -> bool {
    doctrine.validate_graph(graph).is_ok()
}

/// Computes the downward closure of a set of nodes.
///
/// Returns the set of all nodes from which there is a directed path to any node in `start`.
/// Includes the start nodes themselves.
///
/// # Citations
/// - Reachability in directed graphs: Cormen et al., "Introduction to Algorithms", Section 22.4 (2009)
fn downward_closure<P>(graph: &Codeswitch<P>, start: &HashSet<NodeId>) -> HashSet<NodeId> {
    let mut visited = HashSet::new();
    // Deterministic order: sort start nodes
    let mut start_nodes: Vec<NodeId> = start.iter().copied().collect();
    start_nodes.sort();
    let mut queue: VecDeque<NodeId> = start_nodes.into_iter().collect();
    while let Some(v) = queue.pop_front() {
        if visited.contains(&v) {
            continue;
        }
        visited.insert(v);
        // Find all predecessors of v (nodes that have an edge to v)
        // Process edges in deterministic order
        for edge in graph.edges_sorted() {
            if edge.targets.contains(&v) {
                // Sort sources for deterministic queue insertion order
                let mut sources: Vec<NodeId> = edge.sources.iter().copied().collect();
                sources.sort();
                for src in sources {
                    if !visited.contains(&src) {
                        queue.push_back(src);
                    }
                }
            }
        }
    }
    visited
}

/// Topologically sorts a subset of nodes in the hypergraph.
///
/// Assumes the subgraph induced by `subset` is acyclic (which holds if the whole graph is acyclic).
/// Returns a vector of node IDs in topological order (sources before targets).
///
/// # Citations
/// - Kahn's algorithm: Kahn, "Topological sorting of large networks" (1962)
fn topological_sort_subgraph<P>(
    graph: &Codeswitch<P>,
    subset: &HashSet<NodeId>,
) -> Vec<NodeId> {
    // Build adjacency and indegree restricted to subset
    let mut successors = std::collections::HashMap::new();
    let mut indegree = std::collections::HashMap::new();
    for &id in subset {
        indegree.insert(id, 0);
    }
    // Process edges in deterministic order
    for edge in graph.edges_sorted() {
        // Only consider edges where both source and target are in subset
        for &src in &edge.sources {
            if !subset.contains(&src) {
                continue;
            }
            for &tgt in &edge.targets {
                if !subset.contains(&tgt) {
                    continue;
                }
                successors.entry(src).or_insert_with(Vec::new).push(tgt);
                *indegree.entry(tgt).or_insert(0) += 1;
            }
        }
    }
    // Sort successor lists for deterministic iteration
    for succs in successors.values_mut() {
        succs.sort();
    }
    // Kahn's algorithm with deterministic order of zero-indegree nodes
    let mut zero_nodes: Vec<NodeId> = indegree
        .iter()
        .filter(|(_, d)| **d == 0)
        .map(|(&id, _)| id)
        .collect();
    zero_nodes.sort();
    let mut queue: VecDeque<NodeId> = zero_nodes.into_iter().collect();
    let mut result = Vec::with_capacity(subset.len());
    while let Some(v) = queue.pop_front() {
        result.push(v);
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
    result
}
