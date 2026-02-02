//! Codeswitch: a resilient, adaptable rewriting engine based on ω-hypergraphs.
//!
//! This crate implements the Codeswitch specification, providing:
//! - ω-hypergraph structure with hyperedges having multiple sources and targets.
//! - Doctrine-based invariants for fast-path modes (globular, linear, DAG).
//! - Backward compatibility with existing hyperopetopes, hypergraphs, and hyperstonewall semantics.
//!
//! # Name Origin: "Codeswitch"
//!
//! The term "codeswitch" is borrowed from Black feminist thought, where it describes the ability
//! to move fluidly between different linguistic and cultural codes while maintaining integrity
//! and resilience. In this context, Codeswitch refers to a rewriter that remains robust and
//! adaptable under changes of lexical environment—preserving meaning while switching between
//! different representational systems (doctrines, surface syntaxes, or semantic domains).
//!
//! # Mathematical Foundations
//!
//! The core abstraction is an ω-hypergraph, a higher-dimensional generalization of directed graphs
//! where each hyperedge connects arbitrary sets of source and target nodes.
//! This follows the ω-hypergraph model of Miyoshi and Tsujishita for weak ω-categories.
//!
//! # References
//!
//! - Miyoshi, Tsujishita. "ω-hypergraphs and weak ω-categories" (2003)
//! - Street, R. "The algebra of oriented simplexes" (1987) – polygraphs/n-computads
//! - Burroni, A. "Higher-dimensional word problems" (1991) – polygraphic rewriting
//! - Lawvere, F.W. "Functorial semantics of algebraic theories" (1963) – doctrine concept
//!
//! # Example
//!
//! ```
//! use codeswitch::prelude::*;
//! use std::collections::HashSet;
//!
//! let mut graph = Codeswitch::new();
//! let a = add_node(&mut graph, "node_a", 0, &Globular).unwrap();
//! let b = add_node(&mut graph, "node_b", 0, &Globular).unwrap();
//! add_edge(&mut graph, HashSet::from([a]), HashSet::from([b]), &Globular).unwrap();
//! ```

pub mod arena;
pub mod boundary;
pub mod core;
pub mod doctrine;
pub mod fingerprint;
pub mod graph;
pub mod normalize;
pub mod operations;
pub mod pattern;
pub mod pattern_graph;
pub mod scope;
pub mod query;
pub mod interface;
pub mod expansion;
pub mod cache;
pub mod traceability;

pub use core::{HyperEdge, Node, NodeId, Codeswitch};
pub use doctrine::{Dag, Doctrine, FullOmegaHypergraph, Globular, Linear};
pub use pattern::{AnchoredPatternMatching, Pattern, PatternMatch, PatternMatchError, RewriteTemplate};
pub use traceability::{HypergraphTraceability, HypergraphTraceStorage, RewriteStep, RewriteTrace, TraceabilityError, TraceStorageError};

// PR1: new performance spine exports
pub use crate::arena::ArenaNodeId;
pub use crate::graph::{FastGraph, TermGraph};
pub use crate::normalize::WorklistNormalizer;
pub use crate::doctrine::ext::ExtendedDoctrine;
pub use crate::doctrine::noop::NoOpDoctrine;

/// Prelude for convenient usage.
pub mod prelude {
    pub use crate::boundary::{Boundary, BoundaryError, HypergraphTyping};
    pub use crate::core::{HyperEdge, Node, NodeId, Codeswitch};
    pub use crate::doctrine::{Dag, Doctrine, FullOmegaHypergraph, Globular, Linear};
    pub use crate::fingerprint::{
        DefinitionalHash, HashValue, PayloadFingerprint, StructuralFingerprint,
        definitional_hashes, edge_content_hash, wl_refinement,
    };
    pub use crate::operations::{add_edge, add_node, commit, evaluate, is_well_formed, rollback};
    pub use crate::pattern::{AnchoredPatternMatching, Pattern, PatternMatch, PatternMatchError, RewriteTemplate};
    pub use crate::traceability::{HypergraphTraceability, HypergraphTraceStorage, RewriteStep, RewriteTrace, TraceabilityError, TraceStorageError};
    // PR1: new performance spine exports
    pub use crate::arena::ArenaNodeId;
    pub use crate::graph::{FastGraph, TermGraph};
    pub use crate::normalize::WorklistNormalizer;
    pub use crate::doctrine::ext::ExtendedDoctrine;
    pub use crate::doctrine::noop::NoOpDoctrine;
}

#[cfg(test)]
mod tests {
    use super::prelude::*;
    use std::collections::HashSet;

    /// Test that an empty hypergraph is well‑formed under all doctrines.
    #[test]
    fn empty_graph() {
        let graph: Codeswitch<()> = Codeswitch::new();
        assert!(is_well_formed(&graph, &Globular));
        assert!(is_well_formed(&graph, &Linear));
        assert!(is_well_formed(&graph, &Dag));
        assert!(is_well_formed(&graph, &FullOmegaHypergraph));
    }

    /// Test adding nodes.
    #[test]
    fn add_nodes() {
        let mut graph = Codeswitch::new();
        let id1 = add_node(&mut graph, "node1", 0, &Globular).unwrap();
        let id2 = add_node(&mut graph, "node2", 0, &Globular).unwrap();
        assert_ne!(id1, id2);
        assert_eq!(graph.node_count(), 2);
        assert_eq!(graph.edge_count(), 0);
    }

    /// Test globular doctrine: only single‑source, single‑target edges allowed.
    #[test]
    fn globular_doctrine() {
        let mut graph = Codeswitch::new();
        let a = add_node(&mut graph, "a", 0, &Globular).unwrap();
        let b = add_node(&mut graph, "b", 0, &Globular).unwrap();
        let c = add_node(&mut graph, "c", 0, &Globular).unwrap();

        // Valid edge
        assert!(
            add_edge(
                &mut graph,
                HashSet::from([a]),
                HashSet::from([b]),
                &Globular
            )
            .is_ok()
        );
        // Invalid: multiple sources
        assert!(
            add_edge(
                &mut graph,
                HashSet::from([a, c]),
                HashSet::from([b]),
                &Globular
            )
            .is_err()
        );
        // Invalid: multiple targets
        assert!(
            add_edge(
                &mut graph,
                HashSet::from([a]),
                HashSet::from([b, c]),
                &Globular
            )
            .is_err()
        );
        // Invalid: empty edge
        assert!(add_edge(&mut graph, HashSet::new(), HashSet::new(), &Globular).is_err());
    }

    /// Test linear doctrine: singleton frontier and linear chain.
    #[test]
    fn linear_doctrine() {
        let mut graph = Codeswitch::new();
        let _a = add_node(&mut graph, "a", 0, &Linear).unwrap();
        // Frontier should be empty initially
        assert_eq!(graph.frontier().len(), 0);
        // Commit creates a node and sets frontier to it
        let b = commit(&mut graph, "b", 0, &Linear).unwrap();
        assert_eq!(graph.frontier(), &HashSet::from([b]));
        // Add another commit
        let c = commit(&mut graph, "c", 0, &Linear).unwrap();
        assert_eq!(graph.frontier(), &HashSet::from([c]));
        // Graph should be linear chain a -> b -> c? Wait commit adds edge from frontier to new node.
        // Initially frontier empty, so first commit has no edge.
        // Second commit adds edge from b to c? Actually commit adds edges from each frontier node to new node.
        // Frontier was {b}, so edge b -> c.
        // So edges: b->c.
        // Check linearity: each node has at most one incoming and one outgoing.
        // a has zero edges.
        // b has one outgoing (to c).
        // c has one incoming (from b).
        // Should be valid.
        assert!(is_well_formed(&graph, &Linear));
        // Attempt to create branching edge should fail
        let d = add_node(&mut graph, "d", 0, &Linear).unwrap();
        assert!(add_edge(&mut graph, HashSet::from([b]), HashSet::from([d]), &Linear).is_err());
    }

    /// Test DAG doctrine: arbitrary edges but acyclic.
    #[test]
    fn dag_doctrine() {
        let mut graph = Codeswitch::new();
        let a = add_node(&mut graph, "a", 0, &Dag).unwrap();
        let b = add_node(&mut graph, "b", 0, &Dag).unwrap();
        let c = add_node(&mut graph, "c", 0, &Dag).unwrap();
        // Diamond shape: a -> b, a -> c, b -> d, c -> d
        let d = add_node(&mut graph, "d", 0, &Dag).unwrap();
        assert!(add_edge(&mut graph, HashSet::from([a]), HashSet::from([b]), &Dag).is_ok());
        assert!(add_edge(&mut graph, HashSet::from([a]), HashSet::from([c]), &Dag).is_ok());
        assert!(add_edge(&mut graph, HashSet::from([b]), HashSet::from([d]), &Dag).is_ok());
        assert!(add_edge(&mut graph, HashSet::from([c]), HashSet::from([d]), &Dag).is_ok());
        // Attempt to create cycle should fail
        assert!(add_edge(&mut graph, HashSet::from([d]), HashSet::from([a]), &Dag).is_err());
    }

    /// Test full ω‑hypergraph doctrine: multi‑source, multi‑target edges.
    #[test]
    fn full_omega_hypergraph_doctrine() {
        let mut graph = Codeswitch::new();
        let a = add_node(&mut graph, "a", 0, &FullOmegaHypergraph).unwrap();
        let b = add_node(&mut graph, "b", 0, &FullOmegaHypergraph).unwrap();
        let c = add_node(&mut graph, "c", 0, &FullOmegaHypergraph).unwrap();
        let d = add_node(&mut graph, "d", 0, &FullOmegaHypergraph).unwrap();
        // Hyperedge with multiple sources and multiple targets
        assert!(
            add_edge(
                &mut graph,
                HashSet::from([a, b]),
                HashSet::from([c, d]),
                &FullOmegaHypergraph
            )
            .is_ok()
        );
        // Should still be acyclic
        assert!(is_well_formed(&graph, &FullOmegaHypergraph));
        // Cycle detection still works
        assert!(
            add_edge(
                &mut graph,
                HashSet::from([c]),
                HashSet::from([a]),
                &FullOmegaHypergraph
            )
            .is_err()
        );
    }

    /// Test evaluation (fold over downward closure).
    #[test]
    fn evaluation() {
        let mut graph = Codeswitch::new();
        let a = add_node(&mut graph, 1, 0, &Dag).unwrap();
        let b = add_node(&mut graph, 2, 0, &Dag).unwrap();
        let c = add_node(&mut graph, 3, 0, &Dag).unwrap();
        // a -> b, a -> c
        add_edge(&mut graph, HashSet::from([a]), HashSet::from([b]), &Dag).unwrap();
        add_edge(&mut graph, HashSet::from([a]), HashSet::from([c]), &Dag).unwrap();
        // Evaluate from frontier {b, c}
        let sum = evaluate(&graph, &HashSet::from([b, c]), 0, |acc, &x| acc + x);
        // Downward closure includes a, b, c. Topological order: a, then b and c (order unspecified).
        // Sum = 1 + 2 + 3 = 6
        assert_eq!(sum, 6);
    }

    /// Test rollback.
    #[test]
    fn rollback_frontier() {
        let mut graph = Codeswitch::new();
        let a = add_node(&mut graph, "a", 0, &Dag).unwrap();
        let b = add_node(&mut graph, "b", 0, &Dag).unwrap();
        let c = add_node(&mut graph, "c", 0, &Dag).unwrap();
        // a -> b, b -> c
        add_edge(&mut graph, HashSet::from([a]), HashSet::from([b]), &Dag).unwrap();
        add_edge(&mut graph, HashSet::from([b]), HashSet::from([c]), &Dag).unwrap();
        // Set frontier to c
        graph.set_frontier_raw(HashSet::from([c]));
        // Rollback to b
        rollback(&mut graph, &HashSet::from([b]), &Dag).unwrap();
        assert_eq!(graph.frontier(), &HashSet::from([b]));
        // Rollback to a
        rollback(&mut graph, &HashSet::from([a]), &Dag).unwrap();
        assert_eq!(graph.frontier(), &HashSet::from([a]));
    }

    /// Test deterministic fingerprinting across different build orders.
    #[test]
    fn fingerprint_determinism() {
        use std::collections::HashMap;
        // Build graph A: linear chain a -> b -> c using add_edge
        let mut graph_a = Codeswitch::new();
        let a1 = add_node(&mut graph_a, "payload_a", 0, &Dag).unwrap();
        let b1 = add_node(&mut graph_a, "payload_b", 0, &Dag).unwrap();
        let c1 = add_node(&mut graph_a, "payload_c", 0, &Dag).unwrap();
        add_edge(&mut graph_a, HashSet::from([a1]), HashSet::from([b1]), &Dag).unwrap();
        add_edge(&mut graph_a, HashSet::from([b1]), HashSet::from([c1]), &Dag).unwrap();

        // Build graph B: same structure but different insertion order (c, a, b) and using commit for edges
        let mut graph_b = Codeswitch::new();
        // Create nodes in different order
        let c2 = add_node(&mut graph_b, "payload_c", 0, &Dag).unwrap();
        let a2 = add_node(&mut graph_b, "payload_a", 0, &Dag).unwrap();
        let b2 = add_node(&mut graph_b, "payload_b", 0, &Dag).unwrap();
        // Add edges in different order
        add_edge(&mut graph_b, HashSet::from([b2]), HashSet::from([c2]), &Dag).unwrap();
        add_edge(&mut graph_b, HashSet::from([a2]), HashSet::from([b2]), &Dag).unwrap();

        // Compute WL fingerprints (3 rounds should be enough for this small graph)
        let fingerprints_a = wl_refinement(&graph_a, 3);
        let fingerprints_b = wl_refinement(&graph_b, 3);

        // The graphs are isomorphic (same shape, same payloads).
        // Node IDs differ, but structural fingerprints should be identical across isomorphism.
        // Since we built the graphs with same payloads and same adjacency structure,
        // the multiset of fingerprint values should be identical.
        let mut multiset_a: Vec<_> = fingerprints_a.values().map(|fp| fp.hash().0).collect();
        let mut multiset_b: Vec<_> = fingerprints_b.values().map(|fp| fp.hash().0).collect();
        multiset_a.sort();
        multiset_b.sort();
        assert_eq!(multiset_a, multiset_b, "WL fingerprint multisets differ");

        // Additionally, definitional hashes should be identical for nodes with same payload/dimension.
        let def_a = definitional_hashes(&graph_a);
        let def_b = definitional_hashes(&graph_b);
        // Map from payload to hash (since NodeIds differ)
        let mut map_a = HashMap::new();
        for (id, hash) in def_a {
            let node = graph_a.get_node(id).unwrap();
            // For simplicity, compare payload strings (they are &str)
            map_a.insert(node.payload, hash.hash().0);
        }
        let mut map_b = HashMap::new();
        for (id, hash) in def_b {
            let node = graph_b.get_node(id).unwrap();
            map_b.insert(node.payload, hash.hash().0);
        }
        assert_eq!(map_a, map_b, "Definitional hashes differ for same payloads");

        // Edge content hashes should also be isomorphic.
        // For each edge in graph_a, find matching edge in graph_b by endpoint payloads.
        // This is more complex; we can skip for Phase 1A.
    }

    /// Strong isomorphism test with explicit node renaming and edge order permutation.
    #[test]
    fn fingerprint_isomorphism() {
        use std::collections::HashMap;
        // Graph shape: three nodes a, b, c with edges a->b, b->c, a->c (small DAG)
        // Build graph A with node creation order a, b, c and edge order a->b, b->c, a->c
        let mut graph_a = Codeswitch::new();
        let a1 = add_node(&mut graph_a, "payload_a", 0, &Dag).unwrap();
        let b1 = add_node(&mut graph_a, "payload_b", 0, &Dag).unwrap();
        let c1 = add_node(&mut graph_a, "payload_c", 0, &Dag).unwrap();
        add_edge(&mut graph_a, HashSet::from([a1]), HashSet::from([b1]), &Dag).unwrap();
        add_edge(&mut graph_a, HashSet::from([b1]), HashSet::from([c1]), &Dag).unwrap();
        add_edge(&mut graph_a, HashSet::from([a1]), HashSet::from([c1]), &Dag).unwrap();

        // Build graph B with different node creation order c, a, b and different edge order
        let mut graph_b = Codeswitch::new();
        let c2 = add_node(&mut graph_b, "payload_c", 0, &Dag).unwrap();
        let a2 = add_node(&mut graph_b, "payload_a", 0, &Dag).unwrap();
        let b2 = add_node(&mut graph_b, "payload_b", 0, &Dag).unwrap();
        // Different edge addition order: a->c, b->c, a->b
        add_edge(&mut graph_b, HashSet::from([a2]), HashSet::from([c2]), &Dag).unwrap();
        add_edge(&mut graph_b, HashSet::from([b2]), HashSet::from([c2]), &Dag).unwrap();
        add_edge(&mut graph_b, HashSet::from([a2]), HashSet::from([b2]), &Dag).unwrap();

        // Compute WL fingerprints (4 rounds for convergence)
        let fingerprints_a = wl_refinement(&graph_a, 4);
        let fingerprints_b = wl_refinement(&graph_b, 4);

        // The two graphs are isomorphic (same shape, same payloads, different NodeIds).
        // Structural fingerprint multisets must be identical.
        let mut multiset_a: Vec<_> = fingerprints_a.values().map(|fp| fp.hash().0).collect();
        let mut multiset_b: Vec<_> = fingerprints_b.values().map(|fp| fp.hash().0).collect();
        multiset_a.sort();
        multiset_b.sort();
        assert_eq!(multiset_a, multiset_b, "WL fingerprint multisets differ under isomorphism");

        // Additionally, verify that definitional hashes match per payload
        let def_a = definitional_hashes(&graph_a);
        let def_b = definitional_hashes(&graph_b);
        let mut map_a = HashMap::new();
        for (id, hash) in def_a {
            let node = graph_a.get_node(id).unwrap();
            map_a.insert(node.payload, hash.hash().0);
        }
        let mut map_b = HashMap::new();
        for (id, hash) in def_b {
            let node = graph_b.get_node(id).unwrap();
            map_b.insert(node.payload, hash.hash().0);
        }
        assert_eq!(map_a, map_b, "Definitional hashes differ for same payloads");

        // Edge content hashes: for each edge in graph_a, there should be a matching edge in graph_b
        // with same endpoint payloads, and their content hashes should match.
        // We'll compute edge content hashes using definitional hashes.
        let def_map_a: HashMap<NodeId, DefinitionalHash> = definitional_hashes(&graph_a);
        let def_map_b: HashMap<NodeId, DefinitionalHash> = definitional_hashes(&graph_b);
        let mut edge_hashes_a = Vec::new();
        for edge in graph_a.edges_sorted() {
            edge_hashes_a.push(edge_content_hash(edge, &def_map_a).0);
        }
        let mut edge_hashes_b = Vec::new();
        for edge in graph_b.edges_sorted() {
            edge_hashes_b.push(edge_content_hash(edge, &def_map_b).0);
        }
        edge_hashes_a.sort();
        edge_hashes_b.sort();
        assert_eq!(edge_hashes_a, edge_hashes_b, "Edge content hashes differ under isomorphism");
    }

    /// Test that pattern matching APIs compile and can be used (Phase 2 stub).
    #[test]
    fn pattern_api_smoke_test() {
        use super::prelude::*;
        use std::collections::HashSet;

        // Create a simple graph
        let mut graph: Codeswitch<&str> = Codeswitch::new();
        let a = add_node(&mut graph, "a", 0, &Dag).unwrap();
        let b = add_node(&mut graph, "b", 0, &Dag).unwrap();
        add_edge(&mut graph, HashSet::from([a]), HashSet::from([b]), &Dag).unwrap();

        // Create a pattern
        let pattern = Pattern::new();
        // In real usage, we'd add pattern nodes and edges
        // This just tests that the API compiles

        // Test that find_matches compiles (returns empty list for stub)
        let matches = graph.find_matches(&pattern);
        assert_eq!(matches.len(), 0);

        // Test that we can create a PatternMatch
        let node_map = std::collections::HashMap::new();
        let match_fp = HashValue::zero();
        let pattern_match = PatternMatch::new(node_map, match_fp);

        // Test that we can create a RewriteTemplate
        let rhs = Codeswitch::new();
        let preservation_map = std::collections::HashMap::new();
        let template = RewriteTemplate::new(rhs, preservation_map);

        // Test that apply_template compiles (returns Ok for stub)
        let result = graph.apply_template(&pattern_match, &template);
        assert!(result.is_ok());
    }

    /// Test that traceability APIs compile and can be used (Phase 2 stub).
    #[test]
    fn traceability_api_smoke_test() {
        use super::prelude::*;

        // Create a simple graph
        let graph: Codeswitch<&str> = Codeswitch::new();

        // Test that we can create a RewriteTrace
        let trace = RewriteTrace::new(graph.clone());
        assert_eq!(trace.step_count(), 0);
        assert_eq!(trace.current_version(), 0);

        // Test that HypergraphTraceability trait is implemented
        // (compile-time check only)
    }

    /// Test that HypergraphTraceStorage trait is exported and can be used.
    #[test]
    fn trace_storage_export() {
        use super::prelude::*;
        // Ensure the trait is in scope
        let graph: Codeswitch<&str> = Codeswitch::new();
        // This calls the stub implementation; we just verify it compiles
        let result = graph.get_trace();
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }
}
