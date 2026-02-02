//! Adapter for reusing existing doctrine validation on FastGraph neighborhoods.
//!
//! `FastToStonewallAdapter` constructs a temporary Codeswitch that
//! represents the local neighborhood of a focus node, allowing existing
//! `Doctrine::validate_graph` to be applied without modifying doctrine
//! implementations.

use crate::arena::{ArenaNodeId, EXTERN_INPUTS_NODE, EXTERN_OUTPUTS_NODE};
use crate::core::{HyperEdge, Node, NodeId, Codeswitch};
use crate::graph::fast::FastGraph;
use std::collections::{HashMap, HashSet};
use std::ops::Deref;

/// Adapter that presents a FastGraph local neighborhood as a Codeswitch.
///
/// The adapter constructs a temporary graph containing:
/// - the focus node
/// - its immediate neighbors (inputs and outputs)
/// - the reserved extern pseudo‑nodes if they appear in the neighborhood
///
/// All edges among these nodes are replicated as hyperedges with singleton
/// sources/targets (FastGraph edges are always binary).
pub struct FastToStonewallAdapter<P> {
    /// The temporary Codeswitch graph.
    temp_graph: Codeswitch<P>,
    /// Mapping from original ArenaNodeId to temporary NodeId.
    /// Only includes nodes that were actually added to temp_graph.
    _mapping: HashMap<ArenaNodeId, NodeId>,
}

impl<P: Clone> FastToStonewallAdapter<P> {
    /// Constructs a new adapter for the neighborhood of `focus` in `graph`.
    ///
    /// The construction is deterministic: nodes and edges are added in sorted
    /// order of ArenaNodeId.
    pub fn new(graph: &FastGraph<P>, focus: ArenaNodeId) -> Self {
        let mut temp_graph = Codeswitch::new();
        let mut mapping = HashMap::new();
        let mut nodes_to_add = HashSet::new();

        // Include focus
        nodes_to_add.insert(focus);
        // Include its immediate neighbors (inputs and outputs)
        if let Some(data) = graph.node_data(focus) {
            for &nb in &data.inputs {
                nodes_to_add.insert(nb);
            }
            for &nb in &data.outputs {
                nodes_to_add.insert(nb);
            }
        }
        // Ensure extern pseudo‑nodes are added if they are neighbors
        if nodes_to_add.contains(&EXTERN_INPUTS_NODE) {
            nodes_to_add.insert(EXTERN_INPUTS_NODE);
        }
        if nodes_to_add.contains(&EXTERN_OUTPUTS_NODE) {
            nodes_to_add.insert(EXTERN_OUTPUTS_NODE);
        }

        // Convert to sorted vector for deterministic insertion order
        let mut sorted_nodes: Vec<ArenaNodeId> = nodes_to_add.into_iter().collect();
        sorted_nodes.sort();

        // Add each node to temp_graph
        for &arena_id in &sorted_nodes {
            let node_id = Self::add_node_to_temp(&mut temp_graph, graph, arena_id);
            mapping.insert(arena_id, node_id);
        }

        // Add edges
        for &arena_id in &sorted_nodes {
            Self::add_edges_for_node(&mut temp_graph, graph, arena_id, &mapping);
        }

        Self {
            temp_graph,
            _mapping: mapping,
        }
    }

    /// Adds a single node from the FastGraph to the temporary Codeswitch.
    ///
    /// Returns the newly created NodeId.
    fn add_node_to_temp(
        temp: &mut Codeswitch<P>,
        graph: &FastGraph<P>,
        arena_id: ArenaNodeId,
    ) -> NodeId {
        // For extern pseudo‑nodes, we create a dummy payload.
        // The payload type must be Clone, so we need a default value.
        // Since we cannot invent a payload of arbitrary P, we must have a
        // payload already stored in the FastGraph for these nodes.
        // However, the pseudo‑nodes are never stored in the arena with user data.
        // Therefore we require that P implements Default for the adapter.
        // This is a limitation of the adapter approach; in practice, doctrines
        // that need to validate pseudo‑nodes should override validate_fast_local.
        // For PR1 we assume pseudo‑nodes are not validated.
        let payload = if arena_id == EXTERN_INPUTS_NODE || arena_id == EXTERN_OUTPUTS_NODE {
            // We'll need a default payload. Since we cannot create one,
            // we'll panic if pseudo‑nodes are actually used in validation.
            // This is acceptable for PR1 because NoOpDoctrine overrides.
            panic!("Adapter cannot handle extern pseudo‑nodes; override validate_fast_local");
        } else {
            graph
                .node_data(arena_id)
                .expect("node must exist in FastGraph")
                .payload
                .clone()
        };
        let dim = 0; // FastGraph does not track dimension; use default.
        let node_id = temp.fresh_id();
        let node = Node::new(node_id, payload, dim);
        temp.add_node_raw(node);
        node_id
    }

    /// Adds edges incident to `arena_id` to the temporary graph.
    fn add_edges_for_node(
        temp: &mut Codeswitch<P>,
        graph: &FastGraph<P>,
        arena_id: ArenaNodeId,
        mapping: &HashMap<ArenaNodeId, NodeId>,
    ) {
        let Some(data) = graph.node_data(arena_id) else { return };
        let src_id = mapping[&arena_id];

        // Output edges: arena_id → each output
        for &out in &data.outputs {
            if let Some(&tgt_id) = mapping.get(&out) {
                let edge = HyperEdge::new(HashSet::from([src_id]), HashSet::from([tgt_id]));
                temp.add_edge_raw(edge);
            }
        }
        // Input edges: each input → arena_id
        for &inp in &data.inputs {
            if let Some(&tgt_id) = mapping.get(&inp) {
                // Note: tgt_id is the input node's NodeId, src_id is the focus.
                // Edge direction is input → focus.
                let edge = HyperEdge::new(HashSet::from([tgt_id]), HashSet::from([src_id]));
                temp.add_edge_raw(edge);
            }
        }
    }
}

impl<P> Deref for FastToStonewallAdapter<P> {
    type Target = Codeswitch<P>;
    fn deref(&self) -> &Self::Target {
        &self.temp_graph
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctrine::ext::ExtendedDoctrine;
    use crate::NoOpDoctrine;

    #[test]
    fn adapter_constructs_deterministically() {
        let mut graph: FastGraph<&'static str> = FastGraph::new();
        let a = graph.add_primitive("a");
        let b = graph.add_primitive("b");
        let c = graph.add_compose(a, b, "c");
        // Focus on c
        let adapter = FastToStonewallAdapter::new(&graph, c);
        // Should have nodes a, b, c
        assert_eq!(adapter.temp_graph.node_count(), 3);
        // Should have edges a→c, b→c
        assert_eq!(adapter.temp_graph.edge_count(), 2);
    }

    #[test]
    fn adapter_works_with_noop_doctrine() {
        let mut graph: FastGraph<&'static str> = FastGraph::new();
        let a = graph.add_primitive("a");
        let b = graph.add_primitive("b");
        let _c = graph.add_compose(a, b, "c");
        let doctrine = NoOpDoctrine;
        // validate_fast_local should succeed (via adapter)
        let result = doctrine.validate_fast_local(&graph, a);
        assert!(result.is_ok());
    }
}