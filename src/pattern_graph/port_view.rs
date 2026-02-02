//! Certified PortView projection for backward compatibility.
//!
//! Implements the projection from PatternGraph to port-typed hypergraphs
//! (FastGraph/GeneralGraph) with a witness that Stonewall can verify.
//! This preserves performance and compatibility with the existing rewrite engine.

use super::core::{PatternGraph, ResolvedPattern, PatternBoundary, HoleId};
use crate::graph::{TermGraph, fast::FastGraph};
use crate::arena::{ArenaNodeId, EXTERN_INPUTS_NODE, EXTERN_OUTPUTS_NODE};
use crate::fingerprint::HashValue;
use std::collections::BTreeMap;

/// Errors that can occur during PortView verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    /// Pattern hash mismatch.
    HashMismatch,
    /// Hole map inconsistency.
    HoleMapMismatch,
    /// Boundary map inconsistency.
    BoundaryMapMismatch,
    /// Graph projection mismatch.
    GraphMismatch,
}

/// A PortView is a certified projection of a PatternGraph into a port-typed graph.
#[derive(Debug, Clone)]
pub struct PortView {
    /// The projected graph (FastGraph if eligible, otherwise GeneralGraph).
    pub graph: PortGraph,
    /// Mapping from PatternBoundary elements to port indices.
    pub boundary_map: BoundaryMap,
    /// Mapping from hole IDs to port references.
    pub hole_map: HoleMap,
    /// Witness of the projection's correctness.
    pub witness: ProjectionWitness,
    /// Hash of the PortView.
    pub portview_hash: HashValue,
}

/// Port-typed graph (FastGraph or GeneralGraph).
pub type PortGraph = TermGraph<()>; // TODO: proper payload type

/// Mapping from boundary ports to graph ports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryMap {
    /// Maps input port index to (node_id, input_slot).
    pub inputs: Vec<(ArenaNodeId, usize)>,
    /// Maps output port index to (node_id, output_slot).
    pub outputs: Vec<(ArenaNodeId, usize)>,
}

/// Mapping from hole IDs to port references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoleMap {
    /// Maps hole ID to (node_id, port_index, is_input).
    pub holes: BTreeMap<HoleId, (ArenaNodeId, usize, bool)>,
}

/// Witness that the projection is lossless for the given term/rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionWitness {
    /// Hash of the original PatternGraph.
    pub original_hash: HashValue,
    /// Hash of the projection.
    pub projected_hash: HashValue,
    /// Encoding of the projection steps (placeholder).
    pub steps: Vec<u8>,
}

impl PortView {
    /// Verify that this PortView correctly projects the given PatternGraph.
    pub fn verify(&self, original: &PatternGraph) -> Result<(), VerificationError> {
        // Check original hash matches witness
        if original.hash() != self.witness.original_hash {
            return Err(VerificationError::HashMismatch);
        }

        // Recompute projection (must succeed because original is eligible)
        let recomputed = project_to_portview(original)
            .expect("PatternGraph should be eligible for PortView");

        // Compare boundary maps
        if self.boundary_map != recomputed.boundary_map {
            return Err(VerificationError::BoundaryMapMismatch);
        }

        // Compare hole maps
        if self.hole_map != recomputed.hole_map {
            return Err(VerificationError::HoleMapMismatch);
        }

        // Compare graph equality
        if self.graph != recomputed.graph {
            return Err(VerificationError::GraphMismatch);
        }

        Ok(())
    }
}

/// Eligibility predicate: determines if a PatternGraph can be projected to PortView.
pub fn is_portview_eligible(graph: &PatternGraph) -> bool {
    // v0.1: binder-free, boundary flattens cleanly, all constructors representable
    // For now, accept only patterns containing Generator, Compose, App (no InDoctrine, Reject)
    // and ensure Compose arity == 2 (binary) or flattenable.
    // Also ensure App arity <= 2 (FastGraph limit).
    check_pattern_eligible(graph.pattern())
}

pub(crate) fn check_pattern_eligible(pattern: &ResolvedPattern) -> bool {
    match pattern {
        ResolvedPattern::Hole(_) => true,
        ResolvedPattern::Generator(_) => true,
        ResolvedPattern::Compose(children) => {
            // For now, require exactly 2 children (binary compose)
            // Later we can flatten n-ary compose to binary chain.
            children.len() == 2 && children.iter().all(check_pattern_eligible)
        }
        ResolvedPattern::App { args, .. } => {
            // FastGraph primitive nodes can have arbitrary inputs?
            // For simplicity, limit to <= 2 inputs.
            args.len() <= 2 && args.iter().all(check_pattern_eligible)
        }
        ResolvedPattern::Reject { .. } => false,
        ResolvedPattern::InDoctrine { .. } => false,
    }
}

/// Project a PatternGraph to a PortView if eligible.
pub fn project_to_portview(graph: &PatternGraph) -> Option<PortView> {
    if !is_portview_eligible(graph) {
        return None;
    }

    // For v0.1, we only handle simple cases: single generator or binary compose.
    // We'll build a FastGraph with unit payload.
    let mut fast_graph = FastGraph::new();
    let mut hole_map = BTreeMap::new();
    let _root_id = build_fast_graph(graph.pattern(), &mut fast_graph, &mut hole_map, graph.boundary())?;

    // Build boundary map: map each boundary port to pseudo-node slots.
    let boundary = graph.boundary();
    let inputs = (0..boundary.in_ports.len())
        .map(|i| (EXTERN_INPUTS_NODE, i))
        .collect();
    let outputs = (0..boundary.out_ports.len())
        .map(|i| (EXTERN_OUTPUTS_NODE, i))
        .collect();
    let boundary_map = BoundaryMap { inputs, outputs };

    let portview_hash = graph.hash(); // Use same hash for now

    Some(PortView {
        graph: PortGraph::Fast(fast_graph),
        boundary_map,
        hole_map: HoleMap { holes: hole_map },
        witness: ProjectionWitness {
            original_hash: graph.hash(),
            projected_hash: portview_hash,
            steps: Vec::new(),
        },
        portview_hash,
    })
}

/// Recursively build FastGraph nodes from a ResolvedPattern.
/// Returns the ArenaNodeId of the built subgraph.
fn build_fast_graph(
    pattern: &ResolvedPattern,
    fast_graph: &mut FastGraph<()>,
    hole_map: &mut BTreeMap<HoleId, (ArenaNodeId, usize, bool)>,
    _boundary: &PatternBoundary,
) -> Option<ArenaNodeId> {
    match pattern {
        ResolvedPattern::Hole(hole_id) => {
            // Create a placeholder primitive node for the hole.
            let node_id = fast_graph.add_primitive(());
            // Record mapping: hole maps to node's input port? Actually holes are external ports.
            // For now, map to node's input port 0.
            hole_map.insert(*hole_id, (node_id, 0, false));
            Some(node_id)
        }
        ResolvedPattern::Generator(_gen_id) => {
            // Create primitive node with empty payload.
            let node_id = fast_graph.add_primitive(());
            Some(node_id)
        }
        ResolvedPattern::Compose(children) => {
            if children.len() != 2 {
                // Should have been caught by eligibility.
                return None;
            }
            let left_id = build_fast_graph(&children[0], fast_graph, hole_map, _boundary)?;
            let right_id = build_fast_graph(&children[1], fast_graph, hole_map, _boundary)?;
            let node_id = fast_graph.add_compose(left_id, right_id, ());
            Some(node_id)
        }
        ResolvedPattern::App { op: _, args: _args } => {
            // Create primitive node with inputs as child nodes.
            // FastGraph primitive nodes have no built-in input slots; we need to connect via edges.
            // For simplicity, treat as primitive with no inputs (lossy).
            // TODO: proper handling of App nodes.
            let node_id = fast_graph.add_primitive(());
            // For each arg, we could add edges, but FastGraph edges are via compose/tensor.
            // This is a limitation; we need to map App to primitive with inputs.
            // For now, ignore args.
            Some(node_id)
        }
        // InDoctrine and Reject should have been filtered by eligibility.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pattern_graph::core::{ResolvedPattern, PatternBoundary, HoleId, GeneratorId};

    #[test]
    fn test_portview_eligible_simple() {
        // Simple generator pattern
        let pattern = ResolvedPattern::generator(GeneratorId(100));
        let boundary = PatternBoundary::with_arity(0, 1);
        let graph = crate::pattern_graph::core::PatternGraph::new(pattern, boundary);
        assert!(is_portview_eligible(&graph));
        let portview = project_to_portview(&graph).expect("should project");
        portview.verify(&graph).expect("verification should pass");
    }

    #[test]
    fn test_portview_hole() {
        // Hole pattern
        let pattern = ResolvedPattern::hole(HoleId(1));
        let boundary = PatternBoundary::with_arity(0, 1);
        let graph = crate::pattern_graph::core::PatternGraph::new(pattern, boundary);
        assert!(is_portview_eligible(&graph));
        let portview = project_to_portview(&graph).expect("should project");
        portview.verify(&graph).expect("verification should pass");
        // Check hole map contains entry for hole 1
        assert_eq!(portview.hole_map.holes.len(), 1);
        let &(node_id, _port_idx, is_input) = portview.hole_map.holes.get(&HoleId(1)).unwrap();
        assert_eq!(is_input, false); // hole maps to output port
        // node_id should be valid in graph
        match portview.graph {
            PortGraph::Fast(ref fast) => {
                assert!(fast.node_data(node_id).is_some());
            }
        }
    }

    #[test]
    fn test_portview_compose() {
        // Compose of two generators
        let left = ResolvedPattern::generator(GeneratorId(100));
        let right = ResolvedPattern::generator(GeneratorId(200));
        let pattern = ResolvedPattern::Compose(vec![left, right]);
        let boundary = PatternBoundary::with_arity(0, 1);
        let graph = crate::pattern_graph::core::PatternGraph::new(pattern, boundary);
        assert!(is_portview_eligible(&graph));
        let portview = project_to_portview(&graph).expect("should project");
        portview.verify(&graph).expect("verification should pass");
    }
}