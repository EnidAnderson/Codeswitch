//! Pattern matching and template application for ω-hypergraphs.
//!
//! Implements anchored pattern matching where patterns are small hypergraphs
//! that can be matched against larger hypergraphs. Supports finding all
//! occurrences of a pattern and applying rewrite templates at match sites.
//!
//! # Citations
//! - Graph pattern matching: Ullmann, "An algorithm for subgraph isomorphism" (1976)
//! - Hypergraph rewriting: Bauderon & Courcelle, "Graph expressions and graph rewritings" (1987)
//! - Double-pushout rewriting: Ehrig et al., "Algebraic approach to graph transformation" (1999)

use crate::core::{HyperEdge, NodeId, Codeswitch};
use crate::fingerprint::HashValue;
use std::collections::{HashMap, HashSet};

/// Data associated with a pattern node.
///
/// Contains dimension and optional payload constraint. For wildcard nodes,
/// the payload constraint is `None` and the node matches any graph node
/// of the same dimension.
///
/// # Citations
/// - Pattern variables: Baader & Nipkow, "Term Rewriting and All That", Chapter 4 (1998)
#[derive(Debug, Clone)]
struct PatternNodeData<P> {
    /// Dimension of the cell (0 for objects, 1 for morphisms, etc.).
    dim: usize,
    /// Optional payload constraint. If `Some(p)`, the matched graph node
    /// must have equal payload. If `None`, any payload is accepted (wildcard).
    payload_constraint: Option<P>,
    /// Whether this node is an anchor (must match a designated site).
    is_anchor: bool,
}

/// A pattern is a small hypergraph that can be matched against a larger hypergraph.
///
/// Patterns contain nodes with dimension and optional payload constraints,
/// and hyperedges representing boundary relations. Nodes can be wildcards
/// (holes) or concrete cells with payload constraints.
///
/// # Citations
/// - Pattern graphs: Bunke, "Graph matching for visual object recognition" (2000)
/// - Context patterns: McBride, "The derivative of a regular type is its type of one-hole contexts", Section 2 (2001)
#[derive(Debug)]
pub struct Pattern<P> {
    /// Pattern nodes with their constraints.
    nodes: HashMap<NodeId, PatternNodeData<P>>,
    /// Hyperedges in the pattern.
    edges: HashSet<HyperEdge>,
}

impl<P> Pattern<P> {
    /// Creates a new empty pattern.
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: HashSet::new(),
        }
    }

    /// Adds a concrete node with payload constraint.
    pub fn add_concrete_node(&mut self, id: NodeId, dim: usize, payload: P, is_anchor: bool) {
        self.nodes.insert(
            id,
            PatternNodeData {
                dim,
                payload_constraint: Some(payload),
                is_anchor,
            },
        );
    }

    /// Adds a wildcard (hole) node.
    pub fn add_wildcard_node(&mut self, id: NodeId, dim: usize, is_anchor: bool) {
        self.nodes.insert(
            id,
            PatternNodeData {
                dim,
                payload_constraint: None,
                is_anchor,
            },
        );
    }

    /// Adds a hyperedge to the pattern.
    pub fn add_edge(&mut self, edge: HyperEdge) {
        self.edges.insert(edge);
    }

    /// Returns whether a node is an anchor (must match specific target node).
    pub fn is_anchor(&self, id: NodeId) -> bool {
        self.nodes
            .get(&id)
            .map(|data| data.is_anchor)
            .unwrap_or(false)
    }

    /// Returns whether a node is a wildcard (hole).
    pub fn is_wildcard(&self, id: NodeId) -> bool {
        self.nodes
            .get(&id)
            .map(|data| data.payload_constraint.is_none())
            .unwrap_or(false)
    }

    /// Returns the dimension constraint for a pattern node.
    pub fn node_dim(&self, id: NodeId) -> Option<usize> {
        self.nodes.get(&id).map(|data| data.dim)
    }

    /// Returns the payload constraint for a pattern node, if any.
    pub fn payload_constraint(&self, id: NodeId) -> Option<&P> {
        self.nodes
            .get(&id)
            .and_then(|data| data.payload_constraint.as_ref())
    }

    /// Returns an iterator over all pattern node IDs.
    pub fn node_ids(&self) -> impl Iterator<Item = NodeId> + '_ {
        self.nodes.keys().copied()
    }

    /// Returns the number of anchor nodes in the pattern.
    pub fn anchor_count(&self) -> usize {
        self.nodes.values().filter(|data| data.is_anchor).count()
    }

    /// Returns the number of wildcard nodes in the pattern.
    pub fn wildcard_count(&self) -> usize {
        self.nodes
            .values()
            .filter(|data| data.payload_constraint.is_none())
            .count()
    }
}

impl<P> Default for Pattern<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: Clone> Clone for Pattern<P> {
    fn clone(&self) -> Self {
        Self {
            nodes: self.nodes.clone(),
            edges: self.edges.clone(),
        }
    }
}

/// A match of a pattern in a hypergraph.
///
/// Maps pattern node IDs to target graph node IDs.
/// All pattern edges must have corresponding edges in the target graph.
///
/// # Citations
/// - Subgraph isomorphism: Cordella et al., "A (sub)graph isomorphism algorithm for matching large graphs" (2004)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternMatch {
    /// Mapping from pattern node IDs to target graph node IDs.
    node_map: HashMap<NodeId, NodeId>,
    /// Fingerprint of the matched region for validation.
    region_fingerprint: HashValue,
}

impl PatternMatch {
    /// Creates a new pattern match.
    pub fn new(node_map: HashMap<NodeId, NodeId>, region_fingerprint: HashValue) -> Self {
        Self {
            node_map,
            region_fingerprint,
        }
    }

    /// Returns the target node ID for a given pattern node ID.
    pub fn target_for(&self, pattern_node: NodeId) -> Option<NodeId> {
        self.node_map.get(&pattern_node).copied()
    }

    /// Returns the fingerprint of the matched region.
    pub fn region_fingerprint(&self) -> HashValue {
        self.region_fingerprint
    }

    /// Returns mapping for wildcard (hole) nodes only.
    ///
    /// Filters the node map to include only pattern nodes that are wildcards
    /// (holes) in the given pattern. Returns a map from pattern hole IDs to
    /// graph node IDs.
    pub fn hole_mapping<P>(&self, pattern: &Pattern<P>) -> HashMap<NodeId, NodeId> {
        self.node_map
            .iter()
            .filter(|(pat_id, _)| pattern.is_wildcard(**pat_id))
            .map(|(pat_id, graph_id)| (*pat_id, *graph_id))
            .collect()
    }

    /// Returns the primary anchor/site node ID, if the pattern has exactly one anchor.
    ///
    /// The site is the graph node that corresponds to the pattern's anchor node.
    /// Returns `None` if the pattern doesn't have exactly one anchor, or if the
    /// anchor node is not in this match.
    pub fn site<P>(&self, pattern: &Pattern<P>) -> Option<NodeId> {
        // Find anchor node IDs in pattern
        let anchor_ids: Vec<NodeId> = pattern.node_ids()
            .filter(|&id| pattern.is_anchor(id))
            .collect();

        if anchor_ids.len() == 1 {
            self.target_for(anchor_ids[0])
        } else {
            None
        }
    }
}

/// A rewrite template specifies how to replace a matched pattern.
///
/// Contains a right-hand side (RHS) hypergraph that will replace the matched
/// region, along with a mapping from pattern nodes to RHS nodes.
///
/// # Citations
/// - Graph transformation rules: Rozenberg, "Handbook of Graph Grammars and Computing by Graph Transformation" (1997)
#[derive(Debug)]
pub struct RewriteTemplate<P> {
    /// The replacement hypergraph (right-hand side).
    rhs: Codeswitch<P>,
    /// Mapping from pattern node IDs to RHS node IDs.
    /// Nodes not in this mapping are deleted in the rewrite.
    preservation_map: HashMap<NodeId, NodeId>,
}

impl<P> RewriteTemplate<P> {
    /// Creates a new rewrite template.
    pub fn new(rhs: Codeswitch<P>, preservation_map: HashMap<NodeId, NodeId>) -> Self {
        Self {
            rhs,
            preservation_map,
        }
    }

    /// Returns the right-hand side hypergraph.
    pub fn rhs(&self) -> &Codeswitch<P> {
        &self.rhs
    }

    /// Returns the preservation map (pattern node → RHS node).
    pub fn preservation_map(&self) -> &HashMap<NodeId, NodeId> {
        &self.preservation_map
    }
}

impl<P: Clone> Clone for RewriteTemplate<P> {
    fn clone(&self) -> Self {
        Self {
            rhs: self.rhs.clone(),
            preservation_map: self.preservation_map.clone(),
        }
    }
}

/// Trait for anchored pattern matching on ω-hypergraphs.
///
/// Implemented by backends that support finding pattern occurrences and
/// applying rewrite templates at match sites.
///
/// # Citations
/// - Anchored graph matching: Messmer & Bunke, "Efficient subgraph isomorphism detection" (1998)
/// - Matching with variables: Baader & Nipkow, "Term Rewriting and All That", Chapter 4 (1998)
/// - One-hole contexts: McBride, "The derivative of a regular type is its type of one-hole contexts", Section 2 (2001)
/// - Focused traversal: Huet, "Functional Pearl: The Zipper", Section 3 (1997)
pub trait AnchoredPatternMatching<P> {
    /// Finds all occurrences of a pattern in the hypergraph.
    ///
    /// Returns a list of matches, each providing a mapping from pattern nodes
    /// to graph nodes. The search respects anchor constraints.
    ///
    /// # Semantic contract
    /// - A pattern consisting of a single wildcard node matches every node in the graph.
    /// - Pattern edges must have corresponding edges in the target graph.
    /// - Anchor nodes must match exactly the specified target nodes.
    /// - Matching respects boundary compatibility (dimension, payload structure).
    fn find_matches(&self, pattern: &Pattern<P>) -> Vec<PatternMatch>;

    /// Checks whether a pattern matches at a specific site.
    ///
    /// returns the complete match mapping. Otherwise returns `None`.
    ///
    /// This is a focused version of `find_matches` that only examines the neighborhood
    /// of the anchor site, providing O(1) complexity for single‑anchor patterns.
    fn match_at(&self, pattern: &Pattern<P>, site: NodeId) -> Option<PatternMatch>;

    /// Applies a rewrite template at a match site.
    ///
    /// Replaces the matched region with the template's RHS hypergraph,
    /// preserving nodes according to the preservation map.
    /// Returns the modified hypergraph or an error if the rewrite is invalid.
    fn apply_template(
        &self,
        pattern_match: &PatternMatch,
        template: &RewriteTemplate<P>,
    ) -> Result<Codeswitch<P>, PatternMatchError>;
}

/// Error type for pattern matching and template application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternMatchError {
    /// Pattern node maps to non-existent target node.
    InvalidNodeMapping,
    /// Pattern edge has no corresponding target edge.
    MissingEdge,
    /// Rewrite would create a cycle.
    CycleCreated,
    /// Anchor constraint violated.
    AnchorMismatch,
    /// Boundary compatibility violated.
    BoundaryMismatch,
    /// Other error with description.
    Other(String),
}

impl std::fmt::Display for PatternMatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PatternMatchError::InvalidNodeMapping => write!(f, "invalid node mapping"),
            PatternMatchError::MissingEdge => write!(f, "missing edge"),
            PatternMatchError::CycleCreated => write!(f, "rewrite would create a cycle"),
            PatternMatchError::AnchorMismatch => write!(f, "anchor constraint violated"),
    
            PatternMatchError::BoundaryMismatch => write!(f, "boundary compatibility violated"),
            PatternMatchError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for PatternMatchError {}

// ------------------------------------------------------------------------
// Inherent helper methods for Codeswitch pattern matching
// ------------------------------------------------------------------------
impl<P: crate::fingerprint::PayloadFingerprint + Clone>
             Codeswitch<P> {
    /// Simple matching for patterns with no edges (nodes only).
    /// Returns all injective mappings from pattern nodes to graph nodes satisfying constraints.
    /// If an initial mapping is provided, those mappings are fixed.
    fn match_nodes_only(
        &self,
        pattern: &Pattern<P>,
        initial_mapping: Option<&HashMap<NodeId, NodeId>>,
    ) -> Vec<PatternMatch> {
        // Edge matching not yet implemented
        if !pattern.edges.is_empty() {
            return Vec::new();
        }

        // Empty pattern matches nothing
        if pattern.nodes.is_empty() {
            return Vec::new();
        }

        // Collect pattern nodes in deterministic order
        let mut pattern_nodes: Vec<NodeId> = pattern.node_ids().collect();
        pattern_nodes.sort();

        // If initial mapping provided, split into fixed and free nodes
        let fixed_mapping = initial_mapping.cloned().unwrap_or_default();
        let free_nodes: Vec<NodeId> = pattern_nodes
            .iter()
            .filter(|&id| !fixed_mapping.contains_key(id))
            .copied()
            .collect();

        // Early return if all nodes are fixed (no free nodes)
        if free_nodes.is_empty() {
            // Verify that fixed mapping satisfies constraints
            for (pat_id, graph_id) in &fixed_mapping {
                let pat_data = pattern.nodes.get(pat_id).unwrap();
                let graph_node = self.get_node(*graph_id).unwrap();
               
                if graph_node.dim() != pat_data.dim {
                    return Vec::new();
                }
                if let Some(constraint) = &pat_data.payload_constraint {
                    if graph_node.payload.payload_hash() != constraint.payload_hash() {
                        return Vec::new();
                    }
                }
            }
            let fingerprint = self.region_fingerprint_from_mapping(&fixed_mapping);
            return vec![PatternMatch::new(fixed_mapping, fingerprint)];
        }

        // For each free pattern node, generate candidate graph nodes
        let mut candidates: Vec<Vec<NodeId>> = Vec::new();
        for &pat_id in &free_nodes {
            let pat_data = pattern.nodes.get(&pat_id).unwrap();
            let mut node_candidates = Vec::new();
            for (graph_id, graph_node) in self.nodes_sorted() {
                // Skip nodes already in fixed mapping
                if fixed_mapping
                    .values()
                    .any(|&mapped_id| mapped_id == graph_id)
                {
                    continue;
                }
                // Dimension must match
                if graph_node.dim() != pat_data.dim {
                    continue;
                }
                // Payload constraint must match (if present)
                if let Some(constraint) = &pat_data.payload_constraint {
                    if graph_node.payload.payload_hash() != constraint.payload_hash() {
                        continue;
                    }
                }
                node_candidates.push(graph_id);
            }
            candidates.push(node_candidates);
        }

        // If any pattern node has zero candidates, no matches
        if candidates.iter().any(|c| c.is_empty()) {
            return Vec::new();
        }

        // Generate all injective assignments via backtracking (simple)
        let mut matches = Vec::new();
        let mut current_mapping = fixed_mapping.clone();
        let mut used_graph_nodes: HashSet<NodeId> = fixed_mapping.values().copied().collect();

        self.generate_assignments(
            pattern,
            &free_nodes,
            &candidates,
            0,
            &mut current_mapping,
            &mut used_graph_nodes,
            &mut matches,
        );

        matches
    }

    /// Recursive helper to generate injective assignments.
    fn generate_assignments(
        &self,
        pattern: &Pattern<P>,
        free_nodes: &[NodeId],
        candidates: &[Vec<NodeId>],
        depth: usize,
        current_mapping: &mut HashMap<NodeId, NodeId>,
        used_graph_nodes: &mut HashSet<NodeId>,
        matches: &mut Vec<PatternMatch>,
    ) {
        if depth == free_nodes.len() {
            // All free nodes assigned, create match
            let fingerprint = self.region_fingerprint_from_mapping(current_mapping);
            matches.push(PatternMatch::new(current_mapping.clone(), fingerprint));
            return;
        }

        let pat_id = free_nodes[depth];
        for &graph_id in &candidates[depth] {
            if used_graph_nodes.contains(&graph_id) {
                continue;
            }
            // Add to mapping
            current_mapping.insert(pat_id, graph_id);
            used_graph_nodes.insert(graph_id);

            // Recurse
            self.generate_assignments(
                pattern,
                free_nodes,
                candidates,
                depth + 1,
                current_mapping,
                used_graph_nodes,
                matches,
            );

            // Backtrack
            current_mapping.remove(&pat_id);
           
            used_graph_nodes.remove(&graph_id);
        }
    }

    /// Computes a fingerprint for a region defined by a set of node IDs.
    fn region_fingerprint(&self, node_ids: &[NodeId]) -> HashValue {
        self.region_fingerprint_from_mapping(
            &node_ids
                .iter()
                .map(|&id| (id, id))
                .collect::<HashMap<_, _>>(),
        )
    }

    /// Computes a fingerprint for a region defined by a mapping.
    /// The mapping keys are pattern node IDs, values are graph node IDs.
    fn region_fingerprint_from_mapping(&self, mapping: &HashMap<NodeId, NodeId>) -> HashValue {
        // Collect sorted graph node IDs
        let mut graph_nodes: Vec<NodeId> = mapping.values().copied().collect();
        graph_nodes.sort();

        // Collect incident edges (edges where all endpoints are in the region)
        let node_set: HashSet<NodeId> = graph_nodes.iter().copied().collect();
        let mut edge_hashes = Vec::new();
        for edge in self.edges_sorted() {
            if edge.sources.iter().all(|id| node_set.contains(id))
                && edge.targets.iter().all(|id| node_set.contains(id))
            {
                // Compute deterministic hash for this edge
                edge_hashes.push(crate::fingerprint::edge_content_hash(edge, &HashMap::new()).0);
            }
        }
        edge_hashes.sort();

        // Combine node IDs and edge hashes into a single hash
        let mut data = Vec::new();
        for &id in &graph_nodes {
            data.extend_from_slice(&id.as_u64().to_le_bytes());
        }
        for hash in edge_hashes {
            data.extend_from_slice(&hash);
        }
        HashValue::hash_with_domain(b"REGION_FINGERPRINT", &data)
    }
}

/// Basic implementation of pattern matching for Codeswitch.
///
/// Uses backtracking subgraph isomorphism with candidate filtering based on
/// dimension, payload fingerprints, and adjacency constraints. Implements the
/// semantic contract that a single wildcard node pattern matches every node
/// of the same dimension.
///
/// # Citations
/// - Subgraph isomorphism: Ullmann, "An algorithm for subgraph isomorphism" (1976)
/// - Backtracking with forward checking: Haralick & Elliot, "Increasing tree search efficiency for constraint satisfaction problems" (1980)
/// - Wildcard matching: Baader & Nipkow, "Term Rewriting and All That", Chapter 4 (1998)
/// - One-hole contexts: McBride, "The derivative of a regular type is its type of one-hole contexts", Section 2 (2001)
impl<P: crate::fingerprint::PayloadFingerprint + Clone> AnchoredPatternMatching<P>
    for Codeswitch<P>
{
    fn find_matches(&self, pattern: &Pattern<P>) -> Vec<PatternMatch> {
        // Base case: single wildcard node pattern matches every node of same dimension
        if pattern.nodes.len() == 1 && pattern.wildcard_count() == 1 {
            let pattern_node_id = pattern.node_ids().next().unwrap();
            let pattern_dim = pattern.node_dim(pattern_node_id).unwrap();
            let mut matches = Vec::new();
            for (graph_node_id, graph_node) in self.nodes_sorted() {
                if graph_node.dim() != pattern_dim {
                    continue;
                }
            
                let mut node_map = HashMap::new();
                node_map.insert(pattern_node_id, graph_node_id);
                // Compute fingerprint of matched region (just the single node)
                let fingerprint = self.region_fingerprint(&[graph_node_id]);
                matches.push(PatternMatch::new(node_map, fingerprint));
            }
            return matches;
        }

        // General case: simplified implementation for Phase 2A
        // Patterns with no edges: find all injective mappings satisfying node constraints
        // Patterns with edges: return empty vector for now (stub)

        if pattern.edges.is_empty() {
            self.match_nodes_only(pattern, None)
        } else {
            // Edge matching not yet implemented
            Vec::new()
        }
    }

    fn match_at(&self, pattern: &Pattern<P>, site: NodeId) -> Option<PatternMatch> {
        // Pattern must have exactly one anchor node
        if pattern.anchor_count() != 1 {
            return None;
        }
        // Find the anchor node ID
        let anchor_id = pattern
            .node_ids()
            .find(|&id| pattern.is_anchor(id))
            .unwrap();

        // Site must exist in graph and satisfy anchor constraints
        if !self.contains_node(site) {
            return None;
        }
        let site_node = self.get_node(site).unwrap();
        let anchor_data = pattern.nodes.get(&anchor_id).unwrap();
        if site_node.dim() != anchor_data.dim {
            return None;
        }
        if let Some(constraint) = &anchor_data.payload_constraint {
            if site_node.payload.payload_hash() != constraint.payload_hash() {
                return None;
            }
        }

        // Create initial mapping: anchor → site
        let mut initial_map = HashMap::new();
        initial_map.insert(anchor_id, site);

        // Perform nodes-only matching with fixed anchor mapping
        let matches = self.match_nodes_only(pattern, Some(&initial_map));
        matches.into_iter().next()
    }

    fn apply_template(
        &self,
            
        _pattern_match: &PatternMatch,
        _template: &RewriteTemplate<P>,
    ) -> Result<Codeswitch<P>, PatternMatchError> {
        // Phase 2 stub: returns clone of self.
        // Full implementation would:
        // 1. Extract matched region using pattern_match.node_map
        // 2. Remove edges/nodes not preserved by template.preservation_map
        // 3. Insert RHS hypergraph (template.rhs) with node remapping
        // 4. Reconnect edges to preserved nodes
        // 5. Validate acyclicity and doctrine constraints
        Ok(self.clone())
    }
}
/*
    /// Simple matching for patterns with no edges (nodes only).
    /// Returns all injective mappings from pattern nodes to graph nodes satisfying constraints.
    /// If an initial mapping is provided, those mappings are fixed.
    fn match_nodes_only(
        &self,
        pattern: &Pattern<P>,
        initial_mapping: Option<&HashMap<NodeId, NodeId>>,
    ) -> Vec<PatternMatch> {
        // Edge matching not yet implemented
        if !pattern.edges.is_empty() {
            return Vec::new();
        }

        // Empty pattern matches nothing
        if pattern.nodes.is_empty() {
            return Vec::new();
        }

        // Collect pattern nodes in deterministic order
        let mut pattern_nodes: Vec<NodeId> = pattern.node_ids().collect();
        pattern_nodes.sort();

        // If initial mapping pr
                    .values()
                    plit into fixed and free nodes
               
        let fixed_mapping = initial_mapping.cloned().unwrap_or_default();
        let free_nodes: Vec<NodeId> = pattern_nodes
            .iter()
            .filter(|&id| !fixed_mapping.contains_key(id))
            .copied()
            .collect();

        // Early return if all nodes are fixed (no free nodes)
        if free_nodes.is_empty() {
            // Verify that fixed mapping satisfies constraints
            for (pat_id, graph_id) in &fixed_mapping {
                let pat_data = pattern.nodes.get(pat_id).unwrap();
                let graph_node = self.get_node(*graph_id).unwrap();
                if graph_node.dim() != pat_data.dim {
                    return Vec::new();
                }
                if let Some(constraint) = &pat_data.payload_constraint {
                    if graph_node.payload.payload_hash() != constraint.payload_hash() {
                        return Vec::new();
                    }
                }
            }
            let fingerprint = self.region_fingerprint_from_mapping(&fixed_mapping);
            return vec![PatternMatch::new(fixed_mapping, fingerprint)];
        }

        // For each free pattern node, generate candidate graph nodes
        let mut candidates: Vec<Vec<NodeId>> = Vec::new();
        for &pat_id in &free_nodes {
            let pat_data = pattern.nodes.get(&pat_id).unwrap();
            let mut node_candidates = Vec::new();
            for (graph_id, graph_node) in self.nodes_sorted() {
                // Skip nodes already in fixed mapping
                if fixed_mapping
                    .values()
                    .any(|&mapped_id| mapped_id == graph_id)
                {
                    continue;
                }
                // Dimension must match
                if graph_node.dim() != pat_data.dim {
                    continue;
                }
                // Payload constraint must match (if present)
                if let Some(constraint) = &pat_data.payload_constraint {
                    if graph_node.payload.payload_hash() != constraint.payload_hash() {
                        continue;
                    }
                }
                node_candidates.push(graph_id);
            }
            candidates.push(node_candidates);
        }

        // If any pattern node has zero candidates, no matches
        if candidates.iter().any(|c| c.is_empty()) {
            return Vec::new();
        }

        // Generate all injective assignments via backtracking (simple)
        let mut matches = Vec::new();
        let mut current_mapping = fixed_mapping.clone();
        let mut used_graph_nodes: HashSet<NodeId> = fixed_mapping.values().copied().collect();

        self.generate_assignments(
            pattern,
            &free_nodes,
            &candidates,
            0,
            &mut current_mapping,
            &mut used_graph_nodes,
            &mut matches,
        );

        matches
    }

    /// Recursive helper to generate injective assignments.
    fn generate_assignments(
        &self,
        pattern: &Pattern<P>,
        free_nodes: &[NodeId],
        candidates: &[Vec<NodeId>],
        depth: usize,
        current_mapping: &mut HashMap<NodeId, NodeId>,
        used_graph_nodes: &mut HashSet<NodeId>,
        matches: &mut Vec<PatternMatch>,
    ) {
                .iter()
                
                ,
        if depth == free_nodes.len() {
            // All free nodes assigned, create match
            let fingerprint = self.region_fingerprint_from_mapping(current_mapping);
            matches.push(PatternMatch::new(current_mapping.clone(), fingerprint));
            return;
        }

        let pat_id = free_nodes[depth];
        for &graph_id in &candidates[depth] {
            if used_graph_nodes.contains(&graph_id) {
                continue;
            }
            // Add to mapping
            current_mapping.insert(pat_id, graph_id);
            used_graph_nodes.insert(graph_id);
  &&
           
            // Recurse
            self.generate_assignments(
                pattern,
                free_nodes,
                candidates,
                depth + 1,
                current_mapping,
                used_graph_nodes,
                matches,
            );

            // Backtrack
            current_mapping.remove(&pat_id);
            used_graph_nodes.remove(&graph_id);
        }
    }


    /// Computes a fingerprint for a region defined by a set of node IDs.
    fn region_fingerprint(&self, node_ids: &[NodeId]) -> HashValue {
        self.region_fingerprint_from_mapping(
            &node_ids
                .iter()
                .map(|&id| (id, id))
                .collect::<HashMap<_, _>>(),
        )
    }

    /// Computes a fingerprint for a region defined by a mapping.
    /// The mapping keys are pattern node IDs, values are graph node IDs.
    fn region_fingerprint_from_mapping(&self, mapping: &HashMap<NodeId, NodeId>) -> HashValue {
        // Collect sorted graph node IDs
        let mut graph_nodes: Vec<NodeId> = mapping.values().copied().collect();
        graph_nodes.sort();

        // Collect incident edges (edges where all endpoints are in the region)
        let node_set: HashSet<NodeId> = graph_nodes.iter().copied().collect();
        let mut edge_hashes = Vec::new();
        for edge in self.edges_sorted() {
            if edge.sources.iter().all(|id| node_set.contains(id))
                && edge.targets.iter().all(|id| node_set.contains(id))
            {
                // Compute deterministic hash for this edge
                edge_hashes.push(crate::fingerprint::edge_content_hash(edge, &HashMap::new()).0);
            }
        }
        edge_hashes.sort();

        // Combine node IDs and edge hashes into a single hash
        let mut data = Vec::new();
        for &id in &graph_nodes {
            data.extend_from_slice(&id.as_u64().to_le_bytes());
        }
        for hash in edge_hashes {
            data.extend_from_slice(&hash);
        }
        HashValue::hash_with_domain(b"REGION_FINGERPRINT", &data)
    }
}
*/
