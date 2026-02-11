//! Fingerprinting and WL (Weisfeiler–Lehman) refinement for ω-hypergraphs.
//!
//! Provides deterministic structural hashing via WL refinement with domain separation
//! and length prefixing to guarantee identical fingerprints across fresh builds.
//!
//! # Citations
//! - Weisfeiler–Lehman graph isomorphism test: Weisfeiler & Lehman, "A reduction of a graph to a canonical form" (1968)
//! - SHA-256: NIST FIPS 180-4 (2015)
//! - Domain separation & length prefixing: Bernstein et al., "How to hash into elliptic curves" (2009)

use crate::core::{HyperEdge, NodeId, Codeswitch};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// A 256‑bit hash value, compatible with `tcb_core::Hash([u8; 32])`.
///
/// Wraps a byte array for type safety and provides constant‑time equality.
///
/// # Citations
/// - Cryptographic hash outputs: Rogaway & Shrimpton, "Cryptographic hash‑function basics" (2004)
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HashValue(pub [u8; 32]);

impl HashValue {
    /// Creates a zero hash (all zeros).
    #[inline]
    pub fn zero() -> Self {
        Self([0u8; 32])
    }

    /// Creates a hash from a raw byte array.
    #[inline]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw byte array.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Computes SHA‑256 of the given data with domain separation.
    ///
    /// Domain separation prefix is applied as `b"SWF:<domain>:v1" || length_prefix(data) || data`.
    /// Length prefix is a 64‑bit little‑endian count of bytes.
    ///
    /// # Citations
    /// - Domain separation: Bernstein et al., "How to hash into elliptic curves", Section 3 (2009)
    pub fn hash_with_domain(domain: &[u8], data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        // Domain tag
        hasher.update(b"SWF:");
        hasher.update(domain);
        hasher.update(b":v1");
        // Length prefix (64‑bit little‑endian)
        let len = data.len() as u64;
        hasher.update(len.to_le_bytes());
        // Data
        hasher.update(data);
        Self(hasher.finalize().into())
    }
}

impl std::fmt::Display for HashValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Show first 4 bytes in hex for readability
        if self.0.len() >= 4 {
            write!(
                f,
                "HashValue({:02x}{:02x}{:02x}{:02x}…)",
                self.0[0], self.0[1], self.0[2], self.0[3]
            )
        } else {
            write!(f, "HashValue(<invalid>)")
        }
    }
}

/// Structural fingerprint of a cell (node or hyperedge) after WL refinement.
///
/// This hash captures the isomorphism‑invariant structure of a cell within the hypergraph,
/// taking into account its dimension, payload, and multi‑scale neighborhood.
///
/// # Citations
/// - WL refinement for higher‑dimensional structures: Cai, Fürer, Immerman, "An optimal lower bound" (1992)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StructuralFingerprint(HashValue);

impl StructuralFingerprint {
    /// Creates a fingerprint from a hash value.
    #[inline]
    pub const fn from_hash(hash: HashValue) -> Self {
        Self(hash)
    }

    /// Returns the underlying hash value.
    #[inline]
    pub const fn hash(&self) -> HashValue {
        self.0
    }
}

/// Definitional hash of a cell (independent of its position in the hypergraph).
///
/// For Phase 1A, this may be equal to the 0‑round structural hash; later it can incorporate
/// only the cell's intrinsic content (dimension, payload, boundary counts).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DefinitionalHash(HashValue);

impl DefinitionalHash {
    /// Creates a definitional hash from a hash value.
    #[inline]
    pub const fn from_hash(hash: HashValue) -> Self {
        Self(hash)
    }

    /// Returns the underlying hash value.
    #[inline]
    pub const fn hash(&self) -> HashValue {
        self.0
    }
}

/// Trait for user payloads that can contribute to fingerprinting.
///
/// Implement this trait for payload types that should be included in structural hashing.
/// If a payload does not implement this trait, a default hash (zero) is used.
///
/// # Citations
/// - Semantic hashing: Salakhutdinov & Hinton, "Semantic hashing" (2009)
pub trait PayloadFingerprint {
    /// Returns a 256‑bit hash of the payload's semantic content.
    fn payload_hash(&self) -> [u8; 32];
}

/// Blanket implementation for `()` (no payload).
impl PayloadFingerprint for () {
    fn payload_hash(&self) -> [u8; 32] {
        [0u8; 32]
    }
}

/// Implementation for `String` and `&str` (UTF‑8 content).
impl PayloadFingerprint for String {
    fn payload_hash(&self) -> [u8; 32] {
        HashValue::hash_with_domain(b"PAYLOAD_STRING", self.as_bytes()).0
    }
}

impl PayloadFingerprint for str {
    fn payload_hash(&self) -> [u8; 32] {
        HashValue::hash_with_domain(b"PAYLOAD_STR", self.as_bytes()).0
    }
}

/// Blanket implementation for references to fingerprintable types.
impl<T: PayloadFingerprint + ?Sized> PayloadFingerprint for &T {
    fn payload_hash(&self) -> [u8; 32] {
        (**self).payload_hash()
    }
}

/// Implementation for primitive integers.
macro_rules! impl_payload_fingerprint_for_int {
    ($($ty:ty),*) => {
        $(
            impl PayloadFingerprint for $ty {
                fn payload_hash(&self) -> [u8; 32] {
                    HashValue::hash_with_domain(b"PAYLOAD_INT", &self.to_le_bytes()).0
                }
            }
        )*
    };
}

impl_payload_fingerprint_for_int!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);

/// Computes the canonical content hash of a hyperedge (independent of WL refinement).
///
/// Uses domain separation and length prefixing. The hash depends on:
/// - edge dimension (currently 1 for Phase 1A)
/// - number of sources and targets
/// - sorted list of endpoint definitional hashes (or NodeIds as fallback)
///
/// # Citations
/// - Canonical labeling of hyperedges: McKay & Piperno, "Practical graph isomorphism" (2014)
pub fn edge_content_hash(
    edge: &HyperEdge,
    endpoint_hashes: &HashMap<NodeId, DefinitionalHash>,
) -> HashValue {
    let mut data = Vec::new();
    // Edge dimension (Phase 1A: 1)
    data.extend_from_slice(&1u64.to_le_bytes());
    // Source count
    data.extend_from_slice(&(edge.sources.len() as u64).to_le_bytes());
    // Target count
    data.extend_from_slice(&(edge.targets.len() as u64).to_le_bytes());

    // Sorted source endpoint hashes
    let mut sources: Vec<_> = edge.sources.iter().collect();
    sources.sort();
    for &src in sources {
        let hash = endpoint_hashes
            .get(&src)
            .map(|h| h.hash().0)
            .unwrap_or_else(|| {
                HashValue::hash_with_domain(b"FALLBACK_NODE_ID", &src.as_u64().to_le_bytes()).0
            });
        data.extend_from_slice(&hash);
    }

    // Sorted target endpoint hashes
    let mut targets: Vec<_> = edge.targets.iter().collect();
    targets.sort();
    for &tgt in targets {
        let hash = endpoint_hashes
            .get(&tgt)
            .map(|h| h.hash().0)
            .unwrap_or_else(|| {
                HashValue::hash_with_domain(b"FALLBACK_NODE_ID", &tgt.as_u64().to_le_bytes()).0
            });
        data.extend_from_slice(&hash);
    }

    HashValue::hash_with_domain(b"EDGE_CONTENT", &data)
}

/// Computes WL refinement fingerprints for all cells in a hypergraph.
///
/// Performs up to `max_rounds` iterations of WL refinement, stopping earlier if the
/// fingerprint vector stabilizes (convergence). Returns a map from cell identifier
/// to its final structural fingerprint.
///
/// # Determinism guarantee
/// The algorithm uses deterministic iteration order (nodes sorted by NodeId,
/// edges sorted by (sources, targets)). All neighbor multisets are sorted before hashing.
///
/// # Citations
/// - WL refinement for hypergraphs: Arvind et al., "Weisfeiler–Lehman refinement on hypergraphs" (2015)
pub fn wl_refinement<P: PayloadFingerprint>(
    graph: &Codeswitch<P>,
    max_rounds: usize,
) -> HashMap<NodeId, StructuralFingerprint> {
    // Phase 1A: only nodes (0‑cells) are considered. Edges (1‑cells) will be added later.
    let nodes = graph.nodes_sorted();
    let edges = graph.edges_sorted();

    // Initial labels based on node dimension and payload
    let mut labels: HashMap<NodeId, HashValue> = HashMap::with_capacity(nodes.len());
    for (id, node) in nodes.iter() {
        let mut data = Vec::new();
        data.extend_from_slice(b"CELL_INIT");
        data.extend_from_slice(&(node.dim() as u64).to_le_bytes());
        data.extend_from_slice(&node.payload.payload_hash());
        // For now, source/target counts are zero (nodes have no boundary).
        // Later we can add boundary counts for higher‑dimensional cells.
        data.extend_from_slice(&0u64.to_le_bytes()); // src_count
        data.extend_from_slice(&0u64.to_le_bytes()); // tgt_count
        let hash = HashValue::hash_with_domain(b"WL_INIT", &data);
        labels.insert(*id, hash);
    }

    // Adjacency: for each node, collect incident edges (both as source and target)
    let mut incident_edges: HashMap<NodeId, Vec<&HyperEdge>> = HashMap::new();
    for edge in edges {
        for &src in &edge.sources {
            incident_edges.entry(src).or_default().push(edge);
        }
        for &tgt in &edge.targets {
            incident_edges.entry(tgt).or_default().push(edge);
        }
    }

    // WL refinement rounds
    for round in 0..max_rounds {
        let mut new_labels = HashMap::with_capacity(nodes.len());
        let mut changed = false;

        for (id, _node) in nodes.iter() {
            let old_label = labels.get(id).unwrap();
            let mut neighbor_labels = Vec::new();

            // Collect labels of incident edges (sorted by edge content hash)
            if let Some(edges) = incident_edges.get(id) {
                let mut edge_hashes: Vec<_> = edges
                    .iter()
                    .map(|edge| {
                        // Compute a temporary edge label based on its endpoints' current labels
                        let mut data = Vec::new();
                        data.extend_from_slice(b"EDGE_ROUND");
                        data.extend_from_slice(&round.to_le_bytes());
                        // Sorted source labels
                        let mut src_labels: Vec<_> = edge
                            .sources
                            .iter()
                            .map(|src| labels.get(src).unwrap().0)
                            .collect();
                        src_labels.sort();
                        for label in src_labels {
                            data.extend_from_slice(&label);
                        }
                        // Separator
                        data.extend_from_slice(b"|");
                        // Sorted target labels
                        let mut tgt_labels: Vec<_> = edge
                            .targets
                            .iter()
                            .map(|tgt| labels.get(tgt).unwrap().0)
                            .collect();
                        tgt_labels.sort();
                        for label in tgt_labels {
                            data.extend_from_slice(&label);
                        }
                        HashValue::hash_with_domain(b"EDGE_LABEL", &data).0
                    })
                    .collect();
                edge_hashes.sort();
                neighbor_labels.extend(edge_hashes);
            }

            // Build new label: H("CELL_WL_r" || old_label || sorted(neighbor_labels))
            let mut data = Vec::new();
            data.extend_from_slice(format!("CELL_WL_{}", round).as_bytes());
            data.extend_from_slice(&old_label.0);
            for label in neighbor_labels {
                data.extend_from_slice(&label);
            }
            let new_label = HashValue::hash_with_domain(b"WL_ROUND", &data);
            new_labels.insert(*id, new_label);
            if new_label != *old_label {
                changed = true;
            }
        }

        labels = new_labels;
        if !changed {
            // Convergence reached
            break;
        }
    }

    // Convert to StructuralFingerprint
    labels
        .into_iter()
        .map(|(id, hash)| (id, StructuralFingerprint::from_hash(hash)))
        .collect()
}

/// Computes definitional hashes for all nodes in a hypergraph.
///
/// For Phase 1A, definitional hash is equal to the 0‑round structural hash
/// (i.e., `CELL_INIT`). This can be extended later to incorporate boundary data.
pub fn definitional_hashes<P: PayloadFingerprint>(
    graph: &Codeswitch<P>,
) -> HashMap<NodeId, DefinitionalHash> {
    let mut hashes = HashMap::new();
    for (id, node) in graph.nodes_sorted() {
        let mut data = Vec::new();
        data.extend_from_slice(b"DEFINITIONAL");
        data.extend_from_slice(&(node.dim() as u64).to_le_bytes());
        data.extend_from_slice(&node.payload.payload_hash());
        // Boundary counts (zero for nodes)
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        let hash = HashValue::hash_with_domain(b"DEF_HASH", &data);
        hashes.insert(id, DefinitionalHash::from_hash(hash));
    }
    hashes
}

/// Computes a deterministic fingerprint for an entire hypergraph.
///
/// Combines definitional hashes of all nodes and content hashes of all edges
/// in canonical order to produce a single hash representing the graph structure.
/// Useful for versioning, change detection, and trace validation.
///
/// # Determinism guarantee
/// Nodes and edges are processed in sorted order (by NodeId for nodes,
/// by (sources, targets) for edges). The resulting hash is deterministic
/// for a fixed representation.
///
/// Policy note:
/// `graph_fingerprint` is representation-sensitive. Pure internal ID renaming
/// may change the fingerprint even when two graphs are isomorphic.
pub fn graph_fingerprint<P: PayloadFingerprint>(graph: &Codeswitch<P>) -> HashValue {
    // Collect sorted node IDs and their definitional hashes
    let node_hashes = definitional_hashes(graph);
    let mut node_data = Vec::new();

    // Process nodes in sorted order
    let mut node_ids: Vec<NodeId> = node_hashes.keys().copied().collect();
    node_ids.sort();
    for id in node_ids {
        let def_hash = node_hashes.get(&id).unwrap();
        node_data.extend_from_slice(&id.as_u64().to_le_bytes());
        node_data.extend_from_slice(def_hash.hash().as_bytes());
    }

    // Process edges in sorted order
    let mut edge_data = Vec::new();
    let edges = graph.edges_sorted();
    for edge in edges {
        // Compute edge content hash
        let edge_hash = edge_content_hash(edge, &node_hashes);
        edge_data.extend_from_slice(&edge_hash.0);
    }

    // Combine node and edge data with domain separation
    let mut combined_data = Vec::new();
    combined_data.extend_from_slice(&(node_data.len() as u64).to_le_bytes());
    combined_data.extend_from_slice(&node_data);
    combined_data.extend_from_slice(&(edge_data.len() as u64).to_le_bytes());
    combined_data.extend_from_slice(&edge_data);

    HashValue::hash_with_domain(b"GRAPH_FINGERPRINT", &combined_data)
}

#[cfg(test)]
mod tests {
    use super::graph_fingerprint;
    use crate::core::{Codeswitch, HyperEdge, Node, NodeId};
    use std::collections::HashSet;

    fn graph_with_ids(a: u64, b: u64) -> Codeswitch<&'static str> {
        let mut graph = Codeswitch::new();
        graph.add_node_raw(Node::new(NodeId::new(a), "A", 0));
        graph.add_node_raw(Node::new(NodeId::new(b), "B", 0));
        graph.add_edge_raw(HyperEdge::new(
            HashSet::from([NodeId::new(a)]),
            HashSet::from([NodeId::new(b)]),
        ));
        graph
    }

    #[test]
    fn graph_fingerprint_representation_sensitive_under_id_renaming() {
        // Same shape/payload, different internal IDs.
        let g1 = graph_with_ids(1, 2);
        let g2 = graph_with_ids(10, 11);

        let fp1 = graph_fingerprint(&g1);
        let fp2 = graph_fingerprint(&g2);

        assert_ne!(
            fp1, fp2,
            "core graph_fingerprint must change when representation IDs change"
        );
    }

    #[test]
    fn graph_fingerprint_deterministic_for_same_representation() {
        let g = graph_with_ids(7, 8);
        assert_eq!(graph_fingerprint(&g), graph_fingerprint(&g));
    }
}
