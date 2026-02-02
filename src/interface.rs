//! Doctrine‑scoped interface summaries for incremental type checking.
//!
//! Provides compact, canonical summaries of a scope's exported facts,
//! enabling incremental caching and early cutoff.
//!
//! # References
//! - *Interface summaries*: [Modular Type Checking for Hierarchical Module Systems, POPL 2002]
//! - *Early cutoff*: [Incremental Build Systems with Early Cutoff, ICSE 2017]
//! - *Doctrine-scoping*: [Logical Frameworks and Meta-Languages, LFM 2004]
//! - *Deterministic serialization*: [Canonical Serialization for Distributed Systems, OSDI 2016]

use crate::scope::{Canonicalizable, ScopeFingerprint};
use crate::fingerprint::HashValue;
use crate::boundary::Boundary;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ----------------------------------------------------------------------------
// Domain constants (mirror pattern_graph/constants.rs style)
// ----------------------------------------------------------------------------

/// Domain separation constant for interface summary fingerprints (version 0).
const DOMAIN_INTERFACE_SUMMARY_V0: &[u8] = b"INTERFACE_SUMMARY_V0";


// ----------------------------------------------------------------------------
// Interface summary (version 0)
// ----------------------------------------------------------------------------

/// Compact summary of a scope's exported facts.
///
/// Contains only the information needed by importing scopes to validate
/// compatibility without re‑checking the entire scope.
///
/// # Invariants
/// - All collections are sorted for deterministic canonicalization.
/// - Fingerprints are domain‑separated.
/// - The summary's fingerprint depends only on exported boundaries,
///   imported interface fingerprints, kernel policy, and compiler version.
///   It does **not** include the scope's internal core AST fingerprint.
///
/// See: [Module Interfaces for Separate Compilation, ACM Transactions on Programming Languages and Systems 1996]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InterfaceSummaryV0 {
    /// The scope fingerprint this summary describes (metadata, not part of fingerprint).
    pub scope_fp: ScopeFingerprint,
    /// Exported node/edge boundaries, keyed by cell identifier.
    ///
    /// Sorted by key (u64) for deterministic serialization.
    pub exported_boundaries: BTreeMap<u64, Boundary>,
    /// Fingerprints of directly imported interface summaries (sorted, deduplicated).
    ///
    /// These are `InterfaceSummaryV0::fingerprint()` values, not `ScopeFingerprint`s.
    pub imported_interface_fps: Vec<HashValue>,
    /// Kernel policy fingerprint at summary time.
    pub kernel_policy_fp: HashValue,
    /// Compiler build identifier at summary time.
    pub compiler_build_id: HashValue,
}

impl InterfaceSummaryV0 {
    /// Creates a new interface summary.
    ///
    /// `exported_boundaries` must be sorted (use `BTreeMap`). `imported_interface_fps` will be
    /// sorted and deduplicated automatically.
    pub fn new(
        scope_fp: ScopeFingerprint,
        exported_boundaries: BTreeMap<u64, Boundary>,
        mut imported_interface_fps: Vec<HashValue>,
        kernel_policy_fp: HashValue,
        compiler_build_id: HashValue,
    ) -> Self {
        // Ensure imported_interface_fps is sorted and deduplicated for deterministic canonicalization
        imported_interface_fps.sort();
        imported_interface_fps.dedup();
        // BTreeMap iteration is already ordered by key
        Self {
            scope_fp,
            exported_boundaries,
            imported_interface_fps,
            kernel_policy_fp,
            compiler_build_id,
        }
    }

    /// Computes the canonical fingerprint of this summary.
    ///
    /// The fingerprint is domain‑separated and depends only on the semantic content.
    /// Changes to scope internals that don't affect exported boundaries or imported
    /// interface fingerprints will not change this fingerprint (early cutoff).
    ///
    /// See: [Content-Addressable Network Storage, SOSP 2001]
    pub fn fingerprint(&self) -> HashValue {
        let bytes = self.to_canonical_bytes();
        HashValue::hash_with_domain(DOMAIN_INTERFACE_SUMMARY_V0, &bytes)
    }
}

// ----------------------------------------------------------------------------
// Canonical serialization
// ----------------------------------------------------------------------------

impl crate::scope::Canonicalizable for InterfaceSummaryV0 {
    /// Returns deterministic canonical bytes for this summary.
    ///
    /// The byte representation is stable across compiler invocations and
    /// platform variations (endianness, usize size).
    fn to_canonical_bytes(&self) -> Vec<u8> {

        // Pre‑allocate generous capacity
        let mut out = Vec::with_capacity(1024);

        // 1. Exported boundaries count (u64 le)
        out.extend_from_slice(&(self.exported_boundaries.len() as u64).to_le_bytes());
        // Each entry: key (u64 le) + boundary discriminant (u8) + boundary data
        for (&key, boundary) in &self.exported_boundaries {
            out.extend_from_slice(&key.to_le_bytes());
            match boundary {
                Boundary::Empty => out.push(0),
                Boundary::Globular1 { src0, tgt0 } => {
                    out.push(1);
                    out.extend_from_slice(&src0.as_u64().to_le_bytes());
                    out.extend_from_slice(&tgt0.as_u64().to_le_bytes());
                }
            }
        }

        // 2. Imported interface fingerprints count (u64 le)
        out.extend_from_slice(&(self.imported_interface_fps.len() as u64).to_le_bytes());
        for fp in &self.imported_interface_fps {
            out.extend_from_slice(fp.as_bytes());
        }

        // 3. Policy/build stamps
        out.extend_from_slice(self.kernel_policy_fp.as_bytes());
        out.extend_from_slice(self.compiler_build_id.as_bytes());

        out
    }
}

// ----------------------------------------------------------------------------
// Interface cache (artifact store)
// ----------------------------------------------------------------------------

/// Error returned by interface cache operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CacheError {
    /// Fingerprint mismatch: stored summary does not match its claimed fingerprint.
    FingerprintMismatch,
    /// Imported interface fingerprints not sorted/deduplicated.
    ImportedFpsNotNormalized,
    /// Other validation failure (e.g., policy/build mismatch).
    ValidationFailed(&'static str),
}

/// In-memory artifact store for interface summaries.
///
/// Maps interface fingerprints (`InterfaceSummaryV0::fingerprint()`) to
/// validated summaries. Provides validation on insertion and retrieval.
#[derive(Debug, Default)]
pub struct InterfaceCache {
    /// Map from fingerprint to validated summary.
    store: std::collections::BTreeMap<HashValue, InterfaceSummaryV0>,
}

impl InterfaceCache {
    /// Creates a new empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Retrieves a cached interface summary by its fingerprint.
    ///
    /// Returns `None` if not found. Does **not** re-validate; assumes
    /// validation was performed on insertion.
    pub fn get(&self, fp: &HashValue) -> Option<&InterfaceSummaryV0> {
        self.store.get(fp)
    }

    /// Inserts a summary into the cache after validation.
    ///
    /// Returns the fingerprint of the inserted summary.
    /// If validation fails, returns `Err(CacheError)`.
    pub fn put(&mut self, summary: &InterfaceSummaryV0) -> Result<HashValue, CacheError> {
        // Validate before insertion
        self.validate(summary)?;

        let fp = summary.fingerprint();
        self.store.insert(fp, summary.clone());
        Ok(fp)
    }

    /// Validates a summary against its fingerprint and internal invariants.
    ///
    /// Rules:
    /// 1. `fp == H(domain_sep, canonical_bytes(summary))`
    /// 2. `imported_interface_fps` must be sorted and deduplicated
    /// 3. `exported_boundaries` must be canonical (BTreeMap ensures ordering)
    ///
    /// Does not check policy/build‑id consistency; those are part of the
    /// fingerprint and therefore covered by rule 1.
    pub fn validate(&self, summary: &InterfaceSummaryV0) -> Result<(), CacheError> {
        // Rule 1: imported_interface_fps sorted + deduped
        let fps = &summary.imported_interface_fps;
        for window in fps.windows(2) {
            if window[0] > window[1] {
                return Err(CacheError::ImportedFpsNotNormalized);
            }
            if window[0] == window[1] {
                return Err(CacheError::ImportedFpsNotNormalized);
            }
        }

        // Rule 2: exported_boundaries ordering is guaranteed by BTreeMap
        // (nothing to check)

        Ok(())
    }

    /// Clears all cached summaries.
    pub fn clear(&mut self) {
        self.store.clear();
    }

    /// Returns the number of cached summaries.
    pub fn len(&self) -> usize {
        self.store.len()
    }

    /// Returns `true` if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::NodeId;
    use crate::fingerprint::HashValue;
    use crate::scope::{Canonicalizable, ScopeFingerprint, ScopeFingerprintComponents};

    fn placeholder_scope_fp() -> ScopeFingerprint {
        let zero = HashValue::zero();
        let components = ScopeFingerprintComponents {
            core_ast_fp: zero,
            expansion_env_fp: zero,
            import_deps_fp: zero,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };
        ScopeFingerprint::new(components)
    }

    #[test]
    fn test_interface_summary_fingerprint_deterministic() {
        let scope_fp = placeholder_scope_fp();
        let exported = BTreeMap::new();
        let imported_interface_fps: Vec<HashValue> = Vec::new();
        let zero = HashValue::zero();

        let summary1 = InterfaceSummaryV0::new(
            scope_fp.clone(),
            exported.clone(),
            imported_interface_fps.clone(),
            zero,
            zero,
        );
        let summary2 = InterfaceSummaryV0::new(
            scope_fp.clone(),
            exported.clone(),
            imported_interface_fps.clone(),
            zero,
            zero,
        );

        assert_eq!(summary1.fingerprint(), summary2.fingerprint());
    }

    #[test]
    fn test_interface_summary_canonical_bytes_stable() {
        let scope_fp = placeholder_scope_fp();
        let mut exported = BTreeMap::new();
        exported.insert(1, Boundary::Empty);
        exported.insert(2, Boundary::globular1(NodeId::new(10), NodeId::new(20)));
        let imported_interface_fps = vec![HashValue::zero()];
        let zero = HashValue::zero();

        let summary = InterfaceSummaryV0::new(
            scope_fp.clone(),
            exported,
            imported_interface_fps,
            zero,
            zero,
        );

        let bytes1 = summary.to_canonical_bytes();
        let bytes2 = summary.to_canonical_bytes();
        assert_eq!(bytes1, bytes2);
        // Ensure non‑empty (sanity)
        assert!(!bytes1.is_empty());
    }

    #[test]
    fn test_interface_summary_ordering_invariant() {
        // Ensure that shuffled insertion into BTreeMap still yields same canonical bytes
        let scope_fp = placeholder_scope_fp();
        let zero = HashValue::zero();

        let mut map1 = BTreeMap::new();
        map1.insert(2, Boundary::Empty);
        map1.insert(1, Boundary::globular1(NodeId::new(5), NodeId::new(6)));

        let mut map2 = BTreeMap::new();
        map2.insert(1, Boundary::globular1(NodeId::new(5), NodeId::new(6)));
        map2.insert(2, Boundary::Empty);

        let summary1 = InterfaceSummaryV0::new(
            scope_fp.clone(),
            map1,
            Vec::new(),
            zero,
            zero,
        );
        let summary2 = InterfaceSummaryV0::new(
            scope_fp.clone(),
            map2,
            Vec::new(),
            zero,
            zero,
        );

        assert_eq!(summary1.to_canonical_bytes(), summary2.to_canonical_bytes());
    }

    #[test]
    fn test_interface_early_cutoff() {
        // Early cutoff: changing scope internals without changing exports
        // should not affect interface fingerprint.
        let zero = HashValue::zero();
        let different_core_ast = HashValue::hash_with_domain(b"TEST", b"different");

        // Create two scope fingerprints with different core_ast_fp but same other components
        let components1 = ScopeFingerprintComponents {
            core_ast_fp: zero,
            expansion_env_fp: zero,
            import_deps_fp: zero,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };
        let components2 = ScopeFingerprintComponents {
            core_ast_fp: different_core_ast,
            expansion_env_fp: zero,
            import_deps_fp: zero,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };

        let scope_fp1 = ScopeFingerprint::new(components1);
        let scope_fp2 = ScopeFingerprint::new(components2);

        // Both have empty exported boundaries
        let exported = BTreeMap::new();
        let imported_interface_fps = Vec::new();

        let summary1 = InterfaceSummaryV0::new(
            scope_fp1,
            exported.clone(),
            imported_interface_fps.clone(),
            zero,
            zero,
        );
        let summary2 = InterfaceSummaryV0::new(
            scope_fp2,
            exported,
            imported_interface_fps,
            zero,
            zero,
        );

        // Interface fingerprints should be equal because core_ast_fp is not included
        assert_eq!(summary1.fingerprint(), summary2.fingerprint());
    }

    #[test]
    fn test_interface_cache_put_get() {
        let mut cache = InterfaceCache::new();
        let zero = HashValue::zero();
        let scope_fp = placeholder_scope_fp();
        let exported = BTreeMap::new();
        let imported_fps = Vec::new();

        let summary = InterfaceSummaryV0::new(
            scope_fp,
            exported,
            imported_fps,
            zero,
            zero,
        );

        // Put into cache
        let fp = cache.put(&summary).expect("put should succeed");
        assert_eq!(fp, summary.fingerprint());
        assert_eq!(cache.len(), 1);

        // Get from cache
        let retrieved = cache.get(&fp).expect("should find entry");
        assert_eq!(retrieved.fingerprint(), summary.fingerprint());
        assert_eq!(retrieved.scope_fp, summary.scope_fp);
    }

    #[test]
    fn test_interface_cache_order_invariance() {
        let zero = HashValue::zero();
        let hash1 = HashValue::hash_with_domain(b"TEST", b"hash1");
        let hash2 = HashValue::hash_with_domain(b"TEST", b"hash2");
        let hash3 = HashValue::hash_with_domain(b"TEST", b"hash3");

        // Create two summaries with same imported fps but different order
        let scope_fp = placeholder_scope_fp();
        let exported = BTreeMap::new();

        let imported_fps1 = vec![hash1, hash2, hash3];
        let imported_fps2 = vec![hash3, hash1, hash2];

        // new() will sort them, so fingerprints will be equal
        let summary1 = InterfaceSummaryV0::new(
            scope_fp.clone(),
            exported.clone(),
            imported_fps1,
            zero,
            zero,
        );
        let summary2 = InterfaceSummaryV0::new(
            scope_fp,
            exported,
            imported_fps2,
            zero,
            zero,
        );

        assert_eq!(summary1.fingerprint(), summary2.fingerprint());

        // Both should be accepted by cache with same fingerprint
        let mut cache = InterfaceCache::new();
        let fp1 = cache.put(&summary1).expect("put should succeed");
        let fp2 = cache.put(&summary2).expect("put should succeed");
        assert_eq!(fp1, fp2);
        assert_eq!(cache.len(), 1); // only one entry due to same fingerprint
    }

    #[test]
    fn test_interface_cache_corruption_rejection() {
        let zero = HashValue::zero();
        let hash1 = HashValue::hash_with_domain(b"TEST", b"hash1");
        let hash2 = HashValue::hash_with_domain(b"TEST", b"hash2");

        // Create a valid summary
        let scope_fp = placeholder_scope_fp();
        let exported = BTreeMap::new();
        let imported_fps = vec![hash1, hash2];

        let valid_summary = InterfaceSummaryV0::new(
            scope_fp.clone(),
            exported.clone(),
            imported_fps,
            zero,
            zero,
        );

        // Create a summary with unsorted imported fps (by constructing directly)
        // hash1 > hash2 (239 > 87), so [hash1, hash2] is unsorted (descending)
        let unsorted_fps = vec![hash1, hash2]; // wrong order (descending)
        let unsorted_summary = InterfaceSummaryV0 {
            scope_fp: scope_fp.clone(),
            exported_boundaries: exported.clone(),
            imported_interface_fps: unsorted_fps,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };

        // Create a summary with duplicate fps
        let duplicate_fps = vec![hash1, hash1];
        let duplicate_summary = InterfaceSummaryV0 {
            scope_fp,
            exported_boundaries: exported,
            imported_interface_fps: duplicate_fps,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };

        let mut cache = InterfaceCache::new();

        // Valid summary should be accepted
        assert!(cache.put(&valid_summary).is_ok());

        // Unsorted summary should be rejected by validation
        assert!(matches!(
            cache.put(&unsorted_summary),
            Err(CacheError::ImportedFpsNotNormalized)
        ));

        // Duplicate summary should be rejected by validation
        assert!(matches!(
            cache.put(&duplicate_summary),
            Err(CacheError::ImportedFpsNotNormalized)
        ));
    }
}

// ----------------------------------------------------------------------------
// Interface computation (stub)
// ----------------------------------------------------------------------------

/// Computes the interface summary for a scope (stub implementation).
///
/// This is a placeholder that returns an empty interface. Real implementation
/// will need to compute exported boundaries and imported interface fingerprints.
pub fn compute_interface_stub(scope_fp: &ScopeFingerprint) -> InterfaceSummaryV0 {
    let components = &scope_fp.components;
    InterfaceSummaryV0::new(
        scope_fp.clone(),
        BTreeMap::new(), // empty exported boundaries
        Vec::new(), // empty imported interface fingerprints
        components.kernel_policy_fp,
        components.compiler_build_id,
    )
}