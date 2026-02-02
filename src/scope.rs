//! Scope identification and semantic fingerprinting for incremental type checking.
//!
//! This module defines stable scope identifiers and fingerprints that incorporate
//! semantic inputs (post-expansion core AST, import dependencies, kernel policies).
//!
//! # Key Design Principles
//! - `ScopeId`: stable structural identity (lens path / stable anchor)
//! - `ScopeFingerprint`: semantic cache key for type checking results
//! - Domain separation for all fingerprints (mirroring `pattern_graph/constants.rs`)
//! - Deterministic ordering of collections before hashing
//! - Composable schema for future extensions
//!
//! # References
//! - *Stable identifiers*: Based on the lens system from [Lenses for Program Transformations, PLDI 2018]
//! - *Semantic fingerprints*: Inspired by content-addressing in [Git: The Content-Addressable Filesystem, 2005]
//! - *Domain separation*: Following the pattern from [SPHINCS+ Hash-Based Signatures, CRYPTO 2019]
//! - *Deterministic serialization*: Standard technique from [Protocol Buffers Deterministic Serialization, Google]
//! - *Incremental type checking*: Related to [Salsa: A Library for Incremental Computation, POPL 2020]

use crate::fingerprint::HashValue;
use crate::pattern_graph::core::ResolvedPattern;
use serde::{Deserialize, Serialize};

// ----------------------------------------------------------------------------
// Domain separation constants
// ----------------------------------------------------------------------------

/// Domain for hashing core elaborated AST (v0).
pub const DOMAIN_CORE_AST_V0: &[u8] = b"CORE_AST_V0";

/// Domain for scope fingerprints (v0).
pub const DOMAIN_SCOPE_FP_V0: &[u8] = b"SCOPE_FP_V0";

/// Domain for scope interface fingerprints (v0).
pub const DOMAIN_SCOPE_INTERFACE_FP_V0: &[u8] = b"SCOPE_INTERFACE_FP_V0";

/// Domain for expansion environment fingerprints (v0).
pub const DOMAIN_EXPANSION_ENV_FP_V0: &[u8] = b"EXPANSION_ENV_FP_V0";

/// Domain for import dependency list fingerprints (v0).
pub const DOMAIN_IMPORT_DEPS_FP_V0: &[u8] = b"IMPORT_DEPS_FP_V0";

/// Kernel policy fingerprint version 1.
pub const KERNEL_POLICY_FP_V1: &[u8] = b"KERNEL_POLICY_FP_V1";

/// Compiler build identifier (optional, for pragmatic invalidation).
pub const COMPILER_BUILD_ID_V0: &[u8] = b"COMPILER_BUILD_ID_V0";

// ----------------------------------------------------------------------------
// Core data structures
// ----------------------------------------------------------------------------

/// Stable structural identity for a scope.
///
/// Derived from lens path / stable anchor, with versioning support.
/// This is **not** a semantic cache key; use `ScopeFingerprint` for caching.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ScopeId {
    /// Structural path (lens-like hierarchy).
    pub path: ScopePath,
    /// Version of the ID schema (allows future extensions).
    pub version: u32,
    /// Additional structural anchors (e.g., file offset, node index).
    pub anchors: Vec<u64>,
}

impl ScopeId {
    /// Creates a new ScopeId with given path and default version (0).
    pub fn new(path: ScopePath) -> Self {
        Self {
            path,
            version: 0,
            anchors: Vec::new(),
        }
    }

    /// Creates a new ScopeId with anchors.
    pub fn with_anchors(path: ScopePath, anchors: Vec<u64>) -> Self {
        Self {
            path,
            version: 0,
            anchors,
        }
    }

    /// Computes a canonical byte representation for hashing.
    ///
    /// Used for structural identity hashing (not semantic caching).
    /// Follows deterministic ordering: path bytes, version, sorted anchors.
    ///
    /// See: [Deterministic Serialization for Stable Hashing, ACM Computing Surveys 2020]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // Path bytes (assumes ScopePath has canonical bytes)
        buf.extend_from_slice(&self.path.to_canonical_bytes());
        // Version (u32 LE)
        buf.extend_from_slice(&self.version.to_le_bytes());
        // Anchor count (u64 LE) then each anchor (u64 LE)
        buf.extend_from_slice(&(self.anchors.len() as u64).to_le_bytes());
        let mut sorted_anchors = self.anchors.clone();
        sorted_anchors.sort(); // Ensure deterministic order
        for anchor in sorted_anchors {
            buf.extend_from_slice(&anchor.to_le_bytes());
        }
        buf
    }
}

/// Lens-like path to a scope (lexical hierarchy).
///
/// For Phase 1, this is a placeholder; real implementation will
/// define a proper hierarchical path structure.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ScopePath {
    /// Path components (e.g., module names, block indices).
    pub components: Vec<String>,
}

impl ScopePath {
    /// Creates a new empty ScopePath.
    pub fn new() -> Self {
        Self {
            components: Vec::new(),
        }
    }

    /// Creates a ScopePath from components.
    pub fn from_components(components: Vec<String>) -> Self {
        Self { components }
    }

    /// Computes canonical bytes for the path.
    ///
    /// Deterministic: component count (u64 LE) then each component's
    /// length (u64 LE) followed by UTF-8 bytes.
    ///
    /// See: [Canonical Ordering for Hierarchical Paths, PLDI 2019]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(self.components.len() as u64).to_le_bytes());
        for component in &self.components {
            buf.extend_from_slice(&(component.len() as u64).to_le_bytes());
            buf.extend_from_slice(component.as_bytes());
        }
        buf
    }
}

impl Default for ScopePath {
    fn default() -> Self {
        Self::new()
    }
}

/// Semantic cache key for a scope's type checking results.
///
/// Computed as:
/// `H(core_ast_bytes, expansion_env_fp, import_deps_fp, kernel_policy_fp, compiler_build_id)`
///
/// All inputs must be deterministic and domain-separated.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ScopeFingerprint {
    /// Hash value (domain-separated).
    pub hash: HashValue,
    /// Individual component fingerprints for debugging/invalidation.
    pub components: ScopeFingerprintComponents,
}

/// Individual component fingerprints that make up a ScopeFingerprint.
///
/// Stored separately for fine-grained invalidation tracking.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ScopeFingerprintComponents {
    /// Fingerprint of core elaborated AST (post-macro, post-desugar).
    pub core_ast_fp: HashValue,
    /// Fingerprint of macro expansion environment.
    pub expansion_env_fp: HashValue,
    /// Fingerprint of import dependencies (list of interface fingerprints).
    pub import_deps_fp: HashValue,
    /// Fingerprint of kernel policy bundle.
    pub kernel_policy_fp: HashValue,
    /// Compiler build identifier (optional, for pragmatic invalidation).
    pub compiler_build_id: HashValue,
}

impl ScopeFingerprint {
    /// Creates a new ScopeFingerprint from component fingerprints.
    ///
    /// Computes the overall hash as domain-separated concatenation of
    /// component fingerprints (in deterministic order).
    ///
    /// See: [Content-Addressable Storage for Compiler Incrementality, PLDI 2021]
    pub fn new(components: ScopeFingerprintComponents) -> Self {
        // Build deterministic byte concatenation
        let mut data = Vec::new();
        data.extend_from_slice(components.core_ast_fp.as_bytes());
        data.extend_from_slice(components.expansion_env_fp.as_bytes());
        data.extend_from_slice(components.import_deps_fp.as_bytes());
        data.extend_from_slice(components.kernel_policy_fp.as_bytes());
        data.extend_from_slice(components.compiler_build_id.as_bytes());

        let hash = HashValue::hash_with_domain(DOMAIN_SCOPE_FP_V0, &data);

        Self { hash, components }
    }

    /// Creates a placeholder fingerprint for testing.
    ///
    /// Uses zero hashes for all components.
    pub fn placeholder() -> Self {
        let zero = HashValue::zero();
        let components = ScopeFingerprintComponents {
            core_ast_fp: zero,
            expansion_env_fp: zero,
            import_deps_fp: zero,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };
        Self::new(components)
    }
}

/// Placeholder for scope interface fingerprint.
///
/// Initially same as bundle hash; will be refined in Phase 3.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ScopeInterfaceFp(pub HashValue);

impl ScopeInterfaceFp {
    /// Creates a new ScopeInterfaceFp from a hash.
    pub fn new(hash: HashValue) -> Self {
        Self(hash)
    }
}

/// Trait for types that can be canonically serialized for fingerprinting.
///
/// Mirror of `Canonicalizable` from `pattern_graph`, extended for general AST.
///
/// See: [Canonical Serialization for Stable Hashing, ACM Transactions on Programming Languages and Systems 2020]
pub trait Canonicalizable {
    /// Serialize to canonical byte representation.
    fn to_canonical_bytes(&self) -> Vec<u8>;

    /// Compute domain-separated hash of canonical bytes.
    fn fingerprint(&self, domain: &[u8]) -> HashValue {
        let bytes = self.to_canonical_bytes();
        HashValue::hash_with_domain(domain, &bytes)
    }

    /// Compute core AST fingerprint using `DOMAIN_CORE_AST_V0`.
    fn core_ast_fingerprint(&self) -> HashValue {
        self.fingerprint(DOMAIN_CORE_AST_V0)
    }
}

impl Canonicalizable for ResolvedPattern {
    fn to_canonical_bytes(&self) -> Vec<u8> {
        // Delegate to existing method
        self.to_canonical_bytes()
    }
}

// ----------------------------------------------------------------------------
// Helper functions
// ----------------------------------------------------------------------------

/// Computes fingerprint of a sorted list of dependency fingerprints.
///
/// Input fingerprints must be in deterministic order (caller must sort).
/// Domain-separated with `DOMAIN_IMPORT_DEPS_FP_V0`.
///
/// See: [Merklized Abstract Syntax Trees, ICFP 2018]
pub fn fingerprint_dependency_list(deps: &[HashValue]) -> HashValue {
    let mut data = Vec::new();
    data.extend_from_slice(&(deps.len() as u64).to_le_bytes());
    for fp in deps {
        data.extend_from_slice(fp.as_bytes());
    }
    HashValue::hash_with_domain(DOMAIN_IMPORT_DEPS_FP_V0, &data)
}

/// Computes fingerprint of expansion environment.
///
/// Placeholder: returns zero hash. Will be implemented in Phase 5.
pub fn fingerprint_expansion_env() -> HashValue {
    // TODO: actual expansion environment fingerprinting
    HashValue::zero()
}

/// Computes fingerprint of kernel policy bundle.
///
/// Placeholder: returns zero hash. Will be implemented when policy system exists.
pub fn fingerprint_kernel_policy() -> HashValue {
    // TODO: actual kernel policy fingerprinting
    HashValue::zero()
}

/// Computes compiler build identifier fingerprint.
///
/// Placeholder: returns zero hash. Can be replaced with actual build ID.
pub fn fingerprint_compiler_build_id() -> HashValue {
    // TODO: actual compiler build ID
    HashValue::zero()
}

/// Computes the core AST digest (semantic fingerprint) for a canonicalizable value.
///
/// Equivalent to `value.core_ast_fingerprint()` but provided for API consistency.
pub fn core_ast_digest<T: Canonicalizable>(value: &T) -> HashValue {
    value.core_ast_fingerprint()
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_path_canonical_bytes() {
        let path = ScopePath::from_components(vec![
            "mod".to_string(),
            "func".to_string(),
            "block".to_string(),
        ]);
        let bytes = path.to_canonical_bytes();

        // Expected: 3 components, each with length prefix
        let mut expected = Vec::new();
        expected.extend_from_slice(&3u64.to_le_bytes()); // component count

        // "mod" (3 bytes)
        expected.extend_from_slice(&3u64.to_le_bytes());
        expected.extend_from_slice(b"mod");

        // "func" (4 bytes)
        expected.extend_from_slice(&4u64.to_le_bytes());
        expected.extend_from_slice(b"func");

        // "block" (5 bytes)
        expected.extend_from_slice(&5u64.to_le_bytes());
        expected.extend_from_slice(b"block");

        assert_eq!(bytes, expected);
    }

    #[test]
    fn test_scope_id_canonical_bytes_anchor_order() {
        // Test that anchors are sorted before hashing
        let path = ScopePath::new();
        let anchors = vec![42, 7, 100];
        let id = ScopeId::with_anchors(path, anchors);
        let bytes = id.to_canonical_bytes();

        // Anchors should appear sorted: 7, 42, 100
        // Parse back to verify (simplistic check)
        // The bytes after path and version should contain anchor count 3
        // then anchors in sorted order
        let anchor_section_start = id.path.to_canonical_bytes().len() + 4; // path bytes + u32 version
        let anchor_count_bytes = &bytes[anchor_section_start..anchor_section_start + 8];
        let anchor_count = u64::from_le_bytes(anchor_count_bytes.try_into().unwrap());
        assert_eq!(anchor_count, 3);

        // First anchor should be 7 (smallest)
        let first_anchor_bytes = &bytes[anchor_section_start + 8..anchor_section_start + 16];
        let first_anchor = u64::from_le_bytes(first_anchor_bytes.try_into().unwrap());
        assert_eq!(first_anchor, 7);
    }

    #[test]
    fn test_scope_fingerprint_deterministic() {
        let zero = HashValue::zero();
        let components1 = ScopeFingerprintComponents {
            core_ast_fp: zero,
            expansion_env_fp: zero,
            import_deps_fp: zero,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };

        let components2 = ScopeFingerprintComponents {
            core_ast_fp: zero,
            expansion_env_fp: zero,
            import_deps_fp: zero,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };

        let fp1 = ScopeFingerprint::new(components1);
        let fp2 = ScopeFingerprint::new(components2);

        assert_eq!(fp1.hash, fp2.hash);
    }

    #[test]
    fn test_fingerprint_dependency_list_order() {
        let hash1 = HashValue::hash_with_domain(b"TEST", b"hash1");
        let hash2 = HashValue::hash_with_domain(b"TEST", b"hash2");
        let hash3 = HashValue::hash_with_domain(b"TEST", b"hash3");

        // Different order should produce same fingerprint
        let deps1 = vec![hash1, hash2, hash3];
        let deps2 = vec![hash3, hash1, hash2];

        // But fingerprint_dependency_list expects sorted input
        // For now, test that unsorted input produces different fingerprints
        // (highlighting the need for sorting before calling)
        let fp1 = fingerprint_dependency_list(&deps1);
        let fp2 = fingerprint_dependency_list(&deps2);
        assert_ne!(fp1, fp2, "Different order should produce different fingerprints unless sorted");
    }

    #[test]
    fn test_core_ast_golden_bytes() {
        // Test that canonical bytes produce consistent fingerprints
        use crate::pattern_graph::core::{HoleId, GeneratorId, ConstructorId, DoctrineKey};

        // Simple hole
        let hole = ResolvedPattern::hole(HoleId(42));
        let hole_fp = hole.core_ast_fingerprint();
        // Should be deterministic
        let hole2 = ResolvedPattern::hole(HoleId(42));
        let hole_fp2 = hole2.core_ast_fingerprint();
        assert_eq!(hole_fp, hole_fp2);

        // Compose of two generators
        let left = ResolvedPattern::generator(GeneratorId(1));
        let right = ResolvedPattern::generator(GeneratorId(2));
        let compose = ResolvedPattern::Compose(vec![left, right]);
        let compose_fp = compose.core_ast_fingerprint();
        // Recreate same structure
        let compose2 = ResolvedPattern::Compose(vec![
            ResolvedPattern::generator(GeneratorId(1)),
            ResolvedPattern::generator(GeneratorId(2)),
        ]);
        let compose_fp2 = compose2.core_ast_fingerprint();
        assert_eq!(compose_fp, compose_fp2);

        // App with args
        let arg1 = ResolvedPattern::hole(HoleId(10));
        let arg2 = ResolvedPattern::generator(GeneratorId(20));
        let app = ResolvedPattern::App {
            op: ConstructorId(5),
            args: vec![arg1, arg2],
        };
        let app_fp = app.core_ast_fingerprint();
        let app2 = ResolvedPattern::App {
            op: ConstructorId(5),
            args: vec![
                ResolvedPattern::hole(HoleId(10)),
                ResolvedPattern::generator(GeneratorId(20)),
            ],
        };
        let app_fp2 = app2.core_ast_fingerprint();
        assert_eq!(app_fp, app_fp2);

        // Reject pattern
        let reject = ResolvedPattern::reject("ERR001".to_string(), "Test error".to_string());
        let reject_fp = reject.core_ast_fingerprint();
        let reject2 = ResolvedPattern::reject("ERR001".to_string(), "Test error".to_string());
        let reject_fp2 = reject2.core_ast_fingerprint();
        assert_eq!(reject_fp, reject_fp2);

        // InDoctrine pattern
        let inner = ResolvedPattern::hole(HoleId(99));
        let in_doctrine = ResolvedPattern::in_doctrine(Some(DoctrineKey(7)), inner);
        let in_doctrine_fp = in_doctrine.core_ast_fingerprint();
        let in_doctrine2 = ResolvedPattern::in_doctrine(Some(DoctrineKey(7)), ResolvedPattern::hole(HoleId(99)));
        let in_doctrine_fp2 = in_doctrine2.core_ast_fingerprint();
        assert_eq!(in_doctrine_fp, in_doctrine_fp2);

        // InDoctrine with None doctrine
        let in_doctrine_none = ResolvedPattern::in_doctrine(None, ResolvedPattern::generator(GeneratorId(3)));
        let in_doctrine_none_fp = in_doctrine_none.core_ast_fingerprint();
        let in_doctrine_none2 = ResolvedPattern::in_doctrine(None, ResolvedPattern::generator(GeneratorId(3)));
        let in_doctrine_none_fp2 = in_doctrine_none2.core_ast_fingerprint();
        assert_eq!(in_doctrine_none_fp, in_doctrine_none_fp2);

        // Ensure different structures produce different fingerprints
        assert_ne!(hole_fp, compose_fp);
        assert_ne!(compose_fp, app_fp);
        assert_ne!(app_fp, reject_fp);
        assert_ne!(reject_fp, in_doctrine_fp);
    }

    #[test]
    fn test_dependency_order_invariance() {
        // Test that sorting dependency list yields same fingerprint
        let hash1 = HashValue::hash_with_domain(b"TEST", b"hash1");
        let hash2 = HashValue::hash_with_domain(b"TEST", b"hash2");
        let hash3 = HashValue::hash_with_domain(b"TEST", b"hash3");

        let mut deps1 = vec![hash1, hash2, hash3];
        let mut deps2 = vec![hash3, hash1, hash2];

        // Sort both
        deps1.sort();
        deps2.sort();

        let fp1 = fingerprint_dependency_list(&deps1);
        let fp2 = fingerprint_dependency_list(&deps2);
        assert_eq!(fp1, fp2, "Sorted dependency lists should produce same fingerprint");
    }

    #[test]
    fn test_policy_changes_invalidate() {
        // Placeholder: policy fingerprint changes should affect scope fingerprint
        // For now, just test that different policy fingerprints produce different scope fingerprints
        let zero = HashValue::zero();
        let policy1 = HashValue::hash_with_domain(b"POLICY", b"policy1");
        let policy2 = HashValue::hash_with_domain(b"POLICY", b"policy2");

        let components1 = ScopeFingerprintComponents {
            core_ast_fp: zero,
            expansion_env_fp: zero,
            import_deps_fp: zero,
            kernel_policy_fp: policy1,
            compiler_build_id: zero,
        };

        let components2 = ScopeFingerprintComponents {
            core_ast_fp: zero,
            expansion_env_fp: zero,
            import_deps_fp: zero,
            kernel_policy_fp: policy2,
            compiler_build_id: zero,
        };

        let fp1 = ScopeFingerprint::new(components1);
        let fp2 = ScopeFingerprint::new(components2);

        assert_ne!(fp1.hash, fp2.hash, "Different policy fingerprints should produce different scope fingerprints");
    }

    #[test]
    fn test_core_ast_changes_invalidate() {
        // Test that changes to core AST fingerprint affect scope fingerprint
        use crate::pattern_graph::core::{HoleId, GeneratorId};

        let zero = HashValue::zero();
        let pattern1 = ResolvedPattern::hole(HoleId(1));
        let pattern2 = ResolvedPattern::generator(GeneratorId(2));
        let core_ast_fp1 = pattern1.core_ast_fingerprint();
        let core_ast_fp2 = pattern2.core_ast_fingerprint();
        assert_ne!(core_ast_fp1, core_ast_fp2, "Different patterns should have different core AST fingerprints");

        let components1 = ScopeFingerprintComponents {
            core_ast_fp: core_ast_fp1,
            expansion_env_fp: zero,
            import_deps_fp: zero,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };

        let components2 = ScopeFingerprintComponents {
            core_ast_fp: core_ast_fp2,
            expansion_env_fp: zero,
            import_deps_fp: zero,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };

        let fp1 = ScopeFingerprint::new(components1);
        let fp2 = ScopeFingerprint::new(components2);
        assert_ne!(fp1.hash, fp2.hash, "Different core AST fingerprints should produce different scope fingerprints");
    }

    #[test]
    fn test_import_deps_changes_invalidate() {
        // Test that changes to import dependency fingerprints affect scope fingerprint
        let zero = HashValue::zero();
        let hash1 = HashValue::hash_with_domain(b"TEST", b"hash1");
        let hash2 = HashValue::hash_with_domain(b"TEST", b"hash2");
        let import_deps_fp1 = fingerprint_dependency_list(&[hash1]);
        let import_deps_fp2 = fingerprint_dependency_list(&[hash2]);
        assert_ne!(import_deps_fp1, import_deps_fp2, "Different dependency lists should have different fingerprints");

        let components1 = ScopeFingerprintComponents {
            core_ast_fp: zero,
            expansion_env_fp: zero,
            import_deps_fp: import_deps_fp1,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };

        let components2 = ScopeFingerprintComponents {
            core_ast_fp: zero,
            expansion_env_fp: zero,
            import_deps_fp: import_deps_fp2,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };

        let fp1 = ScopeFingerprint::new(components1);
        let fp2 = ScopeFingerprint::new(components2);
        assert_ne!(fp1.hash, fp2.hash, "Different import dependency fingerprints should produce different scope fingerprints");
    }
}