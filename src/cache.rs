//! Caching layer for incremental type checking.
//!
//! Provides higher-level cache structures that integrate with the query engine
//! and support deterministic invalidation based on dependency graphs.
//!
//! # Phase 3 Scope
//! - `TypeCacheKey`: composite key for type checking results
//! - `TypeCache`: memoization storage integrating with query tables
//! - `CacheInvalidation`: logic for invalidating caches based on dependency changes
//! - Interface summaries cached as query results
//!
//! # References
//! - *Cache invalidation*: [Two Hard Things in Computer Science, Phil Karlton]
//! - *Dependency‑aware caching*: [Incremental Computation with Self‑Adjusting Computation, POPL 2009]
//! - *Deterministic cache keys*: [Stable Hashing for Incremental Computation, PLDI 2021]

use crate::fingerprint::HashValue;
use serde::{Deserialize, Serialize};
use serde_cbor;

/// Key for type checking cache entries.
///
/// Combines the semantic inputs that determine type checking results.
/// Changing any component invalidates the cache entry.
///
/// # Formula (Phase 3)
/// `TypeCacheKey = H(core_ast_fp, imported_interface_fps, policy_versions, compiler_version)`
///
/// For Phase 3 we use a simplified version that reuses `ScopeFingerprint`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TypeCacheKey {
    /// Fingerprint of the core AST (post‑expansion, post‑macro).
    pub core_ast_fp: HashValue,
    /// Fingerprints of imported interface summaries (sorted).
    pub imported_interface_fps: Vec<HashValue>,
    /// Kernel policy fingerprint (doctrine version).
    pub policy_version: HashValue,
    /// Compiler build identifier.
    pub compiler_version: HashValue,
}

impl TypeCacheKey {
    /// Creates a new cache key from its components.
    ///
    /// `imported_interface_fps` will be sorted and deduplicated.
    pub fn new(
        core_ast_fp: HashValue,
        mut imported_interface_fps: Vec<HashValue>,
        policy_version: HashValue,
        compiler_version: HashValue,
    ) -> Self {
        imported_interface_fps.sort();
        imported_interface_fps.dedup();
        Self {
            core_ast_fp,
            imported_interface_fps,
            policy_version,
            compiler_version,
        }
    }

    /// Computes the deterministic hash of this cache key.
    pub fn fingerprint(&self) -> HashValue {
        use crate::scope::Canonicalizable;
        let bytes = self.to_canonical_bytes();
        HashValue::hash_with_domain(b"TYPE_CACHE_KEY_V0", &bytes)
    }
}

impl crate::scope::Canonicalizable for TypeCacheKey {
    /// Returns deterministic canonical bytes for this cache key.
    fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1024);
        out.extend_from_slice(self.core_ast_fp.as_bytes());
        out.extend_from_slice(&(self.imported_interface_fps.len() as u64).to_le_bytes());
        for fp in &self.imported_interface_fps {
            out.extend_from_slice(fp.as_bytes());
        }
        out.extend_from_slice(self.policy_version.as_bytes());
        out.extend_from_slice(self.compiler_version.as_bytes());
        out
    }
}

/// Cache storage for type checking results.
///
/// Wraps a memo table and provides higher‑level operations.
/// Integrates with the query engine's dependency tracking.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TypeCache {
    /// Underlying memo table.
    memo: crate::query::MemoTable,
    // Future: dependency graph for fine‑grained invalidation (Phase 4).
}

impl TypeCache {
    /// Creates a new empty cache.
    pub fn new() -> Self {
        Self {
            memo: crate::query::MemoTable::new(),
        }
    }

    /// Looks up a cached result by key.
    pub fn get(&self, _key: &TypeCacheKey) -> Option<&crate::query::MemoEntry> {
        // Convert TypeCacheKey to QueryKey placeholder.
        // For Phase 3 we don't have a direct mapping; this is a stub.
        // Real implementation will integrate with query engine.
        None
    }

    /// Inserts a result into the cache.
    pub fn insert(&mut self, _key: TypeCacheKey, _entry: crate::query::MemoEntry) {
        // Stub
    }

    /// Clears all cached results (coarse invalidation).
    pub fn clear(&mut self) {
        self.memo.clear();
    }
}

impl TypeCache {
    /// Serializes the cache to CBOR bytes.
    ///
    /// Returns an error if serialization fails.
    pub fn to_cbor(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let bytes = serde_cbor::to_vec(self)?;
        Ok(bytes)
    }

    /// Deserializes the cache from CBOR bytes.
    ///
    /// Returns an error if deserialization fails.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let cache: Self = serde_cbor::from_slice(bytes)?;
        Ok(cache)
    }

    /// Saves the cache to a file.
    ///
    /// Uses CBOR format.
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
        let bytes = self.to_cbor()?;
        std::fs::write(path, bytes)?;
        Ok(())
    }

    /// Loads the cache from a file.
    ///
    /// Uses CBOR format.
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let bytes = std::fs::read(path)?;
        Self::from_cbor(&bytes)
    }
}

/// Logic for cache invalidation based on dependency changes.
///
/// Phase 3: stub implementation. Phase 4 will implement proper invalidation
/// using the query engine's dependency graph.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CacheInvalidation {
    // Future: map from input changes to affected cache keys.
}

impl CacheInvalidation {
    /// Creates a new invalidation tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that an input has changed.
    pub fn mark_input_changed(&mut self, _input: HashValue) {
        // Stub
    }

    /// Returns cache keys that need invalidation due to recorded changes.
    pub fn keys_to_invalidate(&self) -> Vec<TypeCacheKey> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::HashValue;

    #[test]
    fn test_type_cache_key_deterministic() {
        let zero = HashValue::zero();
        let one = HashValue::hash_with_domain(b"test", b"one");

        let key1 = TypeCacheKey::new(zero, vec![one], zero, zero);
        let key2 = TypeCacheKey::new(zero, vec![one], zero, zero);
        assert_eq!(key1.fingerprint(), key2.fingerprint());
    }

    #[test]
    fn test_type_cache_key_ordering() {
        let zero = HashValue::zero();
        let one = HashValue::hash_with_domain(b"test", b"one");
        let two = HashValue::hash_with_domain(b"test", b"two");

        let key1 = TypeCacheKey::new(zero, vec![one], zero, zero);
        let key2 = TypeCacheKey::new(zero, vec![two], zero, zero);
        // Different imported fingerprints → different keys
        assert_ne!(key1.fingerprint(), key2.fingerprint());
    }

    #[test]
    fn test_type_cache_serialization() {
        // Test roundtrip serialization of empty cache
        let cache: TypeCache = TypeCache::new();
        let bytes = cache.to_cbor().expect("serialization should succeed");
        let decoded: TypeCache = TypeCache::from_cbor(&bytes).expect("deserialization should succeed");
        // Verify roundtrip equality by serializing again
        let bytes2 = decoded.to_cbor().expect("second serialization should succeed");
        assert_eq!(bytes, bytes2);
    }

}