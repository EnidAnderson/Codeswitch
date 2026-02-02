//! Boundary typing for ω-hypergraphs.
//!
//! Provides boundary specifications for cells and compatibility checking
//! required for composition (pasting) in higher categories.
//!
//! # Citations
//! - Higher category boundaries: Leinster, "Higher Operads, Higher Categories", Chapter 1 (2004)
//! - Globular sets: Street, "The algebra of oriented simplexes" (1987)
//! - Scoped/incremental type checking: [Salsa: A Library for Incremental Computation, POPL 2020]

use crate::core::{HyperEdge, NodeId};
use crate::scope::{ScopeId, ScopeFingerprint};
use crate::query::{QueryEngine, QueryInstance, QueryKey, QueryError, DepKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Boundary specification of a k‑cell.
///
/// For Phase 1A we support:
/// - `Empty`: 0‑cells (objects) have empty boundary.
/// - `Globular1`: 1‑cells (morphisms) have a single source and single target 0‑cell.
///
/// # Invariants
/// - A boundary is well‑formed if all referenced cells exist and have appropriate dimensions.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Boundary {
    /// Empty boundary (0‑cells).
    Empty,
    /// Globular 1‑cell boundary: source and target 0‑cells.
    Globular1 {
        /// Source 0‑cell.
        src0: NodeId,
        /// Target 0‑cell.
        tgt0: NodeId,
    },
}

impl Boundary {
    /// Creates a globular 1‑cell boundary.
    #[inline]
    pub fn globular1(src0: NodeId, tgt0: NodeId) -> Self {
        Self::Globular1 { src0, tgt0 }
    }

    /// Returns the set of 0‑cells appearing in this boundary.
    pub fn cells(&self) -> HashSet<NodeId> {
        match self {
            Boundary::Empty => HashSet::new(),
            Boundary::Globular1 { src0, tgt0 } => HashSet::from([*src0, *tgt0]),
        }
    }

    /// Checks whether this boundary is compatible with another boundary for composition.
    ///
    /// For 1‑cells `f` and `g`, `f.target == g.source` must hold.
    /// Returns `Ok(())` if compatible, `Err(BoundaryError)` otherwise.
    ///
    /// # Citations
    /// - Composition in globular categories: Leinster, "Higher Operads, Higher Categories", Definition 1.1.2 (2004)
    pub fn compatible_with(&self, other: &Boundary) -> Result<(), BoundaryError> {
        match (self, other) {
            (Boundary::Empty, Boundary::Empty) => Ok(()),
            (Boundary::Globular1 { tgt0, .. }, Boundary::Globular1 { src0, .. })
                if tgt0 == src0 =>
            {
                Ok(())
            }
            _ => Err(BoundaryError::IncompatibleBoundaries),
        }
    }
}

/// Error type for boundary operations.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BoundaryError {
    /// The two boundaries are incompatible for composition.
    IncompatibleBoundaries,
    /// Referenced cell does not exist.
    MissingCell,
    /// Cell dimension does not match boundary expectation.
    DimensionMismatch,
    /// Hyperedge is not globular (multiple sources/targets).
    NonGlobularHyperedge,
}

/// Error type for incremental type checking operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypingError {
    /// Boundary checking error.
    Boundary(BoundaryError),
    /// Query engine error (e.g., cycle).
    Query(QueryError),
}

impl std::fmt::Display for BoundaryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BoundaryError::IncompatibleBoundaries => {
                write!(f, "boundaries are incompatible for composition")
            }
            BoundaryError::MissingCell => write!(f, "referenced cell does not exist"),
            BoundaryError::DimensionMismatch => {
                write!(f, "cell dimension does not match boundary expectation")
            }
            BoundaryError::NonGlobularHyperedge => {
                write!(f, "hyperedge is not globular (multiple sources/targets)")
            }
        }
    }
}

impl std::error::Error for BoundaryError {}

impl std::fmt::Display for TypingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TypingError::Boundary(err) => write!(f, "boundary error: {}", err),
            TypingError::Query(err) => write!(f, "query error: {}", err),
        }
    }
}

impl std::error::Error for TypingError {}

/// Trait for hypergraph structures that support boundary typing.
///
/// Provides methods to retrieve the boundary of a cell (node or hyperedge)
/// and to check boundary compatibility.
pub trait HypergraphTyping {
    /// Returns the boundary of a node (0‑cell or higher).
    ///
    /// For Phase 1A, nodes are 0‑cells and have empty boundary.
    /// Higher‑dimensional cells (future) will have non‑empty boundaries.
    fn node_boundary(&self, node_id: NodeId) -> Result<Boundary, BoundaryError>;

    /// Returns the boundary of a hyperedge (1‑cell).
    ///
    /// Assumes hyperedges are 1‑cells connecting 0‑cells.
    /// Returns `BoundaryError::NonGlobularHyperedge` if the hyperedge is not globular.
    fn hyperedge_boundary(&self, edge: &HyperEdge) -> Result<Boundary, BoundaryError>;

    /// Checks whether two cells can be composed (pasted).
    ///
    /// For 1‑cells `f` and `g`, checks that `f.target == g.source`.
    /// Returns `Ok(())` on success.
    fn check_composition(&self, f: NodeId, g: NodeId) -> Result<(), BoundaryError> {
        let bound_f = self.node_boundary(f)?;
        let bound_g = self.node_boundary(g)?;
        bound_f.compatible_with(&bound_g)
    }

    /// Returns the boundary of a node within a specific scope.
    ///
    /// For Phase 1A, scope is ignored and delegates to `node_boundary`.
    /// Future implementations may use scope for incremental caching.
    ///
    /// See: [Scoped Type Checking for Module Systems, POPL 1999]
    fn node_boundary_scoped(&self, node_id: NodeId, _scope: Option<ScopeId>) -> Result<Boundary, BoundaryError> {
        // Default implementation ignores scope for backward compatibility
        self.node_boundary(node_id)
    }

    /// Returns the boundary of a hyperedge within a specific scope.
    ///
    /// For Phase 1A, scope is ignored and delegates to `hyperedge_boundary`.
    ///
    /// See: [Scoped Type Checking for Module Systems, POPL 1999]
    fn hyperedge_boundary_scoped(&self, edge: &HyperEdge, _scope: Option<ScopeId>) -> Result<Boundary, BoundaryError> {
        // Default implementation ignores scope for backward compatibility
        self.hyperedge_boundary(edge)
    }

    /// Checks whether two cells can be composed within a specific scope.
    ///
    /// For Phase 1A, scope is ignored and delegates to `check_composition`.
    ///
    /// See: [Scoped Type Checking for Module Systems, POPL 1999]
    fn check_composition_scoped(&self, f: NodeId, g: NodeId, _scope: Option<ScopeId>) -> Result<(), BoundaryError> {
        // Default implementation ignores scope for backward compatibility
        self.check_composition(f, g)
    }
}

/// Simple implementation of `HypergraphTyping` for `Codeswitch<P>`.
///
/// This implementation treats nodes as 0‑cells (empty boundary) and hyperedges as 1‑cells
/// (globular boundaries). It assumes the hypergraph is well‑formed and all referenced cells exist.
impl<P> HypergraphTyping for crate::core::Codeswitch<P> {
    fn node_boundary(&self, node_id: NodeId) -> Result<Boundary, BoundaryError> {
        if !self.contains_node(node_id) {
            return Err(BoundaryError::MissingCell);
        }
        // Phase 1A: all nodes are 0‑cells
        Ok(Boundary::Empty)
    }

    fn hyperedge_boundary(&self, edge: &HyperEdge) -> Result<Boundary, BoundaryError> {
        // Check globularity: single source, single target
        if edge.sources.len() != 1 || edge.targets.len() != 1 {
            return Err(BoundaryError::NonGlobularHyperedge);
        }
        let src0 = *edge.sources.iter().next().unwrap();
        let tgt0 = *edge.targets.iter().next().unwrap();
        // Verify that src0 and tgt0 exist (they should, by hypergraph invariants)
        if !self.contains_node(src0) || !self.contains_node(tgt0) {
            return Err(BoundaryError::MissingCell);
        }
        Ok(Boundary::globular1(src0, tgt0))
    }

    // Scoped methods delegate to unscoped versions (scope ignored for Phase 1A)
    fn node_boundary_scoped(&self, node_id: NodeId, _scope: Option<ScopeId>) -> Result<Boundary, BoundaryError> {
        self.node_boundary(node_id)
    }

    fn hyperedge_boundary_scoped(&self, edge: &HyperEdge, _scope: Option<ScopeId>) -> Result<Boundary, BoundaryError> {
        self.hyperedge_boundary(edge)
    }

    fn check_composition_scoped(&self, f: NodeId, g: NodeId, _scope: Option<ScopeId>) -> Result<(), BoundaryError> {
        self.check_composition(f, g)
    }
}

// ----------------------------------------------------------------------------
// Incremental (query‑based) boundary checking
// ----------------------------------------------------------------------------

/// Checks boundary compatibility using the incremental query engine.
///
/// Returns a cached result if the same query has been executed before with the
/// same scope fingerprint and boundary pair.
///
/// # Examples
/// ```
/// # use codeswitch::boundary::{Boundary, check_boundary_compatibility_cached};
/// # use codeswitch::scope::{ScopeFingerprint, ScopeFingerprintComponents};
/// # use codeswitch::fingerprint::HashValue;
/// # use codeswitch::query::QueryEngine;
/// # let zero = HashValue::zero();
/// # let components = ScopeFingerprintComponents {
/// #     core_ast_fp: zero,
/// #     expansion_env_fp: zero,
/// #     import_deps_fp: zero,
/// #     kernel_policy_fp: zero,
/// #     compiler_build_id: zero,
/// # };
/// # let scope_fp = ScopeFingerprint::new(components);
/// # let engine = QueryEngine::new();
/// let left = Boundary::Empty;
/// let right = Boundary::Empty;
/// let result = check_boundary_compatibility_cached(&engine, scope_fp, left, right);
/// assert!(result.is_ok());
/// ```
pub fn check_boundary_compatibility_cached(
    engine: &QueryEngine,
    scope_fp: ScopeFingerprint,
    left: Boundary,
    right: Boundary,
) -> Result<(), BoundaryError> {
    let instance = QueryInstance::new(scope_fp, QueryKey::CheckBoundaryCompatibility { left: left.clone(), right: right.clone() });
    let query_result = engine.execute(instance, || {
        crate::query::QueryResult::BoundaryCompatibilityResult(
            crate::query::BoundaryCompatibilityResult(left.compatible_with(&right))
        )
    }).unwrap_or_else(|e| match e {
        // QueryError should not happen in correct usage
        _ => panic!("query engine error: {:?}", e),
    });
    match query_result {
        crate::query::QueryResult::BoundaryCompatibilityResult(crate::query::BoundaryCompatibilityResult(inner)) => inner,
        _ => panic!("unexpected query result variant"),
    }
}

/// Checks composition compatibility using the incremental query engine.
///
/// Returns a cached result if the same query has been executed before with the
/// same scope fingerprint and node pair.
///
/// # Examples
/// ```
/// # use codeswitch::boundary::{Boundary, check_composition_cached, HypergraphTyping};
/// # use codeswitch::scope::{ScopeFingerprint, ScopeFingerprintComponents};
/// # use codeswitch::fingerprint::HashValue;
/// # use codeswitch::query::QueryEngine;
/// # use codeswitch::core::{NodeId, Codeswitch};
/// # let zero = HashValue::zero();
/// # let components = ScopeFingerprintComponents {
/// #     core_ast_fp: zero,
/// #     expansion_env_fp: zero,
/// #     import_deps_fp: zero,
/// #     kernel_policy_fp: zero,
/// #     compiler_build_id: zero,
/// # };
/// # let scope_fp = ScopeFingerprint::new(components);
/// # let engine = QueryEngine::new();
/// # let graph = Codeswitch::<()>::new();
/// // Assuming graph has nodes with compatible boundaries...
/// # let f = NodeId::new(1);
/// # let g = NodeId::new(2);
/// let result = check_composition_cached(&engine, scope_fp, &graph, f, g);
/// // Result depends on actual graph contents
/// ```
pub fn check_composition_cached<H: HypergraphTyping>(
    engine: &QueryEngine,
    scope_fp: ScopeFingerprint,
    hypergraph: &H,
    f: NodeId,
    g: NodeId,
) -> Result<(), BoundaryError> {
    let instance = QueryInstance::new(scope_fp, QueryKey::CheckComposition { f: f.as_u64(), g: g.as_u64() });
    let query_result = engine.execute(instance, || {
        crate::query::QueryResult::CompositionResult(
            crate::query::CompositionResult(hypergraph.check_composition(f, g))
        )
    }).unwrap_or_else(|e| match e {
        // QueryError should not happen in correct usage
        _ => panic!("query engine error: {:?}", e),
    });
    match query_result {
        crate::query::QueryResult::CompositionResult(crate::query::CompositionResult(inner)) => inner,
        _ => panic!("unexpected query result variant"),
    }
}

/// Incremental type checking entry point.
///
/// Bumps versions of the given changed dependencies, causing any queries
/// that depend on them to be invalidated. Subsequent calls to cached
/// type checking functions will recompute as needed via lazy validation.
///
/// This is a coarse-grained API; for fine-grained control, use `QueryEngine`
/// methods directly.
pub fn incremental_typecheck(
    engine: &QueryEngine,
    changed: &[DepKey],
) {
    engine.bump_versions(changed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::HashValue;
    use crate::scope::ScopeFingerprintComponents;

    #[test]
    fn test_check_boundary_compatibility_cached() {
        let zero = HashValue::zero();
        let components = ScopeFingerprintComponents {
            core_ast_fp: zero,
            expansion_env_fp: zero,
            import_deps_fp: zero,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };
        let scope_fp = ScopeFingerprint::new(components);
        let engine = QueryEngine::new();

        let left = Boundary::Empty;
        let right = Boundary::Empty;
        let result = check_boundary_compatibility_cached(&engine, scope_fp.clone(), left.clone(), right.clone());
        assert!(result.is_ok());

        // Second call should hit cache (no panic)
        let result2 = check_boundary_compatibility_cached(&engine, scope_fp, left, right);
        assert!(result2.is_ok());
    }

    #[test]
    fn test_check_composition_cached() {
        use crate::core::Codeswitch;

        let zero = HashValue::zero();
        let components = ScopeFingerprintComponents {
            core_ast_fp: zero,
            expansion_env_fp: zero,
            import_deps_fp: zero,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };
        let scope_fp = ScopeFingerprint::new(components);
        let engine = QueryEngine::new();

        // Create a simple hypergraph with two nodes
        let graph = Codeswitch::<()>::new();
        // Nodes are automatically added when referenced? Actually we need to add nodes.
        // For now, we'll test with node IDs that don't exist; node_boundary will return MissingCell error.
        // That's fine - we just want to verify caching works.
        let f = NodeId::new(1);
        let g = NodeId::new(2);

        // First call should execute and produce MissingCell error
        let result = check_composition_cached(&engine, scope_fp.clone(), &graph, f, g);
        assert!(matches!(result, Err(BoundaryError::MissingCell)));

        // Second call should hit cache (same error)
        let result2 = check_composition_cached(&engine, scope_fp, &graph, f, g);
        assert!(matches!(result2, Err(BoundaryError::MissingCell)));
    }

    #[test]
    fn test_incremental_typecheck() {
        use crate::fingerprint::HashValue;
        use crate::scope::ScopeFingerprintComponents;
        use crate::query::record_imported_interface_dependency;

        let zero = HashValue::zero();
        let components = ScopeFingerprintComponents {
            core_ast_fp: zero,
            expansion_env_fp: zero,
            import_deps_fp: zero,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };
        let scope_fp = ScopeFingerprint::new(components);
        let engine = QueryEngine::new();

        // Create a query that depends on an imported interface
        let interface_fp = HashValue::hash_with_domain(b"TEST", b"interface");
        let instance = QueryInstance::new(scope_fp.clone(), QueryKey::CheckEdge { edge_id: 42 });

        let mut compute_count = 0;
        // First execution, record dependency on imported interface
        let result1 = engine.execute(instance.clone(), || {
            compute_count += 1;
            record_imported_interface_dependency(interface_fp);
            crate::query::QueryResult::BoundaryResult(
                crate::query::BoundaryResult(Ok(Boundary::Empty))
            )
        }).unwrap();
        assert_eq!(compute_count, 1);
        let crate::query::QueryResult::BoundaryResult(crate::query::BoundaryResult(inner1)) = result1 else { panic!("expected BoundaryResult"); };
        assert!(inner1.is_ok());

        // Second execution: cache hit
        let _result2 = engine.execute(instance.clone(), || {
            compute_count += 1;
            panic!("should not be called");
        }).unwrap();
        assert_eq!(compute_count, 1);

        // Incremental type checking: bump version of imported interface
        incremental_typecheck(&engine, &[DepKey::ImportedInterface(interface_fp)]);

        // Third execution: cache miss due to version bump
        let result3 = engine.execute(instance.clone(), || {
            compute_count += 1;
            crate::query::QueryResult::BoundaryResult(
                crate::query::BoundaryResult(Ok(Boundary::Empty))
            )
        }).unwrap();
        assert_eq!(compute_count, 2);
        let crate::query::QueryResult::BoundaryResult(crate::query::BoundaryResult(inner3)) = result3 else { panic!("expected BoundaryResult"); };
        assert!(inner3.is_ok());
    }

    #[test]
    fn test_incremental_typecheck_rewrite_trace() {
        // Test that type checking queries depending on rewrite traces are invalidated
        let zero = HashValue::zero();
        let components = ScopeFingerprintComponents {
            core_ast_fp: zero,
            expansion_env_fp: zero,
            import_deps_fp: zero,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };
        let scope_fp = ScopeFingerprint::new(components);
        let engine = QueryEngine::new();

        // Create a query that depends on a rewrite trace
        let rewrite_trace_fp = HashValue::hash_with_domain(b"TEST", b"rewrite_trace");
        let instance = QueryInstance::new(scope_fp.clone(), QueryKey::CheckEdge { edge_id: 42 });

        let mut compute_count = 0;
        // First execution, record dependency on rewrite trace
        let result1 = engine.execute(instance.clone(), || {
            compute_count += 1;
            crate::query::record_rewrite_trace_dependency(rewrite_trace_fp);
            crate::query::QueryResult::BoundaryResult(
                crate::query::BoundaryResult(Ok(Boundary::Empty))
            )
        }).unwrap();
        assert_eq!(compute_count, 1);
        let crate::query::QueryResult::BoundaryResult(crate::query::BoundaryResult(inner1)) = result1 else { panic!("expected BoundaryResult"); };
        assert!(inner1.is_ok());

        // Second execution: cache hit
        let _result2 = engine.execute(instance.clone(), || {
            compute_count += 1;
            panic!("should not be called");
        }).unwrap();
        assert_eq!(compute_count, 1);

        // Incremental type checking: bump version of rewrite trace
        incremental_typecheck(&engine, &[DepKey::RewriteTrace(rewrite_trace_fp)]);

        // Third execution: cache miss due to version bump
        let result3 = engine.execute(instance.clone(), || {
            compute_count += 1;
            crate::query::QueryResult::BoundaryResult(
                crate::query::BoundaryResult(Ok(Boundary::Empty))
            )
        }).unwrap();
        assert_eq!(compute_count, 2);
        let crate::query::QueryResult::BoundaryResult(crate::query::BoundaryResult(inner3)) = result3 else { panic!("expected BoundaryResult"); };
        assert!(inner3.is_ok());
    }
}
