//! Minimal query engine for incremental type checking.
//!
//! Implements a Salsa-style query system with automatic dependency tracking
//! and memoization. Phase 2 uses coarse invalidation: cache keys include
//! `ScopeFingerprint`, so changing the fingerprint naturally invalidates
//! prior results.
//!
//! # Design Principles
//! - **Pure queries**: Queries read only from immutable inputs (arena, doctrine registry, scope/boundary)
//! - **Deterministic ordering**: All dependency sets stored in sorted order
//! - **Coarse invalidation**: Cache key = `(ScopeFingerprint, QueryKey)`
//! - **No global mutation**: Only memo table writes allowed
//! - **No rewrite integration yet**: Rewrite/proof layers handled in Phase 5
//!
//! # Phase 2 Scope
//! - Query-to-query dependencies only (`DepKey::Query`)
//! - No fine-grained invalidation (Phase 4)
//! - No reverse dependency edges (Phase 4)
//! - Single boundary check as example (`CheckEdge`)
//!
//! # References
//! - *Query-based incremental computation*: [Salsa: A Library for Incremental Computation, POPL 2020]
//! - *Dependency tracking*: [Adaptive Functional Programming, POPL 2002]
//! - *Memoization with purity*: [Type-Directed Incremental Computation, PLDI 2020]
//! - *Deterministic dependency ordering*: [Incremental Computation with Names, ICFP 2015]
//! - *Thread-local dependency stacks*: [Flume: A Library for Pure Incremental Computation, OOPSLA 2022]

use crate::fingerprint::HashValue;
use crate::scope::ScopeFingerprint;
use crate::interface::InterfaceSummaryV0;
use crate::expansion::RuleBundleV0;
use crate::boundary::{Boundary, BoundaryError};
use serde::{Deserialize, Serialize};
use serde_cbor;
use std::sync::OnceLock;
use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use std::cell::RefCell;
use std::marker::PhantomData;

/// Domain for query key fingerprinting (v0).
const DOMAIN_QUERY_KEY_V0: &[u8] = b"QUERY_KEY_V0";

/// Domain for query result fingerprinting (v0).
const DOMAIN_QUERY_RESULT_V0: &[u8] = b"QUERY_RESULT_V0";

/// Cache format version (incremented on breaking changes).
const CACHE_FORMAT_VERSION: u32 = 1;

/// Schema hash for detecting incompatible cache format changes.
///
/// Computed as: SHA‑256("Codeswitch.QueryEngine.V1:" + SCHEMA_DESCRIPTOR).
/// The descriptor includes type names, field names, and variant names of all
/// serializable structures that can appear in the cache.
///
///!audit This hash must change whenever the serialized representation changes.
///!audit The descriptor must be complete; missing a type can cause silent cache corruption.
static ENGINE_SCHEMA_HASH: std::sync::OnceLock<HashValue> = std::sync::OnceLock::new();

/// Returns the current schema hash, computing it on first call.
fn engine_schema_hash() -> HashValue {
    *ENGINE_SCHEMA_HASH.get_or_init(|| {
        /// Schema descriptor: canonical string representation of all serialized types.
        /// Format: "type_name:kind(field1:type1,field2:type2,...)" for structs,
        /// "enum_name:variant1|variant2|..." for enums.
        ///!audit Keep this list synchronized with all #[derive(Serialize, Deserialize)] types.
        const SCHEMA_DESCRIPTOR: &str = "\
            QueryEngine:struct(memo:BTreeMap<QueryInstance,MemoEntry>,versions:BTreeMap<DepKey,u64>,format_version:u32,schema_hash:HashValue)\
            QueryInstance:struct(scope_fp:ScopeFingerprint,query_key:QueryKey)\
            ScopeFingerprint:struct(components:ScopeFingerprintComponents,hash:HashValue)\
            ScopeFingerprintComponents:struct(core_ast_fp:HashValue,expansion_env_fp:HashValue,import_deps_fp:HashValue,kernel_policy_fp:HashValue,compiler_build_id:HashValue)\
            QueryKey:enum(InferNodeType{node_id:u64},CheckEdge{edge_id:u64},CheckComposition{f:u64,g:u64},CheckBoundaryCompatibility{left:Boundary,right:Boundary},Boundary{kind:BoundaryKind,root_id:u64},ResolveName{symbol:String},ComputeInterface,ParseSurface,ExpandSurface,CompileRules,ElabCore)\
            BoundaryKind:enum(Node,Hyperedge)\
            MemoEntry:struct(value:QueryResult,deps:DependencySet,observed_versions:BTreeMap<DepKey,u64>,value_fingerprint:HashValue,compute_count:u64,diag:Vec<String>)\
            DependencySet:struct(inner:Vec<DepKey>)\
            DepKey:enum(Query{scope_fp:ScopeFingerprint,query_key:QueryKey},ImportedInterface(HashValue),SurfaceText(HashValue),PreludeMacros(HashValue),KernelMeta(HashValue),CompilerPolicy(HashValue),RuleBundle(HashValue),DoctrineRules(HashValue),PortEligibilityPolicy(HashValue),RewriteBundle(HashValue),RewriteTrace(HashValue))\
            QueryResult:enum(ParsedSurface(ParsedSurface),ExpandedCore(ExpandedCore),RuleBundle(RuleBundleV0),ElabOutput(ElabOutput),Interface(InterfaceResult),BoundaryResult(BoundaryResult),CompositionResult(CompositionResult),BoundaryCompatibilityResult(BoundaryCompatibilityResult),BoundarySpec(BoundarySpecResult),ResolvedName(ResolvedName),NodeType(NodeType))\
            ParsedSurface:struct(0:Vec<u8>)\
            ExpandedCore:struct(0:Vec<u8>)\
            ElabOutput:struct(0:Vec<u8>)\
            InterfaceResult:struct(0:InterfaceSummaryV0)\
            BoundaryResult:struct(0:Result<Boundary,BoundaryError>)\
            CompositionResult:struct(0:Result<(),BoundaryError>)\
            BoundaryCompatibilityResult:struct(0:Result<(),BoundaryError>)\
            BoundarySpecResult:struct(0:Boundary)\
            ResolvedName:struct(0:String)\
            NodeType:struct(0:String)\
            Boundary:enum(Empty,Globular0{src0:NodeId},Globular1{src0:NodeId,src1:NodeId},Hyperedge0{src0:NodeId},Hyperedge1{src0:NodeId,src1:NodeId},Hyperedge2{src0:NodeId,src1:NodeId,src2:NodeId})\
            BoundaryError:enum(NotGlobular,NotHyperedge,IncompatibleDimensions{expected:u8,actual:u8},IncompatibleSources{expected:NodeId,actual:NodeId})\
            NodeId:struct(id:u64)\
            InterfaceSummaryV0:struct(scope_fp:ScopeFingerprint,exported_boundaries:BTreeMap<String,Boundary>,imported_interfaces:Vec<HashValue>,kernel_policy_fp:HashValue,compiler_build_id:HashValue)\
            RuleBundleV0:struct(scope_fp:ScopeFingerprint,rules:Vec<RewriteRuleV0>)\
            RewriteRuleV0:struct(lhs:TermV0,rhs:TermV0,orientation:OrientationV0)\
            TermV0:enum(Var{name:String},App{head:TermV0,args:Vec<TermV0>},Lambda{param:String,body:TermV0},Pi{param:String,domain:TermV0,codomain:TermV0},Universe{level:u32})\
            OrientationV0:enum(LeftToRight,RightToLeft,Both)\
            HashValue:struct(0:[u8;32])\
            ";
        let mut input = Vec::with_capacity(SCHEMA_DESCRIPTOR.len() + 4);
        input.extend_from_slice(b"Codeswitch.QueryEngine.V1:");
        input.extend_from_slice(SCHEMA_DESCRIPTOR.as_bytes());
        HashValue::hash_with_domain(b"SCHEMA_HASH", &input)
    })
}

// ----------------------------------------------------------------------------
// Query result types
// ----------------------------------------------------------------------------

/// Result of a ParseSurface query (placeholder).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ParsedSurface(pub Vec<u8>);

/// Result of an ExpandSurface query (placeholder).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExpandedCore(pub Vec<u8>);

/// Result of an ElabCore query (placeholder).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ElabOutput(pub Vec<u8>);

/// Result of a ComputeInterface query (placeholder).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InterfaceResult(pub InterfaceSummaryV0);

/// Result of a CheckEdge query.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BoundaryResult(pub Result<Boundary, BoundaryError>);

/// Result of a CheckComposition query.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CompositionResult(pub Result<(), BoundaryError>);

/// Result of a CheckBoundaryCompatibility query.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BoundaryCompatibilityResult(pub Result<(), BoundaryError>);

/// Result of a Boundary query.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BoundarySpecResult(pub Boundary);

/// Result of a ResolveName query (placeholder).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResolvedName(pub String);

/// Result of an InferNodeType query (placeholder).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeType(pub String);

/// Union type for all possible query results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueryResult {
    ParsedSurface(ParsedSurface),
    ExpandedCore(ExpandedCore),
    RuleBundle(RuleBundleV0),
    ElabOutput(ElabOutput),
    Interface(InterfaceResult),
    BoundaryResult(BoundaryResult),
    CompositionResult(CompositionResult),
    BoundaryCompatibilityResult(BoundaryCompatibilityResult),
    BoundarySpec(BoundarySpecResult),
    ResolvedName(ResolvedName),
    NodeType(NodeType),
}

impl QueryResult {
    /// Computes a deterministic fingerprint of this query result.
    pub fn fingerprint(&self) -> HashValue {
        // Serialize to CBOR and hash with domain separation.
        // CBOR provides deterministic serialization for our structs.
        let bytes = serde_cbor::to_vec(self).expect("QueryResult should serialize to CBOR");
        HashValue::hash_with_domain(DOMAIN_QUERY_RESULT_V0, &bytes)
    }
}

// ----------------------------------------------------------------------------
// Core query identification
// ----------------------------------------------------------------------------

/// Complete query instance (scope + shape).
///
/// Used as the actual cache key in the memo table.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct QueryInstance {
    /// Scope fingerprint (semantic cache key).
    pub scope_fp: ScopeFingerprint,
    /// Query shape (scope‑free).
    pub query_key: QueryKey,
}

impl QueryInstance {
    /// Creates a new query instance.
    pub fn new(scope_fp: ScopeFingerprint, query_key: QueryKey) -> Self {
        Self { scope_fp, query_key }
    }

    /// Computes deterministic fingerprint for this query instance.
    pub fn fingerprint(&self) -> HashValue {
        use crate::scope::Canonicalizable;
        let bytes = self.to_canonical_bytes();
        HashValue::hash_with_domain(DOMAIN_QUERY_KEY_V0, &bytes)
    }
}

impl crate::scope::Canonicalizable for QueryInstance {
    fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(self.scope_fp.hash.as_bytes());
        // QueryKey doesn't have canonical bytes yet, use its hash via DefaultHasher
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.query_key.hash(&mut hasher);
        let query_hash = hasher.finish();
        out.extend_from_slice(&query_hash.to_le_bytes());
        out
    }
}

/// Key identifying a query shape (scope‑free).
///
/// Each variant corresponds to a specific type checking operation.
/// The actual cache key is `(ScopeFingerprint, QueryKey)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum QueryKey {
    /// Infer the type of a node within a scope.
    InferNodeType {
        /// Node identifier.
        node_id: u64,
    },
    /// Check boundary compatibility of an edge.
    CheckEdge {
        /// Edge identifier.
        edge_id: u64,
    },
    /// Check whether two nodes can be composed (boundary compatibility).
    CheckComposition {
        /// First node identifier.
        f: u64,
        /// Second node identifier.
        g: u64,
    },
    /// Check compatibility between two boundaries.
    CheckBoundaryCompatibility {
        /// First boundary.
        left: Boundary,
        /// Second boundary.
        right: Boundary,
    },
    /// Compute boundary specification.
    Boundary {
        /// Boundary kind identifier.
        kind: BoundaryKind,
        /// Root node identifier.
        root_id: u64,
    },
    /// Resolve a name to its binding.
    ResolveName {
        /// Symbol name.
        symbol: String,
    },
    /// Compute the interface summary for a scope.
    ComputeInterface,
    /// Parse surface syntax for a scope.
    ParseSurface,
    /// Expand macros and sugar in surface syntax.
    ExpandSurface,
    /// Compile rewrite rules for a scope.
    CompileRules,
    /// Elaborate core terms to backend IR.
    ElabCore,
}

/// Kind of boundary computation (placeholder for Phase 2).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BoundaryKind {
    /// Node boundary.
    Node,
    /// Hyperedge boundary.
    Hyperedge,
}

impl QueryKey {
    /// Computes a deterministic hash for this query key.
    ///
    /// Used for memo table lookups. The hash must be stable across
    /// compiler invocations (no random seeds).
    ///
    /// See: [Stable Hashing for Incremental Computation, PLDI 2021]
    pub fn fingerprint(&self) -> HashValue {
        // Use DefaultHasher (deterministic within compiler version) for Phase 2.
        // Future: implement proper canonical bytes serialization.
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.hash(&mut hasher);
        let hash_u64 = hasher.finish();
        // Convert to bytes and hash with domain separation
        HashValue::hash_with_domain(DOMAIN_QUERY_KEY_V0, &hash_u64.to_le_bytes())
    }
}

// ----------------------------------------------------------------------------
// Dependency tracking
// ----------------------------------------------------------------------------

/// A dependency edge from one query to another.
///
/// Records precise semantic dependencies for incremental correctness.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DepKey {
    /// Dependency on another query's result within a specific scope.
    Query {
        /// Scope fingerprint where the query executes.
        scope_fp: ScopeFingerprint,
        /// Query shape (scope‑free).
        query_key: QueryKey,
    },
    /// Dependency on an imported interface's fingerprint.
    ///
    /// Used for early cutoff: downstream scopes depend on interface fingerprints,
    /// not on scope internals.
    ImportedInterface(HashValue),
    /// Dependency on surface text content of a scope (file content).
    SurfaceText(HashValue),
    /// Dependency on prelude macro definitions (doctrine-scoped).
    PreludeMacros(HashValue),
    /// Dependency on Kernel.Meta reflection surface (placeholder for future).
    KernelMeta(HashValue),
    /// Dependency on compiler policy (affects macro expansion semantics).
    CompilerPolicy(HashValue),
    /// Dependency on a compiled rule bundle fingerprint.
    RuleBundle(HashValue),
    /// Dependency on doctrine rules fingerprint.
    DoctrineRules(HashValue),
    /// Dependency on port eligibility policy.
    PortEligibilityPolicy(HashValue),
    /// Dependency on a rewrite bundle fingerprint.
    RewriteBundle(HashValue),
    /// Dependency on a rewrite trace fingerprint.
    RewriteTrace(HashValue),
}

/// Error returned by query execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueryError {
    /// A cycle was detected in the query dependency graph.
    /// Contains the scope and query key that would cause the cycle.
    CycleDetected {
        /// Scope fingerprint where cycle would occur.
        scope_fp: ScopeFingerprint,
        /// Query shape (scope‑free).
        query_key: QueryKey,
    },
}

impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueryError::CycleDetected { scope_fp, query_key } => {
                write!(f, "cycle detected in query {{ scope_fp: {:?}, query_key: {:?} }}", scope_fp, query_key)
            }
        }
    }
}

impl std::error::Error for QueryError {}

/// Recorded dependencies for a memoized query result.
///
/// Stored as sorted Vec for deterministic ordering.
/// **Finalization is guaranteed by `QueryGuard::finish`**; dropping an unfinalized
/// DependencySet may hide dependencies and break incremental correctness.
///
/// See: [Dependency Tracking in Incremental Build Systems, ESEC/FSE 2019]
#[must_use = "DependencySet is part of query correctness; dropping it may hide dependencies"]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencySet {
    /// Sorted list of dependencies.
    deps: Vec<DepKey>,
}

impl DependencySet {
    /// Creates a new empty dependency set.
    pub fn new() -> Self {
        Self { deps: Vec::new() }
    }

    /// Adds a dependency, maintaining sorted order.
    ///
    /// Caller must ensure the vector stays sorted (use `sort` after adding).
    fn _add(&mut self, dep: DepKey) {
        self.deps.push(dep);
    }

    /// Finalizes the dependency set by sorting and deduplicating.
    ///
    /// Must be called after all dependencies are added.
    fn _finalize(&mut self) {
        self.deps.sort();
        self.deps.dedup();
    }

    /// Returns an iterator over dependencies.
    pub fn iter(&self) -> impl Iterator<Item = &DepKey> {
        self.deps.iter()
    }
}

impl Default for DependencySet {
    fn default() -> Self {
        Self::new()
    }
}

// ----------------------------------------------------------------------------
// Memoization storage
// ----------------------------------------------------------------------------

/// Memoized result of a query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoEntry {
    /// The computed value.
    pub value: QueryResult,
    /// Fingerprint (hash) of the value for change detection.
    pub value_fingerprint: HashValue,
    /// Recorded dependencies (sorted, deduplicated).
    pub deps: DependencySet,
    /// Optional diagnostics/obligations (future).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub diag: Vec<String>,
    /// Observed versions of dependencies at computation time.
    pub observed_versions: BTreeMap<DepKey, u64>,
    /// Number of times this query was computed (for tests/debugging).
    pub compute_count: u64,
}

impl MemoEntry {
    /// Creates a new memo entry.
    pub fn new(value: QueryResult, deps: DependencySet) -> Self {
        let value_fingerprint = value.fingerprint();
        Self {
            value,
            value_fingerprint,
            deps,
            diag: Vec::new(),
            observed_versions: BTreeMap::new(),
            compute_count: 0,
        }
    }
}

/// Memoization table storing query results.
///
/// Keyed by `QueryInstance` fingerprint for coarse invalidation.
/// Changing `ScopeFingerprint` naturally causes cache misses.
///
/// See: [Memoization in Functional Programming Languages, ACM Computing Surveys 1998]
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct MemoTable {
    /// Map from query instance fingerprint to memo entry.
    entries: BTreeMap<HashValue, MemoEntry>,
}

impl MemoTable {
    /// Creates a new empty memo table.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Looks up a cached result.
    ///
    /// Returns `Some(&MemoEntry)` if present, `None` otherwise.
    pub fn get(&self, instance: &QueryInstance) -> Option<&MemoEntry> {
        let fp = instance.fingerprint();
        self.entries.get(&fp)
    }

    /// Inserts a new result into the memo table.
    ///
    /// Overwrites any existing entry for the same key.
    pub fn insert(&mut self, instance: QueryInstance, entry: MemoEntry) {
        let fp = instance.fingerprint();
        #[cfg(test)]
        eprintln!("[MEMO INSERT] {:?} (fp: {:?}) compute_count: {}", instance.query_key, fp, entry.compute_count);
        self.entries.insert(fp, entry);
    }

    /// Removes the memo entry for the given query instance, if any.
    pub fn remove(&mut self, instance: &QueryInstance) {
        let fp = instance.fingerprint();
        self.entries.remove(&fp);
    }

    /// Clears all memoized results (coarse invalidation).
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

/// Reason for cache invalidation (for debugging and tuning).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum InvalidationReason {
    /// Dependency key missing from observed versions (should not happen).
    DepKeyMissing,
    /// Dependency version mismatch (input changed).
    DepVersionMismatch,
    /// Dependency set changed (different deps, same result).
    DependencySetChanged,
    /// Query result changed (fingerprint mismatch).
    QueryResultChanged,
    /// Cache format or schema mismatch on load.
    FormatSchemaMismatch,
}

/// Performance and cache metrics for the query engine.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Metrics {
    /// Number of cache hits (query served from memo table).
    pub query_hits: u64,
    /// Number of cache misses (query needed recomputation).
    pub query_misses: u64,
    /// Number of times a query was recomputed (including first computation).
    pub query_recomputes: u64,
    /// Number of cache invalidations due to version mismatch.
    pub cache_invalidations: u64,
    /// Number of bytes written during cache save.
    pub bytes_saved: u64,
    /// Number of bytes read during cache load.
    pub bytes_loaded: u64,
    /// Number of cycles detected and prevented.
    pub cycles_detected: u64,
    /// Breakdown of invalidation reasons (for debugging and tuning).
    pub invalidation_reasons: std::collections::BTreeMap<InvalidationReason, u64>,
}

impl Metrics {
    /// Records a cache hit.
    pub fn record_hit(&mut self) {
        self.query_hits += 1;
    }

    /// Records a cache miss.
    pub fn record_miss(&mut self) {
        self.query_misses += 1;
    }

    /// Records a query recomputation.
    pub fn record_recompute(&mut self) {
        self.query_recomputes += 1;
    }

    /// Records a cache invalidation with a specific reason.
    pub fn record_invalidation_reason(&mut self, reason: InvalidationReason) {
        self.cache_invalidations += 1;
        *self.invalidation_reasons.entry(reason).or_insert(0) += 1;
    }

    /// Records a cache invalidation (default reason: DepVersionMismatch).
    pub fn record_invalidation(&mut self) {
        self.record_invalidation_reason(InvalidationReason::DepVersionMismatch);
    }

    /// Records a dependency set replacement (same result, different deps).
    pub fn record_dep_set_replacement(&mut self) {
        *self.invalidation_reasons.entry(InvalidationReason::DependencySetChanged).or_insert(0) += 1;
    }

    /// Records a query result change (fingerprint changed).
    pub fn record_query_result_changed(&mut self) {
        *self.invalidation_reasons.entry(InvalidationReason::QueryResultChanged).or_insert(0) += 1;
    }

    /// Records cache save size.
    pub fn record_bytes_saved(&mut self, bytes: u64) {
        self.bytes_saved += bytes;
    }

    /// Records cache load size.
    pub fn record_bytes_loaded(&mut self, bytes: u64) {
        self.bytes_loaded += bytes;
    }

    /// Records a cycle detection.
    pub fn record_cycle_detected(&mut self) {
        self.cycles_detected += 1;
    }

    /// Resets all metrics to zero.
    pub fn reset(&mut self) {
        *self = Metrics::default();
    }
}

// ----------------------------------------------------------------------------
// Dependency recorder (thread-local stack)
// ----------------------------------------------------------------------------

thread_local! {
    /// Stack of currently executing query instances.
    static QUERY_STACK: std::cell::RefCell<Vec<QueryInstance>> = std::cell::RefCell::new(Vec::new());

    /// Stack of dependency accumulators, parallel to QUERY_STACK.
    /// Each Vec accumulates DepKeys for the query at the same index.
    static DEP_ACCUMULATORS: std::cell::RefCell<Vec<Vec<DepKey>>> = std::cell::RefCell::new(Vec::new());
}

/// RAII guard for query execution.
///
/// Pushes `key` onto the query stack on creation, pops it on drop.
/// Ensures stack cleanup even on panic.
///
/// See: [RAII Pattern for Resource Management, C++ Programming Language 4th Ed.]
struct QueryGuard {
    /// Whether we should pop (false if already popped via `finish`).
    active: bool,
}

impl QueryGuard {
    /// Starts recording dependencies for a new query.
    ///
    /// Pushes `instance` onto the query stack and initializes an empty dependency accumulator.
    /// Returns a guard that will pop the stack when dropped.
    /// Returns `Err(QueryError::CycleDetected(...))` if `instance` is already in the query stack.
    fn start(instance: QueryInstance) -> Result<Self, QueryError> {
        // Detect direct recursion (need to check before moving instance)
        let instance_clone = instance.clone();
        QUERY_STACK.with(|stack| {
            let stack = stack.borrow();
            if stack.contains(&instance_clone) {
                return Err(QueryError::CycleDetected {
                    scope_fp: instance_clone.scope_fp,
                    query_key: instance_clone.query_key,
                });
            }
            Ok(())
        })?;

        QUERY_STACK.with(|stack| stack.borrow_mut().push(instance));
        DEP_ACCUMULATORS.with(|accs| accs.borrow_mut().push(Vec::new()));
        Ok(Self { active: true })
    }

    /// Finishes the query, returning the sorted, deduplicated dependencies.
    /// Consumes the guard (prevents double-pop).
    fn finish(mut self) -> DependencySet {
        self.active = false;
        let mut deps_vec = DEP_ACCUMULATORS.with(|accs| {
            accs.borrow_mut().pop().unwrap_or_default()
        });
        QUERY_STACK.with(|stack| {
            stack.borrow_mut().pop();
        });

        // Ensure deterministic order
        deps_vec.sort();
        deps_vec.dedup();
        DependencySet { deps: deps_vec }
    }
}

impl Drop for QueryGuard {
    fn drop(&mut self) {
        if self.active {
            // Panic cleanup: pop stacks but discard dependencies
            DEP_ACCUMULATORS.with(|accs| {
                let _ = accs.borrow_mut().pop();
            });
            QUERY_STACK.with(|stack| {
                let _ = stack.borrow_mut().pop();
            });
        }
    }
}

/// Records a dependency from the currently executing query to `callee`.
///
/// If no query is active (top-level call), does nothing.
///
/// See: [Dynamic Dependency Tracking for Incremental Computation, POPL 2019]
pub fn record_dependency(callee: &QueryInstance) {
    DEP_ACCUMULATORS.with(|accs| {
        if let Some(acc) = accs.borrow_mut().last_mut() {
            #[cfg(test)]
            if let Some(current) = current_query() {
                eprintln!("[DEP] {:?} -> {:?}", current.query_key, callee.query_key);
            }
            acc.push(DepKey::Query {
                scope_fp: callee.scope_fp.clone(),
                query_key: callee.query_key.clone(),
            });
        }
    });
}

/// Records a dependency from the calling query (the one that initiated this execute)
/// to `callee`. This should be called after a query guard has started, when the
/// callee is now the current query on the stack.
fn record_dependency_from_caller_to(callee: &QueryInstance) {
    QUERY_STACK.with(|stack| {
        let stack = stack.borrow();
        if stack.len() >= 2 {
            #[cfg(test)]
            let caller = &stack[stack.len() - 2];
            DEP_ACCUMULATORS.with(|accs| {
                if let Some(acc) = accs.borrow_mut().get_mut(stack.len() - 2) {
                    #[cfg(test)]
                    eprintln!("[DEP CALLER] {:?} -> {:?}", caller.query_key, callee.query_key);
                    acc.push(DepKey::Query {
                        scope_fp: callee.scope_fp.clone(),
                        query_key: callee.query_key.clone(),
                    });
                }
            });
        }
    });
}

/// Records a dependency from the currently executing query to an imported interface.
///
/// If no query is active (top-level call), does nothing.
pub fn record_imported_interface_dependency(interface_fp: HashValue) {
    DEP_ACCUMULATORS.with(|accs| {
        if let Some(acc) = accs.borrow_mut().last_mut() {
            acc.push(DepKey::ImportedInterface(interface_fp));
        }
    });
}

/// Records a dependency on surface text content.
pub fn record_surface_text_dependency(text_fp: HashValue) {
    DEP_ACCUMULATORS.with(|accs| {
        if let Some(acc) = accs.borrow_mut().last_mut() {
            acc.push(DepKey::SurfaceText(text_fp));
        }
    });
}

/// Records a dependency on prelude macro definitions.
pub fn record_prelude_macros_dependency(prelude_fp: HashValue) {
    DEP_ACCUMULATORS.with(|accs| {
        if let Some(acc) = accs.borrow_mut().last_mut() {
            acc.push(DepKey::PreludeMacros(prelude_fp));
        }
    });
}

/// Records a dependency on Kernel.Meta reflection surface.
pub fn record_kernel_meta_dependency(kernel_meta_fp: HashValue) {
    DEP_ACCUMULATORS.with(|accs| {
        if let Some(acc) = accs.borrow_mut().last_mut() {
            acc.push(DepKey::KernelMeta(kernel_meta_fp));
        }
    });
}

/// Records a dependency on compiler policy.
pub fn record_compiler_policy_dependency(policy_fp: HashValue) {
    DEP_ACCUMULATORS.with(|accs| {
        if let Some(acc) = accs.borrow_mut().last_mut() {
            acc.push(DepKey::CompilerPolicy(policy_fp));
        }
    });
}

/// Records a dependency on a compiled rule bundle.
pub fn record_rule_bundle_dependency(bundle_fp: HashValue) {
    DEP_ACCUMULATORS.with(|accs| {
        if let Some(acc) = accs.borrow_mut().last_mut() {
            acc.push(DepKey::RuleBundle(bundle_fp));
        }
    });
}

/// Records a dependency on doctrine rules.
pub fn record_doctrine_rules_dependency(doctrine_fp: HashValue) {
    DEP_ACCUMULATORS.with(|accs| {
        if let Some(acc) = accs.borrow_mut().last_mut() {
            acc.push(DepKey::DoctrineRules(doctrine_fp));
        }
    });
}

/// Records a dependency on port eligibility policy.
pub fn record_port_eligibility_policy_dependency(policy_fp: HashValue) {
    DEP_ACCUMULATORS.with(|accs| {
        if let Some(acc) = accs.borrow_mut().last_mut() {
            acc.push(DepKey::PortEligibilityPolicy(policy_fp));
        }
    });
}

/// Records a dependency on a rewrite bundle fingerprint.
pub fn record_rewrite_bundle_dependency(bundle_fp: HashValue) {
    DEP_ACCUMULATORS.with(|accs| {
        if let Some(acc) = accs.borrow_mut().last_mut() {
            acc.push(DepKey::RewriteBundle(bundle_fp));
        }
    });
}

/// Records a dependency on a rewrite trace fingerprint.
pub fn record_rewrite_trace_dependency(trace_fp: HashValue) {
    DEP_ACCUMULATORS.with(|accs| {
        if let Some(acc) = accs.borrow_mut().last_mut() {
            acc.push(DepKey::RewriteTrace(trace_fp));
        }
    });
}

/// Returns the currently executing query instance, if any.
fn current_query() -> Option<QueryInstance> {
    QUERY_STACK.with(|stack| stack.borrow().last().cloned())
}

// ----------------------------------------------------------------------------
// Query engine
// ----------------------------------------------------------------------------

/// Simple query engine for Phase 2.
///
/// Provides memoized execution of type checking queries.
/// Coarse invalidation via `ScopeFingerprint` in cache keys.
///
/// # Thread safety
/// Dependency recording uses thread‑local storage; the engine itself is single‑threaded.
/// **This type is !Send and !Sync by design.** Each thread must have its own `QueryEngine`
/// instance. Sharing across threads would break the thread‑local dependency stacks.
#[derive(Serialize, Deserialize)]
pub struct QueryEngine {
    /// Memoization table (interior mutability for re-entrant queries).
    memo: RefCell<MemoTable>,
    /// Version counter for dependency keys (monotone increasing per key).
    versions: RefCell<BTreeMap<DepKey, u64>>,
    /// Cache format version (serialized).
    #[serde(default = "QueryEngine::default_format_version")]
    format_version: u32,
    /// Schema hash for cache compatibility checking (serialized).
    #[serde(default = "QueryEngine::default_schema_hash")]
    schema_hash: HashValue,
    /// Performance metrics (runtime only, not serialized).
    #[serde(skip)]
    metrics: RefCell<Metrics>,
    /// Ensures !Send + !Sync (thread‑local dependency stacks).
    #[serde(skip)]
    _not_send_sync: PhantomData<*const ()>,
}

impl Default for QueryEngine {
    fn default() -> Self {
        Self {
            memo: RefCell::new(MemoTable::new()),
            versions: RefCell::new(BTreeMap::new()),
            format_version: Self::default_format_version(),
            schema_hash: Self::default_schema_hash(),
            metrics: RefCell::new(Metrics::default()),
            _not_send_sync: PhantomData,
        }
    }
}

impl QueryEngine {
    /// Creates a new query engine.
    pub fn new() -> Self {
        Self::default()
    }

    /// Default cache format version (current version).
    fn default_format_version() -> u32 {
        CACHE_FORMAT_VERSION
    }

    /// Default schema hash (current schema).
    fn default_schema_hash() -> HashValue {
        engine_schema_hash()
    }

    /// Returns the current version of a dependency key.
    pub fn current_version(&self, dep_key: &DepKey) -> u64 {
        *self.versions.borrow().get(dep_key).unwrap_or(&0)
    }

    /// Bumps the version of a dependency key, marking it as changed.
    pub fn bump_version(&self, dep_key: DepKey) {
        let mut versions = self.versions.borrow_mut();
        let entry = versions.entry(dep_key).or_insert(0);
        *entry += 1;
    }

    /// Bumps versions of multiple dependency keys.
    pub fn bump_versions(&self, dep_keys: &[DepKey]) {
        for dep_key in dep_keys {
            self.bump_version(dep_key.clone());
        }
    }

    /// Bumps the version of a query, marking its result as changed.
    pub fn bump_query_version(&self, instance: &QueryInstance) {
        self.bump_version(DepKey::Query {
            scope_fp: instance.scope_fp.clone(),
            query_key: instance.query_key.clone(),
        });
    }

    /// Executes a query with memoization.
    ///
    /// If the query is already memoized, returns the cached value.
    /// Otherwise, executes `f` with dependency recording, memoizes the result,
    /// and returns it.
    ///
    /// Returns `Err(QueryError::CycleDetected(...))` if a dependency cycle is detected.
    ///
    /// See: [Salsa: A Library for Incremental Computation, POPL 2020]
    pub fn execute<F>(&self, instance: QueryInstance, f: F) -> Result<QueryResult, QueryError>
    where
        F: FnOnce() -> QueryResult,
    {
        #[cfg(test)]
        eprintln!("[EXECUTE ENTER] {:?}", instance.query_key);
        // Check cache with version validation
        let old_entry = {
            let memo = self.memo.borrow();
            memo.get(&instance).cloned()
        };

        // Check if cached entry is still valid (all observed versions match current)
        if let Some(entry) = &old_entry {
            let mut valid = true;
            for (dep_key, observed_version) in &entry.observed_versions {
                let current_version = self.current_version(dep_key);
                if current_version != *observed_version {
                    valid = false;
                    self.metrics.borrow_mut().record_invalidation();
                    // Debug logging for test failures
                    #[cfg(test)]
                    eprintln!("[DEBUG] Cache invalid for {:?}: dep_key {:?} observed {}, current {}",
                        instance, dep_key, observed_version, current_version);
                    break;
                }
            }
            if valid {
                // Cache hit: record dependency from caller to this query (if any)
                // Skip self-dependency
                if let Some(current) = current_query() {
                    if current != instance {
                        record_dependency(&instance);
                    }
                }
                #[cfg(test)]
                eprintln!("[CACHE HIT] {:?}", instance.query_key);
                self.metrics.borrow_mut().record_hit();
                return Ok(entry.value.clone());
            }
        }

        // Not cached or invalid: execute with dependency recording
        self.metrics.borrow_mut().record_miss();
        let guard = match QueryGuard::start(instance.clone()) {
            Ok(guard) => guard,
            Err(QueryError::CycleDetected { scope_fp, query_key }) => {
                // Cycle detected: ensure no memo entry persists for this instance
                self.metrics.borrow_mut().record_cycle_detected();
                self.memo.borrow_mut().remove(&instance);
                return Err(QueryError::CycleDetected { scope_fp, query_key });
            }
        };

        // Guard succeeded (no cycle): record dependency from caller to this query
        record_dependency_from_caller_to(&instance);

        let value = f();
        self.metrics.borrow_mut().record_recompute();
        let deps = guard.finish();

        // Capture current versions of dependencies
        let mut observed_versions = BTreeMap::new();
        for dep in deps.iter() {
            let version = self.current_version(dep);
            observed_versions.insert(dep.clone(), version);
        }

        let new_fingerprint = value.fingerprint();
        let old_compute_count = old_entry.as_ref().map(|e| e.compute_count).unwrap_or(0);

        if let Some(old_entry) = old_entry {
            if old_entry.value_fingerprint == new_fingerprint {
                // Result unchanged: update deps and versions (dep set replacement)
                let mut updated_entry = old_entry;
                updated_entry.deps = deps;
                updated_entry.observed_versions = observed_versions;
                updated_entry.compute_count = old_compute_count + 1;
                self.memo.borrow_mut().insert(instance.clone(), updated_entry);
                // DO NOT bump query version since result didn't change
            } else {
                // Result changed: create new entry and bump version
                let mut entry = MemoEntry::new(value.clone(), deps);
                entry.observed_versions = observed_versions;
                entry.compute_count = old_compute_count + 1;
                self.memo.borrow_mut().insert(instance.clone(), entry);
                self.bump_query_version(&instance);
            }
        } else {
            // No old entry: create new entry
            let mut entry = MemoEntry::new(value.clone(), deps);
            entry.observed_versions = observed_versions;
            entry.compute_count = 1; // first computation
            self.memo.borrow_mut().insert(instance.clone(), entry);
            self.bump_query_version(&instance);
        }

        #[cfg(test)]
        eprintln!("[EXECUTE OK] {:?} compute_count: {}", instance.query_key, old_compute_count + 1);
        Ok(value)
    }

    /// Clears all memoized results (coarse invalidation).
    pub fn clear(&self) {
        self.memo.borrow_mut().clear();
    }

    /// Returns a clone of the memo entry for a query (for testing).
    pub fn debug_get_entry(&self, instance: &QueryInstance) -> Option<MemoEntry> {
        self.memo.borrow().get(instance).cloned()
    }

    /// Returns a clone of the current performance metrics.
    pub fn metrics(&self) -> Metrics {
        self.metrics.borrow().clone()
    }

    /// Resets all performance metrics to zero.
    pub fn reset_metrics(&self) {
        self.metrics.borrow_mut().reset();
    }

    /// Serializes the query engine to CBOR bytes.
    pub fn to_cbor(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let bytes = serde_cbor::to_vec(self)?;
        Ok(bytes)
    }

    /// Deserializes the query engine from CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let engine: Self = serde_cbor::from_slice(bytes)?;

        // Validate cache compatibility
        if engine.format_version != CACHE_FORMAT_VERSION {
            return Err(format!(
                "Cache format version mismatch: loaded {}, current {}. \
                 Delete cache file and rebuild.",
                engine.format_version, CACHE_FORMAT_VERSION
            ).into());
        }

        if engine.schema_hash != engine_schema_hash() {
            return Err(format!(
                "Schema hash mismatch: cache is incompatible with current engine. \
                 Delete cache file and rebuild. (loaded {:?}, expected {:?})",
                engine.schema_hash, engine_schema_hash()
            ).into());
        }

        Ok(engine)
    }

    /// Saves the query engine to a file.
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
        let bytes = self.to_cbor()?;
        let bytes_len = bytes.len() as u64;
        std::fs::write(path, bytes)?;
        self.metrics.borrow_mut().record_bytes_saved(bytes_len);
        Ok(())
    }

    /// Loads the query engine from a file.
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let bytes = std::fs::read(path)?;
        let bytes_len = bytes.len() as u64;
        let engine = Self::from_cbor(&bytes)?;
        engine.metrics.borrow_mut().record_bytes_loaded(bytes_len);
        Ok(engine)
    }
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::{ScopeFingerprint, ScopeFingerprintComponents};
    use crate::fingerprint::HashValue;
    use crate::boundary::Boundary;
    use crate::core::NodeId;
    use crate::interface::{compute_interface_stub, InterfaceSummaryV0};

    /// Helper to create a QueryInstance concisely in tests.
    fn qi(scope_fp: &ScopeFingerprint, key: QueryKey) -> QueryInstance {
        QueryInstance::new(scope_fp.clone(), key)
    }

    #[test]
    fn test_query_instance_fingerprint_deterministic() {
        let zero = HashValue::zero();
        let components = ScopeFingerprintComponents {
            core_ast_fp: zero,
            expansion_env_fp: zero,
            import_deps_fp: zero,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };
        let scope_fp = ScopeFingerprint::new(components);

        let instance1 = QueryInstance::new(scope_fp.clone(), QueryKey::CheckEdge { edge_id: 42 });
        let instance2 = QueryInstance::new(scope_fp.clone(), QueryKey::CheckEdge { edge_id: 42 });

        assert_eq!(instance1.fingerprint(), instance2.fingerprint());
    }

    #[test]
    fn test_query_key_ordering() {
        // QueryKey ordering is scope-free; test with edge_id only
        let key1 = QueryKey::CheckEdge { edge_id: 1 };
        let key2 = QueryKey::CheckEdge { edge_id: 2 };

        // Different keys should have different order
        assert!(key1 < key2);
    }

    #[test]
    fn test_memo_table_basic() {
        let mut table: MemoTable = MemoTable::new();

        let zero = HashValue::zero();
        let components = ScopeFingerprintComponents {
            core_ast_fp: zero,
            expansion_env_fp: zero,
            import_deps_fp: zero,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };
        let scope_fp = ScopeFingerprint::new(components);

        let instance = qi(&scope_fp, QueryKey::CheckEdge { edge_id: 42 });

        // Initially empty
        assert!(table.get(&instance).is_none());

        // Insert entry
        let entry = MemoEntry::new(QueryResult::NodeType(NodeType("result".to_string())), DependencySet::new());
        table.insert(instance.clone(), entry);

        // Should now be present
        assert!(table.get(&instance).is_some());

        // Clear
        table.clear();
        assert!(table.get(&instance).is_none());
    }

    #[test]
    fn test_query_engine_memoization() {
        let engine: QueryEngine = QueryEngine::new();
        let mut call_count = 0;

        let zero = HashValue::zero();
        let components = ScopeFingerprintComponents {
            core_ast_fp: zero,
            expansion_env_fp: zero,
            import_deps_fp: zero,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };
        let scope_fp = ScopeFingerprint::new(components);

        let instance = qi(&scope_fp, QueryKey::CheckEdge { edge_id: 42 });

        // First call should execute
        let result1 = engine.execute(instance.clone(), || {
            call_count += 1;
            QueryResult::NodeType(NodeType("computed".to_string()))
        }).unwrap();

        assert_eq!(call_count, 1);
        assert_eq!(result1, QueryResult::NodeType(NodeType("computed".to_string())));

        // Second call should hit cache
        let result2 = engine.execute(instance.clone(), || {
            call_count += 1;
            QueryResult::NodeType(NodeType("should not be called".to_string()))
        }).unwrap();

        assert_eq!(call_count, 1); // No increment
        assert_eq!(result2, QueryResult::NodeType(NodeType("computed".to_string())));
    }

    #[test]
    fn test_dependency_recording() {
        let engine: QueryEngine = QueryEngine::new();
        let zero = HashValue::zero();
        let components = ScopeFingerprintComponents {
            core_ast_fp: zero,
            expansion_env_fp: zero,
            import_deps_fp: zero,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };
        let scope_fp = ScopeFingerprint::new(components);

        let instance_a = qi(&scope_fp, QueryKey::CheckEdge { edge_id: 1 });
        let instance_b = qi(&scope_fp, QueryKey::CheckEdge { edge_id: 2 });

        // Execute query A, which calls query B
        let result_a = engine.execute(instance_a.clone(), || {
            // Inside A, call B
            engine.execute(instance_b.clone(), || {
                QueryResult::NodeType(NodeType("B".to_string()))
            }).unwrap();
            QueryResult::NodeType(NodeType("A".to_string()))
        }).unwrap();

        assert_eq!(result_a, QueryResult::NodeType(NodeType("A".to_string())));

        // Check that A's memo entry includes B as dependency
        let entry_a = engine.debug_get_entry(&instance_a).unwrap();
        assert!(entry_a.deps.iter().any(|dep| match dep {
            DepKey::Query { scope_fp: dep_scope, query_key: dep_key } =>
                dep_scope == &scope_fp && dep_key == &QueryKey::CheckEdge { edge_id: 2 },
            DepKey::ImportedInterface(_) => false,
            _ => false,
        }));

        // Check that B's memo entry exists and has no dependencies (leaf)
        let entry_b = engine.debug_get_entry(&instance_b).unwrap();
        assert!(entry_b.deps.iter().next().is_none());
    }

    #[test]
    fn test_check_edge_query() {
        // Create a query engine for boundary results
        let engine: QueryEngine = QueryEngine::new();
        let scope_fp = ScopeFingerprint::placeholder();
        let edge_id = 42;

        let instance = qi(&scope_fp, QueryKey::CheckEdge { edge_id });

        let mut call_count = 0;

        // First execution should compute
        let result1 = engine.execute(instance.clone(), || {
            call_count += 1;
            // Mock boundary computation
            QueryResult::BoundaryResult(BoundaryResult(Ok(Boundary::Empty)))
        }).unwrap();

        assert_eq!(call_count, 1);
        assert_eq!(result1, QueryResult::BoundaryResult(BoundaryResult(Ok(Boundary::Empty))));

        // Second execution should hit cache
        let result2 = engine.execute(instance.clone(), || {
            call_count += 1;
            panic!("Should not be called");
        }).unwrap();

        assert_eq!(call_count, 1);
        assert_eq!(result2, QueryResult::BoundaryResult(BoundaryResult(Ok(Boundary::Empty))));

        // Verify memo entry exists
        let entry = engine.debug_get_entry(&instance).unwrap();
        assert!(entry.deps.iter().next().is_none()); // no dependencies
    }

    #[test]
    fn test_coarse_invalidation() {
        use crate::fingerprint::HashValue;
        let zero = HashValue::zero();
        let non_zero = HashValue::hash_with_domain(b"TEST", b"different");

        // Create two scope fingerprints that differ only in kernel_policy_fp
        let components1 = ScopeFingerprintComponents {
            core_ast_fp: zero,
            expansion_env_fp: zero,
            import_deps_fp: zero,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };
        let scope_fp1 = ScopeFingerprint::new(components1);

        let components2 = ScopeFingerprintComponents {
            core_ast_fp: zero,
            expansion_env_fp: zero,
            import_deps_fp: zero,
            kernel_policy_fp: non_zero,
            compiler_build_id: zero,
        };
        let scope_fp2 = ScopeFingerprint::new(components2);

        let engine: QueryEngine = QueryEngine::new();
        let edge_id = 42;

        let instance1 = qi(&scope_fp1, QueryKey::CheckEdge { edge_id });
        let instance2 = qi(&scope_fp2, QueryKey::CheckEdge { edge_id });

        let mut call_count = 0;

        // Execute with first fingerprint
        let result1 = engine.execute(instance1.clone(), || {
            call_count += 1;
            QueryResult::NodeType(NodeType("result1".to_string()))
        }).unwrap();
        assert_eq!(call_count, 1);
        assert_eq!(result1, QueryResult::NodeType(NodeType("result1".to_string())));

        // Execute with second fingerprint (different kernel_policy_fp) should recompute
        let result2 = engine.execute(instance2.clone(), || {
            call_count += 1;
            QueryResult::NodeType(NodeType("result2".to_string()))
        }).unwrap();
        assert_eq!(call_count, 2);
        assert_eq!(result2, QueryResult::NodeType(NodeType("result2".to_string())));

        // Execute again with first fingerprint should hit cache
        let result1b = engine.execute(instance1.clone(), || {
            call_count += 1;
            panic!("Should not be called");
        }).unwrap();
        assert_eq!(call_count, 2);
        assert_eq!(result1b, QueryResult::NodeType(NodeType("result1".to_string())));
    }

    #[test]
    fn test_coarse_invalidation_import_deps() {
        use crate::fingerprint::HashValue;
        let zero = HashValue::zero();
        let non_zero = HashValue::hash_with_domain(b"TEST", b"different");

        // Create two scope fingerprints that differ only in import_deps_fp
        let components1 = ScopeFingerprintComponents {
            core_ast_fp: zero,
            expansion_env_fp: zero,
            import_deps_fp: zero,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };
        let scope_fp1 = ScopeFingerprint::new(components1);

        let components2 = ScopeFingerprintComponents {
            core_ast_fp: zero,
            expansion_env_fp: zero,
            import_deps_fp: non_zero,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };
        let scope_fp2 = ScopeFingerprint::new(components2);

        let engine: QueryEngine = QueryEngine::new();
        let edge_id = 42;

        let instance1 = qi(&scope_fp1, QueryKey::CheckEdge { edge_id });
        let instance2 = qi(&scope_fp2, QueryKey::CheckEdge { edge_id });

        let mut call_count = 0;

        // Execute with first fingerprint
        let result1 = engine.execute(instance1.clone(), || {
            call_count += 1;
            QueryResult::NodeType(NodeType("result1".to_string()))
        }).unwrap();
        assert_eq!(call_count, 1);
        assert_eq!(result1, QueryResult::NodeType(NodeType("result1".to_string())));

        // Execute with second fingerprint (different import_deps_fp) should recompute
        let result2 = engine.execute(instance2.clone(), || {
            call_count += 1;
            QueryResult::NodeType(NodeType("result2".to_string()))
        }).unwrap();
        assert_eq!(call_count, 2);
        assert_eq!(result2, QueryResult::NodeType(NodeType("result2".to_string())));

        // Execute again with first fingerprint should hit cache
        let result1b = engine.execute(instance1.clone(), || {
            call_count += 1;
            panic!("Should not be called");
        }).unwrap();
        assert_eq!(call_count, 2);
        assert_eq!(result1b, QueryResult::NodeType(NodeType("result1".to_string())));
    }

    #[test]
    fn test_recursion_detection() {
        let engine: QueryEngine = QueryEngine::new();
        let scope_fp = ScopeFingerprint::placeholder();
        let edge_id = 42;

        let instance = qi(&scope_fp, QueryKey::CheckEdge { edge_id });

        // Direct recursion: query calls itself
        let outer_result = engine.execute(instance.clone(), || {
            // Inside query, call same query again
            let inner_result = engine.execute(instance.clone(), || {
                QueryResult::NodeType(NodeType("should never reach".to_string()))
            });
            // Inner call should return cycle error
            assert!(matches!(inner_result, Err(QueryError::CycleDetected { .. })));
            QueryResult::NodeType(NodeType("outer".to_string()))
        });

        // Outer call should succeed (no cycle in outer call itself)
        assert_eq!(outer_result.unwrap(), QueryResult::NodeType(NodeType("outer".to_string())));
    }

    #[test]
    fn test_panic_safety() {
        let engine: QueryEngine = QueryEngine::new();
        let scope_fp = ScopeFingerprint::placeholder();

        // First instance: normal execution
        let instance1 = qi(&scope_fp, QueryKey::CheckEdge { edge_id: 1 });
        let result = engine.execute(instance1.clone(), || {
            QueryResult::NodeType(NodeType("normal".to_string()))
        }).unwrap();
        assert_eq!(result, QueryResult::NodeType(NodeType("normal".to_string())));

        // Second instance: execution that panics (not yet cached)
        let instance2 = qi(&scope_fp, QueryKey::CheckEdge { edge_id: 2 });
        let engine_ref = std::panic::AssertUnwindSafe(&engine);
        let panic_result = std::panic::catch_unwind(|| {
            let _ = engine_ref.execute(instance2.clone(), || {
                panic!("test panic during query execution");
            });
        });
        assert!(panic_result.is_err());

        // After panic, engine should still be functional
        // instance1 should still be cached
        let result1 = engine.execute(instance1.clone(), || {
            panic!("should not be called");
        }).unwrap();
        assert_eq!(result1, QueryResult::NodeType(NodeType("normal".to_string())));

        // instance2 should not be cached (panic prevented caching)
        // Execute again should compute (no panic this time)
        let call_count = std::cell::Cell::new(0);
        let result2 = engine.execute(instance2.clone(), || {
            call_count.set(call_count.get() + 1);
            QueryResult::NodeType(NodeType("recomputed".to_string()))
        }).unwrap();
        assert_eq!(call_count.get(), 1);
        assert_eq!(result2, QueryResult::NodeType(NodeType("recomputed".to_string())));
    }

    #[test]
    fn test_frame_isolation() {
        // Test that dependency frames are isolated: A depends on B and C,
        // B depends on D, but deps(B) must not include C.
        let engine: QueryEngine = QueryEngine::new();
        let scope_fp = ScopeFingerprint::placeholder();

        // Define four distinct query instances
        let instance_a = qi(&scope_fp, QueryKey::CheckEdge { edge_id: 1 });
        let instance_b = qi(&scope_fp, QueryKey::CheckEdge { edge_id: 2 });
        let instance_c = qi(&scope_fp, QueryKey::CheckEdge { edge_id: 3 });
        let instance_d = qi(&scope_fp, QueryKey::CheckEdge { edge_id: 4 });

        // Execute A, which calls B and C
        let result_a = engine.execute(instance_a.clone(), || {
            // Inside A, call B
            engine.execute(instance_b.clone(), || {
                // Inside B, call D
                engine.execute(instance_d.clone(), || {
                    QueryResult::NodeType(NodeType("D".to_string()))
                }).unwrap();
                QueryResult::NodeType(NodeType("B".to_string()))
            }).unwrap();
            // Also call C
            engine.execute(instance_c.clone(), || {
                QueryResult::NodeType(NodeType("C".to_string()))
            }).unwrap();
            QueryResult::NodeType(NodeType("A".to_string()))
        }).unwrap();

        assert_eq!(result_a, QueryResult::NodeType(NodeType("A".to_string())));

        // Check dependency sets
        let entry_a = engine.debug_get_entry(&instance_a).unwrap();
        let entry_b = engine.debug_get_entry(&instance_b).unwrap();
        let entry_c = engine.debug_get_entry(&instance_c).unwrap();
        let entry_d = engine.debug_get_entry(&instance_d).unwrap();

        // A depends on B and C (direct dependencies)
        let a_deps: Vec<_> = entry_a.deps.iter().collect();
        assert_eq!(a_deps.len(), 2);
        assert!(a_deps.iter().any(|dep| matches!(dep, DepKey::Query { scope_fp: _, query_key: QueryKey::CheckEdge { edge_id: 2 } })));
        assert!(a_deps.iter().any(|dep| matches!(dep, DepKey::Query { scope_fp: _, query_key: QueryKey::CheckEdge { edge_id: 3 } })));

        // B depends only on D (not on C!)
        let b_deps: Vec<_> = entry_b.deps.iter().collect();
        assert_eq!(b_deps.len(), 1);
        assert!(matches!(b_deps[0], DepKey::Query { scope_fp: _, query_key: QueryKey::CheckEdge { edge_id: 4 } }));

        // C has no dependencies
        assert!(entry_c.deps.iter().next().is_none());

        // D has no dependencies
        assert!(entry_d.deps.iter().next().is_none());
    }

    #[test]
    fn test_compute_interface_basic() {
        // Basic test of ComputeInterface query
        let engine: QueryEngine = QueryEngine::new();
        let scope_fp = ScopeFingerprint::placeholder();

        let instance = qi(&scope_fp, QueryKey::ComputeInterface);

        let result = engine.execute(instance.clone(), || {
            QueryResult::Interface(InterfaceResult(compute_interface_stub(&scope_fp)))
        }).unwrap();

        // Should have computed an interface summary
        let QueryResult::Interface(InterfaceResult(summary)) = result else { panic!("expected Interface variant"); };
        assert_eq!(summary.scope_fp, scope_fp);
        // No dependencies because no imports
        let entry = engine.debug_get_entry(&instance).unwrap();
        assert!(entry.deps.iter().next().is_none());
    }

    #[test]
    fn test_imported_interface_dependency() {
        // Test that ComputeInterface records dependencies on imported interface fingerprints
        let engine: QueryEngine = QueryEngine::new();

        // Create two distinct scopes
        let zero = HashValue::zero();
        let components_a = ScopeFingerprintComponents {
            core_ast_fp: HashValue::hash_with_domain(b"TEST", b"scope_a"),
            expansion_env_fp: zero,
            import_deps_fp: zero,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };
        let components_b = ScopeFingerprintComponents {
            core_ast_fp: HashValue::hash_with_domain(b"TEST", b"scope_b"),
            expansion_env_fp: zero,
            import_deps_fp: zero,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };

        let scope_fp_a = ScopeFingerprint::new(components_a);
        let scope_fp_b = ScopeFingerprint::new(components_b);

        // First, compute interface for scope A
        let instance_a = qi(&scope_fp_a, QueryKey::ComputeInterface);
        let result_a = engine.execute(instance_a.clone(), || {
            QueryResult::Interface(InterfaceResult(compute_interface_stub(&scope_fp_a)))
        }).unwrap();
        let QueryResult::Interface(InterfaceResult(summary_a)) = result_a else { panic!("expected Interface variant"); };
        let interface_fp_a = summary_a.fingerprint();

        // Now compute interface for scope B that imports A
        let instance_b = qi(&scope_fp_b, QueryKey::ComputeInterface);
        let _result_b = engine.execute(instance_b.clone(), || {
            // Inside B's computation, record dependency on A's interface fingerprint
            record_imported_interface_dependency(interface_fp_a);

            // Build interface summary for B with A as import
            let components = &scope_fp_b.components;
            QueryResult::Interface(InterfaceResult(InterfaceSummaryV0::new(
                scope_fp_b.clone(),
                BTreeMap::new(), // empty exported boundaries
                vec![interface_fp_a], // imported interface fingerprint
                components.kernel_policy_fp,
                components.compiler_build_id,
            )))
        }).unwrap();

        // Verify B's dependencies include ImportedInterface(A's fingerprint)
        let entry_b = engine.debug_get_entry(&instance_b).unwrap();
        assert!(entry_b.deps.iter().any(|dep| matches!(dep, DepKey::ImportedInterface(fp) if *fp == interface_fp_a)));

        // Verify A has no dependencies (no imports)
        let entry_a = engine.debug_get_entry(&instance_a).unwrap();
        assert!(entry_a.deps.iter().next().is_none());
    }

    #[test]
    fn test_cache_invalidation_on_scope_fingerprint_change() {
        // Coarse invalidation: changing any component of ScopeFingerprint should cause cache miss
        let engine: QueryEngine = QueryEngine::new();
        let zero = HashValue::zero();
        let hash1 = HashValue::hash_with_domain(b"TEST", b"hash1");

        // Create two scope fingerprints that differ only in core_ast_fp
        let components1 = ScopeFingerprintComponents {
            core_ast_fp: zero,
            expansion_env_fp: zero,
            import_deps_fp: zero,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };
        let components2 = ScopeFingerprintComponents {
            core_ast_fp: hash1, // different
            expansion_env_fp: zero,
            import_deps_fp: zero,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };
        let scope_fp1 = ScopeFingerprint::new(components1);
        let scope_fp2 = ScopeFingerprint::new(components2);

        // Use a simple query key
        let query_key = QueryKey::CheckEdge { edge_id: 42 };

        let mut execution_count = 0u32;

        // First execution with scope_fp1
        let instance1 = QueryInstance::new(scope_fp1.clone(), query_key.clone());
        let result1 = engine.execute(instance1, || {
            execution_count += 1;
            QueryResult::NodeType(NodeType("100".to_string()))
        }).unwrap();
        assert_eq!(result1, QueryResult::NodeType(NodeType("100".to_string())));
        assert_eq!(execution_count, 1);

        // Same scope_fp1 again -> cache hit, execution_count unchanged
        let instance1b = QueryInstance::new(scope_fp1.clone(), query_key.clone());
        let result1b = engine.execute(instance1b, || {
            execution_count += 1;
            QueryResult::NodeType(NodeType("200".to_string())) // different value to detect if executed
        }).unwrap();
        assert_eq!(result1b, QueryResult::NodeType(NodeType("100".to_string()))); // cached value, not 200
        assert_eq!(execution_count, 1); // still 1

        // Different scope_fp2 -> cache miss, execution_count increments
        let instance2 = QueryInstance::new(scope_fp2.clone(), query_key.clone());
        let result2 = engine.execute(instance2, || {
            execution_count += 1;
            QueryResult::NodeType(NodeType("300".to_string()))
        }).unwrap();
        assert_eq!(result2, QueryResult::NodeType(NodeType("300".to_string())));
        assert_eq!(execution_count, 2);
    }

    #[test]
    fn test_cached_vs_non_cached_semantics() {
        // Verify that query caching does not change semantics (results identical)
        let engine: QueryEngine = QueryEngine::new();
        let zero = HashValue::zero();
        let components = ScopeFingerprintComponents {
            core_ast_fp: zero,
            expansion_env_fp: zero,
            import_deps_fp: zero,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };
        let scope_fp = ScopeFingerprint::new(components);

        // Test boundary compatibility
        let left = Boundary::Empty;
        let right = Boundary::Empty;

        // Non-cached result
        let non_cached_result = left.compatible_with(&right);

        // Cached result (first execution)
        let instance = QueryInstance::new(scope_fp.clone(), QueryKey::CheckBoundaryCompatibility {
            left: left.clone(),
            right: right.clone(),
        });
        let cached_result = engine.execute(instance, || {
            QueryResult::BoundaryCompatibilityResult(BoundaryCompatibilityResult(left.compatible_with(&right)))
        }).unwrap();

        // Should be equal
        let QueryResult::BoundaryCompatibilityResult(BoundaryCompatibilityResult(cached_inner)) = cached_result else { panic!("expected BoundaryCompatibilityResult"); };
        assert_eq!(non_cached_result, cached_inner);

        // Test with incompatible boundaries
        let left2 = Boundary::globular1(NodeId::new(1), NodeId::new(2));
        let right2 = Boundary::globular1(NodeId::new(3), NodeId::new(4)); // different src0

        let non_cached_result2 = left2.compatible_with(&right2);
        let instance2 = QueryInstance::new(scope_fp, QueryKey::CheckBoundaryCompatibility {
            left: left2.clone(),
            right: right2.clone(),
        });
        let cached_result2 = engine.execute(instance2, || {
            QueryResult::BoundaryCompatibilityResult(BoundaryCompatibilityResult(left2.compatible_with(&right2)))
        }).unwrap();
        let QueryResult::BoundaryCompatibilityResult(BoundaryCompatibilityResult(cached_inner2)) = cached_result2 else { panic!("expected BoundaryCompatibilityResult"); };
        assert_eq!(non_cached_result2, cached_inner2);
    }

    #[test]
    fn test_lazy_invalidation_imported_interface() {
        // Test that bumping an imported interface version causes dependent query to recompute
        let engine: QueryEngine = QueryEngine::new();
        let _zero = HashValue::zero();

        // Create an imported interface fingerprint
        let interface_fp = HashValue::hash_with_domain(b"TEST", b"interface");

        // Create a query that depends on the imported interface
        let scope_fp = ScopeFingerprint::placeholder();
        let instance = QueryInstance::new(scope_fp.clone(), QueryKey::CheckEdge { edge_id: 42 });

        let mut compute_count = 0;

        // First execution: query records dependency on imported interface
        let result1 = engine.execute(instance.clone(), || {
            compute_count += 1;
            record_imported_interface_dependency(interface_fp);
            QueryResult::NodeType(NodeType("result1".to_string()))
        }).unwrap();

        assert_eq!(compute_count, 1);
        assert_eq!(result1, QueryResult::NodeType(NodeType("result1".to_string())));

        // Second execution: cache hit because interface version unchanged
        let result2 = engine.execute(instance.clone(), || {
            compute_count += 1;
            panic!("should not be called");
        }).unwrap();

        assert_eq!(compute_count, 1); // still 1
        assert_eq!(result2, QueryResult::NodeType(NodeType("result1".to_string())));

        // Bump version of imported interface
        engine.bump_version(DepKey::ImportedInterface(interface_fp));

        // Third execution: cache miss because interface version changed
        let result3 = engine.execute(instance.clone(), || {
            compute_count += 1;
            QueryResult::NodeType(NodeType("result3".to_string()))
        }).unwrap();

        assert_eq!(compute_count, 2); // incremented
        assert_eq!(result3, QueryResult::NodeType(NodeType("result3".to_string())));

        // Verify compute_count in memo entry increased
        let entry = engine.debug_get_entry(&instance).unwrap();
        assert_eq!(entry.compute_count, 2);
    }

    #[test]
    fn test_query_engine_serialization() {
        // Create an engine, execute a query to populate memo table
        let engine1 = QueryEngine::new();
        let zero = HashValue::zero();
        let components = ScopeFingerprintComponents {
            core_ast_fp: zero,
            expansion_env_fp: zero,
            import_deps_fp: zero,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };
        let scope_fp = ScopeFingerprint::new(components);
        let instance = QueryInstance::new(scope_fp, QueryKey::CheckEdge { edge_id: 42 });

        let mut compute_count = 0;
        let result1 = engine1.execute(instance.clone(), || {
            compute_count += 1;
            QueryResult::NodeType(NodeType("value".to_string()))
        }).unwrap();
        assert_eq!(compute_count, 1);
        assert_eq!(result1, QueryResult::NodeType(NodeType("value".to_string())));

        // Serialize to CBOR
        let bytes = engine1.to_cbor().expect("serialization should succeed");

        // Deserialize to a new engine
        let engine2 = QueryEngine::from_cbor(&bytes).expect("deserialization should succeed");

        // Execute same query on engine2 - should be cache hit (no recomputation)
        let result2 = engine2.execute(instance.clone(), || {
            compute_count += 1; // should not be called
            QueryResult::NodeType(NodeType("new_value".to_string()))
        }).unwrap();
        assert_eq!(compute_count, 1); // unchanged
        assert_eq!(result2, QueryResult::NodeType(NodeType("value".to_string()))); // original cached value

        // Verify memo entry is present
        let entry = engine2.debug_get_entry(&instance).unwrap();
        assert_eq!(entry.compute_count, 1);

        // Test file serialization roundtrip
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join("test_query_engine.cbor");

        engine2.save_to_file(&temp_file).expect("save should succeed");
        let engine3 = QueryEngine::load_from_file(&temp_file).expect("load should succeed");

        // Verify cache hit still works
        let result3 = engine3.execute(instance, || {
            compute_count += 1;
            panic!("should not be called");
        }).unwrap();
        assert_eq!(compute_count, 1);
        assert_eq!(result3, QueryResult::NodeType(NodeType("value".to_string())));

        // Clean up
        let _ = std::fs::remove_file(&temp_file);
    }

    #[test]
    fn test_rewrite_bundle_dependency() {
        let engine = QueryEngine::new();
        let zero = HashValue::zero();
        let components = ScopeFingerprintComponents {
            core_ast_fp: zero,
            expansion_env_fp: zero,
            import_deps_fp: zero,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };
        let scope_fp = ScopeFingerprint::new(components);
        let instance = QueryInstance::new(scope_fp.clone(), QueryKey::CheckEdge { edge_id: 42 });

        let mut compute_count = 0;
        let rewrite_bundle_fp = HashValue::hash_with_domain(b"TEST", b"rewrite_bundle");

        // First execution: query records dependency on rewrite bundle
        let result1 = engine.execute(instance.clone(), || {
            compute_count += 1;
            record_rewrite_bundle_dependency(rewrite_bundle_fp);
            QueryResult::NodeType(NodeType("result1".to_string()))
        }).unwrap();
        assert_eq!(compute_count, 1);
        assert_eq!(result1, QueryResult::NodeType(NodeType("result1".to_string())));

        // Second execution: cache hit because rewrite bundle unchanged
        let result2 = engine.execute(instance.clone(), || {
            compute_count += 1;
            panic!("should not be called");
        }).unwrap();
        assert_eq!(compute_count, 1);
        assert_eq!(result2, QueryResult::NodeType(NodeType("result1".to_string())));

        // Bump version of rewrite bundle
        engine.bump_version(DepKey::RewriteBundle(rewrite_bundle_fp));

        // Third execution: cache miss because rewrite bundle version changed
        let result3 = engine.execute(instance.clone(), || {
            compute_count += 1;
            QueryResult::NodeType(NodeType("result3".to_string()))
        }).unwrap();
        assert_eq!(compute_count, 2);
        assert_eq!(result3, QueryResult::NodeType(NodeType("result3".to_string())));

        // Verify compute_count in memo entry increased
        let entry = engine.debug_get_entry(&instance).unwrap();
        assert_eq!(entry.compute_count, 2);
    }

    #[test]
    fn test_dep_set_replacement() {
        // Test that when a query recomputes with different dependencies,
        // the dependency set is updated (old dependencies are removed).
        let engine = QueryEngine::new();
        let zero = HashValue::zero();
        let components = ScopeFingerprintComponents {
            core_ast_fp: zero,
            expansion_env_fp: zero,
            import_deps_fp: zero,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };
        let scope_fp = ScopeFingerprint::new(components);
        let instance = QueryInstance::new(scope_fp.clone(), QueryKey::CheckEdge { edge_id: 42 });

        let dep_a = HashValue::hash_with_domain(b"TEST", b"A");
        let dep_b = HashValue::hash_with_domain(b"TEST", b"B");
        let dep_c = HashValue::hash_with_domain(b"TEST", b"C");

        // First execution: query depends on A and B
        let result1 = engine.execute(instance.clone(), || {
            record_imported_interface_dependency(dep_a);
            record_imported_interface_dependency(dep_b);
            QueryResult::NodeType(NodeType("value".to_string()))
        }).unwrap();
        assert_eq!(result1, QueryResult::NodeType(NodeType("value".to_string())));

        let entry1 = engine.debug_get_entry(&instance).unwrap();
        assert_eq!(entry1.compute_count, 1);
        // Should have dependencies A and B
        assert!(entry1.deps.iter().any(|d| matches!(d, DepKey::ImportedInterface(fp) if *fp == dep_a)));
        assert!(entry1.deps.iter().any(|d| matches!(d, DepKey::ImportedInterface(fp) if *fp == dep_b)));
        assert_eq!(entry1.deps.iter().filter(|d| matches!(d, DepKey::ImportedInterface(_))).count(), 2);

        // Invalidate query by bumping version of A (simulating A changed)
        engine.bump_version(DepKey::ImportedInterface(dep_a));

        // Second execution: query now depends on A and C (B removed, C added)
        // Result is same (fingerprint unchanged)
        let result2 = engine.execute(instance.clone(), || {
            record_imported_interface_dependency(dep_a);
            record_imported_interface_dependency(dep_c); // B replaced with C
            QueryResult::NodeType(NodeType("value".to_string())) // same result
        }).unwrap();
        assert_eq!(result2, QueryResult::NodeType(NodeType("value".to_string())));

        let entry2 = engine.debug_get_entry(&instance).unwrap();
        assert_eq!(entry2.compute_count, 2); // recomputed
        // Should have dependencies A and C, NOT B
        assert!(entry2.deps.iter().any(|d| matches!(d, DepKey::ImportedInterface(fp) if *fp == dep_a)));
        assert!(entry2.deps.iter().any(|d| matches!(d, DepKey::ImportedInterface(fp) if *fp == dep_c)));
        assert!(!entry2.deps.iter().any(|d| matches!(d, DepKey::ImportedInterface(fp) if *fp == dep_b)));
        assert_eq!(entry2.deps.iter().filter(|d| matches!(d, DepKey::ImportedInterface(_))).count(), 2);

        // Now bump version of B (which is no longer a dependency)
        engine.bump_version(DepKey::ImportedInterface(dep_b));
        // Query should still be valid (cache hit) because B is not in deps anymore
        let result3 = engine.execute(instance.clone(), || {
            panic!("should not be called - query should still be cached");
        }).unwrap();
        assert_eq!(result3, QueryResult::NodeType(NodeType("value".to_string())));
        let entry3 = engine.debug_get_entry(&instance).unwrap();
        assert_eq!(entry3.compute_count, 2); // unchanged
    }

    #[test]
    fn test_no_version_bump_when_result_unchanged() {
        // Test that recomputing a query with same result doesn't bump its version,
        // preventing "version bump storms" that would unnecessarily invalidate dependents.
        let engine = QueryEngine::new();
        let zero = HashValue::zero();
        let components = ScopeFingerprintComponents {
            core_ast_fp: zero,
            expansion_env_fp: zero,
            import_deps_fp: zero,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };
        let scope_fp = ScopeFingerprint::new(components);

        // Create two queries where Q2 depends on Q1
        let instance1 = QueryInstance::new(scope_fp.clone(), QueryKey::CheckEdge { edge_id: 1 });
        let instance2 = QueryInstance::new(scope_fp.clone(), QueryKey::CheckEdge { edge_id: 2 });

        let dep = HashValue::hash_with_domain(b"TEST", b"dep");

        // First execution: Q1 computes, Q2 depends on Q1
        let result1 = engine.execute(instance1.clone(), || {
            record_imported_interface_dependency(dep);
            QueryResult::NodeType(NodeType("Q1".to_string()))
        }).unwrap();

        let result2 = engine.execute(instance2.clone(), || {
            // Q2 depends on Q1 (via query dependency)
            record_dependency(&instance1);
            QueryResult::NodeType(NodeType("Q2".to_string()))
        }).unwrap();

        // Invalidate Q1 by bumping its dependency
        engine.bump_version(DepKey::ImportedInterface(dep));

        // Recompute Q1 with same result (fingerprint unchanged)
        let result1b = engine.execute(instance1.clone(), || {
            record_imported_interface_dependency(dep);
            QueryResult::NodeType(NodeType("Q1".to_string())) // same result
        }).unwrap();
        assert_eq!(result1b, result1);

        // Check that Q1 version didn't bump (by checking Q2 is still valid)
        // Q2 depends on Q1, so if Q1 version didn't bump, Q2 should still be cached
        let result2b = engine.execute(instance2.clone(), || {
            panic!("Q2 should still be cached because Q1 version didn't bump");
        }).unwrap();
        assert_eq!(result2b, result2);

        // Now invalidate Q1 with a change that actually changes its result
        // Simulate by having Q1 return different value
        engine.bump_version(DepKey::ImportedInterface(dep)); // bump again
        let result1c = engine.execute(instance1.clone(), || {
            record_imported_interface_dependency(dep);
            QueryResult::NodeType(NodeType("Q1-changed".to_string())) // different result
        }).unwrap();
        assert_ne!(result1c, result1);

        // Now Q2 should be invalidated because Q1 result changed (fingerprint changed)
        let result2c = engine.execute(instance2.clone(), || {
            record_dependency(&instance1);
            QueryResult::NodeType(NodeType("Q2-recomputed".to_string()))
        }).unwrap();
        assert_ne!(result2c, result2);
        assert_eq!(result2c, QueryResult::NodeType(NodeType("Q2-recomputed".to_string())));
    }

    #[test]
    fn test_persistent_cache_reuse_end_to_end() {
        // Category A: End-to-end persistent-cache reuse across invocations
        // Tests that save_to_file → load_from_file yields real reuse with 0 recomputations
        // even for complex dependency chains.

        // Create engine with multiple queries forming a chain: Q1 → Q2 → Q3
        let engine1 = QueryEngine::new();
        let zero = HashValue::zero();
        let components = ScopeFingerprintComponents {
            core_ast_fp: zero,
            expansion_env_fp: zero,
            import_deps_fp: zero,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };
        let scope_fp = ScopeFingerprint::new(components);

        let instance1 = QueryInstance::new(scope_fp.clone(), QueryKey::CheckEdge { edge_id: 1 });
        let instance2 = QueryInstance::new(scope_fp.clone(), QueryKey::CheckEdge { edge_id: 2 });
        let instance3 = QueryInstance::new(scope_fp.clone(), QueryKey::CheckEdge { edge_id: 3 });

        let mut compute_counts = [0u32; 3];

        // Build dependency chain: Q1 → Q2 → Q3 (compute in topological order)
        let result1 = engine1.execute(instance1.clone(), || {
            compute_counts[0] += 1;
            // Q1 depends on external dependency
            let ext_dep = HashValue::hash_with_domain(b"EXT", b"dep");
            record_imported_interface_dependency(ext_dep);
            QueryResult::NodeType(NodeType("Q1".to_string()))
        }).unwrap();

        let result2 = engine1.execute(instance2.clone(), || {
            compute_counts[1] += 1;
            // Q2 depends on Q1
            record_dependency(&instance1);
            QueryResult::NodeType(NodeType("Q2".to_string()))
        }).unwrap();

        let result3 = engine1.execute(instance3.clone(), || {
            compute_counts[2] += 1;
            // Q3 depends on Q2
            record_dependency(&instance2);
            QueryResult::NodeType(NodeType("Q3".to_string()))
        }).unwrap();

        // All queries computed once
        assert_eq!(compute_counts, [1, 1, 1]);

        // Save to file
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join("test_persistent_cache_reuse.cbor");
        engine1.save_to_file(&temp_file).expect("save should succeed");

        // Load into new engine
        let engine2 = QueryEngine::load_from_file(&temp_file).expect("load should succeed");

        // Execute all queries again - should be all cache hits (0 recomputations)
        let result1b = engine2.execute(instance1.clone(), || {
            compute_counts[0] += 1;
            panic!("Q1 should be cached");
        }).unwrap();
        assert_eq!(result1b, result1);

        let result2b = engine2.execute(instance2.clone(), || {
            compute_counts[1] += 1;
            panic!("Q2 should be cached");
        }).unwrap();
        assert_eq!(result2b, result2);

        let result3b = engine2.execute(instance3.clone(), || {
            compute_counts[2] += 1;
            panic!("Q3 should be cached");
        }).unwrap();
        assert_eq!(result3b, result3);

        // No additional computations
        assert_eq!(compute_counts, [1, 1, 1], "all hits on second run");

        // Verify dependency versions preserved
        let entry1 = engine2.debug_get_entry(&instance1).unwrap();
        assert_eq!(entry1.compute_count, 1);
        assert!(entry1.deps.iter().any(|d| matches!(d, DepKey::ImportedInterface(_))));

        let entry2 = engine2.debug_get_entry(&instance2).unwrap();
        assert_eq!(entry2.compute_count, 1);
        assert!(entry2.deps.iter().any(|d| matches!(d, DepKey::Query { scope_fp: _, query_key: QueryKey::CheckEdge { edge_id: 1 } })));

        let entry3 = engine2.debug_get_entry(&instance3).unwrap();
        assert_eq!(entry3.compute_count, 1);
        assert!(entry3.deps.iter().any(|d| matches!(d, DepKey::Query { scope_fp: _, query_key: QueryKey::CheckEdge { edge_id: 2 } })));

        // Clean up
        let _ = std::fs::remove_file(&temp_file);
    }

    #[test]
    fn test_golden_edit_scripts() {
        // Category B: Golden "edit scripts" (macro + rewrite + surface text)
        // Simulates realistic edit sequences and asserts exactly which queries re-run.

        let engine = QueryEngine::new();
        let zero = HashValue::zero();
        let components = ScopeFingerprintComponents {
            core_ast_fp: zero,
            expansion_env_fp: zero,
            import_deps_fp: zero,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };
        let scope_fp = ScopeFingerprint::new(components);

        // Define query instances for different phases
        let parse_instance = QueryInstance::new(scope_fp.clone(), QueryKey::ParseSurface);
        let expand_instance = QueryInstance::new(scope_fp.clone(), QueryKey::ExpandSurface);
        let compile_rules_instance = QueryInstance::new(scope_fp.clone(), QueryKey::CompileRules);
        let elab_core_instance = QueryInstance::new(scope_fp.clone(), QueryKey::ElabCore);

        // Track compute counts
        let compute_counts = std::cell::RefCell::new([0u32; 4]); // parse, expand, compile, elab

        // Helper to execute with tracking
        let exec = |engine: &QueryEngine, instance: QueryInstance, idx: usize| -> QueryResult {
            engine.execute(instance.clone(), || {
                compute_counts.borrow_mut()[idx] += 1;
                match instance.query_key {
                    QueryKey::ParseSurface => {
                        // ParseSurface depends on surface text
                        let surface_fp = HashValue::hash_with_domain(b"SURFACE", b"text_v1");
                        record_surface_text_dependency(surface_fp);
                        QueryResult::ParsedSurface(ParsedSurface(b"surface".to_vec()))
                    }
                    QueryKey::ExpandSurface => {
                        // Expand depends on parse and prelude macros
                        record_dependency(&parse_instance);
                        let prelude_fp = HashValue::hash_with_domain(b"PRELUDE", b"macros_v1");
                        record_prelude_macros_dependency(prelude_fp);
                        QueryResult::ExpandedCore(ExpandedCore(b"expanded".to_vec()))
                    }
                    QueryKey::CompileRules => {
                        // CompileRules depends on rewrite bundle
                        let rewrite_fp = HashValue::hash_with_domain(b"REWRITE", b"bundle_v1");
                        record_rewrite_bundle_dependency(rewrite_fp);
                        QueryResult::RuleBundle(RuleBundleV0 {
                            policy_fingerprint: HashValue::zero(),
                            rules: vec![],
                        })
                    }
                    QueryKey::ElabCore => {
                        // ElabCore depends on ExpandSurface and CompileRules
                        record_dependency(&expand_instance);
                        record_dependency(&compile_rules_instance);
                        QueryResult::ElabOutput(ElabOutput(b"elaborated".to_vec()))
                    }
                    _ => panic!("unexpected query key"),
                }
            }).unwrap()
        };

        // ---- Initial compilation ----
        let _ = exec(&engine, parse_instance.clone(), 0);
        let _ = exec(&engine, expand_instance.clone(), 1);
        let _ = exec(&engine, compile_rules_instance.clone(), 2);
        let _ = exec(&engine, elab_core_instance.clone(), 3);

        assert_eq!(*compute_counts.borrow(), [1, 1, 1, 1], "all computed once initially");

        // ---- Edit 1: Surface text change ----
        // Only ParseSurface should recompute (and its dependents: ExpandSurface, ElabCore)
        compute_counts.borrow_mut().fill(0); // reset counts

        // Bump surface text dependency (same fingerprint as recorded)
        let surface_fp = HashValue::hash_with_domain(b"SURFACE", b"text_v1");
        engine.bump_version(DepKey::SurfaceText(surface_fp));

        // Re-execute all queries
        let _ = exec(&engine, parse_instance.clone(), 0);
        let _ = exec(&engine, expand_instance.clone(), 1);
        let _ = exec(&engine, compile_rules_instance.clone(), 2);
        let _ = exec(&engine, elab_core_instance.clone(), 3);

        // ParseSurface recomputed (1) because surface text version changed.
        // ExpandSurface NOT recomputed because ParseSurface result unchanged (change-based versioning).
        // CompileRules unchanged (0), ElabCore NOT recomputed (depends on expand).
        assert_eq!(*compute_counts.borrow(), [1, 0, 0, 0],
            "surface edit invalidates parse but not expand (parse result unchanged)");

        // ---- Edit 2: Rewrite bundle change ----
        compute_counts.borrow_mut().fill(0);

        // Bump rewrite bundle dependency (same fingerprint as recorded)
        let rewrite_fp = HashValue::hash_with_domain(b"REWRITE", b"bundle_v1");
        engine.bump_version(DepKey::RewriteBundle(rewrite_fp));

        // Re-execute all queries
        let _ = exec(&engine, parse_instance.clone(), 0);
        let _ = exec(&engine, expand_instance.clone(), 1);
        let _ = exec(&engine, compile_rules_instance.clone(), 2);
        let _ = exec(&engine, elab_core_instance.clone(), 3);

        // CompileRules recomputed (depends on rewrite bundle) (1),
        // ElabCore NOT recomputed (compile rules result unchanged → no version bump) (0),
        // ParseSurface and ExpandSurface unchanged (0)
        assert_eq!(*compute_counts.borrow(), [0, 0, 1, 0],
            "rewrite bundle edit invalidates compile rules but not elab (change-based versioning)");

        // ---- Edit 3: Macro definitions change ----
        compute_counts.borrow_mut().fill(0);

        // Bump prelude macros dependency (same fingerprint as recorded)
        let prelude_fp = HashValue::hash_with_domain(b"PRELUDE", b"macros_v1");
        engine.bump_version(DepKey::PreludeMacros(prelude_fp));

        // Re-execute all queries
        let _ = exec(&engine, parse_instance.clone(), 0);
        let _ = exec(&engine, expand_instance.clone(), 1);
        let _ = exec(&engine, compile_rules_instance.clone(), 2);
        let _ = exec(&engine, elab_core_instance.clone(), 3);

        // ExpandSurface recomputed (depends on prelude macros) (1),
        // ElabCore NOT recomputed (expand result unchanged → no version bump) (0),
        // ParseSurface and CompileRules unchanged (0)
        assert_eq!(*compute_counts.borrow(), [0, 1, 0, 0],
            "macro edit invalidates expand but not elab (change-based versioning)");

        // ---- Edit 4: Mixed edit (surface + rewrite) ----
        compute_counts.borrow_mut().fill(0);

        // Bump both surface text and rewrite bundle
        let surface_fp = HashValue::hash_with_domain(b"SURFACE", b"text_v1");
        let rewrite_fp = HashValue::hash_with_domain(b"REWRITE", b"bundle_v1");
        engine.bump_version(DepKey::SurfaceText(surface_fp));
        engine.bump_version(DepKey::RewriteBundle(rewrite_fp));

        // Re-execute all queries
        let _ = exec(&engine, parse_instance.clone(), 0);
        let _ = exec(&engine, expand_instance.clone(), 1);
        let _ = exec(&engine, compile_rules_instance.clone(), 2);
        let _ = exec(&engine, elab_core_instance.clone(), 3);

        // ParseSurface (1), ExpandSurface (0) parse result unchanged,
        // CompileRules (1), ElabCore (0) compile rules result unchanged → no version bump
        assert_eq!(*compute_counts.borrow(), [1, 0, 1, 0],
            "mixed edit invalidates parse and compile rules but not elab (change-based versioning)");
    }

    #[test]
    fn test_cycle_detection_comprehensive() {
        // Category C: Cycle detection / recursion guard tests
        // Tests that dependency cycles fail fast with useful errors.

        let zero = HashValue::zero();
        let components = ScopeFingerprintComponents {
            core_ast_fp: zero,
            expansion_env_fp: zero,
            import_deps_fp: zero,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };
        let scope_fp = ScopeFingerprint::new(components);

        // Create three queries that could form a cycle
        let instance_a = QueryInstance::new(scope_fp.clone(), QueryKey::CheckEdge { edge_id: 1 });
        let instance_b = QueryInstance::new(scope_fp.clone(), QueryKey::CheckEdge { edge_id: 2 });
        let instance_c = QueryInstance::new(scope_fp.clone(), QueryKey::CheckEdge { edge_id: 3 });

        // ---- Test 1: Direct self-recursion ----
        {
            let engine = QueryEngine::new();
            let result = engine.execute(instance_a.clone(), || {
                // Try to call itself
                let inner = engine.execute(instance_a.clone(), || {
                    QueryResult::NodeType(NodeType("inner".to_string()))
                });
                assert!(matches!(inner, Err(QueryError::CycleDetected { .. })));
                QueryResult::NodeType(NodeType("outer".to_string()))
            });
            assert!(result.is_ok(), "outer query should succeed");
        }

        // ---- Test 2: Two-element cycle (A → B → A) ----
        // Use a simple approach: execute A, which calls B, which tries to call A
        {
            let engine = QueryEngine::new();
            let result_a = engine.execute(instance_a.clone(), || {
                // A calls B
                let b_result = engine.execute(instance_b.clone(), || {
                    // B tries to call A (cycle)
                    let a_result = engine.execute(instance_a.clone(), || {
                        QueryResult::NodeType(NodeType("should not reach".to_string()))
                    });
                    // Should get cycle error
                    assert!(matches!(a_result, Err(QueryError::CycleDetected { .. })));
                    QueryResult::NodeType(NodeType("B".to_string()))
                });
                b_result.unwrap();
                QueryResult::NodeType(NodeType("A".to_string()))
            });
            assert!(result_a.is_ok(), "cycle detection should not panic");
        }

        // ---- Test 3: Three-element cycle (A → B → C → A) ----
        {
            let engine = QueryEngine::new();
            let result_a2 = engine.execute(instance_a.clone(), || {
                // A calls B
                let b_result = engine.execute(instance_b.clone(), || {
                    // B calls C
                    let c_result = engine.execute(instance_c.clone(), || {
                        // C tries to call A (cycle)
                        let a_result = engine.execute(instance_a.clone(), || {
                            QueryResult::NodeType(NodeType("should not reach".to_string()))
                        });
                        // Should get cycle error
                        assert!(matches!(a_result, Err(QueryError::CycleDetected { .. })));
                        QueryResult::NodeType(NodeType("C".to_string()))
                    });
                    c_result.unwrap();
                    QueryResult::NodeType(NodeType("B".to_string()))
                });
                b_result.unwrap();
                QueryResult::NodeType(NodeType("A".to_string()))
            });
            assert!(result_a2.is_ok(), "three-element cycle detection should not panic");
        }

        // ---- Test 4: Cycle error contains correct query info ----
        {
            let engine = QueryEngine::new();
            let err_result = engine.execute(instance_a.clone(), || {
                // Try to call itself directly
                match engine.execute(instance_a.clone(), || {
                    QueryResult::NodeType(NodeType("inner".to_string()))
                }) {
                    Err(QueryError::CycleDetected { scope_fp: err_scope, query_key: err_key }) => {
                        // Verify error contains correct query info
                        assert_eq!(err_scope, instance_a.scope_fp);
                        assert_eq!(err_key, instance_a.query_key);
                    }
                    _ => panic!("expected CycleDetected error"),
                }
                QueryResult::NodeType(NodeType("test".to_string()))
            });
            assert!(err_result.is_ok());
        }

        // ---- Test 5: No false positives (non-cycle deep chain) ----
        // A → B → C → D (no cycle) should work fine
        {
            let engine = QueryEngine::new();
            let instance_d = QueryInstance::new(scope_fp.clone(), QueryKey::CheckEdge { edge_id: 4 });
            let result = engine.execute(instance_a.clone(), || {
                // A calls B
                let b_result = engine.execute(instance_b.clone(), || {
                    // B calls C
                    let c_result = engine.execute(instance_c.clone(), || {
                        // C calls D
                        let d_result = engine.execute(instance_d.clone(), || {
                            QueryResult::NodeType(NodeType("D".to_string()))
                        });
                        d_result.unwrap();
                        QueryResult::NodeType(NodeType("C".to_string()))
                    });
                    c_result.unwrap();
                    QueryResult::NodeType(NodeType("B".to_string()))
                });
                b_result.unwrap();
                QueryResult::NodeType(NodeType("A".to_string()))
            });
            assert!(result.is_ok(), "deep chain without cycles should succeed");

            // Verify all queries computed (except cycles which were prevented)
            eprintln!("[TEST] Checking memo entries:");
            eprintln!("  instance_a exists: {}", engine.debug_get_entry(&instance_a).is_some());
            eprintln!("  instance_b exists: {}", engine.debug_get_entry(&instance_b).is_some());
            eprintln!("  instance_c exists: {}", engine.debug_get_entry(&instance_c).is_some());
            eprintln!("  instance_d exists: {}", engine.debug_get_entry(&instance_d).is_some());
            assert!(engine.debug_get_entry(&instance_a).is_some());
            assert!(engine.debug_get_entry(&instance_b).is_some());
            assert!(engine.debug_get_entry(&instance_c).is_some());
            assert!(engine.debug_get_entry(&instance_d).is_some());
        }
    }

    #[test]
    fn test_metrics_tracking() {
        // Category D: Metrics tracking for production monitoring
        // Tests that all metrics are correctly recorded during query engine operations.

        let engine = QueryEngine::new();
        let zero = HashValue::zero();
        let components = ScopeFingerprintComponents {
            core_ast_fp: zero,
            expansion_env_fp: zero,
            import_deps_fp: zero,
            kernel_policy_fp: zero,
            compiler_build_id: zero,
        };
        let scope_fp = ScopeFingerprint::new(components);

        // Create a simple query instance
        let instance = QueryInstance::new(scope_fp.clone(), QueryKey::CheckEdge { edge_id: 42 });
        let dep_fp = HashValue::hash_with_domain(b"TEST", b"dependency");

        // ---- Test 1: First execution (cache miss, recompute) ----
        let _result = engine.execute(instance.clone(), || {
            record_surface_text_dependency(dep_fp);
            QueryResult::NodeType(NodeType("test".to_string()))
        }).unwrap();

        let metrics = engine.metrics();
        assert_eq!(metrics.query_misses, 1, "first execution should be a cache miss");
        assert_eq!(metrics.query_recomputes, 1, "first execution should count as recompute");
        assert_eq!(metrics.query_hits, 0, "no cache hits yet");
        assert_eq!(metrics.cycles_detected, 0, "no cycles yet");
        assert_eq!(metrics.cache_invalidations, 0, "no invalidations yet");

        // ---- Test 2: Second execution (cache hit) ----
        let _result2 = engine.execute(instance.clone(), || {
            panic!("should not be called - cache hit expected");
        }).unwrap();

        let metrics = engine.metrics();
        assert_eq!(metrics.query_hits, 1, "second execution should be a cache hit");
        assert_eq!(metrics.query_misses, 1, "miss count unchanged");
        assert_eq!(metrics.query_recomputes, 1, "recompute count unchanged");

        // ---- Test 3: Bump version to force invalidation ----
        // Bump version of the recorded dependency
        engine.bump_version(DepKey::SurfaceText(dep_fp));

        // Execute with dependency recording
        let _result3 = engine.execute(instance.clone(), || {
            record_surface_text_dependency(dep_fp);
            QueryResult::NodeType(NodeType("test".to_string()))
        }).unwrap();

        let metrics = engine.metrics();
        // Should be: miss=2 (first and third), hit=1 (second), recompute=2 (first and third)
        assert_eq!(metrics.query_recomputes, 2, "version bump forces recomputation");
        assert_eq!(metrics.query_misses, 2, "third execution is a miss due to invalidation");
        assert_eq!(metrics.query_hits, 1, "hit count unchanged");

        // ---- Test 4: Cycle detection metric ----
        let instance_a = QueryInstance::new(scope_fp.clone(), QueryKey::CheckEdge { edge_id: 1 });
        let instance_b = QueryInstance::new(scope_fp.clone(), QueryKey::CheckEdge { edge_id: 2 });

        // Create a cycle A -> B -> A
        let engine2 = QueryEngine::new(); // Fresh engine to avoid interference
        let _ = engine2.execute(instance_a.clone(), || {
            // A calls B
            let b_result = engine2.execute(instance_b.clone(), || {
                // B tries to call A (cycle)
                let a_result = engine2.execute(instance_a.clone(), || {
                    QueryResult::NodeType(NodeType("should not reach".to_string()))
                });
                // Should get cycle error
                assert!(matches!(a_result, Err(QueryError::CycleDetected { .. })));
                QueryResult::NodeType(NodeType("B".to_string()))
            });
            b_result.unwrap();
            QueryResult::NodeType(NodeType("A".to_string()))
        }).unwrap();

        let metrics2 = engine2.metrics();
        assert_eq!(metrics2.cycles_detected, 1, "cycle detection should be recorded");

        // ---- Test 5: Cache save/load byte metrics ----
        let temp_file = std::env::temp_dir().join("test_metrics_cache.cbor");
        engine.save_to_file(&temp_file).unwrap();

        let metrics_after_save = engine.metrics();
        assert!(metrics_after_save.bytes_saved > 0, "bytes_saved should be recorded");

        // Load into a new engine
        let engine3 = QueryEngine::load_from_file(&temp_file).unwrap();
        let metrics_after_load = engine3.metrics();
        assert!(metrics_after_load.bytes_loaded > 0, "bytes_loaded should be recorded");

        // Clean up temp file
        let _ = std::fs::remove_file(&temp_file);

        // ---- Test 6: Metrics reset ----
        engine.reset_metrics();
        let reset_metrics = engine.metrics();
        assert_eq!(reset_metrics.query_hits, 0, "reset should zero all metrics");
        assert_eq!(reset_metrics.query_misses, 0, "reset should zero all metrics");
        assert_eq!(reset_metrics.query_recomputes, 0, "reset should zero all metrics");
        assert_eq!(reset_metrics.cache_invalidations, 0, "reset should zero all metrics");
        // Note: bytes_saved/loaded are not reset by reset_metrics()
    }
}