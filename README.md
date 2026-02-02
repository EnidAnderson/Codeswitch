# Codeswitch: Resilient ω‑Hypergraph Rewriting Engine

**Codeswitch** is a unified, incremental rewriting engine for higher‑dimensional algebraic structures, built on ω‑hypergraphs with pattern‑based unification and deterministic caching.

## Name Origin

The term **“codeswitch”** is borrowed from Black feminist thought, where it describes the ability to move fluidly between different linguistic and cultural codes while maintaining integrity and resilience. In this context, Codeswitch refers to a rewriter that remains robust and adaptable under changes of lexical environment—preserving meaning while switching between different representational systems (doctrines, surface syntaxes, or semantic domains).

## Purpose & Relation to Mac Lane

Codeswitch implements the mathematical foundation needed for **Mac Lane’s coherence theorems** in a computational setting. It provides:

1. **ω‑Hypergraph Core** – A generalization of directed graphs where each hyperedge can have multiple sources and targets, following the Miyoshi–Tsujishita model of weak ω‑categories. This representation is sufficiently general to encode arbitrary **pattern‑graph relations** (see “Data Model” below).

2. **Doctrine‑Based Fast Paths** – Configurable operational modes (Globular, Linear, DAG, FullOmegaHypergraph) that enforce specific structural invariants, allowing efficient rewriting when stronger guarantees hold.

3. **Pattern‑Graph Rewriting** – A unification‑based rewriting engine where rewrite rules are expressed as patterns that match subgraphs, enabling declarative specification of type‑checking, normalization, and transformation rules.

4. **Incremental Query Engine** – A Salsa‑style memoization system with automatic dependency tracking, change‑based versioning, and persistent caching. Queries are pure functions over immutable inputs; the engine recomputes only what changed.

5. **Deterministic Fingerprinting** – Content‑based hashing with domain separation and Weisfeiler–Lehman refinement, ensuring that isomorphic graphs produce identical fingerprints regardless of construction order.

6. **Backward Compatibility** – Maintains compatibility with earlier hyperopetope, hypergraph, and hyperstonewall modules, providing a unified foundation for the JetSp kernel.

## Data Model: ω‑Hypergraphs as General Pattern Graphs

The core data structure is an **ω‑hypergraph**—a directed acyclic hypergraph where each hyperedge connects arbitrary sets of source nodes to arbitrary sets of target nodes. Despite the “ω” prefix (which historically indicates infinite‑dimensional higher categories), the representation is **sufficiently general to encode arbitrary pattern‑graph relations**.

### What Is Actually Constrained?

1. **Hyperedge shape**: A hyperedge is simply `(sources: Set<NodeId>, targets: Set<NodeId>)`.
   – Sources and targets may be empty (but not both).
   – No limit on the number of incident nodes.
   – No restriction on the dimensions of source/target nodes.

2. **Global invariant**: The hypergraph must remain **acyclic** (no directed cycles in the transitive closure of hyperedges). This is a sensible invariant for incremental rewriting and caching.

3. **No built‑in stratification**: Although nodes carry a `dim: usize` field (0‑cells, 1‑cells, …), **no validation** requires hyperedges to respect dimension boundaries. A hyperedge may connect a 0‑cell directly to a 2‑cell, or mix nodes of different dimensions in its source/target sets.

### How Do “Pattern Graphs” Fit?

A **pattern graph** is a hypergraph where edges represent arbitrary relations (e.g., typing constraints, rewriting rules, unification equations). In Codeswitch:

* Pattern‑graph relations are encoded directly as hyperedges.
* The `FullOmegaHypergraph` doctrine imposes **only** acyclicity and node‑existence checks—no further restrictions.
* Thus, any pattern‑graph relation that can be expressed as a directed acyclic hyperedge is representable **without reification tricks or auxiliary nodes**.

### Optional Constraints via Doctrines

If your application requires stronger guarantees, you can select a stricter doctrine:

* **`Globular`** – single source, single target per hyperedge (globular higher categories).
* **`Linear`** – linear chains (Git‑like history).
* **`Dag`** – arbitrary edges but still acyclic.
* **`FullOmegaHypergraph`** – the most general shape (arbitrary source/target sets).

These are **semantic choices**, not limitations of the underlying representation. You can start with `FullOmegaHypergraph` for arbitrary pattern‑graph work and later switch to a more restrictive doctrine if you need to enforce additional invariants.

### Summary

Codeswitch’s ω‑hypergraph core is **already a pattern‑graph representation**. The “ω‑hypergraph” terminology reflects its mathematical heritage, but the implementation is a general directed acyclic hypergraph capable of expressing arbitrary multi‑source/multi‑target relations. All dimension‑stratification, globularity, and boundary‑operator constraints are optional and enforced via the doctrine system, not hard‑wired into the data model.

## Core Abstractions

- **`Codeswitch<P>`** – The main ω‑hypergraph data structure, parameterized by node payload type `P`.
- **`Doctrine`** – A runtime‑configurable set of structural invariants (e.g., “edges must have single source and target” for Globular mode).
- **`Pattern`** / **`PatternMatch`** – Template subgraphs and their unifications against a host graph.
- **`RewriteTemplate`** – A pair of patterns (LHS → RHS) that can be applied to a graph.
- **`QueryEngine`** – Incremental memoization table with dependency tracking and version‑aware caching.
- **`ScopeFingerprint`** – Deterministic hash of a compilation scope, used as a coarse cache key.

## Example

### Simple globular edge (single source, single target)

```rust
use codeswitch::prelude::*;
use std::collections::HashSet;

let mut graph = Codeswitch::new();
let a = add_node(&mut graph, "node_a", 0, &Globular).unwrap();
let b = add_node(&mut graph, "node_b", 0, &Globular).unwrap();
add_edge(&mut graph, HashSet::from([a]), HashSet::from([b]), &Globular).unwrap();
```

### General hyperedge with multiple sources and targets

```rust
use codeswitch::prelude::*;
use std::collections::HashSet;

let mut graph = Codeswitch::new();
let n1 = add_node(&mut graph, "payload1", 0, &FullOmegaHypergraph).unwrap();
let n2 = add_node(&mut graph, "payload2", 1, &FullOmegaHypergraph).unwrap();  // different dimension
let n3 = add_node(&mut graph, "payload3", 0, &FullOmegaHypergraph).unwrap();
let n4 = add_node(&mut graph, "payload4", 2, &FullOmegaHypergraph).unwrap();

// Hyperedge connecting three sources to two targets, mixing dimensions
add_edge(
    &mut graph,
    HashSet::from([n1, n2, n3]),   // three sources, dimensions 0, 1, 0
    HashSet::from([n3, n4]),       // two targets, dimensions 0, 2
    &FullOmegaHypergraph,
).unwrap();
```

The second example demonstrates the full generality of the representation: hyperedges can connect arbitrary sets of nodes, regardless of their dimensions, as long as the overall hypergraph remains acyclic.

## Integration with Surface Syntax (Comrade Lisp)

Codeswitch is designed to be the backend for the new Comrade Lisp surface‑syntax module. The integration path is:

1. Surface syntax parses source text into an s‑expression AST.
2. Macros expand the AST into core forms (`begin`, `touch`, `def`, `rule`).
3. The elaborated core forms are translated into a `CoreBundleV0`.
4. The bundle is handed to `codeswitch_adapter`, which builds pattern graphs and executes queries.
5. The incremental query engine caches each phase, so editing a macro definition only recomputes downstream phases whose results actually changed.

## Performance Guarantees

- **Change‑Based Versioning** – Query versions increment only when the result fingerprint changes, preventing unnecessary recomputation.
- **Arena Allocation** – Graph nodes and edges are stored in contiguous arenas for cache‑friendly traversal.
- **Worklist Normalization** – Graph normalization uses iterative worklists instead of recursion.
- **Skip‑Serialization Optimization** – Empty diagnostic vectors are omitted from serialized cache files.

## Safety & Correctness

- **Cycle Detection** – The query engine detects dependency cycles before they can poison the cache.
- **Schema‑Versioned Cache** – Cache files include a format version and a schema hash; mismatches cause clear errors rather than silent corruption.
- **Deterministic Builds** – All fingerprints are computed from canonical byte representations, ensuring reproducibility across runs and compiler versions.

## References

- Miyoshi, Tsujishita. “ω‑hypergraphs and weak ω‑categories”, *Journal of Pure and Applied Algebra* (2003).
- Street, R. “The algebra of oriented simplexes”, *Journal of Pure and Applied Algebra* (1987) – polygraphs/n‑computads.
- Burroni, A. “Higher‑dimensional word problems with applications to higher‑dimensional rewriting” (1991).
- Lawvere, F.W. “Functorial semantics of algebraic theories” (1963) – doctrine concept.
- Mac Lane, S. *Categories for the Working Mathematician* (1971) – coherence theorems.

## License

Hippocratic License 3.0 (HL3)
