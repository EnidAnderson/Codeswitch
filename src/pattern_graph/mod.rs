//! PatternGraph: authoritative pattern-defined hypergraph representation.
//!
//! This module implements the PatternGraph rewrite engine as specified in the
//! formal spec. PatternGraph is the authoritative internal representation for
//! pattern-indexed relations, with certified PortView projection for backward
//! compatibility with the existing port-typed hypergraph substrate.
//!
//! # Citations
//! - Pattern-defined hypergraphs: This specification
//! - Locally nameless representation: Charguéraud, "The locally nameless representation" (2012)
//! - First-order unification: Robinson, "A machine-oriented logic based on the resolution principle" (1965)
//!
//! # Maintenance Protocol
//!
//! To preserve the "0 corners cut" guarantee of deterministic behavior and collision resistance,
//! the following contract must be respected when modifying this module:
//!
//! ## Canonical Bytes Format
//! - If the canonical byte serialization format changes, you must:
//!   1. Bump the corresponding `DOMAIN_PATTERN_*` constant (and any downstream domains that incorporate it)
//!   2. Update the golden tests in `core::tests::test_canonical_bytes_golden` intentionally
//!
//! ## PortView Eligibility
//! - If PortView eligibility rules change, you must:
//!   1. Bump `PORTVIEW_ELIGIBILITY_POLICY_V*` constant
//!   2. Expect all PortView fingerprints to change (backward incompatible)
//!
//! ## Critical-Pair Enumeration
//! - If critical-pair enumeration semantics change, you must:
//!   1. Bump `CRITICAL_PAIR_POLICY_V*` constant
//!   2. Keep enumeration order-invariant (always sort by canonical key, not by hash iteration)
//!
//! ## Verification & Testing
//! - All release builds must run the same correctness checks as debug builds
//!   (see `fast_step_check` structural equality verification)
//! - CI must run `cargo test --release` to exercise release code paths
//! - Differential testing (fast path vs slow path) must be maintained
//!

pub mod constants;
pub mod core;
pub mod unification;
pub mod rewrite;
pub mod port_view;