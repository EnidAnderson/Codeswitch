//! Centralized domain separation tags and policy identifiers.
//!
//! All hash domains and policy version IDs used in PatternGraph must be defined here
//! to avoid accidental reuse and ensure consistent versioning.

/// Domain for hashing PatternGraph patterns (v0, binder-free).
pub const DOMAIN_PATTERN_V0: &[u8] = b"PATTERN_V0";

/// Domain for hashing pattern substitutions (v0).
pub const DOMAIN_PATTERN_SUBST_V0: &[u8] = b"PATTERN_SUBST_V0";

/// Domain for rule set fingerprints (v0).
pub const DOMAIN_RULE_SET_V0: &[u8] = b"RULE_SET_V0";

/// Domain for critical pair set fingerprints (v0).
pub const DOMAIN_CRITICAL_PAIR_SET_V0: &[u8] = b"CRITICAL_PAIR_SET_V0";

/// Domain for combined doctrine fingerprints (v0).
pub const DOMAIN_DOCTRINE_FP_V0: &[u8] = b"DOCTRINE_FP_V0";

/// Critical pair enumeration policy version 1.
///
/// This policy defines:
/// - Which fragment of patterns is considered for critical pairs
/// - Hole-hole unification tie-breaking rule (smaller ID wins)
/// - Position traversal order (deterministic preorder)
/// - Pruning of trivial pairs (equal results)
/// - Exclusion of root overlaps when container_is_first == true to avoid duplicates
pub const CRITICAL_PAIR_POLICY_V1: &[u8] = b"CRITICAL_PAIR_POLICY_V1";

/// PortView eligibility policy version 1.
///
/// This policy defines the syntactic fragment that can be projected to PortView.
/// Currently: binder-free, binary compose, limited App arity, no Reject/InDoctrine.
pub const PORTVIEW_ELIGIBILITY_POLICY_V1: &[u8] = b"PORTVIEW_ELIGIBILITY_POLICY_V1";