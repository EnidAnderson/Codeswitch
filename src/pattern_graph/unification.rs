//! Unification and matching for PatternGraph.
//!
//! This module will use the shared pattern unification functions from
//! `tcb_core::pattern` when available. For now, provides stubs.

use super::core::{HoleId, ResolvedPattern};
use std::collections::HashMap;

/// Unify two ResolvedPatterns, treating Hole(HoleId) as metavariables.
///
/// Returns a substitution map HoleId -> ResolvedPattern, or None if not unifiable.
///
/// This is a stub that will be replaced with the shared implementation.
pub fn unify_patterns(
    _a: &ResolvedPattern,
    _b: &ResolvedPattern,
) -> Option<HashMap<HoleId, ResolvedPattern>> {
    // TODO: Use shared unification from tcb_core::pattern
    None
}

/// Check if two patterns are unifiable (without computing substitution).
pub fn are_unifiable(a: &ResolvedPattern, b: &ResolvedPattern) -> bool {
    unify_patterns(a, b).is_some()
}