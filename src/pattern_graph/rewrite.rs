//! Pattern-native rewriting engine.
//!
//! Implements rewriting on PatternGraph using unification and subposition traversal.
//! Will use shared pattern matching functions when available.

use super::constants;
use super::core::{HoleId, PatternGraph, PatternRule, ResolvedPattern, unify_patterns, iter_positions, get_subpattern, replace_subpattern, resolve, encode_term_path, decode_term_path};
use super::port_view::{project_to_portview, check_pattern_eligible};
use crate::fingerprint::HashValue;
use std::collections::BTreeMap;

/// Deterministically hash a substitution map.
pub(crate) fn hash_substitution(sigma: &BTreeMap<HoleId, ResolvedPattern>) -> HashValue {
    // Serialize substitution deterministically:
    // For each (hole, pattern) in sorted order (BTreeMap guarantees order):
    // - hole ID as u64 LE
    // - pattern hash (32 bytes)
    let mut data = Vec::new();
    for (hole, pattern) in sigma {
        data.extend_from_slice(&hole.0.to_le_bytes());
        data.extend_from_slice(pattern.hash().as_bytes());
    }
    HashValue::hash_with_domain(constants::DOMAIN_PATTERN_SUBST_V0, &data)
}

/// Execution mode of a rewrite step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewriteMode {
    /// Step executed natively in PatternGraph.
    Native,
    /// Step executed via PortView fast path.
    PortViewFast {
        /// Hash of the PortView used for projection.
        portview_hash: HashValue,
        /// Hash of the port engine step (optional, for verification).
        port_step_hash: Option<HashValue>,
    },
}

/// A rewrite step applied to a PatternGraph.
#[derive(Debug, Clone)]
pub struct PatternRewriteStep {
    /// Rule identifier.
    pub rule_id: u64,
    /// Position where the rewrite was applied (encoded path).
    pub position: Vec<u32>,
    /// Substitution applied (canonical BTreeMap for deterministic serialization).
    pub substitution: BTreeMap<HoleId, ResolvedPattern>,
    /// Hash of PatternGraph before the step.
    pub before_hash: HashValue,
    /// Hash of PatternGraph after the step.
    pub after_hash: HashValue,
    /// Execution mode.
    pub mode: RewriteMode,
}

/// Apply a rule at a specific position in a PatternGraph.
///
/// Returns the modified PatternGraph or an error.
pub fn apply_rule_at_position(
    graph: &PatternGraph,
    rule: &PatternRule,
    position: &[u32],
) -> Result<PatternGraph, RewriteError> {
    // Decode position to TermPath
    let term_path = super::core::decode_term_path(position)
        .ok_or(RewriteError::InvalidPosition)?;

    // Get subpattern at position
    let sub = super::core::get_subpattern(graph.pattern(), &term_path)
        .ok_or(RewriteError::InvalidPosition)?;

    // Unify rule LHS with subpattern
    let sigma = super::core::unify_patterns(&rule.lhs_pattern, sub)
        .ok_or(RewriteError::UnificationFailed)?;

    // Apply substitution to RHS (TODO: hole correspondence)
    // For v0.1, assume identity mapping (same hole IDs)
    let rhs_substituted = rule.rhs_pattern.apply_substitution(&sigma);

    // Replace subpattern at position
    let new_pattern = super::core::replace_subpattern(
        graph.pattern().clone(),
        &term_path,
        rhs_substituted,
    ).map_err(|_| RewriteError::InvalidPosition)?;

    // Create new PatternGraph with same boundary
    let new_graph = super::core::PatternGraph::new(
        new_pattern,
        graph.boundary().clone(),
    );

    Ok(new_graph)
}

/// Replay a recorded rewrite step and verify correctness.
///
/// Returns the resulting PatternGraph if the step replays correctly.
pub fn replay_step(
    step: &PatternRewriteStep,
    rule: &PatternRule,
    before: &PatternGraph,
) -> Result<PatternGraph, RewriteError> {
    // Verify before hash matches
    if before.hash() != step.before_hash {
        return Err(RewriteError::HashMismatch);
    }

    // Replay according to mode
    match &step.mode {
        RewriteMode::Native => {
            // Apply rule natively
            let after = apply_rule_at_position(before, rule, &step.position)?;
            if after.hash() != step.after_hash {
                return Err(RewriteError::HashMismatch);
            }
            Ok(after)
        }
        RewriteMode::PortViewFast { portview_hash, port_step_hash: _ } => {
            // Project before to PortView
            let portview = project_to_portview(before)
                .ok_or(RewriteError::PortViewProjectionFailed)?;
            // Verify portview hash matches
            if portview.portview_hash != *portview_hash {
                return Err(RewriteError::HashMismatch);
            }
            // Verify the PortView is correct
            portview.verify(before)
                .map_err(|_| RewriteError::PortViewVerificationFailed)?;

            // TODO: Run port engine step (for now, just verify native step is admissible)
            // For v0.1, we'll just re-run native step and ensure after is also eligible
            let after = apply_rule_at_position(before, rule, &step.position)?;
            if after.hash() != step.after_hash {
                return Err(RewriteError::HashMismatch);
            }
            // Verify after is also eligible (optional)
            // ...

            Ok(after)
        }
    }
}

/// Check if a native rewrite step can be executed via PortView fast path.
///
/// Returns true if both before and after graphs are eligible for PortView,
/// their projections verify, and the step itself is compatible with PortView
/// (position maps to an eligible subpattern, substitution preserves eligibility).
pub fn fast_step_check(
    step: &PatternRewriteStep,
    rule: &PatternRule,
    before: &PatternGraph,
    after: &PatternGraph,
) -> bool {
    // Both must be eligible
    if !super::port_view::is_portview_eligible(before) ||
       !super::port_view::is_portview_eligible(after) {
        return false;
    }
    // Projections must exist and verify
    let portview_before = match super::port_view::project_to_portview(before) {
        Some(pv) => pv,
        None => return false,
    };
    let portview_after = match super::port_view::project_to_portview(after) {
        Some(pv) => pv,
        None => return false,
    };
    // Verify both projections
    if portview_before.verify(before).is_err() || portview_after.verify(after).is_err() {
        return false;
    }

    // Decode position and check subpattern eligibility
    let term_path = match decode_term_path(&step.position) {
        Some(path) => path,
        None => return false,
    };
    let subpattern = match get_subpattern(before.pattern(), &term_path) {
        Some(sub) => sub,
        None => return false,
    };
    if !check_pattern_eligible(subpattern) {
        return false;
    }

    // Check that the substitution maps holes to eligible patterns
    for pattern in step.substitution.values() {
        if !check_pattern_eligible(pattern) {
            return false;
        }
    }

    // Apply substitution to RHS and check eligibility of result
    let rhs_substituted = rule.rhs_pattern.apply_substitution(&step.substitution);
    if !check_pattern_eligible(&rhs_substituted) {
        return false;
    }

    // Verify that the step replays correctly natively
    match replay_step(step, rule, before) {
        Ok(replayed) => {
            let replayed_hash = replayed.hash();
            let after_hash = after.hash();
            if replayed_hash != after_hash {
                return false;
            }
            // Hashes match; verify structural equality to guard against collisions
            debug_assert_eq!(replayed, *after, "hash collision or bug in replay");
            replayed == *after
        }
        Err(_) => false,
    }
}

/// Find all applicable rule positions in a PatternGraph.
pub fn find_rule_positions(
    _graph: &PatternGraph,
    _rule: &PatternRule,
) -> Vec<Vec<u32>> {
    // TODO: Implement using shared position enumeration
    Vec::new()
}
/// Critical pair between two pattern rules.
#[derive(Debug, Clone)]
pub struct CriticalPair {
    /// Position where the subpattern rule overlaps the container rule (encoded path).
    /// The position is relative to the container rule's LHS.
    pub position: Vec<u32>,
    /// Canonical unifier substitution (deterministic BTreeMap).
    pub substitution: BTreeMap<HoleId, ResolvedPattern>,
    /// Hash of the unifier substitution (redundant, for quick comparison).
    pub unifier_hash: HashValue,
    /// Hash of the term after applying subpattern rule at position.
    pub left_result_hash: HashValue,
    /// First 16 bytes of canonical bytes of left result (collision guard).
    pub left_result_guard: [u8; 16],
    /// Hash of the term after applying container rule at root.
    pub right_result_hash: HashValue,
    /// First 16 bytes of canonical bytes of right result (collision guard).
    pub right_result_guard: [u8; 16],
    /// Hash of the overlap instance (optional, for debugging).
    pub overlap_instance_hash: Option<HashValue>,
    /// True if container rule is the first rule (lhs1/rhs1), false if second rule (lhs2/rhs2).
    pub container_is_first: bool,
}

impl CriticalPair {
    /// Replay this critical pair and verify that the results match the stored hashes.
    ///
    /// Given the two rules (L1 → R1) and (L2 → R2), verifies that:
    /// 1. The substitution unifies the subpattern rule's LHS with a subpattern of the container rule's LHS at position.
    /// 2. Applying subpattern rule at position yields term with `left_result_hash`.
    /// 3. Applying container rule at root yields term with `right_result_hash`.
    /// 4. The two results are different (non-trivial critical pair).
    pub fn replay(
        &self,
        lhs1: &ResolvedPattern,
        rhs1: &ResolvedPattern,
        lhs2: &ResolvedPattern,
        rhs2: &ResolvedPattern,
    ) -> Result<(), RewriteError> {
        // Determine which rule is container and which is subpattern
        let (container_lhs, container_rhs, sub_lhs, sub_rhs) = if self.container_is_first {
            (lhs1, rhs1, lhs2, rhs2)
        } else {
            (lhs2, rhs2, lhs1, rhs1)
        };

        // Decode position
        let term_path = decode_term_path(&self.position)
            .ok_or(RewriteError::InvalidPosition)?;

        // Verify substitution matches stored hash
        let computed_unifier_hash = hash_substitution(&self.substitution);
        if computed_unifier_hash != self.unifier_hash {
            return Err(RewriteError::HashMismatch);
        }

        // Check that sub_lhs unifies with subpattern at position in container_lhs
        let sub = get_subpattern(container_lhs, &term_path)
            .ok_or(RewriteError::InvalidPosition)?;
        let sigma = unify_patterns(sub_lhs, sub)
            .ok_or(RewriteError::UnificationFailed)?;

        // The computed substitution should be equivalent to stored substitution
        // For simplicity, compare hash (should match if unification is deterministic)
        let sigma_hash = hash_substitution(&sigma);
        if sigma_hash != self.unifier_hash {
            return Err(RewriteError::HashMismatch);
        }

        // Compute overlapped term T = container_lhsσ
        let t = resolve(container_lhs, &sigma);

        // Apply subpattern rule at position: replace subpattern with sub_rhsσ
        let sub_rhs_sigma = resolve(sub_rhs, &sigma);
        let left_result = replace_subpattern(t.clone(), &term_path, sub_rhs_sigma)
            .map_err(|_| RewriteError::InvalidPosition)?;
        if left_result.hash() != self.left_result_hash {
            return Err(RewriteError::HashMismatch);
        }
        // Guard against hash collisions
        if left_result.guard_bytes() != self.left_result_guard {
            return Err(RewriteError::HashMismatch);
        }

        // Apply container rule at root: container_rhsσ
        let right_result = resolve(container_rhs, &sigma);
        if right_result.hash() != self.right_result_hash {
            return Err(RewriteError::HashMismatch);
        }
        // Guard against hash collisions
        if right_result.guard_bytes() != self.right_result_guard {
            return Err(RewriteError::HashMismatch);
        }

        // Verify critical pair is non-trivial (results differ)
        if left_result == right_result {
            return Err(RewriteError::UnificationFailed); // trivial pair shouldn't be reported
        }

        // Optional: verify overlap instance hash
        if let Some(overlap_hash) = self.overlap_instance_hash {
            if t.hash() != overlap_hash {
                return Err(RewriteError::HashMismatch);
            }
        }

        Ok(())
    }
}

/// Enumerate critical pairs between two pattern rules.
///
/// Given two rules (L1 → R1) and (L2 → R2), returns all critical pairs
/// where L1 overlaps with a subpattern of L2 (including root).
///
/// Each pair includes position, unifier hash, and result hashes for replay.
pub fn enumerate_critical_pairs(
    lhs1: &ResolvedPattern,
    rhs1: &ResolvedPattern,
    lhs2: &ResolvedPattern,
    rhs2: &ResolvedPattern,
) -> Vec<CriticalPair> {
    let mut pairs = Vec::new();

    // Helper: enumerate overlaps where lhs_a is subpattern of lhs_b
    let enumerate_overlaps = |lhs_a: &ResolvedPattern, rhs_a: &ResolvedPattern,
                              lhs_b: &ResolvedPattern, rhs_b: &ResolvedPattern| {
        let mut local_pairs = Vec::new();
        for pos in iter_positions(lhs_b) {
            if let Some(sub) = get_subpattern(lhs_b, &pos) {
                if let Some(sigma) = unify_patterns(lhs_a, sub) {
                    // Overlapped term T = lhs_bσ
                    let t = resolve(lhs_b, &sigma);

                    // Apply rule A at position pos: replace subpattern with rhs_aσ
                    let rhs_a_sigma = resolve(rhs_a, &sigma);
                    match replace_subpattern(t.clone(), &pos, rhs_a_sigma) {
                        Ok(result_a) => {
                            // Apply rule B at root: result_b = rhs_bσ
                            let result_b = resolve(rhs_b, &sigma);

                            if result_a != result_b {
                                // substitution is already canonical BTreeMap
                                let substitution = sigma;
                                let unifier_hash = hash_substitution(&substitution);
                                let left_result_hash = result_a.hash();
                                let right_result_hash = result_b.hash();
                                let overlap_instance_hash = Some(t.hash());
                                let encoded_position = encode_term_path(&pos);

                                let left_result_guard = result_a.guard_bytes();
                                let right_result_guard = result_b.guard_bytes();
                                local_pairs.push(CriticalPair {
                                    position: encoded_position,
                                    substitution,
                                    unifier_hash,
                                    left_result_hash,
                                    left_result_guard,
                                    right_result_hash,
                                    right_result_guard,
                                    overlap_instance_hash,
                                    container_is_first: false, // container is lhs_b (second rule)
                                });
                            }
                        }
                        Err(_) => continue,
                    }
                }
            }
        }
        local_pairs
    };

    // Overlaps where lhs1 is subpattern of lhs2
    pairs.extend(enumerate_overlaps(lhs1, rhs1, lhs2, rhs2));

    // Overlaps where lhs2 is subpattern of lhs1 (excluding root overlap to avoid duplicate)
    // Root overlap already captured when lhs1 is subpattern of lhs2 at root.
    // So we skip position = root (empty path) in lhs1.
    for pos in iter_positions(lhs1) {
        if pos.steps.is_empty() {
            continue; // skip root
        }
        if let Some(sub) = get_subpattern(lhs1, &pos) {
            if let Some(sigma) = unify_patterns(lhs2, sub) {
                let t = resolve(lhs1, &sigma);
                let rhs2_sigma = resolve(rhs2, &sigma);
                match replace_subpattern(t.clone(), &pos, rhs2_sigma) {
                    Ok(result_left) => {
                        // result_left is from applying rule2 (lhs2->rhs2) at position pos
                        let result_right = resolve(rhs1, &sigma);
                        // result_right is from applying rule1 (lhs1->rhs1) at root
                        if result_left != result_right {
                            // substitution is already canonical BTreeMap
                            let substitution = sigma;
                            let unifier_hash = hash_substitution(&substitution);
                            let left_result_hash = result_left.hash();
                            let right_result_hash = result_right.hash();
                            let left_result_guard = result_left.guard_bytes();
                            let right_result_guard = result_right.guard_bytes();
                            let overlap_instance_hash = Some(t.hash());
                            let encoded_position = encode_term_path(&pos);

                            pairs.push(CriticalPair {
                                position: encoded_position,
                                substitution,
                                unifier_hash,
                                left_result_hash,
                                left_result_guard,
                                right_result_hash,
                                right_result_guard,
                                overlap_instance_hash,
                                container_is_first: true, // container is lhs1 (first rule)
                            });
                        }
                    }
                    Err(_) => continue,
                }
            }
        }
    }

    pairs
}

/// Compute all critical pairs between a set of pattern rules.
///
/// For each unordered pair of rules (including self-pairs), enumerates critical pairs
/// where the left-hand sides overlap. Returns a deterministic vector of critical pairs.
pub fn critical_pairs_for_rules(rules: &[PatternRule]) -> Vec<CriticalPair> {
    let mut all_pairs = Vec::new();
    for i in 0..rules.len() {
        for j in i..rules.len() { // include self-pair when i == j
            let rule_i = &rules[i];
            let rule_j = &rules[j];
            let pairs = enumerate_critical_pairs(
                &rule_i.lhs_pattern,
                &rule_i.rhs_pattern,
                &rule_j.lhs_pattern,
                &rule_j.rhs_pattern,
            );
            all_pairs.extend(pairs);
        }
    }
    // Sort by deterministic key to ensure reproducible output
    all_pairs.sort_by(|a, b| {
        a.unifier_hash
            .cmp(&b.unifier_hash)
            .then_with(|| a.left_result_hash.cmp(&b.left_result_hash))
            .then_with(|| a.right_result_hash.cmp(&b.right_result_hash))
            .then_with(|| a.position.cmp(&b.position))
    });
    all_pairs
}

/// Compute a fingerprint for a set of pattern rules.
///
/// The fingerprint incorporates both the rule hashes and the critical pairs between them,
/// ensuring that any change to the rule set or its coherence properties changes the fingerprint.
/// Also commits to the critical‑pair enumeration policy and PortView eligibility policy.
pub fn rule_set_fingerprint(rules: &[PatternRule]) -> HashValue {
    // Sort rules by their hash for deterministic ordering
    let mut sorted_rules: Vec<&PatternRule> = rules.iter().collect();
    sorted_rules.sort_by_key(|r| r.rule_hash);

    // Hash of rule hashes (includes policy version)
    let mut data = Vec::new();
    data.extend_from_slice(constants::CRITICAL_PAIR_POLICY_V1);
    data.extend_from_slice(constants::PORTVIEW_ELIGIBILITY_POLICY_V1);
    for rule in sorted_rules {
        data.extend_from_slice(rule.rule_hash.as_bytes());
    }
    let rules_hash = HashValue::hash_with_domain(constants::DOMAIN_RULE_SET_V0, &data);

    // Hash of critical pairs (already includes policy)
    let pairs = critical_pairs_for_rules(rules);
    let pairs_hash = critical_pair_set_fingerprint(&pairs);

    // Combine both hashes
    let mut combined = Vec::new();
    combined.extend_from_slice(rules_hash.as_bytes());
    combined.extend_from_slice(pairs_hash.as_bytes());
    HashValue::hash_with_domain(constants::DOMAIN_DOCTRINE_FP_V0, &combined)
}

/// Compute a fingerprint for a set of critical pairs.
///
/// The fingerprint is deterministic and depends on the unifier hashes,
/// result hashes, and positions of each pair, plus the enumeration policy.
pub fn critical_pair_set_fingerprint(pairs: &[CriticalPair]) -> HashValue {
    // Pairs are already sorted (as returned by critical_pairs_for_rules)
    let mut data = Vec::new();
    // Include policy version to commit to enumeration assumptions
    data.extend_from_slice(constants::CRITICAL_PAIR_POLICY_V1);
    for pair in pairs {
        data.extend_from_slice(pair.unifier_hash.as_bytes());
        data.extend_from_slice(pair.left_result_hash.as_bytes());
        data.extend_from_slice(pair.right_result_hash.as_bytes());
        data.extend_from_slice(&(pair.position.len() as u64).to_le_bytes());
        for &coord in &pair.position {
            data.extend_from_slice(&coord.to_le_bytes());
        }
    }
    HashValue::hash_with_domain(constants::DOMAIN_CRITICAL_PAIR_SET_V0, &data)
}

/// Error type for pattern rewriting.
#[derive(Debug, Clone)]
pub enum RewriteError {
    /// Rule does not match at given position.
    NoMatch,
    /// Substitution failed.
    UnificationFailed,
    /// Position is invalid.
    InvalidPosition,
    /// Side condition not satisfied.
    SideConditionFailed,
    /// Not yet implemented.
    NotImplemented,
    /// Hash mismatch during replay.
    HashMismatch,
    /// PortView projection failed.
    PortViewProjectionFailed,
    /// PortView verification failed.
    PortViewVerificationFailed,
    /// Port step mismatch.
    PortStepMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pattern_graph::core::{HoleId, GeneratorId, ConstructorId, ResolvedPattern};

    #[test]
    fn test_critical_pairs_simple() {
        // Create simple patterns
        let hole1 = ResolvedPattern::hole(HoleId(1));
        let hole2 = ResolvedPattern::hole(HoleId(2));
        let gen_a = ResolvedPattern::generator(GeneratorId(100));
        let gen_b = ResolvedPattern::generator(GeneratorId(200));

        // Rule1: hole1 -> gen_a
        // Rule2: hole2 -> gen_b
        // Holes unify (hole-hole unification), so there is an overlap
        let pairs = enumerate_critical_pairs(&hole1, &gen_a, &hole2, &gen_b);
        // Should have at least one critical pair: overlapped term is hole (hole1 or hole2)
        // After unification, substitution maps larger hole ID to smaller.
        // Let's just assert we got some pairs.
        assert!(!pairs.is_empty());

        // Rule with generators that don't unify: should have no overlap
        let pairs = enumerate_critical_pairs(&gen_a, &gen_a, &gen_b, &gen_b);
        assert!(pairs.is_empty());

        // Rule3: hole1 -> hole1 (identity) overlaps with itself at root
        let pairs = enumerate_critical_pairs(&hole1, &hole1, &hole1, &hole1);
        // Should produce trivial pair (hole1, hole1) but we filter out equal pairs
        // So empty
        assert!(pairs.is_empty());
    }

    #[test]
    fn test_critical_pairs_overlap() {
        // Rule1: f(hole1) -> g(hole1)
        // Rule2: hole1 -> a
        // Overlap: hole1 unifies with subpattern hole1 inside f(hole1)
        let hole1 = ResolvedPattern::hole(HoleId(1));
        let gen_a = ResolvedPattern::generator(GeneratorId(100));
        let gen_f = ConstructorId(500);
        let gen_g = ConstructorId(600);

        let lhs1 = ResolvedPattern::app(gen_f, vec![hole1.clone()]);
        let rhs1 = ResolvedPattern::app(gen_g, vec![hole1.clone()]);
        let lhs2 = hole1.clone();
        let rhs2 = gen_a.clone();

        let pairs = enumerate_critical_pairs(&lhs1, &rhs1, &lhs2, &rhs2);
        // Expect at least one critical pair
        // The overlapped term is f(a) (since hole1 -> a)
        // Applying rule1: f(a) -> g(a)
        // Applying rule2 at root: f(hole1) doesn't match because root is f, not hole1
        // Actually rule2 applies at subposition (position 0) because hole1 is inside f.
        // Our algorithm should find overlap where lhs2 (hole1) unifies with subpattern of lhs1 (the hole1 inside f).
        // That's position [AppArg(0)].
        // Then compute critical pair.
        // We'll just assert non-empty.
        assert!(!pairs.is_empty());
    }

    #[test]
    fn test_critical_pairs_missed_overlap() {
        // Test that unification treats holes as metavariables, not constants.
        // lhs1: f(hole1)
        // lhs2: g(hole2, f(hole3)) where hole3 unifies with hole1 (different IDs)
        // Overlap at subposition [ComposeIndex(1), AppArg(0)] (the hole3 inside f)
        let hole1 = ResolvedPattern::hole(HoleId(1));
        let hole2 = ResolvedPattern::hole(HoleId(2));
        let hole3 = ResolvedPattern::hole(HoleId(3));
        let op_f = ConstructorId(100);
        let op_g = ConstructorId(200);

        let lhs1 = ResolvedPattern::app(op_f, vec![hole1.clone()]);
        let rhs1 = ResolvedPattern::app(op_f, vec![ResolvedPattern::generator(GeneratorId(500))]);
        let lhs2 = ResolvedPattern::app(op_g, vec![hole2.clone(), ResolvedPattern::app(op_f, vec![hole3.clone()])]);
        let rhs2 = ResolvedPattern::app(op_g, vec![ResolvedPattern::generator(GeneratorId(600)), ResolvedPattern::generator(GeneratorId(700))]);

        let pairs = enumerate_critical_pairs(&lhs1, &rhs1, &lhs2, &rhs2);
        // Should find at least one overlap where hole1 unifies with hole3 (different IDs)
        assert!(!pairs.is_empty(), "Expected overlap between structural pattern and hole");
    }

    #[test]
    fn test_apply_substitution() {
        use std::collections::BTreeMap;
        let hole1 = ResolvedPattern::hole(HoleId(1));
        let gen_a = ResolvedPattern::generator(GeneratorId(100));
        let pattern = ResolvedPattern::app(ConstructorId(500), vec![hole1.clone()]);
        let mut subst = BTreeMap::new();
        subst.insert(HoleId(1), gen_a.clone());
        let result = pattern.apply_substitution(&subst);
        // Should be app(500, [gen_a])
        match result {
            ResolvedPattern::App { op, args } => {
                assert_eq!(op, ConstructorId(500));
                assert_eq!(args.len(), 1);
                assert_eq!(args[0], gen_a);
            }
            _ => panic!("expected App"),
        }
    }

    #[test]
    fn test_replay_step_simple() {
        use super::*;
        use crate::pattern_graph::core::{PatternId, HoleCorrespondence, PatternBoundary, encode_term_path, TermPath};
        use std::collections::BTreeMap;

        // Create a simple rule: hole1 -> generator(100)
        let lhs = ResolvedPattern::hole(HoleId(1));
        let rhs = ResolvedPattern::generator(GeneratorId(100));
        let rule = PatternRule {
            lhs_id: PatternId(1),
            rhs_id: PatternId(2),
            lhs_pattern: lhs.clone(),
            rhs_pattern: rhs.clone(),
            hole_corr: HoleCorrespondence {},
            side_conditions: Vec::new(),
            rule_hash: HashValue::zero(), // dummy
        };

        // Create a pattern graph: hole1 at root, boundary (0,1)
        let pattern = lhs.clone();
        let boundary = PatternBoundary::with_arity(0, 1);
        let before = PatternGraph::new(pattern, boundary);
        let before_hash = before.hash();

        // Apply rule at root position (empty path)
        let position = encode_term_path(&TermPath { steps: Vec::new() });
        let after = apply_rule_at_position(&before, &rule, &position).expect("apply should succeed");
        let after_hash = after.hash();

        // Create a step in Native mode
        // Unification substitution is empty (hole1 matches hole1)
        let substitution = BTreeMap::new();
        let step = PatternRewriteStep {
            rule_id: 1,
            position: position.clone(),
            substitution,
            before_hash,
            after_hash,
            mode: RewriteMode::Native,
        };

        // Replay step
        let replayed = replay_step(&step, &rule, &before).expect("replay should succeed");
        assert_eq!(replayed.hash(), after_hash);
        assert_eq!(replayed.pattern(), &rhs);
    }

    #[test]
    fn test_critical_pair_replay() {
        use crate::pattern_graph::core::{HoleId, GeneratorId, ConstructorId};
        use super::hash_substitution;

        // Rule1: f(hole1) -> g(hole1)
        // Rule2: hole1 -> a
        let hole1 = ResolvedPattern::hole(HoleId(1));
        let gen_a = ResolvedPattern::generator(GeneratorId(100));
        let gen_f = ConstructorId(500);
        let gen_g = ConstructorId(600);

        let lhs1 = ResolvedPattern::app(gen_f, vec![hole1.clone()]);
        let rhs1 = ResolvedPattern::app(gen_g, vec![hole1.clone()]);
        let lhs2 = hole1.clone();
        let rhs2 = gen_a.clone();

        let pairs = enumerate_critical_pairs(&lhs1, &rhs1, &lhs2, &rhs2);
        assert!(!pairs.is_empty(), "should have at least one critical pair");

        for pair in pairs {
            // Replay the critical pair
            let result = pair.replay(&lhs1, &rhs1, &lhs2, &rhs2);
            assert!(result.is_ok(), "critical pair should replay successfully: {:?}", result);

            // Verify that left and right result hashes are different (non-trivial)
            assert_ne!(pair.left_result_hash, pair.right_result_hash, "critical pair should be non-trivial");

            // Verify substitution hash matches computed hash
            let computed_hash = hash_substitution(&pair.substitution);
            assert_eq!(pair.unifier_hash, computed_hash, "unifier hash mismatch");
        }
    }

    #[test]
    fn test_critical_pair_overlap_at_hole_site_with_expansion() {
        use crate::pattern_graph::core::{HoleId, ConstructorId, decode_term_path, encode_term_path, get_subpattern, ResolvedPattern, TermPath, PathStep};
        use super::hash_substitution;
        use super::enumerate_critical_pairs;

        // Container rule: f(hole1) -> h(hole1)
        // Subpattern rule: g(hole2) -> k(hole2)
        // Overlap at hole site: hole1 expands to g(hole2) under substitution
        let hole1 = ResolvedPattern::hole(HoleId(1));
        let hole2 = ResolvedPattern::hole(HoleId(2));
        let gen_f = ConstructorId(500);
        let gen_g = ConstructorId(600);
        let gen_h = ConstructorId(700);
        let gen_k = ConstructorId(800);

        let lhs1 = ResolvedPattern::app(gen_f, vec![hole1.clone()]);
        let rhs1 = ResolvedPattern::app(gen_h, vec![hole1.clone()]);
        let lhs2 = ResolvedPattern::app(gen_g, vec![hole2.clone()]);
        let rhs2 = ResolvedPattern::app(gen_k, vec![hole2.clone()]);

        // Enumerate critical pairs where lhs2 overlaps with a subpattern of lhs1
        let pairs = enumerate_critical_pairs(&lhs1, &rhs1, &lhs2, &rhs2);
        // Should find at least one overlap where lhs2 unifies with hole1 (position [AppArg(0)])
        assert!(!pairs.is_empty(), "should have at least one critical pair");

        for pair in pairs {
            // Verify position is defined in container LHS (structural)
            // Position should be [AppArg(0)] (encoded)
            let term_path = decode_term_path(&pair.position)
                .expect("position should decode");
            // Verify position is exactly AppArg(0)
            let expected_path = encode_term_path(&TermPath { steps: vec![PathStep::AppArg(0)] });
            assert_eq!(pair.position, expected_path, "position should be AppArg(0)");
            // Check that this position exists in lhs1 (container LHS)
            let sub = get_subpattern(&lhs1, &term_path)
                .expect("position should be valid in container LHS");
            // The subpattern should be hole1 (or something that unifies with lhs2)
            assert!(matches!(sub, ResolvedPattern::Hole(_)), "position should point to a hole");
            assert_eq!(sub, &hole1, "position should point to hole1");

            // Replay the critical pair
            let result = pair.replay(&lhs1, &rhs1, &lhs2, &rhs2);
            assert!(result.is_ok(), "critical pair should replay successfully: {:?}", result);

            // Verify substitution hash matches computed hash
            let computed_hash = hash_substitution(&pair.substitution);
            assert_eq!(pair.unifier_hash, computed_hash, "unifier hash mismatch");

            // Verify that left and right result hashes are different (non-trivial)
            assert_ne!(pair.left_result_hash, pair.right_result_hash, "critical pair should be non-trivial");
        }
    }

    #[test]
    fn test_rule_set_fingerprint() {
        use crate::pattern_graph::core::{PatternId, HoleCorrespondence, HoleId, GeneratorId, ConstructorId};
        use crate::fingerprint::HashValue;

        // Create two simple rules
        let hole1 = ResolvedPattern::hole(HoleId(1));
        let gen_a = ResolvedPattern::generator(GeneratorId(100));
        let gen_f = ConstructorId(500);
        let gen_g = ConstructorId(600);

        let lhs1 = ResolvedPattern::app(gen_f, vec![hole1.clone()]);
        let rhs1 = ResolvedPattern::app(gen_g, vec![hole1.clone()]);
        let lhs2 = hole1.clone();
        let rhs2 = gen_a.clone();

        let rule1 = PatternRule {
            lhs_id: PatternId(1),
            rhs_id: PatternId(2),
            lhs_pattern: lhs1.clone(),
            rhs_pattern: rhs1.clone(),
            hole_corr: HoleCorrespondence {},
            side_conditions: Vec::new(),
            rule_hash: HashValue::hash_with_domain(b"RULE_TEST", b"rule1"),
        };
        let rule2 = PatternRule {
            lhs_id: PatternId(3),
            rhs_id: PatternId(4),
            lhs_pattern: lhs2.clone(),
            rhs_pattern: rhs2.clone(),
            hole_corr: HoleCorrespondence {},
            side_conditions: Vec::new(),
            rule_hash: HashValue::hash_with_domain(b"RULE_TEST", b"rule2"),
        };

        let rules = vec![rule1.clone(), rule2.clone()];
        let fp1 = rule_set_fingerprint(&rules);

        // Fingerprint should be deterministic
        let fp2 = rule_set_fingerprint(&rules);
        assert_eq!(fp1, fp2, "fingerprint should be deterministic");

        // Changing rule order should not affect fingerprint (sorted by hash)
        let rules_reversed = vec![rules[1].clone(), rules[0].clone()];
        let fp3 = rule_set_fingerprint(&rules_reversed);
        assert_eq!(fp1, fp3, "fingerprint should be order-invariant");

        // Adding a duplicate rule should change fingerprint (different rule hash)
        let mut rules_dup = rules.clone();
        rules_dup.push(rules[0].clone());
        let fp4 = rule_set_fingerprint(&rules_dup);
        assert_ne!(fp1, fp4, "adding duplicate rule changes fingerprint");

        // Critical pairs should be included in fingerprint
        // Modify rule2's RHS slightly (different hash), fingerprint should change
        let mut rule2_mod = rule2.clone();
        rule2_mod.rule_hash = HashValue::hash_with_domain(b"RULE_TEST", b"rule2_mod");
        let rules_mod = vec![rule1.clone(), rule2_mod];
        let fp5 = rule_set_fingerprint(&rules_mod);
        assert_ne!(fp1, fp5, "changing rule hash changes fingerprint");
    }

    #[test]
    fn test_btreemap_insertion_order_invariance() {
        use crate::pattern_graph::core::{HoleId, GeneratorId, ConstructorId, ResolvedPattern};
        use std::collections::BTreeMap;
        use super::hash_substitution;

        // Create patterns
        let hole1 = ResolvedPattern::hole(HoleId(1));
        let hole2 = ResolvedPattern::hole(HoleId(2));
        let gen_a = ResolvedPattern::generator(GeneratorId(100));
        let gen_b = ResolvedPattern::generator(GeneratorId(200));
        let pattern = ResolvedPattern::app(ConstructorId(500), vec![hole1.clone(), hole2.clone()]);

        // Create substitution in different insertion orders
        let mut subst_order1 = BTreeMap::new();
        subst_order1.insert(HoleId(1), gen_a.clone());
        subst_order1.insert(HoleId(2), gen_b.clone());

        let mut subst_order2 = BTreeMap::new();
        subst_order2.insert(HoleId(2), gen_b.clone());
        subst_order2.insert(HoleId(1), gen_a.clone());

        // BTreeMap iteration order should be identical regardless of insertion order
        let keys1: Vec<_> = subst_order1.keys().collect();
        let keys2: Vec<_> = subst_order2.keys().collect();
        assert_eq!(keys1, keys2, "BTreeMap key order should be deterministic");

        // Hash should be identical
        let hash1 = hash_substitution(&subst_order1);
        let hash2 = hash_substitution(&subst_order2);
        assert_eq!(hash1, hash2, "substitution hash should be insertion-order invariant");

        // apply_substitution should produce identical results
        let result1 = pattern.apply_substitution(&subst_order1);
        let result2 = pattern.apply_substitution(&subst_order2);
        assert_eq!(result1, result2, "apply_substitution should be insertion-order invariant");
        assert_eq!(result1.hash(), result2.hash(), "hash of results should match");

        // Verify structural equality as well
        match (&result1, &result2) {
            (ResolvedPattern::App { op: op1, args: args1 }, ResolvedPattern::App { op: op2, args: args2 }) => {
                assert_eq!(op1, op2);
                assert_eq!(args1.len(), args2.len());
                for (a, b) in args1.iter().zip(args2.iter()) {
                    assert_eq!(a, b);
                }
            }
            _ => panic!("expected App"),
        }
    }

    #[test]
    fn test_hash_strength_and_equality() {
        use crate::pattern_graph::core::{HoleId, GeneratorId, ConstructorId, ResolvedPattern};
        use std::collections::BTreeMap;

        // Create two different patterns that should have different hashes
        let gen_a = ResolvedPattern::generator(GeneratorId(100));
        let gen_b = ResolvedPattern::generator(GeneratorId(200));
        let pattern1 = ResolvedPattern::app(ConstructorId(500), vec![gen_a.clone()]);
        let pattern2 = ResolvedPattern::app(ConstructorId(500), vec![gen_b.clone()]);

        // Different patterns should have different hashes (collision resistance assumption)
        assert_ne!(pattern1.hash(), pattern2.hash());

        // But equal patterns should have equal hashes and be structurally equal
        let pattern1_clone = pattern1.clone();
        assert_eq!(pattern1.hash(), pattern1_clone.hash());
        assert_eq!(pattern1, pattern1_clone);

        // Test that hash equality plus structural equality ensures correctness
        // This is what fast_step_check relies on
        let mut subst = BTreeMap::new();
        subst.insert(HoleId(1), gen_a.clone());
        let result1 = pattern1.apply_substitution(&subst);
        let result2 = pattern1_clone.apply_substitution(&subst);
        assert_eq!(result1.hash(), result2.hash());
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_fast_step_check_determinism() {
        use crate::pattern_graph::core::{HoleId, GeneratorId, PatternRule, PatternGraph, PatternBoundary, PatternId, HoleCorrespondence};
        use super::{PatternRewriteStep, RewriteMode, fast_step_check};
        use std::collections::BTreeMap;

        // Create a simple rule: hole1 -> generator(100)
        let hole1 = ResolvedPattern::hole(HoleId(1));
        let gen_a = ResolvedPattern::generator(GeneratorId(100));
        let rule = PatternRule {
            lhs_id: PatternId(1),
            rhs_id: PatternId(2),
            lhs_pattern: hole1.clone(),
            rhs_pattern: gen_a.clone(),
            hole_corr: HoleCorrespondence {},
            side_conditions: Vec::new(),
            rule_hash: crate::fingerprint::HashValue::zero(), // dummy
        };

        // Create before/after graphs
        let before = PatternGraph::new(hole1.clone(), PatternBoundary::with_arity(0, 1));
        let after = PatternGraph::new(gen_a.clone(), PatternBoundary::with_arity(0, 1));

        // Create step
        let step = PatternRewriteStep {
            rule_id: 1,
            position: vec![],
            substitution: BTreeMap::new(),
            before_hash: before.hash(),
            after_hash: after.hash(),
            mode: RewriteMode::Native,
        };

        // fast_step_check should return the same result across multiple calls
        let result1 = fast_step_check(&step, &rule, &before, &after);
        let result2 = fast_step_check(&step, &rule, &before, &after);
        assert_eq!(result1, result2, "fast_step_check should be deterministic");

        // Also verify that replay_step works
        match super::replay_step(&step, &rule, &before) {
            Ok(replayed) => assert_eq!(replayed.hash(), after.hash()),
            Err(_) => panic!("replay_step should succeed"),
        }
    }

    #[test]
    fn test_critical_pair_enumeration_order_invariant() {
        use super::critical_pairs_for_rules;
        use crate::pattern_graph::core::{PatternRule, PatternId, HoleCorrespondence, ResolvedPattern, GeneratorId};

        // Create 3 simple rules
        let rule1 = PatternRule {
            lhs_id: PatternId(1),
            rhs_id: PatternId(10),
            lhs_pattern: ResolvedPattern::generator(GeneratorId(1)),
            rhs_pattern: ResolvedPattern::generator(GeneratorId(10)),
            hole_corr: HoleCorrespondence {},
            side_conditions: Vec::new(),
            rule_hash: crate::fingerprint::HashValue::zero(),
        };
        let rule2 = PatternRule {
            lhs_id: PatternId(2),
            rhs_id: PatternId(20),
            lhs_pattern: ResolvedPattern::generator(GeneratorId(2)),
            rhs_pattern: ResolvedPattern::generator(GeneratorId(20)),
            hole_corr: HoleCorrespondence {},
            side_conditions: Vec::new(),
            rule_hash: crate::fingerprint::HashValue::zero(),
        };
        let rule3 = PatternRule {
            lhs_id: PatternId(3),
            rhs_id: PatternId(30),
            lhs_pattern: ResolvedPattern::generator(GeneratorId(3)),
            rhs_pattern: ResolvedPattern::generator(GeneratorId(30)),
            hole_corr: HoleCorrespondence {},
            side_conditions: Vec::new(),
            rule_hash: crate::fingerprint::HashValue::zero(),
        };

        // Create rules array in different orders
        let orders = [
            vec![rule1.clone(), rule2.clone(), rule3.clone()],
            vec![rule3.clone(), rule1.clone(), rule2.clone()],
            vec![rule2.clone(), rule3.clone(), rule1.clone()],
        ];

        let mut previous_pairs = None;
        for rules in &orders {
            let pairs = critical_pairs_for_rules(rules);

            // Convert to comparable representation: sort by deterministic key
            let mut sorted_pairs: Vec<_> = pairs.iter()
                .map(|p| (
                    p.position.clone(),
                    p.unifier_hash,
                    p.left_result_hash,
                    p.right_result_hash,
                    p.container_is_first,
                ))
                .collect();
            sorted_pairs.sort();

            match &previous_pairs {
                None => previous_pairs = Some(sorted_pairs),
                Some(prev) => {
                    assert_eq!(*prev, sorted_pairs, "critical pair sets should be identical regardless of rule insertion order");
                }
            }
        }
    }

    #[test]
    fn test_fast_path_agrees_with_slow_path_deterministic() {
        use super::{fast_step_check, replay_step, PatternRewriteStep, RewriteMode};
        use crate::pattern_graph::core::{PatternRule, PatternGraph, PatternBoundary, PatternId, HoleCorrespondence, ResolvedPattern, GeneratorId, HoleId};
        use crate::pattern_graph::port_view;
        use crate::fingerprint::HashValue;
        use std::collections::BTreeMap;

        // Simple deterministic PRNG for reproducible random generation
        struct DeterministicRng {
            state: u64,
        }

        impl DeterministicRng {
            fn new(seed: u64) -> Self {
                Self { state: seed }
            }

            fn next_u32(&mut self) -> u32 {
                // Xorshift64*
                self.state ^= self.state >> 12;
                self.state ^= self.state << 25;
                self.state ^= self.state >> 27;
                (self.state.wrapping_mul(0x2545F4914F6CDD1D_u64) >> 32) as u32
            }

            fn next_bool(&mut self) -> bool {
                self.next_u32() % 2 == 0
            }

            fn next_usize(&mut self, limit: usize) -> usize {
                (self.next_u32() as usize) % limit
            }
        }

        // Generate a random PortView-eligible pattern
        fn gen_pattern(rng: &mut DeterministicRng, depth: u32, max_depth: u32) -> ResolvedPattern {
            if depth >= max_depth {
                // Leaf: hole or generator
                if rng.next_bool() {
                    ResolvedPattern::hole(HoleId(rng.next_u32() as u64 % 10))
                } else {
                    ResolvedPattern::generator(GeneratorId(rng.next_u32() as u64 % 10))
                }
            } else {
                match rng.next_usize(3) {
                    0 => ResolvedPattern::hole(HoleId(rng.next_u32() as u64 % 10)),
                    1 => ResolvedPattern::generator(GeneratorId(rng.next_u32() as u64 % 10)),
                    2 => {
                        // Binary compose
                        let left = gen_pattern(rng, depth + 1, max_depth);
                        let right = gen_pattern(rng, depth + 1, max_depth);
                        ResolvedPattern::Compose(vec![left, right])
                    }
                    _ => unreachable!(),
                }
            }
        }

        // Test with fixed seeds for reproducibility
        for seed in 0..10 {
            let mut rng = DeterministicRng::new(seed);

            // Generate a simple rule: hole -> generator
            let hole_id = HoleId(0);
            let gen_id = GeneratorId(100 + seed as u64);
            let rule = PatternRule {
                lhs_id: PatternId(1),
                rhs_id: PatternId(2),
                lhs_pattern: ResolvedPattern::hole(hole_id),
                rhs_pattern: ResolvedPattern::generator(gen_id),
                hole_corr: HoleCorrespondence {},
                side_conditions: Vec::new(),
                rule_hash: HashValue::zero(),
            };

            // Generate before pattern (contains hole)
            let before_pattern = gen_pattern(&mut rng, 0, 3);
            // Apply substitution: replace hole with generator
            let mut substitution = BTreeMap::new();
            substitution.insert(hole_id, ResolvedPattern::generator(gen_id));
            let after_pattern = before_pattern.apply_substitution(&substitution);

            // Create PatternGraphs
            let before = PatternGraph::new(before_pattern, PatternBoundary::with_arity(0, 1));
            let after = PatternGraph::new(after_pattern, PatternBoundary::with_arity(0, 1));

            // Create step (position is root)
            let step = PatternRewriteStep {
                rule_id: 1,
                position: vec![], // root position
                substitution,
                before_hash: before.hash(),
                after_hash: after.hash(),
                mode: RewriteMode::Native,
            };

            // Verify replay_step succeeds
            match replay_step(&step, &rule, &before) {
                Ok(replayed) => {
                    // replayed should equal after
                    assert_eq!(replayed, after, "seed {}: replay_step should produce after graph", seed);

                    // Now check fast_step_check
                    let fast_result = fast_step_check(&step, &rule, &before, &after);

                    // Both before and after are PortView eligible (simple patterns),
                    // so fast_step_check should return true
                    if port_view::is_portview_eligible(&before) &&
                       port_view::is_portview_eligible(&after) {
                        assert!(fast_result, "seed {}: fast_step_check should return true for eligible patterns", seed);
                    }
                    // If either is ineligible, fast_step_check should return false
                    // (that's correct behavior)
                }
                Err(_) => {
                    // If replay_step fails, fast_step_check must also return false
                    let fast_result = fast_step_check(&step, &rule, &before, &after);
                    assert!(!fast_result, "seed {}: fast_step_check should return false when replay_step fails", seed);
                }
            }
        }
    }

}