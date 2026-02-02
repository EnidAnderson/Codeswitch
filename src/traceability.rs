//! Traceability and replay for hypergraph rewrites.
//!
//! Provides APIs for tracking rewrite steps, locating match sites, and
//! replaying rewrites for validation or undo/redo operations.
//!
//! # Citations
//! - Version control for graphs: Mens, "A formal foundation for object-oriented software evolution" (1999)
//! - Graph transformation traceability: Varro et al., "Model transformation by example" (2006)

use crate::core::Codeswitch;
use crate::fingerprint::{graph_fingerprint, HashValue};
use crate::pattern::{Pattern, PatternMatch, RewriteTemplate};

/// Identifier for a rewrite rule.
///
/// Used to track which rule was applied in a rewrite step.
/// Can be a string name, UUID, or other persistent identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RuleId(pub String);

/// A rewrite step records a single pattern match and template application.
///
/// Contains enough information to replay the rewrite or locate the affected
/// region in the hypergraph.
///
/// # Citations
/// - Graph rewrite steps: Heckel et al., "Concurrency and loose semantics of open graph transformation systems" (2002)
#[derive(Debug)]
pub struct RewriteStep<P> {
    /// The pattern that was matched.
    pattern: Pattern<P>,
    /// The exact match found in the source graph.
    pattern_match: PatternMatch,
    /// The template applied at the match site.
    template: RewriteTemplate<P>,
    /// Fingerprint of the source graph before rewrite.
    pre_fingerprint: crate::fingerprint::HashValue,
    /// Fingerprint of the target graph after rewrite.
    post_fingerprint: crate::fingerprint::HashValue,
    /// Timestamp or version identifier.
    version: u64,
    /// Identifier of the rule that was applied, if known.
    rule_id: Option<RuleId>,
}

impl<P> RewriteStep<P> {
    /// Creates a new rewrite step.
    pub fn new(
        pattern: Pattern<P>,
        pattern_match: PatternMatch,
        template: RewriteTemplate<P>,
        pre_fingerprint: crate::fingerprint::HashValue,
        post_fingerprint: crate::fingerprint::HashValue,
        version: u64,
    ) -> Self {
        Self::new_with_rule(pattern, pattern_match, template, pre_fingerprint, post_fingerprint, version, None)
    }

    /// Creates a new rewrite step with a rule identifier.
    pub fn new_with_rule(
        pattern: Pattern<P>,
        pattern_match: PatternMatch,
        template: RewriteTemplate<P>,
        pre_fingerprint: crate::fingerprint::HashValue,
        post_fingerprint: crate::fingerprint::HashValue,
        version: u64,
        rule_id: Option<RuleId>,
    ) -> Self {
        Self {
            pattern,
            pattern_match,
            template,
            pre_fingerprint,
            post_fingerprint,
            version,
            rule_id,
        }
    }

    /// Returns the pattern that was matched.
    pub fn pattern(&self) -> &Pattern<P> {
        &self.pattern
    }

    /// Returns the pattern match.
    pub fn pattern_match(&self) -> &PatternMatch {
        &self.pattern_match
    }

    /// Returns the rewrite template.
    pub fn template(&self) -> &RewriteTemplate<P> {
        &self.template
    }

    /// Returns the pre-rewrite fingerprint.
    pub fn pre_fingerprint(&self) -> crate::fingerprint::HashValue {
        self.pre_fingerprint
    }

    /// Returns the post-rewrite fingerprint.
    pub fn post_fingerprint(&self) -> crate::fingerprint::HashValue {
        self.post_fingerprint
    }

    /// Returns the version identifier.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Returns the rule identifier, if any.
    pub fn rule_id(&self) -> Option<&RuleId> {
        self.rule_id.as_ref()
    }
}

impl<P: Clone> Clone for RewriteStep<P> {
    fn clone(&self) -> Self {
        Self {
            pattern: self.pattern.clone(),
            pattern_match: self.pattern_match.clone(),
            template: self.template.clone(),
            pre_fingerprint: self.pre_fingerprint,
            post_fingerprint: self.post_fingerprint,
            version: self.version,
            rule_id: self.rule_id.clone(),
        }
    }
}

/// A trace records a sequence of rewrite steps applied to a hypergraph.
///
/// Maintains the linear history of transformations, enabling replay,
// validation, and undo operations.
///
/// # Citations
/// - Transformation traces: Jouault & Kurtev, "Transforming models with ATL" (2005)
#[derive(Debug)]
pub struct RewriteTrace<P> {
    /// Initial graph (version 0).
    initial: Codeswitch<P>,
    /// Sequence of rewrite steps in application order.
    steps: Vec<RewriteStep<P>>,
    /// Current version (index into steps or 0 for initial).
    current_version: usize,
}

impl<P: Clone> RewriteTrace<P> {
    /// Creates a new trace starting from the given initial graph.
    pub fn new(initial: Codeswitch<P>) -> Self {
        Self {
            initial,
            steps: Vec::new(),
            current_version: 0,
        }
    }

    /// Records a rewrite step and updates the current version.
    pub fn record_step(&mut self, step: RewriteStep<P>) {
        self.steps.push(step);
        self.current_version = self.steps.len();
    }

    /// Returns the graph at the current version.
    pub fn current_graph(&self) -> Codeswitch<P> {
        self.replay_to(self.current_version).unwrap_or_else(|_| self.initial.clone())
    }

    /// Returns the number of recorded steps.
    pub fn step_count(&self) -> usize {
        self.steps.len()
    }

    /// Returns the current version index.
    pub fn current_version(&self) -> usize {
        self.current_version
    }
}

/// Trait for hypergraph traceability and replay.
///
/// Implemented by systems that can track rewrite steps and replay them
/// for validation or navigation.
///
/// # Citations
/// - Graph transformation replay: Giese & Wagner, "Incremental model synchronization with triple graph grammars" (2009)
pub trait HypergraphTraceability<P> {
    /// Replays a rewrite step on a given hypergraph.
    ///
    /// Applies the same pattern match and template as recorded in the step.
    /// Used for validation, undo, or redo operations.
    fn replay_step(
        &self,
        step: &RewriteStep<P>,
    ) -> Result<Codeswitch<P>, TraceabilityError>;

    /// Locates the site of a rewrite step in the current hypergraph.
    ///
    /// Finds nodes corresponding to the original match site, even after
    /// subsequent rewrites may have modified the graph.
    fn locate_site(&self, step: &RewriteStep<P>) -> Result<PatternMatch, TraceabilityError>;
}

/// Error type for trace storage operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceStorageError {
    /// Trace storage capability is not available.
    CapabilityMissing,
    /// Storage backend error (e.g., I/O, database connection).
    BackendError(String),
    /// Trace corrupted or invalid format.
    Corruption(String),
    /// Other error with description.
    Other(String),
}

impl std::fmt::Display for TraceStorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TraceStorageError::CapabilityMissing => write!(f, "trace storage capability missing"),
            TraceStorageError::BackendError(msg) => write!(f, "backend error: {}", msg),
            TraceStorageError::Corruption(msg) => write!(f, "trace corruption: {}", msg),
            TraceStorageError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for TraceStorageError {}

/// Trait for hypergraph trace storage and retrieval.
///
/// Implemented by backends that can store and retrieve rewrite traces
/// associated with hypergraphs.
pub trait HypergraphTraceStorage<P> {
    /// Retrieves the trace associated with this hypergraph, if any.
    fn get_trace(&self) -> Result<Option<RewriteTrace<P>>, TraceStorageError>;
}

/// Error type for traceability and replay operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceabilityError {
    /// Cannot replay step: pattern no longer matches.
    PatternNoLongerMatches,
    /// Cannot locate site: nodes have been modified or deleted.
    SiteLost,
    /// Version mismatch in trace.
    VersionMismatch,
    /// Fingerprint validation failed.
    FingerprintMismatch,
    /// Other error with description.
    Other(String),
}

impl std::fmt::Display for TraceabilityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TraceabilityError::PatternNoLongerMatches => write!(f, "pattern no longer matches"),
            TraceabilityError::SiteLost => write!(f, "rewrite site lost"),
            TraceabilityError::VersionMismatch => write!(f, "version mismatch"),
            TraceabilityError::FingerprintMismatch => write!(f, "fingerprint mismatch"),
            TraceabilityError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for TraceabilityError {}

/// Implementation of traceability for Codeswitch.
impl<P: crate::fingerprint::PayloadFingerprint + Clone> HypergraphTraceability<P>
    for Codeswitch<P>
{
    fn replay_step(
        &self,
        _step: &RewriteStep<P>,
    ) -> Result<Codeswitch<P>, TraceabilityError> {
        // Phase 2 stub: attempts to reapply the template at the recorded match.
        // Full implementation would:
        // 1. Verify the pattern still matches at the recorded location
        // 2. Apply the template using the pattern match
        // 3. Validate the resulting graph matches the recorded post_fingerprint
        Err(TraceabilityError::PatternNoLongerMatches)
    }

    fn locate_site(&self, _step: &RewriteStep<P>) -> Result<PatternMatch, TraceabilityError> {
        // Phase 2 stub: attempts to find nodes corresponding to the original match.
        // Full implementation would:
        // 1. Use WL fingerprints to track nodes across rewrites
        // 2. Follow preservation maps through rewrite history
        // 3. Return current locations of preserved nodes
        Err(TraceabilityError::SiteLost)
    }
}

/// Implementation of trace storage for Codeswitch.
///
/// Stub implementation that returns `None`; a real backend would store
/// traces in a database or file system.
impl<P: crate::fingerprint::PayloadFingerprint + Clone> HypergraphTraceStorage<P>
    for Codeswitch<P>
{
    fn get_trace(&self) -> Result<Option<RewriteTrace<P>>, TraceStorageError> {
        // Phase 2 stub: real implementation would retrieve trace from backend
        Ok(None)
    }
}

impl<P: Clone> RewriteTrace<P> {
    /// Replays the trace up to a specific version.
    ///
    /// Starting from the initial graph, applies rewrite steps in order
    /// until reaching the requested version.
    pub fn replay_to(&self, target_version: usize) -> Result<Codeswitch<P>, TraceabilityError> {
        if target_version > self.steps.len() {
            return Err(TraceabilityError::VersionMismatch);
        }

        let current = self.initial.clone();
        for i in 0..target_version {
            let _step = &self.steps[i];
            // In a real implementation, we would apply the step to current
            // For now, we return an error since pattern matching is not fully implemented
            return Err(TraceabilityError::PatternNoLongerMatches);
        }
        Ok(current)
    }

    /// Rolls back to a previous version.
    pub fn rollback_to(&mut self, target_version: usize) -> Result<(), TraceabilityError> {
        if target_version > self.steps.len() {
            return Err(TraceabilityError::VersionMismatch);
        }
        self.current_version = target_version;
        Ok(())
    }

    /// Returns a reference to a specific rewrite step.
    pub fn get_step(&self, index: usize) -> Option<&RewriteStep<P>> {
        self.steps.get(index)
    }

    /// Returns an iterator over all rewrite steps.
    pub fn steps(&self) -> impl Iterator<Item = &RewriteStep<P>> {
        self.steps.iter()
    }

    /// Returns a specific rewrite step by version (0-indexed).
    /// Alias for `get_step` for API compatibility.
    pub fn step_at(&self, version: usize) -> Option<&RewriteStep<P>> {
        self.get_step(version)
    }
}

impl<P: crate::fingerprint::PayloadFingerprint + Clone> RewriteTrace<P> {
    /// Returns the fingerprint of the initial graph (version 0).
    ///
    /// This fingerprint represents the state of the hypergraph before any
    /// rewrite steps were applied. Useful for validating trace integrity
    /// and detecting changes to the initial state.
    pub fn initial_fingerprint(&self) -> HashValue {
        graph_fingerprint(&self.initial)
    }
}

impl<P: Clone> Clone for RewriteTrace<P> {
    fn clone(&self) -> Self {
        Self {
            initial: self.initial.clone(),
            steps: self.steps.clone(),
            current_version: self.current_version,
        }
    }
}