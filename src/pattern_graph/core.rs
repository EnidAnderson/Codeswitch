//! Core data structures for PatternGraph representation.
//!
//! Defines `Pattern`, `PatternBoundary`, `PatternGraph`, and the node constructors.
//! PatternGraph is a deterministic, acyclic hypergraph (tree in v0.1) where nodes
//! are constructors with ordered child slots.
//!
//! This implementation aligns with the shared pattern module in `tcb_core`
//! (see ../clean_kernel/tcb_core/src/pattern/mod.rs).

use crate::fingerprint::HashValue;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::hash::Hash;

use super::constants;

/// Port specification for pattern boundaries.
///
/// Minimal v0.1: index only. Labels and types may be added later.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PortSpec {
    /// Port index (0-based).
    pub idx: u16,
    /// Optional label for documentation/UI (ignored for equality/hashing).
    pub label: Option<String>,
}

impl PortSpec {
    /// Creates a new port specification with only an index.
    pub fn new(idx: u16) -> Self {
        Self { idx, label: None }
    }

    /// Creates a new port specification with index and label.
    pub fn with_label(idx: u16, label: String) -> Self {
        Self { idx, label: Some(label) }
    }
}

/// Pattern boundary defining input and output ports.
///
/// The boundary is canonical and deterministic; ports are stored in sorted order
/// by index. Derived arity is `(in_ports.len(), out_ports.len())`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternBoundary {
    /// Input ports, sorted by `idx`.
    pub in_ports: Vec<PortSpec>,
    /// Output ports, sorted by `idx`.
    pub out_ports: Vec<PortSpec>,
}

impl PatternBoundary {
    /// Creates a new empty boundary.
    pub fn new() -> Self {
        Self {
            in_ports: Vec::new(),
            out_ports: Vec::new(),
        }
    }

    /// Creates a boundary with given input and output port counts.
    ///
    /// Ports are assigned indices 0..n for inputs and 0..m for outputs.
    pub fn with_arity(in_count: u16, out_count: u16) -> Self {
        let in_ports = (0..in_count).map(PortSpec::new).collect();
        let out_ports = (0..out_count).map(PortSpec::new).collect();
        Self { in_ports, out_ports }
    }

    /// Returns the input arity (number of input ports).
    pub fn in_arity(&self) -> usize {
        self.in_ports.len()
    }

    /// Returns the output arity (number of output ports).
    pub fn out_arity(&self) -> usize {
        self.out_ports.len()
    }

    /// Returns the derived (n,m) arity pair.
    pub fn arity(&self) -> (usize, usize) {
        (self.in_arity(), self.out_arity())
    }
}

impl Default for PatternBoundary {
    fn default() -> Self {
        Self::new()
    }
}

// ----------------------------------------------------------------------------
// ResolvedPattern: tree representation of patterns (compatible with shared module)
// ----------------------------------------------------------------------------

/// Identifier for a hole (metavariable).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HoleId(pub u64);

/// Identifier for a generator (atomic term).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GeneratorId(pub u64);

/// Identifier for a constructor (function symbol).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConstructorId(pub u64);

/// Identifier for a doctrine key (used in InDoctrine nodes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DoctrineKey(pub u64);

/// Tree representation of a resolved pattern.
///
/// This matches the `ResolvedPattern` enum in the shared pattern module
/// (../clean_kernel/tcb_core/src/facet_dsl/pattern_matcher.rs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedPattern {
    Hole(HoleId),
    Generator(GeneratorId),
    Compose(Vec<ResolvedPattern>),
    App {
        op: ConstructorId,
        args: Vec<ResolvedPattern>,
    },
    Reject {
        code: String,
        msg: String,
    },
    InDoctrine {
        doctrine: Option<DoctrineKey>,
        term: Box<ResolvedPattern>,
    },
}

impl ResolvedPattern {
    /// Creates a new hole pattern.
    pub fn hole(id: HoleId) -> Self {
        Self::Hole(id)
    }

    /// Creates a new generator pattern.
    pub fn generator(id: GeneratorId) -> Self {
        Self::Generator(id)
    }

    /// Creates a new compose pattern with given children.
    pub fn compose(children: Vec<ResolvedPattern>) -> Self {
        Self::Compose(children)
    }

    /// Creates a new application pattern.
    pub fn app(op: ConstructorId, args: Vec<ResolvedPattern>) -> Self {
        Self::App { op, args }
    }

    /// Creates a new reject pattern.
    pub fn reject(code: String, msg: String) -> Self {
        Self::Reject { code, msg }
    }

    /// Creates a new doctrine wrapper pattern.
    pub fn in_doctrine(doctrine: Option<DoctrineKey>, term: ResolvedPattern) -> Self {
        Self::InDoctrine {
            doctrine,
            term: Box::new(term),
        }
    }

    /// Returns true if the pattern is a hole.
    pub fn is_hole(&self) -> bool {
        matches!(self, Self::Hole(_))
    }

    /// Returns true if the pattern contains any holes.
    pub fn contains_holes(&self) -> bool {
        match self {
            Self::Hole(_) => true,
            Self::Generator(_) => false,
            Self::Compose(children) => children.iter().any(|c| c.contains_holes()),
            Self::App { args, .. } => args.iter().any(|a| a.contains_holes()),
            Self::Reject { .. } => false,
            Self::InDoctrine { term, .. } => term.contains_holes(),
        }
    }

    /// Collects all hole IDs in the pattern.
    pub fn hole_ids(&self) -> Vec<HoleId> {
        match self {
            Self::Hole(id) => vec![*id],
            Self::Generator(_) => vec![],
            Self::Compose(children) => children.iter().flat_map(|c| c.hole_ids()).collect(),
            Self::App { args, .. } => args.iter().flat_map(|a| a.hole_ids()).collect(),
            Self::Reject { .. } => vec![],
            Self::InDoctrine { term, .. } => term.hole_ids(),
        }
    }

    /// Apply a substitution to this pattern, replacing holes with their bindings.
    ///
    /// Holes not present in the substitution remain unchanged.
    /// If a hole maps to another hole that also has a binding, the chain is followed.
    pub fn apply_substitution(&self, subst: &BTreeMap<HoleId, ResolvedPattern>) -> ResolvedPattern {
        match self {
            Self::Hole(h) => {
                if let Some(bound) = subst.get(h) {
                    // Recursively apply substitution to bound pattern (follow chains)
                    bound.apply_substitution(subst)
                } else {
                    Self::Hole(*h)
                }
            }
            Self::Generator(g) => Self::Generator(*g),
            Self::Compose(children) => Self::Compose(
                children.iter().map(|c| c.apply_substitution(subst)).collect()
            ),
            Self::App { op, args } => Self::App {
                op: *op,
                args: args.iter().map(|a| a.apply_substitution(subst)).collect(),
            },
            Self::Reject { code, msg } => Self::Reject {
                code: code.clone(),
                msg: msg.clone(),
            },
            Self::InDoctrine { doctrine, term } => Self::InDoctrine {
                doctrine: *doctrine,
                term: Box::new(term.apply_substitution(subst)),
            },
        }
    }
}

/// PatternGraph: a wrapper around ResolvedPattern with additional metadata.
///
/// Includes precomputed hash and boundary information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternGraph {
    /// The underlying pattern tree.
    pattern: ResolvedPattern,
    /// Boundary defining input/output ports.
    boundary: PatternBoundary,
    /// Precomputed deterministic hash.
    hash: HashValue,
    /// Map from hole IDs to their positions (for fast lookup).
    /// Each position is encoded as a sequence of steps (Vec<u32>).
    hole_positions: HashMap<HoleId, Vec<Vec<u32>>>,
}

impl PatternGraph {
    /// Creates a new PatternGraph from a ResolvedPattern and boundary.
    ///
    /// Computes the deterministic hash and extracts hole positions.
    pub fn new(pattern: ResolvedPattern, boundary: PatternBoundary) -> Self {
        let hash = Self::compute_hash(&pattern);
        let hole_positions = Self::extract_hole_positions(&pattern);
        Self {
            pattern,
            boundary,
            hash,
            hole_positions,
        }
    }

    /// Returns the underlying pattern.
    pub fn pattern(&self) -> &ResolvedPattern {
        &self.pattern
    }

    /// Returns the boundary.
    pub fn boundary(&self) -> &PatternBoundary {
        &self.boundary
    }

    /// Returns the precomputed hash.
    pub fn hash(&self) -> HashValue {
        self.hash
    }

    /// Returns the hole position map.
    pub fn hole_positions(&self) -> &HashMap<HoleId, Vec<Vec<u32>>> {
        &self.hole_positions
    }

    /// Computes deterministic hash of a ResolvedPattern.
    ///
    /// The hash must be invariant under α‑equivalence when binders are added.
    /// For v0.1 (binder‑free), a structural hash suffices.
    fn compute_hash(pattern: &ResolvedPattern) -> HashValue {
        pattern.hash()
    }

    /// Extracts positions of all holes in the pattern.
    fn extract_hole_positions(pattern: &ResolvedPattern) -> HashMap<HoleId, Vec<Vec<u32>>> {
        let mut map: HashMap<HoleId, Vec<Vec<u32>>> = HashMap::new();
        for pos in iter_positions(pattern) {
            if let Some(sub) = get_subpattern(pattern, &pos) {
                if let ResolvedPattern::Hole(hole_id) = sub {
                    let encoded = encode_term_path(&pos);
                    map.entry(*hole_id).or_default().push(encoded);
                }
            }
        }
        map
    }
}

/// Pattern AST (source-level representation).
///
/// This is the declarative artifact that users write or tools generate.
/// It is compiled into a `PatternGraph` for execution.
pub struct Pattern<P> {
    /// Boundary defining input/output ports.
    pub boundary: PatternBoundary,
    /// Body of the pattern (to be resolved into PatternGraph).
    pub body: PatternBody<P>,
    /// Binder information (empty in v0.1).
    pub binder_info: BinderInfo,
    /// Canonical, α‑invariant hash of the pattern.
    pub pattern_hash: HashValue,
}

/// Body of a pattern (abstract syntax).
pub enum PatternBody<P> {
    /// Reference to a resolved PatternGraph.
    Resolved(PatternGraph),
    /// Unresolved AST (for future compilation passes).
    Ast(P),
}

/// Binder information (placeholder for v0.1).
#[derive(Debug, Clone, Default)]
pub struct BinderInfo {
    // Empty in v0.1
}

impl BinderInfo {
    /// Creates new empty binder info.
    pub fn new() -> Self {
        Self::default()
    }
}

// ----------------------------------------------------------------------------
// Position and traversal
// ----------------------------------------------------------------------------

/// A step in a term path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathStep {
    /// Index into a Compose vector.
    ComposeIndex(usize),
    /// Argument index into an App.
    AppArg(usize),
    /// Into the term of an InDoctrine wrapper.
    InDoctrine,
}

/// A path to a subpattern (deterministic position).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TermPath {
    /// Sequence of steps from the root.
    pub steps: Vec<PathStep>,
}

impl TermPath {
    /// Creates an empty path (root).
    pub fn empty() -> Self {
        Self { steps: Vec::new() }
    }
}

// ----------------------------------------------------------------------------
// Unification
// ----------------------------------------------------------------------------

/// Unify two ResolvedPatterns, treating Hole(HoleId) as metavariables.
///
/// Returns a substitution map HoleId -> ResolvedPattern, or None if not unifiable.
///
/// Implements first-order unification with occurs check.
/// Hole-hole unification deterministically binds larger ID to smaller ID.
pub fn unify_patterns(
    a: &ResolvedPattern,
    b: &ResolvedPattern,
) -> Option<BTreeMap<HoleId, ResolvedPattern>> {
    let mut subst: BTreeMap<HoleId, ResolvedPattern> = BTreeMap::new();
    let mut work: VecDeque<(ResolvedPattern, ResolvedPattern)> = VecDeque::new();
    work.push_back((a.clone(), b.clone()));

    while let Some((p, q)) = work.pop_front() {
        let p = resolve(&p, &subst);
        let q = resolve(&q, &subst);

        if p == q {
            continue;
        }

        match (p, q) {
            (ResolvedPattern::Hole(h), t) => {
                bind_hole(h, t, &mut subst)?;
            }
            (t, ResolvedPattern::Hole(h)) => {
                bind_hole(h, t, &mut subst)?;
            }

            (ResolvedPattern::Generator(g1), ResolvedPattern::Generator(g2)) => {
                if g1 != g2 {
                    return None;
                }
            }

            (ResolvedPattern::Compose(xs), ResolvedPattern::Compose(ys)) => {
                if xs.len() != ys.len() {
                    return None;
                }
                // Deterministic: push in reverse so leftmost is processed first.
                for (x, y) in xs.into_iter().zip(ys.into_iter()).rev() {
                    work.push_front((x, y));
                }
            }

            (
                ResolvedPattern::App { op: op1, args: a1 },
                ResolvedPattern::App { op: op2, args: a2 },
            ) => {
                if op1 != op2 || a1.len() != a2.len() {
                    return None;
                }
                for (x, y) in a1.into_iter().zip(a2.into_iter()).rev() {
                    work.push_front((x, y));
                }
            }

            (
                ResolvedPattern::InDoctrine { doctrine: d1, term: t1 },
                ResolvedPattern::InDoctrine { doctrine: d2, term: t2 },
            ) => {
                if d1 != d2 {
                    return None;
                }
                work.push_front((*t1, *t2));
            }

            (
                ResolvedPattern::Reject { code: c1, msg: m1 },
                ResolvedPattern::Reject { code: c2, msg: m2 },
            ) => {
                if c1 != c2 || m1 != m2 {
                    return None;
                }
            }

            // All other constructor mismatches fail.
            _ => return None,
        }
    }

    Some(finalize_subst(subst))
}

/// Resolve a pattern by repeatedly expanding bound holes.
pub fn resolve(p: &ResolvedPattern, subst: &BTreeMap<HoleId, ResolvedPattern>) -> ResolvedPattern {
    match p {
        ResolvedPattern::Hole(h) => {
            if let Some(t) = subst.get(h) {
                // Follow chains like h -> Hole(h2) -> ...
                resolve(t, subst)
            } else {
                ResolvedPattern::Hole(*h)
            }
        }

        ResolvedPattern::Generator(g) => ResolvedPattern::Generator(*g),

        ResolvedPattern::Compose(xs) => ResolvedPattern::Compose(
            xs.iter().map(|x| resolve(x, subst)).collect()
        ),

        ResolvedPattern::App { op, args } => ResolvedPattern::App {
            op: *op,
            args: args.iter().map(|x| resolve(x, subst)).collect(),
        },

        ResolvedPattern::Reject { code, msg } => ResolvedPattern::Reject {
            code: code.clone(),
            msg: msg.clone(),
        },

        ResolvedPattern::InDoctrine { doctrine, term } => ResolvedPattern::InDoctrine {
            doctrine: *doctrine,
            term: Box::new(resolve(term, subst)),
        },
    }
}

/// Bind a hole `h` to term `t`, with occurs check.
///
/// Also applies a deterministic tie-break when binding hole to hole:
/// - If unifying Hole(h1) with Hole(h2), binds the larger id to the smaller id.
fn bind_hole(
    h: HoleId,
    t: ResolvedPattern,
    subst: &mut BTreeMap<HoleId, ResolvedPattern>,
) -> Option<()> {
    // If already bound, unify the binding with t (caller resolves first, so uncommon).
    if let Some(existing) = subst.get(&h).cloned() {
        // Caller will re-process via worklist if needed; here we just require consistency.
        let ex = resolve(&existing, subst);
        let tt = resolve(&t, subst);
        if ex == tt {
            return Some(());
        } else {
            return None;
        }
    }

    let t = resolve(&t, subst);

    // h := Hole(h) is redundant; treat as success.
    if let ResolvedPattern::Hole(h2) = t {
        if h == h2 {
            return Some(());
        }
        // Deterministic union for hole-hole: bind larger -> smaller.
        let (hi, lo) = if h > h2 { (h, h2) } else { (h2, h) };
        if subst.contains_key(&hi) {
            // If hi already bound (shouldn't happen here), accept only if it resolves to Hole(lo).
            let resolved = resolve(subst.get(&hi).unwrap(), subst);
            if resolved == ResolvedPattern::Hole(lo) {
                return Some(());
            } else {
                return None;
            }
        }
        subst.insert(hi, ResolvedPattern::Hole(lo));
        return Some(());
    }

    // Occurs check: prevent cycles like h := f(... Hole(h) ...)
    if occurs_in(h, &t, subst) {
        return None;
    }

    subst.insert(h, t);
    Some(())
}

/// Returns true if hole `h` occurs in `t` (under current substitution).
fn occurs_in(h: HoleId, t: &ResolvedPattern, subst: &BTreeMap<HoleId, ResolvedPattern>) -> bool {
    match t {
        ResolvedPattern::Hole(h2) => {
            if *h2 == h {
                return true;
            }
            if let Some(bound) = subst.get(h2) {
                occurs_in(h, bound, subst)
            } else {
                false
            }
        }

        ResolvedPattern::Generator(_) => false,

        ResolvedPattern::Compose(xs) => xs.iter().any(|x| occurs_in(h, x, subst)),

        ResolvedPattern::App { op: _, args } => args.iter().any(|x| occurs_in(h, x, subst)),

        ResolvedPattern::Reject { .. } => false,

        ResolvedPattern::InDoctrine { doctrine: _, term } => occurs_in(h, term, subst),
    }
}

/// Finalize substitution by fully resolving each RHS under the substitution itself.
fn finalize_subst(mut subst: BTreeMap<HoleId, ResolvedPattern>) -> BTreeMap<HoleId, ResolvedPattern> {
    // Resolve until stable. Since patterns are acyclic and we did occurs check, this terminates.
    let keys: Vec<HoleId> = subst.keys().cloned().collect();
    for k in keys {
        if let Some(v) = subst.get(&k).cloned() {
            let rv = resolve(&v, &subst);
            subst.insert(k, rv);
        }
    }
    subst
}

// ----------------------------------------------------------------------------
// Position enumeration and subpattern manipulation
// ----------------------------------------------------------------------------

/// Enumerate all positions (TermPath) in a ResolvedPattern in deterministic preorder.
/// Includes positions of holes (leaf positions).
pub fn iter_positions(pattern: &ResolvedPattern) -> Vec<TermPath> {
    let mut positions = Vec::new();
    let mut stack: Vec<(TermPath, &ResolvedPattern)> = Vec::new();
    stack.push((TermPath::empty(), pattern));

    while let Some((path, pat)) = stack.pop() {
        positions.push(path.clone());
        match pat {
            ResolvedPattern::Hole(_) => {}
            ResolvedPattern::Generator(_) => {}
            ResolvedPattern::Reject { .. } => {}
            ResolvedPattern::Compose(parts) => {
                // Push in reverse order to maintain left-to-right processing when popped.
                for (i, part) in parts.iter().enumerate().rev() {
                    let mut new_path = path.clone();
                    new_path.steps.push(PathStep::ComposeIndex(i));
                    stack.push((new_path, part));
                }
            }
            ResolvedPattern::App { op: _, args } => {
                for (i, arg) in args.iter().enumerate().rev() {
                    let mut new_path = path.clone();
                    new_path.steps.push(PathStep::AppArg(i));
                    stack.push((new_path, arg));
                }
            }
            ResolvedPattern::InDoctrine { doctrine: _, term } => {
                let mut new_path = path.clone();
                new_path.steps.push(PathStep::InDoctrine);
                stack.push((new_path, term));
            }
        }
    }
    positions
}

/// Get subpattern at a given TermPath, if it exists.
pub fn get_subpattern<'a>(pattern: &'a ResolvedPattern, path: &TermPath) -> Option<&'a ResolvedPattern> {
    let mut current = pattern;
    for step in &path.steps {
        match (current, step) {
            (ResolvedPattern::Compose(parts), PathStep::ComposeIndex(i)) => {
                if let Some(part) = parts.get(*i) {
                    current = part;
                } else {
                    return None;
                }
            }
            (ResolvedPattern::App { args, .. }, PathStep::AppArg(i)) => {
                if let Some(arg) = args.get(*i) {
                    current = arg;
                } else {
                    return None;
                }
            }
            (ResolvedPattern::InDoctrine { term, .. }, PathStep::InDoctrine) => {
                current = term;
            }
            _ => return None,
        }
    }
    Some(current)
}

/// Replace subpattern at a given TermPath with a new pattern.
/// Returns a new ResolvedPattern with the replacement.
pub fn replace_subpattern(
    pattern: ResolvedPattern,
    path: &TermPath,
    new_sub: ResolvedPattern,
) -> Result<ResolvedPattern, String> {
    if path.steps.is_empty() {
        return Ok(new_sub);
    }
    let first_step = &path.steps[0];
    let rest_path = TermPath { steps: path.steps[1..].to_vec() };
    match (pattern, first_step) {
        (ResolvedPattern::Compose(mut parts), PathStep::ComposeIndex(i)) => {
            if let Some(part) = parts.get_mut(*i) {
                let replaced = replace_subpattern(std::mem::replace(part, ResolvedPattern::hole(HoleId(0))), &rest_path, new_sub)?;
                *part = replaced;
                Ok(ResolvedPattern::Compose(parts))
            } else {
                Err(format!("Compose index out of bounds: {}", i))
            }
        }
        (ResolvedPattern::App { op, mut args }, PathStep::AppArg(i)) => {
            if let Some(arg) = args.get_mut(*i) {
                let replaced = replace_subpattern(std::mem::replace(arg, ResolvedPattern::hole(HoleId(0))), &rest_path, new_sub)?;
                *arg = replaced;
                Ok(ResolvedPattern::App { op, args })
            } else {
                Err(format!("App arg index out of bounds: {}", i))
            }
        }
        (ResolvedPattern::InDoctrine { doctrine, term }, PathStep::InDoctrine) => {
            let replaced = replace_subpattern(*term, &rest_path, new_sub)?;
            Ok(ResolvedPattern::InDoctrine { doctrine, term: Box::new(replaced) })
        }
        _ => Err("Path step does not match pattern constructor".to_string()),
    }
}

// ----------------------------------------------------------------------------
// Path encoding utilities
// ----------------------------------------------------------------------------

/// Encode a TermPath to a vector of u32s for compact storage.
pub fn encode_term_path(path: &TermPath) -> Vec<u32> {
    let mut encoded = Vec::new();
    for step in &path.steps {
        match step {
            PathStep::ComposeIndex(i) => {
                encoded.push((0u32 << 24) | (*i as u32 & 0x00FFFFFF));
            }
            PathStep::AppArg(i) => {
                encoded.push((1u32 << 24) | (*i as u32 & 0x00FFFFFF));
            }
            PathStep::InDoctrine => {
                encoded.push(2u32 << 24);
            }
        }
    }
    encoded
}

/// Decode a vector of u32s back to a TermPath.
pub fn decode_term_path(encoded: &[u32]) -> Option<TermPath> {
    let mut steps = Vec::new();
    for &code in encoded {
        let ty = code >> 24;
        let idx = code & 0x00FFFFFF;
        match ty {
            0 => steps.push(PathStep::ComposeIndex(idx as usize)),
            1 => steps.push(PathStep::AppArg(idx as usize)),
            2 => steps.push(PathStep::InDoctrine),
            _ => return None,
        }
    }
    Some(TermPath { steps })
}

// ----------------------------------------------------------------------------
// Deterministic hashing (v0.1, binder-free)
// ----------------------------------------------------------------------------

impl ResolvedPattern {
    /// Compute deterministic hash of a pattern (v0.1, binder-free).
    ///
    /// Hash is computed as:
    /// - Variant tag (u8)
    /// - For ids: their numeric representation (little-endian bytes)
    /// - For vectors: length (u64 LE) followed by each element's hash
    /// - For strings: length + UTF-8 bytes
    ///
    /// No α-invariance yet (added in PR-D).
    pub fn hash(&self) -> HashValue {
        let bytes = self.to_canonical_bytes();
        HashValue::hash_with_domain(constants::DOMAIN_PATTERN_V0, &bytes)
    }

    /// Serialize pattern to canonical byte representation.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.write_canonical_bytes(&mut buf);
        buf
    }

    /// Return first `n` bytes of canonical representation, padded with zeros if shorter.
    pub fn canonical_bytes_prefix(&self, n: usize) -> Vec<u8> {
        let bytes = self.to_canonical_bytes();
        let len = bytes.len().min(n);
        let mut prefix = vec![0u8; n];
        prefix[..len].copy_from_slice(&bytes[..len]);
        prefix
    }

    /// Return first 16 bytes of canonical representation for collision guard.
    pub fn guard_bytes(&self) -> [u8; 16] {
        let bytes = self.to_canonical_bytes();
        let mut guard = [0u8; 16];
        let len = bytes.len().min(16);
        guard[..len].copy_from_slice(&bytes[..len]);
        guard
    }

    /// Write canonical bytes to buffer.
    fn write_canonical_bytes(&self, buf: &mut Vec<u8>) {
        match self {
            ResolvedPattern::Hole(id) => {
                buf.push(0); // variant tag
                buf.extend_from_slice(&id.0.to_le_bytes());
            }
            ResolvedPattern::Generator(id) => {
                buf.push(1);
                buf.extend_from_slice(&id.0.to_le_bytes());
            }
            ResolvedPattern::Compose(children) => {
                buf.push(2);
                buf.extend_from_slice(&(children.len() as u64).to_le_bytes());
                for child in children {
                    child.write_canonical_bytes(buf);
                }
            }
            ResolvedPattern::App { op, args } => {
                buf.push(3);
                buf.extend_from_slice(&op.0.to_le_bytes());
                buf.extend_from_slice(&(args.len() as u64).to_le_bytes());
                for arg in args {
                    arg.write_canonical_bytes(buf);
                }
            }
            ResolvedPattern::Reject { code, msg } => {
                buf.push(4);
                // Write code string
                buf.extend_from_slice(&(code.len() as u64).to_le_bytes());
                buf.extend_from_slice(code.as_bytes());
                // Write msg string
                buf.extend_from_slice(&(msg.len() as u64).to_le_bytes());
                buf.extend_from_slice(msg.as_bytes());
            }
            ResolvedPattern::InDoctrine { doctrine, term } => {
                buf.push(5);
                // Write doctrine key (0 for None)
                if let Some(d) = doctrine {
                    buf.push(1); // presence flag
                    buf.extend_from_slice(&d.0.to_le_bytes());
                } else {
                    buf.push(0); // absence flag
                }
                term.write_canonical_bytes(buf);
            }
        }
    }
}

/// A pattern rewrite rule.
///
/// Specifies replacement of LHS pattern with RHS pattern, with hole correspondence.
#[derive(Clone)]
pub struct PatternRule {
    /// Left-hand side pattern ID.
    pub lhs_id: PatternId,
    /// Right-hand side pattern ID.
    pub rhs_id: PatternId,
    /// Left-hand side pattern (resolved).
    pub lhs_pattern: ResolvedPattern,
    /// Right-hand side pattern (resolved).
    pub rhs_pattern: ResolvedPattern,
    /// Hole correspondence mapping.
    pub hole_corr: HoleCorrespondence,
    /// Side conditions.
    pub side_conditions: Vec<SideCondition>,
    /// Rule hash.
    pub rule_hash: HashValue,
}

/// Identifier for a pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PatternId(pub u64);

/// Hole correspondence between LHS and RHS.
#[derive(Clone)]
pub struct HoleCorrespondence {
    // TODO: define structure
}

/// Side condition for a rule.
#[derive(Clone)]
pub struct SideCondition {
    // TODO: define structure
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_bytes_golden() {
        // Test 1: Simple hole
        let hole = ResolvedPattern::hole(HoleId(42));
        let bytes = hole.to_canonical_bytes();
        // tag 0 + u64 LE 42
        let expected = vec![
            0x00, // variant tag for Hole
            0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 42u64 LE
        ];
        assert_eq!(bytes, expected, "Hole(42) canonical bytes mismatch");

        // Test 2: Simple generator
        let generator = ResolvedPattern::generator(GeneratorId(100));
        let bytes = generator.to_canonical_bytes();
        // tag 1 + u64 LE 100
        let expected = vec![
            0x01, // variant tag for Generator
            0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 100u64 LE
        ];
        assert_eq!(bytes, expected, "Generator(100) canonical bytes mismatch");

        // Test 3: Compose of two generators
        let left = ResolvedPattern::generator(GeneratorId(1));
        let right = ResolvedPattern::generator(GeneratorId(2));
        let compose = ResolvedPattern::Compose(vec![left, right]);
        let bytes = compose.to_canonical_bytes();
        // tag 2 + len 2u64 LE + Generator(1) + Generator(2)
        let expected = vec![
            0x02, // variant tag for Compose
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 2u64 LE
            0x01, // Generator tag
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1u64 LE
            0x01, // Generator tag
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 2u64 LE
        ];
        assert_eq!(bytes, expected, "Compose(Generator(1), Generator(2)) canonical bytes mismatch");

        // Test 4: App with args (Hole(10), Generator(20))
        let arg1 = ResolvedPattern::hole(HoleId(10));
        let arg2 = ResolvedPattern::generator(GeneratorId(20));
        let app = ResolvedPattern::App {
            op: ConstructorId(5),
            args: vec![arg1, arg2],
        };
        let bytes = app.to_canonical_bytes();
        // tag 3 + op 5u64 LE + args len 2u64 LE + Hole(10) + Generator(20)
        let expected = vec![
            0x03, // variant tag for App
            0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 5u64 LE (ConstructorId)
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 2u64 LE (args length)
            0x00, // Hole tag
            0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 10u64 LE
            0x01, // Generator tag
            0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 20u64 LE
        ];
        assert_eq!(bytes, expected, "App(Constructor(5), [Hole(10), Generator(20)]) canonical bytes mismatch");
    }
}