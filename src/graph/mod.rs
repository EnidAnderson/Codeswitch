//! Graph representations for the performance spine.
//!
//! This module provides two main graph representations:
//! - `FastGraph`: a restricted IR for the fast path (no identities, limited arity).
//! - `GeneralGraph`: the full ω‑hypergraph representation (introduced in PR2).
//!
//! The `TermGraph` enum chooses between them at runtime.

pub mod fast;
// pub mod general; // PR2

pub use fast::FastGraph;

/// Runtime choice between fast and general graph representations.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TermGraph<P> {
    /// Fast‑path representation (binary compose/tensor, small arity).
    Fast(fast::FastGraph<P>),
    // General ω‑hypergraph representation (arbitrary hyperedges).
    // General(general::GeneralGraph<P>), // PR2
}


// Placeholder for PR2
// impl<P> TermGraph<P> {
//     pub fn lower_if_needed(&mut self, doctrine: &impl crate::doctrine::ExtendedDoctrine) {
//         match self {
//             TermGraph::Fast(fast) => {
//                 if doctrine.requires_general_ir(self) {
//                     *self = TermGraph::General(fast.to_general());
//                 }
//             }
//             TermGraph::General(_) => {}
//         }
//     }
// }