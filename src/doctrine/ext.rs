//! Extended doctrine trait for FastGraph compatibility.
//!
//! This trait adds methods for validating FastGraph local neighborhoods and
//! deciding when to lower to a general representation. It is automatically
//! implemented for any existing `Doctrine`.

use super::{Doctrine, DoctrineError};
use crate::arena::ArenaNodeId;
use crate::graph::{fast::FastGraph, TermGraph};

/// Extension of `Doctrine` with FastGraph‑specific validation.
pub trait ExtendedDoctrine: Doctrine {
    /// Validates the local neighborhood around `focus` in a FastGraph.
    ///
    /// The default implementation delegates to `validate_fast_local_via_adapter`,
    /// which reconstructs a temporary Codeswitch and calls the existing
    /// `validate_graph`. Override this method for direct FastGraph validation
    /// when performance is critical (e.g., in `NoOpDoctrine`).
    fn validate_fast_local<P>(
        &self,
        graph: &FastGraph<P>,
        focus: ArenaNodeId,
    ) -> Result<(), DoctrineError>
    where
        P: Clone,
    {
        self.validate_fast_local_via_adapter(graph, focus)
    }

    /// Checks whether the given graph requires lowering to a general
    /// representation (`GeneralGraph`).
    ///
    /// This decision must be:
    /// - **O(1)** (using precomputed flags in `FastGraph`).
    /// - **monotone per normalization run**: once `true` for a given graph
    ///   state, it must never become `false` during the same run.
    fn requires_general_ir<P>(&self, graph: &TermGraph<P>) -> bool {
        match graph {
            TermGraph::Fast(fast) => {
                fast.max_out_arity() > 1
                    || fast.has_non_tree_sharing()
                    || fast.max_in_arity() > 1
            }
            // TermGraph::General(_) => true, // PR2
        }
    }

    /// Adapter‑based validation for FastGraph local neighborhoods.
    ///
    /// Constructs a temporary Codeswitch representing the neighborhood
    /// of `focus` and calls `self.validate_graph` on it.
    ///
    /// This method is provided as a default for `validate_fast_local`; it
    /// ensures backward compatibility but may allocate. Doctrines that need
    /// high‑performance validation should override `validate_fast_local`.
    fn validate_fast_local_via_adapter<P>(
        &self,
        graph: &FastGraph<P>,
        focus: ArenaNodeId,
    ) -> Result<(), DoctrineError>
    where
        P: Clone,
    {
        use crate::doctrine::adapter::FastToStonewallAdapter;
        let adapter = FastToStonewallAdapter::new(graph, focus);
        self.validate_graph(&adapter)
    }
}

