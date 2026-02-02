//! No‑operation doctrine for benchmarking and testing.
//!
//! `NoOpDoctrine` validates every graph and never requires lowering to general
//! representation. It overrides `validate_fast_local` to avoid any allocation,
//! making it suitable for measuring worklist overhead.

use super::{Doctrine, DoctrineError};
use crate::arena::ArenaNodeId;
use crate::core::{HyperEdge, Node, NodeId, Codeswitch};
use crate::graph::{fast::FastGraph, TermGraph};
use std::collections::HashSet;

/// Doctrine that accepts all graphs and never forces general IR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NoOpDoctrine;

impl Doctrine for NoOpDoctrine {
    fn validate_edge<P>(
        &self,
        _edge: &HyperEdge,
        _graph: &Codeswitch<P>,
    ) -> Result<(), DoctrineError> {
        Ok(())
    }

    fn validate_node<P>(
        &self,
        _node: &Node<P>,
        _graph: &Codeswitch<P>,
    ) -> Result<(), DoctrineError> {
        Ok(())
    }

    fn validate_graph<P>(&self, _graph: &Codeswitch<P>) -> Result<(), DoctrineError> {
        Ok(())
    }

    fn validate_frontier<P>(
        &self,
        _frontier: &HashSet<NodeId>,
        _graph: &Codeswitch<P>,
    ) -> Result<(), DoctrineError> {
        Ok(())
    }
}

impl crate::doctrine::ext::ExtendedDoctrine for NoOpDoctrine {
    fn validate_fast_local<P>(
        &self,
        _graph: &FastGraph<P>,
        _focus: ArenaNodeId,
    ) -> Result<(), DoctrineError> {
        // No‑allocation fast path: always valid.
        Ok(())
    }

    fn requires_general_ir<P>(&self, _graph: &TermGraph<P>) -> bool {
        // Never require general IR.
        false
    }

    // We override `validate_fast_local_via_adapter` as well to avoid even
    // constructing the adapter, but the default already calls `validate_fast_local`.
}