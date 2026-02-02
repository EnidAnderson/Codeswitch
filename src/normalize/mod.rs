//! Normalization engine for FastGraph.
//!
//! This module implements a deterministic worklist‑based normalizer that
//! applies local rewrites validated by a doctrine.

pub mod worklist;
// pub mod result; // PR2

pub use worklist::WorklistNormalizer;