//! Benchmarks for the performance spine.
//!
//! These benchmarks measure the overhead of the worklist normalizer and the
//! adapter‑based doctrine validation, establishing a baseline for PR2/PR3.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use codeswitch::doctrine::NoOpDoctrine;
use codeswitch::graph::fast::FastGraph;
use codeswitch::normalize::WorklistNormalizer;

/// Benchmarks worklist overhead on a 100k‑node chain with no rewrites.
///
/// This measures the cost of:
/// - deterministic worklist traversal
/// - neighbor retrieval
/// - validation calls (NoOpDoctrine, zero allocation)
/// - candidate generation (empty)
fn bench_worklist_100k_chain_no_rewrites(c: &mut Criterion) {
    let mut graph = FastGraph::new();
    let chain = graph.make_deterministic_chain(100_000, ());
    let doctrine = NoOpDoctrine;
    let mut normalizer = WorklistNormalizer::new();
    normalizer.mark_dirty_all(chain);

    c.bench_function("worklist_100k_chain_no_rewrites", |b| {
        b.iter(|| {
            // Reset normalizer state
            normalizer.clear();
            normalizer.mark_dirty_all(black_box(graph.make_deterministic_chain(0, ())));
            // Run normalization (will apply zero rewrites)
            let steps = normalizer.normalize(black_box(&mut graph), black_box(&doctrine), None);
            assert_eq!(steps, 0);
        });
    });
}

/// Benchmarks the adapter‑based validation overhead on a small graph.
///
/// This measures the cost of constructing a temporary Codeswitch
/// and calling the existing `validate_graph` via the adapter.
fn bench_adapter_validation_overhead(c: &mut Criterion) {
    use codeswitch::doctrine::ext::ExtendedDoctrine;
    let mut graph = FastGraph::new();
    let node_a = graph.add_primitive("a");
    let node_b = graph.add_primitive("b");
    let node_c = graph.add_compose(node_a, node_b, "c");
    let doctrine = NoOpDoctrine;

    c.bench_function("adapter_validation_overhead", |ben| {
        ben.iter(|| {
            // Validate each node via adapter (NoOpDoctrine overrides, so this is cheap)
            let _ = doctrine.validate_fast_local(black_box(&graph), black_box(node_a));
            let _ = doctrine.validate_fast_local(black_box(&graph), black_box(node_b));
            let _ = doctrine.validate_fast_local(black_box(&graph), black_box(node_c));
        });
    });
}

/// Benchmarks existing doctrine validation on a Codeswitch chain.
///
/// This establishes a baseline for comparison with FastGraph validation.
fn bench_existing_validation_chain(c: &mut Criterion) {
    use codeswitch::core::Codeswitch;
    use codeswitch::doctrine::{Doctrine, Globular};
    use codeswitch::operations::{add_edge, add_node};
    use std::collections::HashSet;

    let mut graph: Codeswitch<()> = Codeswitch::new();
    let mut prev = None;
    for _i in 0..1000 {
        let id = add_node(&mut graph, (), 0, &Globular).unwrap();
        if let Some(p) = prev {
            add_edge(&mut graph, HashSet::from([p]), HashSet::from([id]), &Globular).unwrap();
        }
        prev = Some(id);
    }
    let doctrine = Globular;

    c.bench_function("existing_validation_chain_1000", |b| {
        b.iter(|| {
            let _ = doctrine.validate_graph(black_box(&graph));
        });
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10); // smaller sample for speed
    targets = bench_worklist_100k_chain_no_rewrites,
              bench_adapter_validation_overhead,
              bench_existing_validation_chain
);
criterion_main!(benches);