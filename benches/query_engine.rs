//! Benchmarks for the query engine incremental caching.
//!
//! Measures:
//! - Cold run vs warm run performance
//! - Edit script impact (surface, macro, rewrite edits)
//! - Metrics: wall time, recompute counts, cache size
//!
//! # Edit scripts
//! 1. Surface edit: bump surface text fingerprint
//! 2. Macro edit: bump prelude macros fingerprint
//! 3. Rewrite edit: bump rewrite bundle fingerprint

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use codeswitch::fingerprint::HashValue;
use codeswitch::query::*;
use codeswitch::scope::{ScopeFingerprint, ScopeFingerprintComponents};

/// Creates a zero fingerprint for testing.
fn zero_fp() -> HashValue {
    HashValue::zero()
}

/// Creates a scope fingerprint with all zero components.
fn zero_scope_fp() -> ScopeFingerprint {
    let components = ScopeFingerprintComponents {
        core_ast_fp: zero_fp(),
        expansion_env_fp: zero_fp(),
        import_deps_fp: zero_fp(),
        kernel_policy_fp: zero_fp(),
        compiler_build_id: zero_fp(),
    };
    ScopeFingerprint::new(components)
}

/// Simulates a simple compilation pipeline with three queries:
/// ParseSurface → ExpandSurface → ElabCore
fn setup_pipeline(engine: &QueryEngine, scope_fp: &ScopeFingerprint) -> (QueryInstance, QueryInstance, QueryInstance) {
    let parse = QueryInstance::new(scope_fp.clone(), QueryKey::ParseSurface);
    let expand = QueryInstance::new(scope_fp.clone(), QueryKey::ExpandSurface);
    let elab = QueryInstance::new(scope_fp.clone(), QueryKey::ElabCore);

    // Define dependencies between them (will be recorded when queries execute)
    // We'll execute them in order to build the dependency graph
    let _ = engine.execute(parse.clone(), || {
        let surface_fp = HashValue::hash_with_domain(b"SURFACE", b"initial");
        record_surface_text_dependency(surface_fp);
        QueryResult::ParsedSurface(ParsedSurface(b"parsed".to_vec()))
    }).unwrap();

    let _ = engine.execute(expand.clone(), || {
        record_dependency(&parse);
        let prelude_fp = HashValue::hash_with_domain(b"PRELUDE", b"initial");
        record_prelude_macros_dependency(prelude_fp);
        QueryResult::ExpandedCore(ExpandedCore(b"expanded".to_vec()))
    }).unwrap();

    let _ = engine.execute(elab.clone(), || {
        record_dependency(&expand);
        let rewrite_fp = HashValue::hash_with_domain(b"REWRITE", b"initial");
        record_rewrite_bundle_dependency(rewrite_fp);
        QueryResult::ElabOutput(ElabOutput(b"elaborated".to_vec()))
    }).unwrap();

    (parse, expand, elab)
}

/// Benchmarks cold run (fresh engine) vs warm run (cached results).
fn bench_cold_vs_warm(c: &mut Criterion) {
    let scope_fp = zero_scope_fp();
    let parse_key = QueryKey::ParseSurface;
    let parse_instance = QueryInstance::new(scope_fp.clone(), parse_key);

    let mut group = c.benchmark_group("cold_vs_warm");

    // Cold run: fresh engine, no cache
    group.bench_function(BenchmarkId::new("parse", "cold"), |b| {
        b.iter(|| {
            let engine = QueryEngine::new();
            let result = engine.execute(black_box(parse_instance.clone()), || {
                let surface_fp = HashValue::hash_with_domain(b"SURFACE", b"bench");
                record_surface_text_dependency(surface_fp);
                QueryResult::ParsedSurface(ParsedSurface(b"parsed".to_vec()))
            });
            let _ = black_box(result);
        });
    });

    // Warm run: pre‑warmed cache
    group.bench_function(BenchmarkId::new("parse", "warm"), |b| {
        let engine = QueryEngine::new();
        // Warm the cache
        let _ = engine.execute(parse_instance.clone(), || {
            let surface_fp = HashValue::hash_with_domain(b"SURFACE", b"bench");
            record_surface_text_dependency(surface_fp);
            QueryResult::ParsedSurface(ParsedSurface(b"parsed".to_vec()))
        }).unwrap();

        b.iter(|| {
            let result = engine.execute(black_box(parse_instance.clone()), || {
                panic!("should not be called");
            });
            let _ = black_box(result);
        });
    });

    group.finish();
}

/// Benchmarks edit scripts: surface, macro, rewrite edits.
/// Measures recompute counts and cache invalidation impact.
fn bench_edit_scripts(c: &mut Criterion) {
    let scope_fp = zero_scope_fp();

    let mut group = c.benchmark_group("edit_scripts");
    group.sample_size(10); // smaller sample for speed

    // ---- Baseline: full pipeline cold ----
    group.bench_function(BenchmarkId::new("pipeline", "cold"), |b| {
        b.iter(|| {
            let engine = QueryEngine::new();
            let (parse, expand, elab) = setup_pipeline(&engine, &scope_fp);
            black_box((parse, expand, elab));
        });
    });

    // ---- Warm pipeline (all cached) ----
    group.bench_function(BenchmarkId::new("pipeline", "warm"), |b| {
        let engine = QueryEngine::new();
        let (parse, expand, elab) = setup_pipeline(&engine, &scope_fp);
        // Reset metrics to isolate warm run measurements
        engine.reset_metrics();

        b.iter(|| {
            // Re‑execute all queries (should hit cache)
            let _ = engine.execute(parse.clone(), || panic!("parse should hit"));
            let _ = engine.execute(expand.clone(), || panic!("expand should hit"));
            let _ = engine.execute(elab.clone(), || panic!("elab should hit"));
        });

        // Log metrics for inspection
        let metrics = engine.metrics();
        eprintln!("[BENCH] Warm pipeline metrics: hits={}, misses={}, recomputes={}",
                 metrics.query_hits, metrics.query_misses, metrics.query_recomputes);
    });

    // ---- Surface edit: bump surface text fingerprint ----
    group.bench_function(BenchmarkId::new("edit", "surface"), |b| {
        let engine = QueryEngine::new();
        let (parse, expand, elab) = setup_pipeline(&engine, &scope_fp);
        engine.reset_metrics();

        // Bump surface text version
        let surface_fp = HashValue::hash_with_domain(b"SURFACE", b"initial");
        engine.bump_version(DepKey::SurfaceText(surface_fp));

        b.iter(|| {
            // Re‑execute all queries after edit
            let _ = engine.execute(parse.clone(), || {
                let surface_fp = HashValue::hash_with_domain(b"SURFACE", b"initial");
                record_surface_text_dependency(surface_fp);
                QueryResult::ParsedSurface(ParsedSurface(b"parsed".to_vec()))
            });
            let _ = engine.execute(expand.clone(), || panic!("expand should hit if parse unchanged"));
            let _ = engine.execute(elab.clone(), || panic!("elab should hit"));
        });

        let metrics = engine.metrics();
        eprintln!("[BENCH] Surface edit metrics: hits={}, misses={}, recomputes={}, invalidation_ratio={:.2}%",
                 metrics.query_hits, metrics.query_misses, metrics.query_recomputes,
                 if metrics.query_recomputes > 0 { 100.0 * metrics.query_recomputes as f64 / 3.0 } else { 0.0 });
    });

    // ---- Macro edit: bump prelude macros fingerprint ----
    group.bench_function(BenchmarkId::new("edit", "macro"), |b| {
        let engine = QueryEngine::new();
        let (parse, expand, elab) = setup_pipeline(&engine, &scope_fp);
        engine.reset_metrics();

        // Bump prelude macros version
        let prelude_fp = HashValue::hash_with_domain(b"PRELUDE", b"initial");
        engine.bump_version(DepKey::PreludeMacros(prelude_fp));

        b.iter(|| {
            // Re‑execute all queries after edit
            let _ = engine.execute(parse.clone(), || panic!("parse should hit"));
            let _ = engine.execute(expand.clone(), || {
                record_dependency(&parse);
                let prelude_fp = HashValue::hash_with_domain(b"PRELUDE", b"initial");
                record_prelude_macros_dependency(prelude_fp);
                QueryResult::ExpandedCore(ExpandedCore(b"expanded".to_vec()))
            });
            let _ = engine.execute(elab.clone(), || panic!("elab should hit if expand unchanged"));
        });

        let metrics = engine.metrics();
        eprintln!("[BENCH] Macro edit metrics: hits={}, misses={}, recomputes={}, invalidation_ratio={:.2}%",
                 metrics.query_hits, metrics.query_misses, metrics.query_recomputes,
                 if metrics.query_recomputes > 0 { 100.0 * metrics.query_recomputes as f64 / 3.0 } else { 0.0 });
    });

    // ---- Rewrite edit: bump rewrite bundle fingerprint ----
    group.bench_function(BenchmarkId::new("edit", "rewrite"), |b| {
        let engine = QueryEngine::new();
        let (parse, expand, elab) = setup_pipeline(&engine, &scope_fp);
        engine.reset_metrics();

        // Bump rewrite bundle version
        let rewrite_fp = HashValue::hash_with_domain(b"REWRITE", b"initial");
        engine.bump_version(DepKey::RewriteBundle(rewrite_fp));

        b.iter(|| {
            // Re‑execute all queries after edit
            let _ = engine.execute(parse.clone(), || panic!("parse should hit"));
            let _ = engine.execute(expand.clone(), || panic!("expand should hit"));
            let _ = engine.execute(elab.clone(), || {
                record_dependency(&expand);
                let rewrite_fp = HashValue::hash_with_domain(b"REWRITE", b"initial");
                record_rewrite_bundle_dependency(rewrite_fp);
                QueryResult::ElabOutput(ElabOutput(b"elaborated".to_vec()))
            });
        });

        let metrics = engine.metrics();
        eprintln!("[BENCH] Rewrite edit metrics: hits={}, misses={}, recomputes={}, invalidation_ratio={:.2}%",
                 metrics.query_hits, metrics.query_misses, metrics.query_recomputes,
                 if metrics.query_recomputes > 0 { 100.0 * metrics.query_recomputes as f64 / 3.0 } else { 0.0 });
    });

    group.finish();
}

/// Benchmarks no‑op edit: dependency version changes but query result unchanged.
///
/// Demonstrates change‑based versioning: query version does not increment
/// when result fingerprint stays the same, preventing downstream recomputation.
fn bench_no_op_edit(c: &mut Criterion) {
    let scope_fp = zero_scope_fp();
    let mut group = c.benchmark_group("no_op_edit");
    group.sample_size(10);

    // Setup pipeline: ParseSurface → ExpandSurface → ElabCore
    let engine = QueryEngine::new();
    let parse = QueryInstance::new(scope_fp.clone(), QueryKey::ParseSurface);
    let expand = QueryInstance::new(scope_fp.clone(), QueryKey::ExpandSurface);
    let elab = QueryInstance::new(scope_fp.clone(), QueryKey::ElabCore);

    // Warm cache with initial execution
    let surface_fp = HashValue::hash_with_domain(b"SURFACE", b"initial");
    let prelude_fp = HashValue::hash_with_domain(b"PRELUDE", b"initial");
    let rewrite_fp = HashValue::hash_with_domain(b"REWRITE", b"initial");

    // Execute all queries to build dependency graph
    let _ = engine.execute(parse.clone(), || {
        record_surface_text_dependency(surface_fp);
        QueryResult::ParsedSurface(ParsedSurface(b"parsed".to_vec()))
    }).unwrap();
    let _ = engine.execute(expand.clone(), || {
        record_dependency(&parse);
        record_prelude_macros_dependency(prelude_fp);
        QueryResult::ExpandedCore(ExpandedCore(b"expanded".to_vec()))
    }).unwrap();
    let _ = engine.execute(elab.clone(), || {
        record_dependency(&expand);
        record_rewrite_bundle_dependency(rewrite_fp);
        QueryResult::ElabOutput(ElabOutput(b"elaborated".to_vec()))
    }).unwrap();

    // Reset metrics to isolate measurement
    engine.reset_metrics();

    // Bump surface text version (fingerprint unchanged)
    engine.bump_version(DepKey::SurfaceText(surface_fp));

    // Re‑execute all queries after no‑op edit
    group.bench_function("surface_no_op", |b| b.iter(|| {
        let _ = engine.execute(parse.clone(), || {
            record_surface_text_dependency(surface_fp);
            QueryResult::ParsedSurface(ParsedSurface(b"parsed".to_vec()))
        });
        let _ = engine.execute(expand.clone(), || panic!("expand should hit"));
        let _ = engine.execute(elab.clone(), || panic!("elab should hit"));
    }));

    // Verify metrics: only parse recomputed, others hit cache
    let metrics = engine.metrics();
    eprintln!("[BENCH] No‑op edit metrics: hits={}, misses={}, recomputes={}",
              metrics.query_hits, metrics.query_misses, metrics.query_recomputes);
    // Verify query version did NOT increment for expand/elab
    let parse_dep_key = DepKey::Query { scope_fp: scope_fp.clone(), query_key: QueryKey::ParseSurface };
    let expand_dep_key = DepKey::Query { scope_fp: scope_fp.clone(), query_key: QueryKey::ExpandSurface };
    let elab_dep_key = DepKey::Query { scope_fp: scope_fp.clone(), query_key: QueryKey::ElabCore };
    let parse_version = engine.current_version(&parse_dep_key);
    let expand_version = engine.current_version(&expand_dep_key);
    let elab_version = engine.current_version(&elab_dep_key);
    eprintln!("[BENCH] Query versions: parse={}, expand={}, elab={}",
              parse_version, expand_version, elab_version);
    // Expand and elab versions should be zero (never bumped because results unchanged)
    assert_eq!(expand_version, 0, "expand version should stay zero on no‑op edit");
    assert_eq!(elab_version, 0, "elab version should stay zero on no‑op edit");

    group.finish();
}

/// Benchmarks cache serialization/deserialization overhead.
fn bench_cache_persistence(c: &mut Criterion) {
    use tempfile::NamedTempFile;

    let scope_fp = zero_scope_fp();
    let parse_instance = QueryInstance::new(scope_fp.clone(), QueryKey::ParseSurface);

    let mut group = c.benchmark_group("cache_persistence");

    // Serialize cache to memory
    group.bench_function("serialize", |b| {
        let engine = QueryEngine::new();
        // Warm cache
        let _ = engine.execute(parse_instance.clone(), || {
            let surface_fp = HashValue::hash_with_domain(b"SURFACE", b"bench");
            record_surface_text_dependency(surface_fp);
            QueryResult::ParsedSurface(ParsedSurface(b"parsed".to_vec()))
        }).unwrap();

        b.iter(|| {
            let bytes = engine.to_cbor().unwrap();
            black_box(bytes);
        });
    });

    // Deserialize cache from memory
    group.bench_function("deserialize", |b| {
        let engine = QueryEngine::new();
        // Warm cache
        let _ = engine.execute(parse_instance.clone(), || {
            let surface_fp = HashValue::hash_with_domain(b"SURFACE", b"bench");
            record_surface_text_dependency(surface_fp);
            QueryResult::ParsedSurface(ParsedSurface(b"parsed".to_vec()))
        }).unwrap();
        let bytes = engine.to_cbor().unwrap();

        b.iter(|| {
            let engine2 = QueryEngine::from_cbor(&bytes).unwrap();
            black_box(engine2);
        });
    });

    // Round‑trip file I/O (uses temp file)
    group.bench_function("roundtrip_file", |b| {
        let engine = QueryEngine::new();
        // Warm cache
        let _ = engine.execute(parse_instance.clone(), || {
            let surface_fp = HashValue::hash_with_domain(b"SURFACE", b"bench");
            record_surface_text_dependency(surface_fp);
            QueryResult::ParsedSurface(ParsedSurface(b"parsed".to_vec()))
        }).unwrap();

        b.iter(|| {
            let temp_file = NamedTempFile::new().unwrap();
            engine.save_to_file(temp_file.path()).unwrap();
            let engine2 = QueryEngine::load_from_file(temp_file.path()).unwrap();
            black_box(engine2);
            // temp file automatically deleted on drop
        });
    });

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10); // smaller sample for speed
    targets = bench_cold_vs_warm, bench_edit_scripts, bench_no_op_edit, bench_cache_persistence
);
criterion_main!(benches);