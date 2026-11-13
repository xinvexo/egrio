//! Coarse-mutex session-table baselines under client-scale concurrency —
//! the gate instrument for sharding the session-table locks: coarse
//! `std::Mutex` is fine at current concurrency, and sharding stays a measured
//! question at higher connection counts.
//!
//! Run: cargo bench -p egrio-core --bench session_tables --features bench-internals
//!
//! Covered:
//! - UDP session table: the per-datagram bookkeeping sequence of
//!   `send_udp_flow_datagram` (idle sweep → socket-cache lookup → stats record)
//!   at 16 and 1024 (the table cap) resident sessions, plus each op alone
//!   to attribute where the resident-size dependence lives;
//! - the same sequence hammered from 4 OS threads (the default worker
//!   count) on disjoint flows — a worst case by construction: real traffic
//!   interleaves socket waits between table touches, a tight loop does not;
//! - the server dimension: the same 4-thread
//!   contention with a distinct authenticated user per thread, so the
//!   multi-user `Arc<str>` keying's contention cost is attributable;
//! - session registry: one relay session's ledger lifecycle
//!   (register → stamps → guard drop), 1 thread vs 4 threads, and the same
//!   roundtrip against 16 then 1024 resident sessions — the admission-scale
//!   cost a public inbound's cap check pays under a standing load.
//!
//! Reading the contended groups: each criterion "element" is one op per
//! thread, so the reported throughput is the aggregate op rate across the
//! 4 threads and the reported time is the per-op latency under contention.

use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use egrio_core::bench_internals::{BenchSessionRegistry, BenchUdpSessionTable};

const CONTENTION_THREADS: usize = 4;
/// A fixed logical clock keeps every resident session fresh, so the sweep
/// measures its full-table scan without ever emptying the table mid-bench.
const BENCH_NOW: i64 = 1_000_000;
const RESIDENT_SIZES: [u32; 2] = [16, 1024];
/// The snapshot's loads, up to the registry's admission cap: what the row
/// building costs is what the lock is held for.
const SNAPSHOT_SIZES: [u32; 3] = [16, 1024, 4096];

fn bench_udp_table(c: &mut Criterion) {
    let mut group = c.benchmark_group("udp_session_table");
    group.throughput(Throughput::Elements(1));
    for resident in RESIDENT_SIZES {
        let table = BenchUdpSessionTable::new();
        table.populate(resident, BENCH_NOW);
        assert_eq!(table.len(), resident as usize);
        // Steady state: the measured datagram belongs to a resident flow.
        let datagram = table.datagram(0);

        group.bench_with_input(
            BenchmarkId::new("per_datagram_1_thread", resident),
            &resident,
            |b, _| b.iter(|| table.per_datagram(&datagram, BENCH_NOW)),
        );
        group.bench_with_input(
            BenchmarkId::new("sweep_only", resident),
            &resident,
            |b, _| b.iter(|| table.sweep(BENCH_NOW)),
        );
        group.bench_with_input(
            BenchmarkId::new("record_only", resident),
            &resident,
            |b, _| b.iter(|| table.record(&datagram, BENCH_NOW)),
        );
    }
    group.finish();
}

fn bench_udp_table_contended(c: &mut Criterion) {
    let mut group = c.benchmark_group("udp_session_table_contended");
    group.throughput(Throughput::Elements(CONTENTION_THREADS as u64));
    for resident in RESIDENT_SIZES {
        group.bench_with_input(
            BenchmarkId::new("per_datagram_4_threads", resident),
            &resident,
            |b, &resident| {
                b.iter_custom(|iters| {
                    let table = BenchUdpSessionTable::new();
                    table.populate(resident, BENCH_NOW);
                    let barrier = Arc::new(Barrier::new(CONTENTION_THREADS + 1));
                    let workers: Vec<_> = (0..CONTENTION_THREADS)
                        .map(|worker| {
                            let table = table.clone();
                            let barrier = Arc::clone(&barrier);
                            thread::spawn(move || {
                                // Disjoint resident flows per thread: the
                                // contention is on the shared locks, not on
                                // one entry's bytes.
                                let datagram = table.datagram(worker as u32);
                                barrier.wait();
                                for _ in 0..iters {
                                    table.per_datagram(&datagram, BENCH_NOW);
                                }
                            })
                        })
                        .collect();
                    barrier.wait();
                    let started = Instant::now();
                    for worker in workers {
                        worker.join().expect("bench worker thread");
                    }
                    started.elapsed()
                })
            },
        );
    }
    group.finish();
}

fn bench_session_registry(c: &mut Criterion) {
    let mut group = c.benchmark_group("session_registry");

    group.throughput(Throughput::Elements(1));
    let registry = BenchSessionRegistry::new();
    group.bench_function("session_roundtrip_1_thread", |b| {
        b.iter(|| registry.session_roundtrip())
    });
    assert_eq!(registry.active(), 0);

    group.throughput(Throughput::Elements(CONTENTION_THREADS as u64));
    group.bench_function("session_roundtrip_4_threads", |b| {
        b.iter_custom(|iters| {
            let registry = BenchSessionRegistry::new();
            let barrier = Arc::new(Barrier::new(CONTENTION_THREADS + 1));
            let workers: Vec<_> = (0..CONTENTION_THREADS)
                .map(|_| {
                    let registry = registry.clone();
                    let barrier = Arc::clone(&barrier);
                    thread::spawn(move || {
                        barrier.wait();
                        for _ in 0..iters {
                            registry.session_roundtrip();
                        }
                    })
                })
                .collect();
            barrier.wait();
            let started = Instant::now();
            for worker in workers {
                worker.join().expect("bench worker thread");
            }
            started.elapsed()
        })
    });
    group.finish();
}

/// The per-user variant of [`bench_udp_table_contended`], the server
/// dimension: every thread's flow key carries a distinct
/// authenticated `user`, so this attributes any contention shift to the
/// multi-user keying rather than the flow tuple alone.
fn bench_udp_table_per_user_contended(c: &mut Criterion) {
    let mut group = c.benchmark_group("udp_session_table_per_user_contended");
    group.throughput(Throughput::Elements(CONTENTION_THREADS as u64));
    for resident in RESIDENT_SIZES {
        group.bench_with_input(
            BenchmarkId::new("per_datagram_4_threads", resident),
            &resident,
            |b, &resident| {
                b.iter_custom(|iters| {
                    let table = BenchUdpSessionTable::new();
                    table.populate_per_user(resident, BENCH_NOW);
                    let barrier = Arc::new(Barrier::new(CONTENTION_THREADS + 1));
                    let workers: Vec<_> = (0..CONTENTION_THREADS)
                        .map(|worker| {
                            let table = table.clone();
                            let barrier = Arc::clone(&barrier);
                            thread::spawn(move || {
                                // Distinct user per thread: the contention is
                                // on the shared locks and each key clones an
                                // Arc<str> user (the multi-user dimension).
                                let datagram = table.user_datagram(worker as u32, worker as u32);
                                barrier.wait();
                                for _ in 0..iters {
                                    table.per_datagram(&datagram, BENCH_NOW);
                                }
                            })
                        })
                        .collect();
                    barrier.wait();
                    let started = Instant::now();
                    for worker in workers {
                        worker.join().expect("bench worker thread");
                    }
                    started.elapsed()
                })
            },
        );
    }
    group.finish();
}

/// Admission and teardown cost against a standing session load: the registry
/// roundtrip measured while 16 then 1024 sessions are held resident, the
/// pressure a public inbound's admission cap check runs under — the baseline
/// before the session-table sharding question reopens.
fn bench_session_registry_admission_scale(c: &mut Criterion) {
    let mut group = c.benchmark_group("session_registry_admission_scale");
    group.throughput(Throughput::Elements(1));
    for resident in RESIDENT_SIZES {
        group.bench_with_input(
            BenchmarkId::new("roundtrip_1_thread", resident),
            &resident,
            |b, &resident| {
                let registry = BenchSessionRegistry::new();
                registry.populate(resident as usize);
                assert_eq!(registry.active(), u64::from(resident));
                b.iter(|| registry.session_roundtrip());
            },
        );
    }
    group.finish();
}

/// What a host's poll of the connection table costs, and so how long the
/// ledger lock is held away from admissions and teardowns, at the standing
/// loads a public inbound reaches -- up to the registry's own cap.
fn bench_session_registry_snapshot(c: &mut Criterion) {
    let mut group = c.benchmark_group("session_registry_snapshot");
    for resident in SNAPSHOT_SIZES {
        group.throughput(Throughput::Elements(u64::from(resident)));
        group.bench_with_input(
            BenchmarkId::new("connection_table", resident),
            &resident,
            |b, &resident| {
                let registry = BenchSessionRegistry::new();
                registry.populate(resident as usize);
                assert_eq!(registry.active(), u64::from(resident));
                b.iter(|| assert_eq!(registry.snapshot(), resident as usize));
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_udp_table,
    bench_udp_table_contended,
    bench_udp_table_per_user_contended,
    bench_session_registry,
    bench_session_registry_admission_scale,
    bench_session_registry_snapshot
);
criterion_main!(benches);
