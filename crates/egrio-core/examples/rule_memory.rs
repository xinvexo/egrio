//! Rule-set instrument: the live heap a profile's rule providers cost in each
//! copy the product keeps — the entry lists a host hands the Core and the
//! compiled matcher the Core routes with — and what one route decision over
//! that matcher costs, which every new connection pays.
//!
//! Reads every cached rule-provider file under `EGRIO_RULE_DIR` (Clash
//! `payload:` lists; a file whose entries are all CIDRs is `ipcidr`, one
//! with rule texts such as `DOMAIN-SUFFIX,example.com` is `classical`, any
//! other `domain`), builds the `RuntimeProfile` a host would (one RULE-SET
//! rule per provider, then MATCH) and compiles it into a Core.
//!
//! Usage:
//!   EGRIO_RULE_DIR=<dir> cargo run --release -p egrio-core --example rule_memory

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use egrio_core::profile::{RuleSetBehavior, RuleSetContent, RuleSetEntries};
use egrio_core::{
    NativeCoreDevice, RouteMatchInput, RouteRule, RuleEngine, RuleKind, RuntimeProfile,
};

#[path = "support/os_memory.rs"]
mod os_memory;
use os_memory::os_memory;

struct CountingAllocator;

static LIVE_HEAP: AtomicUsize = AtomicUsize::new(0);
static PEAK_HEAP: AtomicUsize = AtomicUsize::new(0);

fn grew(size: usize) {
    let live = LIVE_HEAP.fetch_add(size, Ordering::Relaxed) + size;
    PEAK_HEAP.fetch_max(live, Ordering::Relaxed);
}

// SAFETY: every call forwards to `System` unchanged; the counters only
// observe sizes.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            grew(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            grew(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        LIVE_HEAP.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(pointer, layout, new_size) };
        if !moved.is_null() {
            grew(new_size);
            LIVE_HEAP.fetch_sub(layout.size(), Ordering::Relaxed);
        }
        moved
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

fn main() {
    let dir = std::env::var("EGRIO_RULE_DIR").unwrap_or_else(|_| {
        eprintln!("set EGRIO_RULE_DIR to a directory of rule-provider files");
        std::process::exit(2);
    });
    let mut files = Vec::new();
    collect_files(Path::new(&dir), &mut files);
    files.sort();

    let start = LIVE_HEAP.load(Ordering::Relaxed);
    let mut rule_sets = Vec::new();
    let mut entry_bytes = 0_usize;
    for (index, file) in files.iter().enumerate() {
        let body = std::fs::read_to_string(file).unwrap_or_default();
        let entries = payload_entries(&body);
        if entries.is_empty() {
            continue;
        }
        entry_bytes += entries.iter().map(str::len).sum::<usize>();
        // A name holds no comma; a rule text has one after its kind.
        let behavior = if entries.iter().all(|entry| looks_like_cidr(entry)) {
            RuleSetBehavior::Ipcidr
        } else if entries.iter().any(|entry| entry.contains(',')) {
            RuleSetBehavior::Classical
        } else {
            RuleSetBehavior::Domain
        };
        rule_sets.push(RuleSetContent {
            name: format!("set{index}"),
            behavior,
            entries,
        });
    }
    let entries: usize = rule_sets.iter().map(|set| set.entries.len()).sum();
    let classical_entries: usize = rule_sets
        .iter()
        .filter(|set| set.behavior == RuleSetBehavior::Classical)
        .map(|set| set.entries.len())
        .sum();
    // What a decision is asked, taken from the sets themselves: a name the
    // first set claims, a name only the last one claims, a name no set has
    // (every set is consulted, then MATCH), an address inside a CIDR set and
    // one outside every set.
    let probes = decision_probes(&rule_sets);
    let mut profile = RuntimeProfile::new("rule-memory");
    profile.rules = rule_sets
        .iter()
        .map(|set| RouteRule {
            kind: RuleKind::RuleSet,
            payload: Some(&set.name),
            outbound: "DIRECT",
            no_resolve: true,
        })
        .chain(std::iter::once(RouteRule {
            kind: RuleKind::Match,
            payload: None,
            outbound: "DIRECT",
            no_resolve: false,
        }))
        .collect();
    profile.rule_sets = rule_sets;
    let host_copy = LIVE_HEAP.load(Ordering::Relaxed) - start;

    PEAK_HEAP.store(LIVE_HEAP.load(Ordering::Relaxed), Ordering::Relaxed);
    let before_compile = LIVE_HEAP.load(Ordering::Relaxed);
    let core = NativeCoreDevice::compile(&profile);
    let compiled = LIVE_HEAP.load(Ordering::Relaxed) - before_compile;
    let compile_peak = PEAK_HEAP.load(Ordering::Relaxed) - before_compile;
    let os_both = os_memory();

    drop(core);
    let os_core_only = os_memory();

    // The decision cost over the same sets. Its own engine, compiled after
    // the memory numbers are taken so it cannot move them.
    let engine = RuleEngine::compile(&profile);
    let timings: Vec<(String, f64)> = probes
        .iter()
        .map(|(label, input)| (label.clone(), nanos_per_decision(&engine, input)))
        .collect();
    drop(engine);
    drop(profile);

    println!("{{");
    println!("  \"harness\": \"egrio-core rule_memory\",");
    println!("  \"os\": \"{}\",", std::env::consts::OS);
    println!("  \"providers\": {},", files.len());
    println!("  \"entries\": {entries},");
    println!("  \"classical_entries\": {classical_entries},");
    println!("  \"entry_text_mib\": {:.1},", mib(entry_bytes));
    println!("  \"host_entry_lists_mib\": {:.1},", mib(host_copy));
    println!("  \"core_compiled_mib\": {:.1},", mib(compiled));
    println!("  \"compile_peak_mib\": {:.1},", mib(compile_peak));
    println!(
        "  \"os_private_with_both_mib\": {:.1},",
        mib(os_both.private)
    );
    println!(
        "  \"os_private_core_only_mib\": {:.1},",
        mib(os_core_only.private)
    );
    println!("  \"decision_nanos\": {{");
    let last = timings.len().saturating_sub(1);
    for (index, (label, nanos)) in timings.iter().enumerate() {
        let comma = if index == last { "" } else { "," };
        println!("    \"{label}\": {nanos:.0}{comma}");
    }
    println!("  }}");
    println!("}}");
}

/// The inputs the decision timings route, drawn from the loaded sets so they
/// exercise the real buckets.
fn decision_probes(rule_sets: &[RuleSetContent]) -> Vec<(String, RouteMatchInput)> {
    let domain_sets: Vec<&RuleSetContent> = rule_sets
        .iter()
        .filter(|set| set.behavior != RuleSetBehavior::Ipcidr)
        .collect();
    let cidr_sets: Vec<&RuleSetContent> = rule_sets
        .iter()
        .filter(|set| set.behavior == RuleSetBehavior::Ipcidr)
        .collect();
    let mut probes = Vec::new();
    let host_input = |host: &str| RouteMatchInput {
        host: Some(host.to_string()),
        destination_port: Some(443),
        network: Some(egrio_core::rule_engine::TransportNetwork::Tcp),
        ..Default::default()
    };
    // A `domain` set's entry is a name behind its shape prefix; a
    // `classical` set's names follow `DOMAIN,` and `DOMAIN-SUFFIX,`.
    let name_of = |set: &RuleSetContent| {
        set.entries.iter().find_map(|entry| {
            let name = if set.behavior == RuleSetBehavior::Classical {
                let (kind, rest) = entry.split_once(',')?;
                matches!(kind.trim(), "DOMAIN" | "DOMAIN-SUFFIX")
                    .then(|| rest.split(',').next().unwrap_or_default().trim())?
            } else {
                entry.trim_start_matches(['+', '.'])
            };
            (!name.is_empty() && !name.contains('*')).then(|| name.to_string())
        })
    };
    if let Some(name) = domain_sets.first().and_then(|set| name_of(set)) {
        probes.push(("name_in_the_first_set".to_string(), host_input(&name)));
    }
    if domain_sets.len() > 1 {
        if let Some(name) = domain_sets.last().and_then(|set| name_of(set)) {
            probes.push(("name_in_the_last_set".to_string(), host_input(&name)));
        }
    }
    probes.push((
        "name_in_no_set".to_string(),
        host_input("no-set-claims-this.bench.example"),
    ));
    let address_input = |text: &str| RouteMatchInput {
        destination_ip: text.parse().ok(),
        destination_port: Some(443),
        network: Some(egrio_core::rule_engine::TransportNetwork::Tcp),
        ..Default::default()
    };
    if let Some(cidr) = cidr_sets
        .first()
        .and_then(|set| set.entries.iter().find(|entry| entry.contains('.')))
    {
        let address = cidr.split('/').next().unwrap_or(cidr).to_string();
        probes.push(("address_in_a_cidr_set".to_string(), address_input(&address)));
    }
    probes.push((
        "address_in_no_set".to_string(),
        address_input("198.51.100.7"),
    ));
    probes
}

/// Nanoseconds one decision takes, over enough of them for the clock to
/// resolve it and after a warmup that leaves the buckets in cache.
fn nanos_per_decision(engine: &RuleEngine, input: &RouteMatchInput) -> f64 {
    const WARMUP: usize = 2_000;
    const ROUNDS: usize = 50_000;
    for _ in 0..WARMUP {
        std::hint::black_box(engine.route(std::hint::black_box(input)));
    }
    let start = std::time::Instant::now();
    for _ in 0..ROUNDS {
        std::hint::black_box(engine.route(std::hint::black_box(input)));
    }
    start.elapsed().as_nanos() as f64 / ROUNDS as f64
}

fn collect_files(dir: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, files);
        } else {
            files.push(path);
        }
    }
}

/// The `payload:` list items of a Clash rule-provider document, unquoted,
/// in one entry block as a host builds it.
fn payload_entries(body: &str) -> RuleSetEntries {
    body.lines()
        .filter_map(|line| line.trim().strip_prefix("- "))
        .map(|item| item.trim().trim_matches(|c| c == '\'' || c == '"'))
        .filter(|item| !item.is_empty() && !item.starts_with('#'))
        .collect()
}

fn looks_like_cidr(entry: &str) -> bool {
    entry.contains('/')
        && entry
            .chars()
            .all(|c| c.is_ascii_hexdigit() || matches!(c, '.' | ':' | '/'))
}

fn mib(bytes: usize) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}
