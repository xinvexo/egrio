//! App-process memory instrument: what the desktop backend holds for a real
//! profile, step by step, so an idle app's footprint can be attributed
//! instead of guessed.
//!
//! Each step reports the live heap and the live allocation count from a
//! counting allocator, as the Core's own instruments do. The steps follow a
//! Runtime start: read the manifest, compose the profile the Core receives
//! (the source's rules, every rule provider's entries, the geodata its rules
//! name), compile the Core from it, start a Runtime on a listener and give
//! it the profile, take 30 000 connections into the connection table's
//! history, and hold every row of it as a table does.
//!
//! Usage:
//!   EGRIO_DATA_DIR=<an app data directory> \
//!     cargo run --release -p egrio-desktop --features bench-internals --example app_memory

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct CountingAllocator;

static LIVE_HEAP: AtomicUsize = AtomicUsize::new(0);
static LIVE_ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static PEAK_HEAP: AtomicUsize = AtomicUsize::new(0);

fn grew(size: usize) {
    let live = LIVE_HEAP.fetch_add(size, Ordering::Relaxed) + size;
    PEAK_HEAP.fetch_max(live, Ordering::Relaxed);
    LIVE_ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
}

fn shrank(size: usize) {
    LIVE_HEAP.fetch_sub(size, Ordering::Relaxed);
    LIVE_ALLOCATIONS.fetch_sub(1, Ordering::Relaxed);
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
        shrank(layout.size());
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(pointer, layout, new_size) };
        if !moved.is_null() {
            grew(new_size);
            shrank(layout.size());
        }
        moved
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

struct Step {
    label: &'static str,
    heap: usize,
    allocations: usize,
}

fn step(label: &'static str) -> Step {
    Step {
        label,
        heap: LIVE_HEAP.load(Ordering::Relaxed),
        allocations: LIVE_ALLOCATIONS.load(Ordering::Relaxed),
    }
}

fn main() {
    if std::env::var_os("EGRIO_DATA_DIR").is_none() {
        eprintln!("set EGRIO_DATA_DIR to an app data directory (configuration/ and geodata/)");
        std::process::exit(2);
    }
    let mut steps = vec![step("process start")];
    let light = egrio_desktop::bench::active_profile_without_providers()
        .unwrap_or_else(|error| panic!("read the active profile: {error}"));
    steps.push(step("the profile the pages read"));
    // A page's reading lasts one request; the source it parsed stays with
    // the store for the next one.
    drop(light);
    steps.push(step("that reading released, its parsed source kept"));
    let profile = egrio_desktop::bench::active_profile_for_core()
        .unwrap_or_else(|error| panic!("compose the profile: {error}"));
    steps.push(step("the profile the Core receives"));
    let core = egrio_core::NativeCoreDevice::compile(&profile);
    steps.push(step("the Core compiled from it"));
    drop(core);
    steps.push(step("that Core released"));

    let entries: usize = profile.rule_sets.iter().map(|set| set.entries.len()).sum();
    let geoip: usize = profile
        .geodata
        .geoip
        .as_ref()
        .map_or(0, |codes| codes.iter().map(|code| code.cidrs.len()).sum());
    let geosite: usize = profile
        .geodata
        .geosite
        .as_ref()
        .map_or(0, |selections| selections.iter().map(|s| s.len()).sum());

    // What a started Runtime holds: the compiled Core, the listener, the DNS
    // service and its cache, the fake-IP store, the session tables and the
    // egress. The start takes the profile, as the app's does, so the profile
    // is not held beside the Core it became. Capture layers are a platform
    // transaction and stay out of this; a listener-only start is the same
    // Core state behind them.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("instrument runtime");
    let manager = egrio_core::CoreSessionManager::default();
    let started = runtime.block_on(
        manager.start_with_config(egrio_core::CoreSessionStartConfig {
            profile,
            egress: Default::default(),
            listen_addr: Some(([127, 0, 0, 1], 0).into()),
            dns_listen_addr: None,
            inbound: egrio_core::CoreInbound::Mixed,
            hysteria2: None,
            socket_guard: None,
        }),
    );
    let listening = started.as_ref().map(|status| status.listen_addr.clone());
    steps.push(step(
        "a Runtime started on a listener, the profile given to it",
    ));
    println!("// listening on {listening:?}");

    // The app's own retention beside the engine: the connection table's
    // history, which keeps rows until a restart or a user clear, and what
    // a table showing all of it holds on top.
    let history = fill_connection_history();
    steps.push(step("the connection history after 30 000 connections"));
    let table = history.changes_since(None);
    steps.push(step("a table holding every row of it"));
    drop(table);
    drop(history);
    manager.stop();
    drop(manager);
    drop(runtime);
    steps.push(step("all of it released"));

    println!("{{");
    println!("  \"harness\": \"egrio-desktop app_memory\",");
    println!("  \"os\": \"{}\",", std::env::consts::OS);
    println!("  \"rule_providers\": {},", profile_providers());
    println!("  \"rule_set_entries\": {entries},");
    println!("  \"geoip_networks\": {geoip},");
    println!("  \"geosite_domains\": {geosite},");
    println!("  \"steps\": [");
    let last = steps.len() - 1;
    let mut previous: Option<&Step> = None;
    for (index, current) in steps.iter().enumerate() {
        let (added_heap, added_allocations) = previous.map_or((0_i64, 0_i64), |before| {
            (
                current.heap as i64 - before.heap as i64,
                current.allocations as i64 - before.allocations as i64,
            )
        });
        println!(
            "    {{ \"step\": \"{}\", \"live_heap_mib\": {:.2}, \"live_allocations\": {}, \"added_mib\": {:.2}, \"added_allocations\": {} }}{}",
            current.label,
            mib(current.heap),
            current.allocations,
            added_heap as f64 / (1024.0 * 1024.0),
            added_allocations,
            if index == last { "" } else { "," }
        );
        previous = Some(current);
    }
    println!("  ],");
    println!(
        "  \"peak_heap_mib\": {:.2}",
        mib(PEAK_HEAP.load(Ordering::Relaxed))
    );
    println!("}}");
}

/// How many providers the composed profile carries, read again so the report
/// does not hold the profile for it.
fn profile_providers() -> usize {
    egrio_desktop::bench::active_profile_for_core()
        .map(|profile| profile.rule_sets.len())
        .unwrap_or_default()
}

/// A connection history as it stands once an app has run for a while: 30 000
/// connections of six programs taken in twenty a poll, so it is at its cap
/// of rows and of removals kept and its index has seen the removals of a
/// long run. Each row arrives with strings of its own, as the Core's
/// sessions have them, so what the history shares is its own doing.
fn fill_connection_history() -> egrio_desktop::connection_history::ConnectionHistory {
    use egrio_core::{
        TrafficConnectionProtocol, TrafficConnectionSnapshot, TrafficConnectionState,
    };
    // Synthetic process names and paths; no installed-app inventory is used.
    const PROGRAMS: [(&str, &str); 6] = [
        (
            "Example Browser Helper",
            "/Applications/Example Browser.app/Contents/Frameworks/Example Browser Framework.framework/Versions/1.0.0.0/Helpers/Example Browser Helper.app/Contents/MacOS/Example Browser Helper",
        ),
        ("Example Viewer", "/Applications/Example Viewer.app/Contents/MacOS/Example Viewer"),
        (
            "com.example.web-content",
            "/Applications/Example Browser.app/Contents/XPCServices/com.example.web-content.xpc/Contents/MacOS/com.example.web-content",
        ),
        ("Example Messenger", "/Applications/Example Messenger.app/Contents/MacOS/Example Messenger"),
        (
            "cargo",
            "/opt/rust/bin/cargo",
        ),
        ("example-daemon", "/usr/sbin/example-daemon"),
    ];
    const OUTBOUNDS: [&str; 4] = ["Proxy A", "Proxy B", "DIRECT", "Proxy C"];
    const RULES: [&str; 5] = [
        "DOMAIN-SUFFIX,example.com,Proxy",
        "RULE-SET,streaming,Proxy",
        "GEOIP,CN,DIRECT",
        "PROCESS-NAME,cargo,DIRECT",
        "MATCH,Proxy",
    ];
    let connection = |index: u32| {
        let (name, path) = PROGRAMS[index as usize % PROGRAMS.len()];
        let at = 1_794_000_000 + i64::from(index);
        TrafficConnectionSnapshot {
            id: format!("core-1-tcp-{index}").into(),
            protocol: TrafficConnectionProtocol::Tcp,
            process_name: Some(name.into()),
            process_path: Some(path.into()),
            source: Some(format!("198.18.0.1:{}", 40000 + index % 20000).into()),
            destination: format!("www.example-{}.com:443", index % 997).into(),
            host: Some(format!("www.example-{}.com", index % 997).into()),
            rule: Some(RULES[index as usize % RULES.len()].into()),
            inbound: "tun",
            outbound: OUTBOUNDS[index as usize % OUTBOUNDS.len()].into(),
            egress_interface: Some(13),
            upload_bytes: 4096,
            download_bytes: 65536,
            opened_at_unix: at,
            updated_at_unix: at,
            state: TrafficConnectionState::Completed,
            termination: Some(egrio_core::ConnectionTermination::Completed),
            closed_at_unix: Some(at),
        }
    };
    let mut history = egrio_desktop::connection_history::ConnectionHistory::default();
    history.set_profile(Some("profile".into()));
    for poll in 0..1_500_u32 {
        let rows = (0..20).map(|row| connection(poll * 20 + row)).collect();
        history.absorb(rows, 1_794_000_000 + i64::from(poll));
    }
    history
}

fn mib(bytes: usize) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}
