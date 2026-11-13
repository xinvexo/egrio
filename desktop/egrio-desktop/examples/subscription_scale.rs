//! Subscription-scale instrument: what a converted subscription of ordinary
//! size costs the backend and the Core, which a hand-written profile of a
//! dozen nodes never shows.
//!
//! It writes a synthetic profile with every node in one select group, a
//! url-test and a fallback group over all of them, a select group for each service that
//! lists the groups and then every node again, an ad-blocking group of
//! REJECT and DIRECT, and thousands of inline rules, imports it into the
//! data directory `EGRIO_DATA_DIR` names, and reports each step a start
//! takes: the import, the node and rule lists the pages read, the profile
//! composed for the Core, the compiled Core's live heap, and what one new
//! connection pays to be routed and to have its group resolved to a node.
//!
//! Usage:
//!   EGRIO_DATA_DIR=<an empty directory> \
//!     cargo run --release -p egrio-desktop --features bench-internals --example subscription_scale
//!   # defaults: 300 nodes and 12 000 rules
//!   EGRIO_SCALE_NODES=1000 EGRIO_SCALE_RULES=0 EGRIO_DATA_DIR=... cargo run ...

use std::alloc::{GlobalAlloc, Layout, System};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use egrio_core::rule_engine::TransportNetwork;
use egrio_core::RouteMatchInput;

struct CountingAllocator;

static LIVE_HEAP: AtomicUsize = AtomicUsize::new(0);
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every call forwards to `System` unchanged; the counters only
// observe sizes.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LIVE_HEAP.fetch_add(layout.size(), Ordering::Relaxed);
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE_HEAP.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LIVE_HEAP.fetch_add(new_size, Ordering::Relaxed);
        LIVE_HEAP.fetch_sub(layout.size(), Ordering::Relaxed);
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

const SERVICES: [&str; 12] = [
    "Telegram",
    "AI",
    "YouTube",
    "Netflix",
    "Bahamut",
    "Bilibili",
    "Media",
    "Domestic",
    "FCM",
    "Microsoft",
    "Apple",
    "Games",
];

fn node_name(index: usize) -> String {
    if index % 2 == 0 {
        format!("HK {index:03}")
    } else {
        format!("JP {index:03}")
    }
}

/// A profile in the layout converters emit, of `nodes` nodes and `rules`
/// inline rules before the three every such profile ends with.
fn source(nodes: usize, rules: usize) -> String {
    let mut yaml = String::from("mixed-port: 7890\nmode: Rule\nproxies:\n");
    for index in 0..nodes {
        let name = node_name(index);
        if index % 2 == 0 {
            writeln!(
                yaml,
                "  - {{name: \"{name}\", type: ss, server: hk{index}.example.net, port: {}, cipher: aes-256-gcm, password: secret{index}, udp: true}}",
                10_000 + index % 50_000
            )
        } else {
            writeln!(
                yaml,
                "  - {{name: \"{name}\", type: trojan, server: jp{index}.example.net, port: 443, password: secret{index}, sni: jp{index}.example.net, udp: true}}"
            )
        }
        .expect("write to a string");
    }
    let all = (0..nodes)
        .map(|index| format!("\"{}\"", node_name(index)))
        .collect::<Vec<_>>()
        .join(", ");
    let members = |first: &str| {
        if all.is_empty() {
            format!("[{first}]")
        } else {
            format!("[{first}, {all}]")
        }
    };
    yaml.push_str("proxy-groups:\n");
    let probed = "url: \"http://www.gstatic.com/generate_204\", interval: 300";
    writeln!(
        yaml,
        "  - {{name: Proxy, type: select, proxies: {}}}",
        members("Auto, Fallback, DIRECT")
    )
    .unwrap();
    writeln!(
        yaml,
        "  - {{name: Auto, type: url-test, {probed}, proxies: {}}}",
        members("DIRECT")
    )
    .unwrap();
    writeln!(
        yaml,
        "  - {{name: Fallback, type: fallback, {probed}, proxies: {}}}",
        members("DIRECT")
    )
    .unwrap();
    for service in SERVICES {
        writeln!(
            yaml,
            "  - {{name: {service}, type: select, proxies: {}}}",
            members("Proxy, Auto, DIRECT")
        )
        .unwrap();
    }
    yaml.push_str("  - {name: Direct, type: select, proxies: [DIRECT, Proxy]}\n");
    yaml.push_str("  - {name: Ads, type: select, proxies: [REJECT, DIRECT]}\n");
    yaml.push_str("  - {name: Final, type: select, proxies: [Proxy, DIRECT]}\n");
    yaml.push_str("rules:\n");
    let targets = [
        "Direct",
        "Ads",
        "Telegram",
        "YouTube",
        "Media",
        "Proxy",
        "Microsoft",
        "Apple",
    ];
    for index in 0..rules {
        let target = targets[index % targets.len()];
        match index % 20 {
            0..=10 => writeln!(
                yaml,
                "  - DOMAIN-SUFFIX,site{index}.example{}.com,{target}",
                index % 53
            ),
            11 | 12 => writeln!(yaml, "  - DOMAIN,host{index}.example.org,{target}"),
            13 => writeln!(yaml, "  - DOMAIN-KEYWORD,keyword{index},{target}"),
            14..=18 => writeln!(
                yaml,
                "  - IP-CIDR,{}.{}.{}.0/24,{target},no-resolve",
                11 + index % 200,
                (index / 200) % 250,
                index % 250
            ),
            _ => writeln!(yaml, "  - PROCESS-NAME,app{index}.exe,{target}"),
        }
        .expect("write to a string");
    }
    yaml.push_str("  - GEOIP,LAN,Direct,no-resolve\n  - MATCH,Final\n");
    yaml
}

fn mib(bytes: usize) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

/// Runs `work` and reports its time, the live heap it left and the
/// allocations it made.
fn step<T>(label: &str, work: impl FnOnce() -> T) -> T {
    let (heap, allocations) = (
        LIVE_HEAP.load(Ordering::Relaxed),
        ALLOCATIONS.load(Ordering::Relaxed),
    );
    let start = Instant::now();
    let value = work();
    println!(
        "    {{ \"step\": \"{label}\", \"millis\": {:.1}, \"kept_mib\": {:.2}, \"allocations\": {} }},",
        start.elapsed().as_secs_f64() * 1000.0,
        mib(LIVE_HEAP.load(Ordering::Relaxed)) - mib(heap),
        ALLOCATIONS.load(Ordering::Relaxed) - allocations
    );
    value
}

fn setting(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn main() {
    let Some(directory) = std::env::var_os("EGRIO_DATA_DIR") else {
        eprintln!("set EGRIO_DATA_DIR to an empty directory");
        std::process::exit(2);
    };
    if std::fs::read_dir(&directory).is_ok_and(|mut entries| entries.next().is_some()) {
        eprintln!("EGRIO_DATA_DIR is not empty: the instrument imports its own profile");
        std::process::exit(2);
    }
    let nodes = setting("EGRIO_SCALE_NODES", 300);
    let rules = setting("EGRIO_SCALE_RULES", 12_000);
    let yaml = source(nodes, rules);

    println!("{{");
    println!("  \"harness\": \"egrio-desktop subscription_scale\",");
    println!("  \"os\": \"{}\",", std::env::consts::OS);
    println!("  \"nodes\": {nodes},");
    println!("  \"groups\": {},", SERVICES.len() + 6);
    println!("  \"rules\": {},", rules + 2);
    println!("  \"source_mib\": {:.2},", mib(yaml.len()));
    println!("  \"steps\": [");
    let saved = step("import", || {
        egrio_desktop::profile_service::import_clash_profile("Scale".into(), yaml.clone())
            .unwrap_or_else(|error| panic!("import the profile: {error}"))
    });
    step("the node list a page reads", || {
        egrio_desktop::profile_service::get_profile_inventory(saved.id.clone())
            .expect("the inventory")
    });
    step("the rule list a page reads", || {
        egrio_desktop::profile_service::get_profile_rules(saved.id.clone()).expect("the rules")
    });
    let profile = step("the profile the Core receives", || {
        egrio_desktop::bench::active_profile_for_core().expect("the composed profile")
    });
    let core = step("the Core compiled from it", || {
        egrio_core::NativeCoreDevice::compile(&profile)
    });
    println!("    {{ \"step\": \"end\" }}");
    println!("  ],");

    // What one new connection pays: the route decision and the walk from the
    // rule's group to the node it dials through.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("instrument runtime");
    let flow = |host: Option<&str>, address: Option<&str>, network| RouteMatchInput {
        host: host.map(str::to_owned),
        destination_ip: address.and_then(|address| address.parse().ok()),
        destination_port: Some(443),
        network: Some(network),
        ..Default::default()
    };
    let flows = [
        (
            "a name an early suffix claims, TCP",
            flow(Some("www.site2.example2.com"), None, TransportNetwork::Tcp),
        ),
        (
            "the same name, UDP",
            flow(Some("www.site2.example2.com"), None, TransportNetwork::Udp),
        ),
        (
            "a name no rule claims, TCP",
            flow(
                Some("nothing.claims.this.example"),
                None,
                TransportNetwork::Tcp,
            ),
        ),
        (
            "an address no rule claims, UDP",
            flow(None, Some("198.51.100.7"), TransportNetwork::Udp),
        ),
        (
            "a name the ad-blocking group rejects, TCP",
            flow(Some("www.site1.example1.com"), None, TransportNetwork::Tcp),
        ),
    ];
    println!("  \"route_and_resolve\": [");
    let last = flows.len() - 1;
    for (index, (label, input)) in flows.iter().enumerate() {
        const ROUNDS: usize = 2_000;
        for _ in 0..50 {
            let _ = runtime.block_on(core.evaluate_route(input));
        }
        let allocations = ALLOCATIONS.load(Ordering::Relaxed);
        let start = Instant::now();
        let mut evaluation = None;
        for _ in 0..ROUNDS {
            evaluation = Some(runtime.block_on(core.evaluate_route(input)));
        }
        let micros = start.elapsed().as_secs_f64() * 1e6 / ROUNDS as f64;
        let made = (ALLOCATIONS.load(Ordering::Relaxed) - allocations) / ROUNDS;
        let ends = match evaluation.expect("a route") {
            Ok(evaluation) => format!(
                "{} -> {}",
                evaluation.decision.outbound, evaluation.resolved_outbound
            ),
            Err(error) => error,
        };
        println!(
            "    {{ \"flow\": \"{label}\", \"micros\": {micros:.1}, \"allocations\": {made}, \"ends\": \"{ends}\" }}{}",
            if index == last { "" } else { "," }
        );
    }
    println!("  ]");
    println!("}}");
}
