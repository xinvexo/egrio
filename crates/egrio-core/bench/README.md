# egrio-core benchmarks

Two layers of benchmarks gate hot-path changes: measure before and after a
change, and reject changes that do not move the numbers or that regress them.
Numbers are only comparable on the same host; re-baseline on the machine you
compare against.

## Micro-benches (criterion)

```
cargo bench -p egrio-core --bench core_hot_paths
cargo bench -p egrio-core --bench session_tables --features bench-internals
cargo bench -p egrio-core --bench outbound_hot_paths --features bench-internals
```

`core_hot_paths` covers the rule-engine route decision and the packet
DNS/UDP decision loop. `session_tables` covers the coarse-mutex
session tables (UDP session table per-datagram bookkeeping, session-registry
lifecycle) single-threaded and from 4 contending threads — the gate for
sharding the session-table locks. `outbound_hot_paths` covers Shadowsocks
per-datagram and per-chunk crypto and the Trojan dial-path costs. The `bench-internals` feature exposes crate-internal
wrappers that mirror the production sequences. criterion stores its own
comparison state under `target/criterion/`.

## E2E throughput (example)

```
cargo run --release -p egrio-core --example e2e_throughput > run.json
# override the per-scenario byte count (default 256 MiB):
EGRIO_E2E_BYTES=536870912 cargo run --release -p egrio-core --example e2e_throughput
# the burst scenario's shape, and the threads the Core and the clients share:
EGRIO_E2E_SESSIONS=128 EGRIO_E2E_ROUNDS=64 EGRIO_E2E_WORKERS=16 \
  cargo run --release -p egrio-core --features bench-internals --example e2e_throughput
```

Drives real HTTP CONNECT and SOCKS5 handshakes through the running
`CoreSessionManager` listener to a loopback sink/source peer, measuring
upload and download for each inbound. This is the gate for any relay-path
change (custom copy buffers, buffer sizing, splice).

The burst scenario is the server-role shape the bulk ones miss: many sessions
at once, each a request/response exchange, which is when a relay direction
gives its buffer back and borrows again. With `--features bench-internals`
the report carries what the two buffer pools handed out (`buffer_pools`:
buffers reused from a pool's free list, and buffers it had to allocate and
zero), so `retain` can be read against the borrowers asking together. They
follow the worker threads, not the sessions, because a direction holds its
buffer only while it has bytes.

The setup scenarios are what a new connection costs before it carries
anything — the client's connect, the inbound handshake answered once the Core
has admitted, routed and dialed it, then the first byte back through the
relay — which the byte scenarios cannot see. One pass opens the connections
one at a time and one opens `EGRIO_E2E_AT_ONCE` of them together, so queuing
shows in the handshake and first-byte distributions. Keep a pass to a few
hundred connections: a few thousand loopback setups can exhaust the host's
ephemeral ports.

Generate baseline and candidate reports locally with the same settings on
the same host. The report measures inbound accept, routing and the relay
path over loopback, isolating Core overhead from network latency. Compare
same-host deltas; absolute values do not represent real-world proxy speed.

## Packet-path (TUN) throughput (example)

```
cargo run --release -p egrio-core --example e2e_packet_throughput > run.json
# override the concurrency and per-flow byte count (defaults 8 flows, 32 MiB):
EGRIO_PKT_FLOWS=16 EGRIO_PKT_BYTES=67108864 cargo run --release -p egrio-core --example e2e_packet_throughput
# serve the flows through 4 capture queues, as a Linux multi-queue TUN:
EGRIO_PKT_QUEUES=4 cargo run --release -p egrio-core --example e2e_packet_throughput
```

Drives `NativeCoreDevice::run_packet_queues` — the packet data plane behind
every platform's TUN — instead of the local listener. Each flow is an
independent client smoltcp stack (its own driver task) sharing in-memory
capture queues (one by default, like a Wintun ring) into one core device that
DIRECT-dials loopback peers; with `EGRIO_PKT_QUEUES=<n>` flow `i` stays on
queue `i mod n`, as the kernel keeps a flow on one queue of a multi-queue
TUN. Reports single-flow and 8-flow-aggregate download and upload
throughput. Each queue's pump runs on a runtime of its own with one worker
thread, as the SDK runs the Core in the product, and the clients and peers on
a separate four-worker runtime; `EGRIO_PKT_CORE_WORKERS=<n>` gives each of
those runtimes n workers, and 0 runs the Core on the clients' runtime.

This is the packet data plane's same-host gate. Single-flow numbers
(especially the first scenario) carry warmup noise; compare same-host deltas,
not absolute numbers. It is a loopback CPU-throughput upper bound: the ~0 RTT
loopback masks TCP window effects, so small per-flow buffers look fine here
while capping a real link. It does **not** replace a real-link comparison of
TUN against the same node's system-proxy path.

### Same-host A/B comparison

Capture fresh baseline and candidate JSON on the same machine with identical
environment variables, then run:

```powershell
cargo xtask bench-compare baseline.json candidate.json
```

Every candidate scenario must retain at least 90% of its matching baseline;
packet aggregate download/upload must also remain at or above the corresponding
single-flow throughput. Exit codes are `0` pass, `1` regression, and `2`
incomparable input.

## E2E UDP baseline (example)

```powershell
cargo run --release -p egrio-core --example e2e_udp_throughput > run.json
# override the per-flow datagram count (default 10 000):
$env:EGRIO_E2E_UDP_DATAGRAMS = "50000"
cargo run --release -p egrio-core --example e2e_udp_throughput |
  Set-Content -Encoding utf8 run.json
Remove-Item Env:EGRIO_E2E_UDP_DATAGRAMS
```

Writes captured IPv4/UDP packets into an in-memory TUN ring drained by
`NativeCoreDevice::run_packet_queue` (packet classification → route →
session table → session-socket actor → real UDP sockets) against loopback
echo peers and counts Core's reply packets: single-source and 64-source
serial TUN writers, plus a single flow taking the last entry of a session
table pre-filled to its 1024-entry cap. The report's `data_plane` is
`packet`. This is the gate for UDP data-path changes such as batched
syscalls and session-table changes.
Generate baseline and candidate reports locally with the current release
example and compare same-host deltas. The ring holds the writer back when
full, so `attempts_per_s` measures how fast Core ingests captured packets,
`enqueued_per_s` measures session-mailbox admissions, and `completion_ratio`
is responses received divided by admitted datagrams. Regenerate reports
rather than translating an older schema.

For real-link UDP checks, build the `socks5_validation_proxy` and
`udp_socks5_probe` release examples and run
`scripts/validation/run-windows-udp-real-link.ps1`. It writes a non-DNS NTP
datagram into an in-memory TUN and relays it through production SOCKS5 UDP
ASSOCIATE and requires an audit-clean
Core shutdown; DNS is deliberately not used because Core or host fake-IP handling
can answer it locally.

## Hysteria2 multi-stream upload (example)

```
cargo run --release -p egrio-core --features server --example hysteria2_fairness
# defaults: 16 flows for 10 s; EGRIO_HY2_UP fixes the client's send rate
EGRIO_FLOWS=64 EGRIO_SECONDS=6 EGRIO_HY2_UP="400 Mbps" cargo run --release -p egrio-core --features server --example hysteria2_fairness
```

Runs a server Core with a Hysteria2 inbound and a client Core whose mixed
listener sends everything through it, each on its own Tokio runtime, and
uploads from N SOCKS5 connections into a loopback sink as fast as they can,
so the streams of one QUIC connection compete for its send space. It reports
the aggregate rate, each flow's bytes and its longest gap between arriving
reads. This is the gate for changes to how the streams of a QUIC connection
share it; compare the per-flow gaps and the process CPU of interleaved runs
on the same host.

## Idle-connection memory (example)

```
cargo run --release -p egrio-core --example idle_flow_memory
EGRIO_IDLE_PATH=socks5 cargo run --release -p egrio-core --example idle_flow_memory
EGRIO_IDLE_PATH=udp cargo run --release -p egrio-core --example idle_flow_memory
# defaults: 200 connections, each uploads 64 KiB and downloads 1 MiB first
EGRIO_IDLE_FLOWS=100 EGRIO_IDLE_DOWNLOAD=2048 EGRIO_IDLE_UPLOAD=512 cargo run --release -p egrio-core --example idle_flow_memory
```

Opens N TCP connections through the Core — captured flows through an
in-memory TUN (`tun`, the default) or SOCKS5 CONNECT sessions through the
listener (`socks5`) — lets each move data to and from a loopback peer, then
holds them open without traffic; `udp` opens N captured UDP flows instead,
each one datagram to a loopback echo peer and back. It reports the Core's live heap per idle
connection from a counting allocator (the TUN path subtracts its in-process
client stacks), the OS private memory per connection, and the allocations
each idle connection keeps by power-of-two size class. Heap figures do not
depend on the allocator or host; OS figures do. The instruments read the OS
figures in one place (`examples/support/os_memory.rs`): private memory is
the commit charge on Windows, resident anonymous pages on Linux and the
physical footprint on macOS. This is the gate for changes to per-connection
buffers.

## Rule-set memory and decision cost (example)

```
EGRIO_RULE_DIR=<dir of cached rule-provider files> cargo run --release -p egrio-core --example rule_memory
```

Reads every rule-provider file under the directory (Clash `payload:` lists;
all-CIDR files are `ipcidr`, files of rule texts such as
`DOMAIN-SUFFIX,example.com` are `classical`, others `domain`), builds the
`RuntimeProfile` a host hands the Core (one RULE-SET rule per provider, then
MATCH) and compiles it. It reports the live heap of the entry lists the host keeps, of the
Core's compiled matcher and of the compile peak, plus the OS private memory
with both copies alive and with only the Core's. It then times one route
decision over those same sets (`decision_nanos`) for a name the first set
claims, a name only the last one claims, a name no set claims, an address a
CIDR set has and one no set has — what every new connection pays. Use the
`provider-cache` directory of a sanitized test profile as input, and a
directory of public `classical` lists for that behavior. This is the gate
for changes to rule-set storage and to the route decision's shape.

## App-process memory (example)

```
EGRIO_DATA_DIR=<an app data directory> \
  cargo run --release -p egrio-desktop --features bench-internals --example app_memory
```

What the desktop backend holds for a supplied test profile, step by step: the profile
the pages read, the profile the Core receives (every rule provider's entries
and the geodata its rules name), the Core compiled from it, a Runtime started
on a listener and given that profile, the connection table's history after
30 000 connections (at its cap of rows and of removals kept), and a table
holding every row of it.
Each step reports the live heap and live allocation count from a counting
allocator, so an idle app's footprint is attributable. Point it at a
separate test data directory with a sanitized profile and `capture_layers`
set to `none`.
This is the gate for app-side retention: the history's cap, the parsed-source
cache, and what a start loads.

## Subscription-scale costs (example)

```
EGRIO_DATA_DIR=<an empty directory> \
  cargo run --release -p egrio-desktop --features bench-internals --example subscription_scale
# defaults: 300 nodes and 12 000 rules
EGRIO_SCALE_NODES=1000 EGRIO_SCALE_RULES=0 EGRIO_DATA_DIR=<an empty directory> \
  cargo run --release -p egrio-desktop --features bench-internals --example subscription_scale
```

What a converted subscription of ordinary size costs, which a hand-written
profile of a dozen nodes never shows. It writes a profile in the layout
subscription converters emit (every node in one select group, a url-test and
a fallback group over all of them, a select group per service listing the
groups and every node again, an ad-blocking group of REJECT and DIRECT, and
thousands of inline rules), imports it into the empty data directory, and
reports each step of a start with its time, the live heap it leaves and its
allocations: the import, the node and rule lists the pages read, the profile
composed for the Core, and the compiled Core. It then times what one new
connection pays to be routed and to have its group resolved to a node, for
flows that end at an indexed rule, at MATCH, and at the rejecting group.
This is the gate for changes to what a profile's size multiplies: per-node
and per-rule state in the compiled Core, group resolution, and the rule
scan.

## Soak churn with RSS sampling (example)

```
cargo run --release -p egrio-core --example soak_churn            # 60 s smoke
EGRIO_SOAK_SECONDS=86400 cargo run --release -p egrio-core --example soak_churn
```

Waves of concurrent TCP relay churn (SOCKS5 CONNECT through the Core
listener, varied payload sizes) plus UDP datagrams captured through an
in-memory TUN,
asserting after every wave that the session ledgers drain
(`CoreRuntime::state_audit`) and sampling process RSS and the live heap from
a counting allocator (`rss_bytes` and `heap_bytes` per wave,
`*_first/_max/_last` in the summary); one JSON line per wave, a summary line
at the end, nonzero exit on any failure. The two curves say what a climb is:
the heap climbing with RSS is memory the Core still owns, RSS climbing alone
is the allocator holding on to what it freed. A curve that climbs and then
stays flat is a bounded structure filling up; keep enough later waves to
distinguish a plateau from continued growth.
