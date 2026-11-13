# Core validation tools

The remaining scripts exercise the reusable Core without managing desktop
capture sessions or deploying artifacts to another machine. General throughput
benchmarks live in [the Core benchmark guide](../../crates/egrio-core/bench/README.md).

## Loopback stability

Build the diagnostics CLI, then run the loopback stability checks:

```bash
cargo build --release -p egrio-daemon --bin egrio-node --features 'capture server'
bash scripts/validation/run-loopback-stability.sh --node-bin target/release/egrio-node
```

The script runs an IPv6 closed-loop check, then `--cycles` (default 25) rounds
of HTTP CONNECT and SOCKS5 profile checks. Reports go to a new directory under
the system temporary directory; the script prints its path.
`EGRIO_VALIDATION_REPORT_DIR` selects another output root.

## SOCKS5 UDP protocol check

`run-windows-udp-real-link.ps1` starts the Core SOCKS5 validation proxy,
sends an NTP datagram through UDP ASSOCIATE, and records the response and
process exit status. Supply `-ProxyExe` and `-ProbeExe` for the built
`socks5_validation_proxy` and `udp_socks5_probe` examples. `-ListenAddr`,
`-NtpServer`, `-NtpPort`, and `-ReportDir` select the endpoints and output.
Without `-ReportDir`, output goes under the current user's temporary directory
from [.NET `Path.GetTempPath()`](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.gettemppath).

## SS2022 独立互通

`ss2022-peer/` 固定使用 SagerNet `sing-shadowsocks` v0.2.9，作为与 Rust codec
无关的 Go 对端。需要 Go 1.22 及以上；它只监听和连接本机回环地址，不改变系统代理、
路由或 DNS。先构建对端，再显式运行默认忽略的互通测试：

```bash
cd scripts/validation/ss2022-peer
go build -o /tmp/egrio-ss2022-peer .
cd ../../..
EGRIO_SS2022_PEER=/tmp/egrio-ss2022-peer cargo test -p egrio-core --lib independent_go_peer_interop -- --ignored --nocapture
```

该测试覆盖三种 SS2022 方法的 TCP/UDP 双向互通：Egrio 出站连接 Go 的协议回显服务，
Go 客户端通过 Egrio 的真实监听器和 DIRECT 路由访问本地 TCP/UDP 回显目标。Go 对端
随测试释放。协议支持范围与责任边界见
[Core 数据面](../../docs/architecture/core.md#模块布局)。

## Real-network acceptance

`real-network-probe.py` measures a running capture on a real network for a
while (default 30 minutes): HTTPS requests to the targets of
`real-network-targets.json`, each on a fresh connection, every 10 seconds,
and STUN binding requests over UDP every second. It reports per route class
(`direct`, `proxy`) the HTTPS success rate and first-byte latency
percentiles, the STUN loss and round-trip percentiles, and with `--pid` the
capturing process's resident memory. The capture's profile must send the
`direct` targets DIRECT and the `proxy` targets through the node under test.
Python 3 standard library and `curl` only:

```bash
report_dir=$(mktemp -d "${TMPDIR:-/tmp}/egrio-real-network.XXXXXX")
EGRIO_RELAY_TRACE=1 egrio-node linux-tun-run <profile.json> <checkpoint-dir> 2> "$report_dir/trace.log" &
python3 scripts/validation/real-network-probe.py --targets scripts/validation/real-network-targets.json --minutes 30 --pid <egrio-node pid> --trace "$report_dir/trace.log" --out "$report_dir/report"
```

Keep profiles containing real node addresses or credentials outside the repository.
Raw traces and reports can contain destination addresses and local process details;
keep them in the system temporary directory and redact them before sharing.

`--resolver host:port` asks that DNS server for the targets' addresses instead
of the system resolver, for a capture that answers names only on its own DNS
listener, including setups where DNS interception does not cover queries
sent to a LAN resolver. This keeps resolver selection explicit during comparisons.

With `--trace` (the Core's stderr with `EGRIO_RELAY_TRACE=1`, which logs each
TCP flow's route, dial and close with a Unix timestamp) every failed request
is attributed to where it failed: `proxy-hop` (the node could not be reached,
authenticated or spoken to), `target` (the destination, directly or as the
node reported it), `dial-timeout` (a proxied dial ran out of its budget
without saying where), `local` (this host refused the dial), `relay` (after
the dial), `client-side` (the flow relayed cleanly), or `no-flow` (it never
reached the Core's dispatch). `probes.jsonl` keeps every probe and
`summary.json` the totals and each failure.

## Sample profiles

The JSON files are plain `egrio_core::RuntimeProfile` inputs with no secrets:

| File | Outbound | Endpoint |
| --- | --- | --- |
| `profiles/http-proxy.json` | HTTP CONNECT | `127.0.0.1:18080` |
| `profiles/socks5-proxy.json` | SOCKS5 | `127.0.0.1:11080` |
| `profiles/direct-flood.json` | DIRECT | No upstream proxy |
