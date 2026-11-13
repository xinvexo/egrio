#!/usr/bin/env python3
"""Real-network acceptance probe for a running Egrio capture.

Probes a fixed set of targets for a while and reports, per route class
(`direct` or `proxy`): HTTPS success rate and first-response latency
percentiles (one fresh connection per request, through whatever captures the
host's traffic), STUN round trips and loss over UDP, and the capturing
process's memory. Given Egrio's per-flow relay trace (the stderr of a Core run
with `EGRIO_RELAY_TRACE=1`), every failed request is attributed to where it
failed: the proxy hop, the destination (directly or as the node reported it),
this host, the relay after the dial, or the client side.

Standard library only; needs `curl`. See README.md.
"""

import argparse
import json
import os
import random
import re
import socket
import statistics
import struct
import subprocess
import sys
import threading
import time

STUN_COOKIE = 0x2112A442


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(fraction * (len(ordered) - 1))))
    return ordered[index]


def resolve(name, resolver):
    """The first A record of `name` from the DNS server `resolver` (host:port)."""
    host, port = resolver.rsplit(":", 1)
    query_id = random.getrandbits(16)
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
    query = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack("!HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        sock.sendto(query, (host, int(port)))
        reply = sock.recv(1500)
    answers = struct.unpack("!H", reply[6:8])[0]
    offset = 12 + len(labels) + 1 + 4
    for _ in range(answers):
        offset += 2 if reply[offset] & 0xC0 == 0xC0 else reply.index(b"\x00", offset) - offset + 1
        kind, _, _, length = struct.unpack("!HHIH", reply[offset:offset + 10])
        offset += 10
        if kind == 1 and length == 4:
            return socket.inet_ntoa(reply[offset:offset + 4])
        offset += length
    raise OSError(f"no A record for {name} from {resolver}")


def http_probe(target, timeout, resolver=None):
    started = time.time()
    command = [
        "curl", "-sS", "-o", os.devnull, "--max-time", str(timeout),
        "-w", "%{http_code} %{time_connect} %{time_appconnect} %{time_starttransfer} %{time_total}",
        target["url"],
    ]
    if resolver:
        host = re.sub(r"^https?://([^/:]+).*$", r"\1", target["url"])
        try:
            command[1:1] = ["--resolve", f"{host}:443:{resolve(host, resolver)}"]
        except OSError as error:
            return {"kind": "http", "t": started, "name": target["name"], "route": target["route"],
                    "host": host, "exit": -1, "code": 0, "ok": False, "error": f"resolve: {error}"}
    process = subprocess.run(command, capture_output=True, text=True)
    fields = process.stdout.split()
    record = {
        "kind": "http", "t": started, "name": target["name"], "route": target["route"],
        "host": re.sub(r"^https?://([^/:]+).*$", r"\1", target["url"]),
        "exit": process.returncode, "error": process.stderr.strip()[:300],
    }
    if len(fields) == 5:
        record.update(code=int(fields[0]), connect=float(fields[1]), tls=float(fields[2]),
                      ttfb=float(fields[3]), total=float(fields[4]))
    else:
        record["code"] = 0
    record["ok"] = process.returncode == 0 and 200 <= record["code"] < 500
    return record


def stun_request():
    transaction = os.urandom(12)
    return transaction, struct.pack("!HHI", 0x0001, 0, STUN_COOKIE) + transaction


def run_http(target, args, stop, results, lock):
    # Spread the targets' first requests over one interval.
    if stop.wait(random.uniform(0, args.http_interval)):
        return
    while not stop.is_set():
        record = http_probe(target, args.http_timeout, args.resolver)
        with lock:
            results.append(record)
        if stop.wait(max(0.0, args.http_interval - (time.time() - record["t"]))):
            return


def run_stun(target, args, stop, results, lock):
    pending = {}
    sock = None
    while not stop.is_set():
        if sock is None:
            try:
                if args.resolver:
                    address = (resolve(target["host"], args.resolver), target["port"])
                else:
                    address = socket.getaddrinfo(target["host"], target["port"], socket.AF_INET,
                                                 socket.SOCK_DGRAM)[0][4]
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.connect(address)
                sock.settimeout(0.05)
            except OSError as error:
                with lock:
                    results.append({"kind": "stun", "t": time.time(), "name": target["name"],
                                    "route": target["route"], "ok": False,
                                    "error": f"resolve/connect: {error}"})
                if stop.wait(args.stun_interval):
                    return
                continue
        transaction, request = stun_request()
        sent_at = time.time()
        pending[transaction] = sent_at
        try:
            sock.send(request)
        except OSError:
            pass
        deadline = sent_at + args.stun_interval
        while time.time() < deadline and not stop.is_set():
            try:
                reply = sock.recv(2048)
            except OSError:
                continue
            if len(reply) >= 20 and reply[:2] == b"\x01\x01":
                started = pending.pop(reply[8:20], None)
                if started is not None:
                    with lock:
                        results.append({"kind": "stun", "t": started, "name": target["name"],
                                        "route": target["route"], "ok": True,
                                        "rtt": time.time() - started})
        now = time.time()
        for transaction_id, started in list(pending.items()):
            if now - started >= args.stun_timeout:
                del pending[transaction_id]
                with lock:
                    results.append({"kind": "stun", "t": started, "name": target["name"],
                                    "route": target["route"], "ok": False, "error": "timeout"})


def process_rss_kb(pid):
    try:
        with open(f"/proc/{pid}/status") as status:
            for line in status:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except OSError:
        pass
    try:
        out = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True)
        return int(out.stdout.strip())
    except (OSError, ValueError):
        return None


def run_memory(args, stop, results, lock):
    while not stop.is_set():
        rss = process_rss_kb(args.pid)
        if rss is not None:
            with lock:
                results.append({"kind": "rss", "t": time.time(), "kb": rss})
        if stop.wait(args.rss_interval):
            return


TRACE = re.compile(r"\[relay-trace\] t=(?P<t>\d+\.\d+) flow=(?P<flow>\d+) (?P<event>\w+) (?P<rest>.*)$")


def read_trace(path):
    flows = {}
    with open(path, errors="replace") as trace:
        for line in trace:
            match = TRACE.search(line.strip())
            if not match:
                continue
            flow = flows.setdefault(match["flow"], {})
            t, event, rest = float(match["t"]), match["event"], match["rest"]
            if event == "routed":
                fields = dict(re.findall(r"(\w+)=(\S+)", rest))
                flow.update(t=t, outbound=fields.get("outbound"),
                            host=fields.get("dial_target", "").rsplit(":", 1)[0])
            elif event == "dialed":
                flow["dialed"] = rest
            elif event == "closed":
                flow["closed"] = rest
    return [flow for flow in flows.values() if "t" in flow]


def classify(record, flows, timeout):
    candidates = [flow for flow in flows if flow["host"] == record["host"]
                  and record["t"] - 0.5 <= flow["t"] <= record["t"] + timeout]
    if not candidates:
        return "no-flow"
    flow = min(candidates, key=lambda flow: flow["t"])
    dialed = flow.get("dialed", "")
    if "result=err(" in dialed:
        if "outbound Hop" in dialed:
            return "proxy-hop"
        if "outbound Target" in dialed or (flow.get("outbound") == "DIRECT" and "budget" in dialed):
            return "target"
        if "budget" in dialed:
            return "dial-timeout"
        return "local"
    if "result=err(" in flow.get("closed", ""):
        return "relay"
    return "client-side"


def summarize(results, flows, args):
    summary = {"minutes": args.minutes, "http": {}, "stun": {}, "rss_kb": {}, "failures": []}
    for route in ("direct", "proxy"):
        http = [r for r in results if r["kind"] == "http" and r["route"] == route]
        if http:
            good = [r for r in http if r["ok"]]
            summary["http"][route] = {
                "requests": len(http), "succeeded": len(good),
                "success_rate": round(len(good) / len(http), 4),
                "ttfb_ms": {name: round(1000 * value, 1) if value is not None else None
                            for name, value in (("p50", percentile([r["ttfb"] for r in good], 0.5)),
                                                ("p90", percentile([r["ttfb"] for r in good], 0.9)),
                                                ("p99", percentile([r["ttfb"] for r in good], 0.99)))},
                "connect_ms_p50": round(1000 * statistics.median([r["connect"] for r in good]), 1) if good else None,
            }
        stun = [r for r in results if r["kind"] == "stun" and r["route"] == route]
        if stun:
            answered = [r for r in stun if r["ok"]]
            summary["stun"][route] = {
                "sent": len(stun), "answered": len(answered),
                "loss": round(1 - len(answered) / len(stun), 4),
                "rtt_ms": {name: round(1000 * value, 1) if value is not None else None
                           for name, value in (("p50", percentile([r["rtt"] for r in answered], 0.5)),
                                               ("p90", percentile([r["rtt"] for r in answered], 0.9)),
                                               ("p99", percentile([r["rtt"] for r in answered], 0.99)))},
            }
    rss = [r["kb"] for r in results if r["kind"] == "rss"]
    if rss:
        summary["rss_kb"] = {"first": rss[0], "max": max(rss), "last": rss[-1]}
    for record in results:
        if record["kind"] == "http" and not record["ok"]:
            failure = {key: record.get(key) for key in ("t", "name", "route", "exit", "code", "error")}
            if flows is not None:
                failure["where"] = classify(record, flows, args.http_timeout)
            summary["failures"].append(failure)
    if flows is not None:
        counts = {}
        for failure in summary["failures"]:
            key = f"{failure['route']}/{failure['where']}"
            counts[key] = counts.get(key, 0) + 1
        summary["failures_by_place"] = counts
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--targets", required=True, help="targets JSON (see real-network-targets.json)")
    parser.add_argument("--minutes", type=float, default=30)
    parser.add_argument("--pid", type=int, help="the capturing process, for its memory")
    parser.add_argument("--trace", help="the Core's EGRIO_RELAY_TRACE output, read after the run")
    parser.add_argument("--out", required=True, help="directory for probes.jsonl and summary.json")
    parser.add_argument("--http-interval", type=float, default=10)
    parser.add_argument("--http-timeout", type=float, default=15)
    parser.add_argument("--stun-interval", type=float, default=1)
    parser.add_argument("--stun-timeout", type=float, default=2)
    parser.add_argument("--rss-interval", type=float, default=30)
    parser.add_argument("--resolver", help="host:port of the DNS server to ask instead of the system's, for a "
                        "capture that answers names only on its own listener")
    args = parser.parse_args()
    with open(args.targets) as targets_file:
        targets = json.load(targets_file)
    os.makedirs(args.out, exist_ok=True)
    results, lock, stop = [], threading.Lock(), threading.Event()
    workers = [threading.Thread(target=run_http, args=(target, args, stop, results, lock))
               for target in targets.get("http", [])]
    workers += [threading.Thread(target=run_stun, args=(target, args, stop, results, lock))
                for target in targets.get("stun", [])]
    if args.pid:
        workers.append(threading.Thread(target=run_memory, args=(args, stop, results, lock)))
    for worker in workers:
        worker.start()
    try:
        stop.wait(args.minutes * 60)
    except KeyboardInterrupt:
        pass
    stop.set()
    for worker in workers:
        worker.join()
    results.sort(key=lambda record: record["t"])
    with open(os.path.join(args.out, "probes.jsonl"), "w") as out:
        for record in results:
            out.write(json.dumps(record) + "\n")
    flows = read_trace(args.trace) if args.trace else None
    summary = summarize(results, flows, args)
    with open(os.path.join(args.out, "summary.json"), "w") as out:
        json.dump(summary, out, indent=2)
    json.dump({key: summary[key] for key in summary if key != "failures"}, sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main()
