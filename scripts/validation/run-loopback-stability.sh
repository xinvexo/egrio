#!/bin/bash
# Loopback stability harness: closed-loop validation through the `egrio-node`
# daemon CLI on any desktop platform. Every arm stays on loopback; nothing
# changes system networking state.
# Usage: run-loopback-stability.sh [--node-bin PATH] [--cycles N]

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODE_BIN=""
CYCLES=25

while [[ $# -gt 0 ]]; do
    case "$1" in
        --node-bin)
            NODE_BIN="$2"
            shift 2
            ;;
        --cycles)
            CYCLES="$2"
            shift 2
            ;;
        *)
            echo "unknown argument: $1" >&2
            exit 64
            ;;
    esac
done

if [[ -z "$NODE_BIN" ]]; then
    for candidate in \
        "$SCRIPT_DIR/../../target/release/egrio-node" \
        "$SCRIPT_DIR/../../target/debug/egrio-node" \
        "$SCRIPT_DIR/egrio-node"; do
        if [[ -x "$candidate" ]]; then
            NODE_BIN="$candidate"
            break
        fi
    done
fi
if [[ -z "$NODE_BIN" || ! -x "$NODE_BIN" ]]; then
    echo "egrio-node binary not found; pass --node-bin PATH" >&2
    exit 66
fi

PROFILE_DIR="$SCRIPT_DIR/profiles"
HTTP_PROFILE="$PROFILE_DIR/http-proxy.json"
SOCKS5_PROFILE="$PROFILE_DIR/socks5-proxy.json"
for profile in "$HTTP_PROFILE" "$SOCKS5_PROFILE"; do
    if [[ ! -f "$profile" ]]; then
        echo "validation profile missing: $profile" >&2
        exit 66
    fi
done

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
REPORT_ROOT="${EGRIO_VALIDATION_REPORT_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/egrio-validation.XXXXXX")}"
REPORT_DIR="$REPORT_ROOT/$TIMESTAMP/loopback"
mkdir -p "$REPORT_DIR"

FAILURES=0
STEP_ROWS=()

run_step() {
    local name="$1"
    shift
    local out="$REPORT_DIR/$name.out.json"
    local err="$REPORT_DIR/$name.err.txt"
    local started ended status
    started=$(date +%s)
    if "$@" >"$out" 2>"$err"; then
        status=PASS
    else
        status=FAIL
        FAILURES=$((FAILURES + 1))
    fi
    ended=$(date +%s)
    STEP_ROWS+=("$status $name $((ended - started))s")
    echo "[$status] $name ($((ended - started))s)"
}

echo "== loopback stability harness =="
echo "node binary: $NODE_BIN"
echo "cycles: $CYCLES  reports: $REPORT_DIR"
"$NODE_BIN" help >/dev/null 2>&1 || {
    echo "node binary is not runnable" >&2
    exit 66
}

# The one-off arm first: it catches broken builds before the long loop.
run_step "ipv6-closed-loop" "$NODE_BIN" ipv6-closed-loop-validation

cycle=1
while [[ $cycle -le $CYCLES ]]; do
    run_step "s1-proxy-http-c$cycle" "$NODE_BIN" proxy-mode-validation "$HTTP_PROFILE"
    run_step "s1-proxy-socks5-c$cycle" "$NODE_BIN" proxy-mode-validation "$SOCKS5_PROFILE"
    cycle=$((cycle + 1))
done

echo
echo "== summary =="
for row in "${STEP_ROWS[@]}"; do
    echo "$row"
done
echo "failed steps: $FAILURES"
echo "reports: $REPORT_DIR"
exit "$FAILURES"
