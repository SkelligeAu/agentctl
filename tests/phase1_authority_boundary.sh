#!/bin/sh
set -eu

[ "$(uname -s)" = Linux ] || { echo "skip: linux-only"; exit 77; }

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=$(dirname "$HERE")
ROOT=$(mktemp -d /tmp/agentctl-phase1.XXXXXX)
export AGENTCTL_ROOT="$ROOT"
export PATH="$REPO:$PATH"
daemon_pid=
cleanup() {
    if [ -n "$daemon_pid" ]; then kill "$daemon_pid" 2>/dev/null || true; fi
    wait "$daemon_pid" 2>/dev/null || true
    rm -rf "$ROOT"
}
trap cleanup EXIT INT TERM

agentd >"$ROOT/daemon.out" 2>&1 &
daemon_pid=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -S "$ROOT/agentd.sock" ] && break
    sleep 0.1
done
[ -S "$ROOT/agentd.sock" ] || { echo "FAIL: agentd did not start"; exit 1; }

agentctl create boundary
agentctl grant boundary "fs.read:$REPO"
agentctl start boundary --exec "$HERE/phase1-probe"

result="$ROOT/agents/boundary/data/phase1-result"
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -f "$result" ] && break
    sleep 0.1
done
[ -f "$result" ] || { echo "FAIL: probe produced no result"; exit 1; }
grep -q '^policy_write=denied ' "$result" || {
    echo "FAIL: supervised process modified config/policy"; cat "$result"; exit 1;
}
grep -q '^control=ERROR unauthorized' "$result" || {
    echo "FAIL: unauthenticated daemon command was not rejected"; cat "$result"; exit 1;
}
kill -0 "$daemon_pid" 2>/dev/null || {
    echo "FAIL: unauthenticated process shut down agentd"; exit 1;
}

agentctl daemon-shutdown >/dev/null
wait "$daemon_pid"
daemon_pid=
echo "PASS: agent cannot write operator config or control agentd"
