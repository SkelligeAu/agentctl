#!/bin/sh
# Verify: only one agentd can run per data root. Second attempt refuses;
# after first exits cleanly, a new one acquires the lock.
#
# Assumes nothing is running yet. The QEMU integration test (step H)
# starts its own agentd; this script manages its own daemon lifecycle.

set -e

# Use an isolated data root so we don't collide with a shared agentd
# that the suite runner already started (run-all.sh starts one for the
# broker tests).
export AGENTCTL_ROOT=/tmp/agentctl-test-single-$$
ALOCK="$AGENTCTL_ROOT/agentd.lock"

PID_FIRST=
PID_THIRD=
cleanup() {
    [ -n "$PID_FIRST" ] && kill "$PID_FIRST" 2>/dev/null || true
    [ -n "$PID_THIRD" ] && kill "$PID_THIRD" 2>/dev/null || true
    [ -n "$PID_FIRST" ] && wait "$PID_FIRST" 2>/dev/null || true
    [ -n "$PID_THIRD" ] && wait "$PID_THIRD" 2>/dev/null || true
    rm -rf "$AGENTCTL_ROOT" 2>/dev/null || true
}
trap cleanup EXIT

# --- Start first agentd ---
agentd > /tmp/agentd-single-A-$$.log 2>&1 &
PID_FIRST=$!
sleep 0.3
if ! kill -0 "$PID_FIRST" 2>/dev/null; then
    echo "FAIL: first agentd died immediately"
    cat /tmp/agentd-single-A-$$.log
    rm -f /tmp/agentd-single-A-$$.log
    exit 1
fi

# --- Second agentd must refuse ---
OUT=$(agentd 2>&1) && rc=0 || rc=$?
if [ "$rc" -eq 0 ]; then
    echo "FAIL: second agentd succeeded (should have refused)"
    exit 1
fi
if ! echo "$OUT" | grep -q "another instance"; then
    echo "FAIL: second agentd's stderr missing 'another instance'"
    echo "$OUT"
    exit 1
fi
echo "PASS: second agentd refused with 'another instance'"

# --- SIGTERM the first, wait, third should succeed ---
kill -TERM "$PID_FIRST"
wait "$PID_FIRST" 2>/dev/null || true
PID_FIRST=
sleep 0.2

agentd > /tmp/agentd-single-C-$$.log 2>&1 &
PID_THIRD=$!
sleep 0.3
if ! kill -0 "$PID_THIRD" 2>/dev/null; then
    echo "FAIL: third agentd failed to start after clean shutdown"
    cat /tmp/agentd-single-C-$$.log
    rm -f /tmp/agentd-single-A-$$.log /tmp/agentd-single-C-$$.log
    exit 1
fi
echo "PASS: third agentd acquired lock after first exited cleanly"

rm -f /tmp/agentd-single-A-$$.log /tmp/agentd-single-C-$$.log
exit 0
