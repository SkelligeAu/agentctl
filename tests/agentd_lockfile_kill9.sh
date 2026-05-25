#!/bin/sh
# Verify: the kernel releases agentd's flock on SIGKILL/OOM. A new agentd
# can acquire the lock immediately after a previous instance is killed.

set -e

# Isolated data root: see agentd_single_instance.sh for rationale.
export AGENTCTL_ROOT=/tmp/agentctl-test-k9-$$
ALOCK="$AGENTCTL_ROOT/agentd.lock"

PID_A=
PID_B=
cleanup() {
    [ -n "$PID_A" ] && kill -9 "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill "$PID_B" 2>/dev/null || true
    [ -n "$PID_A" ] && wait "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && wait "$PID_B" 2>/dev/null || true
    rm -rf "$AGENTCTL_ROOT" 2>/dev/null || true
}
trap cleanup EXIT

# Start agentd A.
agentd > /tmp/agentd-k9-A-$$.log 2>&1 &
PID_A=$!
sleep 0.3
if ! kill -0 "$PID_A" 2>/dev/null; then
    echo "FAIL: agentd A died at startup"
    cat /tmp/agentd-k9-A-$$.log
    rm -f /tmp/agentd-k9-A-$$.log
    exit 1
fi

# SIGKILL it (no graceful unlink path runs).
kill -9 "$PID_A"
wait "$PID_A" 2>/dev/null || true
PID_A=

# Within a tight window, agentd B should acquire the lock cleanly.
sleep 0.1
agentd > /tmp/agentd-k9-B-$$.log 2>&1 &
PID_B=$!
sleep 0.3
if ! kill -0 "$PID_B" 2>/dev/null; then
    echo "FAIL: agentd B could not acquire lock after kill -9"
    cat /tmp/agentd-k9-B-$$.log
    rm -f /tmp/agentd-k9-A-$$.log /tmp/agentd-k9-B-$$.log
    exit 1
fi
echo "PASS: lock released on SIGKILL; successor acquired it"

rm -f /tmp/agentd-k9-A-$$.log /tmp/agentd-k9-B-$$.log
exit 0
