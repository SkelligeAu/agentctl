#!/bin/sh
# Verify: writing "allow X" to a policy file does NOT cause X to materialize
# as an open fd. Authority is fds; the policy file is broker input.

set -e
. "$(dirname "$0")/_lib.sh"
NAME=tpa-req

cleanup() {
    agentctl stop "$NAME" 2>/dev/null || true
    rm -rf "$AAGENTS/$NAME" 2>/dev/null || true
}
trap cleanup EXIT

agentctl create "$NAME" --profile worker > /dev/null
agentctl grant "$NAME" 'mailbox.send:peer-that-does-not-exist' > /dev/null

echo fdtable > "$AAGENTS/$NAME/broker-fault-mode"
agentctl start "$NAME" --exec "$(command -v broker-fault)" > /dev/null
sleep 0.4

FDT="$AAGENTS/$NAME/fdtable"
if [ ! -f "$FDT" ]; then
    echo "FAIL: fdtable not produced by broker-fault"
    exit 1
fi
if grep -q "agent.sock" "$FDT"; then
    echo "FAIL: fdtable shows a peer agent.sock — policy was treated as authority"
    cat "$FDT"
    exit 1
fi
if ! grep -q "^3 socket:" "$FDT"; then
    echo "FAIL: fdtable missing broker channel on fd 3"
    cat "$FDT"
    exit 1
fi
echo "PASS: policy line did not pre-materialize authority"
exit 0
