#!/bin/sh
# Verify: too many SCM_RIGHTS fds → MSG_CTRUNC → broker closes channel.

set -e
. "$(dirname "$0")/_lib.sh"
NAME=tbc-req

cleanup() {
    agentctl stop "$NAME" 2>/dev/null || true
    rm -rf "$AAGENTS/$NAME" 2>/dev/null || true
}
trap cleanup EXIT

agentctl create "$NAME" --profile worker > /dev/null

echo many-fds > "$AAGENTS/$NAME/broker-fault-mode"
agentctl start "$NAME" --exec "$(command -v broker-fault)" > /dev/null
sleep 0.5

if ! grep -q "broker $NAME: oversized or cmsg-truncated" "$ALOG"; then
    echo "FAIL: agentd did not report MSG_CTRUNC"
    exit 1
fi
if ! grep -q "broker protocol violation" "$AAGENTS/$NAME/data/audit.log"; then
    echo "FAIL: agent's audit.log missing protocol-violation entry"
    exit 1
fi
echo "PASS: MSG_CTRUNC closes broker channel"
exit 0
