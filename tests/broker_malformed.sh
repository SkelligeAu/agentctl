#!/bin/sh
# Verify: malformed broker request → "denied: malformed-request"; channel stays open.

set -e
. "$(dirname "$0")/_lib.sh"
NAME=tbm-req

cleanup() {
    agentctl stop "$NAME" 2>/dev/null || true
    rm -rf "$AAGENTS/$NAME" 2>/dev/null || true
}
trap cleanup EXIT

agentctl create "$NAME" --profile worker > /dev/null
agentctl grant "$NAME" 'mailbox.send:nonexistent' > /dev/null

echo malformed > "$AAGENTS/$NAME/broker-fault-mode"
agentctl start "$NAME" --exec "$(command -v broker-fault)" > /dev/null
sleep 0.5

if ! grep -q "broker malformed request" "$AAGENTS/$NAME/audit.log"; then
    echo "FAIL: no 'broker malformed' line in $NAME audit.log"
    exit 1
fi
if ! grep -q "broker denied cap=mailbox.send:nonexistent to=$NAME" "$ALOG"; then
    echo "FAIL: channel appears to have closed after malformed request"
    exit 1
fi
echo "PASS: malformed broker request denied; channel remained usable"
exit 0
