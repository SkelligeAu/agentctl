#!/bin/sh
# Verify: wildcard "allow mailbox.send:*" matches any mailbox.send target.

set -e
. "$(dirname "$0")/_lib.sh"
REQ=tbw-req
TGT=tbw-tgt

cleanup() {
    agentctl stop "$REQ" 2>/dev/null || true
    agentctl stop "$TGT" 2>/dev/null || true
    rm -rf "$AAGENTS/$REQ" "$AAGENTS/$TGT" 2>/dev/null || true
}
trap cleanup EXIT

agentctl create "$TGT" --profile worker > /dev/null
agentctl start  "$TGT" --exec "$(command -v reviewer-agent)" > /dev/null
sleep 0.3

agentctl create "$REQ" --profile worker > /dev/null
agentctl grant  "$REQ" 'mailbox.send:*' > /dev/null
echo "$TGT" > "$AAGENTS/$REQ/broker-target"

agentctl start "$REQ" --exec "$(command -v broker-test)" > /dev/null
sleep 0.5

if ! grep -q "broker issued cap=mailbox.send:$TGT to=$REQ" "$ALOG"; then
    echo "FAIL: wildcard did not allow mailbox.send:$TGT"
    exit 1
fi
echo "PASS: wildcard 'mailbox.send:*' grants matching caps"
exit 0
