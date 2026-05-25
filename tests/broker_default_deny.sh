#!/bin/sh
# Verify: empty policy → broker denies; no fd issued.

set -e
. "$(dirname "$0")/_lib.sh"
NAME_REQ=tbd-req
NAME_TGT=tbd-tgt

cleanup() {
    agentctl stop "$NAME_REQ" 2>/dev/null || true
    agentctl stop "$NAME_TGT" 2>/dev/null || true
    rm -rf "$AAGENTS/$NAME_REQ" "$AAGENTS/$NAME_TGT" 2>/dev/null || true
}
trap cleanup EXIT

agentctl create "$NAME_TGT" --profile worker > /dev/null
agentctl start  "$NAME_TGT" --exec "$(command -v reviewer-agent)" > /dev/null
sleep 0.3

agentctl create "$NAME_REQ" --profile worker > /dev/null
test ! -s "$AAGENTS/$NAME_REQ/policy" || {
    echo "FAIL: policy file is non-empty before grant"; exit 1; }

echo "$NAME_TGT" > "$AAGENTS/$NAME_REQ/broker-target"
agentctl start "$NAME_REQ" --exec "$(command -v broker-test)" > /dev/null
sleep 0.5

if grep -q "broker denied cap=mailbox.send:$NAME_TGT to=$NAME_REQ" "$ALOG"; then
    echo "PASS: broker denied unauthorized cap"
    exit 0
fi
echo "FAIL: expected broker denial line not found in $ALOG"
exit 1
