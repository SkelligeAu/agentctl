#!/bin/sh
set -e
. "$(dirname "$0")/_lib.sh"

REQ=tcon-req
TGT=tcon-tgt
cleanup() {
    agentctl stop "$REQ" 2>/dev/null || true
    agentctl stop "$TGT" 2>/dev/null || true
}
trap cleanup EXIT

agentctl create "$TGT" --profile worker >/dev/null
agentctl start "$TGT" --exec "$(command -v reviewer-agent)" >/dev/null
agentctl create "$REQ" --profile worker >/dev/null
agentctl grant "$REQ" "mailbox.send:$TGT" >/dev/null
echo "$TGT" > "$AAGENTS/$REQ/data/broker-target"
agentctl start "$REQ" --exec "$(command -v broker-concurrency)" >/dev/null
deadline=10
count=0
while [ "$deadline" -gt 0 ]; do
    count=$(grep -c "broker issued cap=mailbox.send:$TGT to=$REQ" \
        "$ALOG" || true)
    [ "$count" -eq 8 ] && break
    sleep 1
    deadline=$((deadline - 1))
done
if [ "$count" -ne 8 ]; then
    echo "FAIL: expected 8 serialized concurrent issuances, got $count"
    exit 1
fi
echo "PASS: 8 forked callers safely matched requests and fd responses"
