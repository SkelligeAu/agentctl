#!/bin/sh
# Verify: agentd does not retain per-issuance state across N issuances.

set -e
. "$(dirname "$0")/_lib.sh"

if [ "$(uname -s)" != Linux ]; then
    echo "skip: linux-only (/proc fd inspection)"
    exit 77
fi
TGT=tns-tgt

cleanup() {
    agentctl stop "$TGT" 2>/dev/null || true
    for i in 1 2 3 4 5; do
        agentctl stop "tns-req-$i" 2>/dev/null || true
        rm -rf "$AAGENTS/tns-req-$i" 2>/dev/null || true
    done
    rm -rf "$AAGENTS/$TGT" 2>/dev/null || true
}
trap cleanup EXIT

AGENTD_PID=$(cat "$APID")
test -n "$AGENTD_PID" || { echo "FAIL: agentd not running"; exit 1; }

FD_BEFORE=$(ls /proc/"$AGENTD_PID"/fd 2>/dev/null | wc -l)

agentctl create "$TGT" --profile worker > /dev/null
agentctl start  "$TGT" --exec "$(command -v reviewer-agent)" > /dev/null
sleep 0.3

for i in 1 2 3 4 5; do
    R="tns-req-$i"
    agentctl create "$R" --profile worker > /dev/null
    agentctl grant  "$R" "mailbox.send:$TGT"   > /dev/null
    echo "$TGT" > "$AAGENTS/$R/data/broker-target"
    agentctl start  "$R" --exec "$(command -v broker-test)" > /dev/null
done
sleep 1.0

agentctl stop "$TGT" > /dev/null
rm -rf "$AAGENTS/$TGT" 2>/dev/null
sleep 0.5

FD_AFTER=$(ls /proc/"$AGENTD_PID"/fd 2>/dev/null | wc -l)
DELTA=$((FD_AFTER - FD_BEFORE))
if [ "$DELTA" -lt 0 ]; then DELTA=$((-DELTA)); fi

if [ "$DELTA" -le 2 ]; then
    echo "PASS: agentd fd count stable across 5 issuances (before=$FD_BEFORE after=$FD_AFTER)"
    exit 0
fi
echo "FAIL: agentd fd count grew across issuances (before=$FD_BEFORE after=$FD_AFTER)"
ls -l /proc/"$AGENTD_PID"/fd
exit 1
