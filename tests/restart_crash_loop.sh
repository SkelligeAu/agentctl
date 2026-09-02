#!/bin/sh
set -e
. "$(dirname "$0")/_lib.sh"

NAME=tcrash
cleanup() { agentctl stop "$NAME" 2>/dev/null || true; }
trap cleanup EXIT

agentctl create "$NAME" --profile worker >/dev/null
agentctl start "$NAME" --exec "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/crash-agent" >/dev/null

deadline=25
while [ "$deadline" -gt 0 ]; do
    status=$(tr -d '\r\n' < "$AAGENTS/$NAME/runtime/status" 2>/dev/null || true)
    [ "$status" = crash-loop ] && break
    sleep 1
    deadline=$((deadline - 1))
done
if [ "${status:-}" != crash-loop ]; then
    echo "FAIL: crash loop was not suppressed (status=${status:-missing})"
    exit 1
fi
desired=$(tr -d '\r\n' < "$AAGENTS/$NAME/config/desired_state")
count=$(tr -d '\r\n' < "$AAGENTS/$NAME/runtime/restart_count")
if [ "$desired" != stopped ] || [ "$count" -ne 5 ]; then
    echo "FAIL: suppression state desired=$desired restart_count=$count"
    exit 1
fi
agentctl list >/dev/null
echo "PASS: exponential backoff suppressed a five-run crash loop"
