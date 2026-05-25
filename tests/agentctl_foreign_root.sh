#!/bin/sh
# Verify: agentctl refuses to operate on a data root it doesn't own.
#
# Two phases:
#   1. Permission gate (always runs): create a dir with mode 0755 and
#      assert the binary refuses with "insecure permissions".
#   2. Foreign-uid gate (sudo-gated; skip 77 if no sudo): create a dir
#      owned by `nobody` and assert "owned by uid".

set -e
. "$(dirname "$0")/_lib.sh"

TMP_PERMS=/tmp/agentctl-perms-test-$$
TMP_FOR=/tmp/agentctl-foreign-test-$$

cleanup() {
    rmdir "$TMP_PERMS" 2>/dev/null || true
    if [ -d "$TMP_FOR" ]; then
        sudo rmdir "$TMP_FOR" 2>/dev/null || rmdir "$TMP_FOR" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# --- Phase 1: permission gate ---
mkdir -m 0755 "$TMP_PERMS"
OUT=$(AGENTCTL_ROOT="$TMP_PERMS" agentctl list 2>&1) && rc=0 || rc=$?
if [ "$rc" -eq 0 ]; then
    echo "FAIL: phase1 expected non-zero exit; got 0"
    echo "$OUT"
    exit 1
fi
if ! echo "$OUT" | grep -q "insecure permissions"; then
    echo "FAIL: phase1 stderr missing 'insecure permissions'"
    echo "$OUT"
    exit 1
fi
echo "PASS phase1: foreign-perms root rejected (insecure permissions)"

# --- Phase 2: foreign-uid gate ---
if ! command -v sudo > /dev/null 2>&1; then
    echo "SKIP phase2: sudo not available"
    exit 0
fi
# In QEMU we run as root; sudo install -o nobody works.
# On macOS dev loop the user is unlikely to want a password prompt,
# so we use `sudo -n` (non-interactive) and skip on failure.
if ! sudo -n install -d -o nobody -m 0700 "$TMP_FOR" 2>/dev/null; then
    echo "SKIP phase2: passwordless sudo install -o nobody not available"
    exit 0
fi
OUT=$(AGENTCTL_ROOT="$TMP_FOR" agentctl list 2>&1) && rc=0 || rc=$?
if [ "$rc" -eq 0 ]; then
    echo "FAIL: phase2 expected non-zero exit; got 0"
    echo "$OUT"
    exit 1
fi
if ! echo "$OUT" | grep -q "owned by uid"; then
    echo "FAIL: phase2 stderr missing 'owned by uid'"
    echo "$OUT"
    exit 1
fi
echo "PASS phase2: foreign-uid root rejected (owned by uid)"
exit 0
