#!/bin/sh
# Run every security-relevant test in this directory. Drives both the
# unit-style C tests (no agentd needed) and the bash drivers that exercise
# the broker against a running agentd.
#
# Assumes: agentctl, agentd, broker-test, broker-fault, reviewer-agent in
# PATH; agentd already running for broker tests. Exits 0 only if all pass.

set -e
HERE=$(cd "$(dirname "$0")" && pwd)

pass=0
fail=0
skip=0

run_one() {
    name=$1; shift
    rc=0
    "$@" || rc=$?
    case $rc in
        0)  echo "  PASS  $name"; pass=$((pass+1)) ;;
        77) echo "  SKIP  $name"; skip=$((skip+1)) ;;
        *)  echo "  FAIL  $name (exit=$rc)"; fail=$((fail+1)) ;;
    esac
}

echo "== ipc unit tests =="
run_one ipc_msg_trunc       "$HERE"/test_ipc_msg_trunc
run_one ipc_msg_ctrunc      "$HERE"/test_ipc_msg_ctrunc
run_one cloexec_propagation "$HERE"/test_cloexec
run_one input_validation   "$HERE"/test_input_validation

echo "== broker integration tests =="
for s in broker_default_deny broker_wildcard broker_concurrency broker_malformed \
         broker_msg_ctrunc policy_not_authority broker_no_state; do
    run_one "$s" sh "$HERE/$s.sh"
done

echo "== per-uid isolation tests =="
# These manage their own AGENTCTL_ROOT and daemon lifecycle, so they
# coexist with the shared agentd the suite runner has running.
for s in agentctl_foreign_root agentd_single_instance agentd_lockfile_kill9; do
    run_one "$s" sh "$HERE/$s.sh"
done

echo "== authority boundary tests =="
run_one phase1_authority_boundary sh "$HERE/phase1_authority_boundary.sh"

echo "== lifecycle hardening tests =="
run_one restart_crash_loop sh "$HERE/restart_crash_loop.sh"

echo
echo "results: pass=$pass fail=$fail skip=$skip"
[ "$fail" -eq 0 ]
