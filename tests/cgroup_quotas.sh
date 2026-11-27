#!/bin/sh
# Run inside the delegated cgroup VM, as its fixture administrator (root).
# agentd and its runtimes must run as the unprivileged reviewer user.
set -eu
[ "$(uname -s)" = Linux ] && [ "$(id -u)" = 0 ] || exit 77
: "${AGENTCTL_ROOT:?start an isolated agentd first}"
: "${AGENT_PROFILES_DIR:?set the test profile directory}"
CLI=${AGENTCTL_TEST_CLI:-/opt/agentctl}
RUNTIME=${AGENTCTL_TEST_RUNTIME:-/opt/runtime-regression}
ctl() { su reviewer -s /bin/sh -c "AGENTCTL_ROOT=$AGENTCTL_ROOT AGENT_PROFILES_DIR=$AGENT_PROFILES_DIR $CLI $*"; }
count=0
reject() {
    kind=$1; value=$2; denied=${3:-}
    name="quota-$kind-$$"
    base="$AGENTCTL_ROOT/agents/$name"
    cg="/sys/fs/cgroup/agents/$name"
    ctl create "$name" >/dev/null
    printf '%s\n' never > "$base/config/restart_policy"
    printf '%s\n' security-minimal > "$base/data/mode"
    printf 'cgroup=on\nCGROUP_CPU_MAX=%s\nCGROUP_MEMORY_MAX=67108864\nCGROUP_PIDS_MAX=16\n' "$value" > "$base/config/config"
    chown -R reviewer:reviewer "$base"
    if [ -n "$denied" ]; then
        mkdir "$cg"
        chown -R reviewer:reviewer "$cg"
        chown root:root "$cg/$denied"
        chmod 400 "$cg/$denied"
    fi
    if ctl start "$name" --exec "$RUNTIME" > "$base/data/start-result" 2>&1; then
        echo "FAIL: $kind started without its requested limit"
        ctl kill "$name" || true
        exit 1
    fi
    grep -q 'spawn failed' "$base/data/start-result"
    grep -q '^cgroup_status=unavailable$' "$base/runtime/enforcement.applied"
    [ ! -e "$base/runtime/pid" ]
    [ ! -e "$base/data/security-ready" ]
    grep -qx failed "$base/runtime/status"
    if [ -d "$cg" ]; then
        grep -q '^populated 0$' "$cg/cgroup.events"
        if [ "$denied" = cpu.max ] || [ "$kind" = kernel-range ]; then
            [ "$(cat "$cg/cpu.max")" = 'max 100000' ]
        fi
    fi
    case "$kind" in
        denied-*) grep -q "reason=$denied: Permission denied" "$base/runtime/enforcement.applied" ;;
        kernel-range) grep -q 'reason=cpu.max: Invalid argument' "$base/runtime/enforcement.applied" ;;
        *) grep -q 'reason=cpu.max invalid quota/period:' "$base/runtime/enforcement.applied" ;;
    esac
    echo "PASS: $kind rejects startup, reports unavailable, and never executes the runtime"
    count=$((count+1))
}
reject syntax garbage
reject zero 0/100000
reject period 1000/1000001
reject overflow 18446744073709551616/100000
reject truncated-prefix 0000000000000000000001000/1000000garbage
long_value=$(printf '%0400d' 1)
reject oversized-line "$long_value"
# This is syntactically valid and fits in microseconds, but exceeds the
# kernel scheduler's bandwidth bound. It tests a real failed kernel write.
reject kernel-range 999999999999999/100000
reject denied-cpu 10000/100000 cpu.max
reject denied-memory 10000/100000 memory.max
reject denied-pids 10000/100000 pids.max
echo "CPU QUOTA REGRESSIONS: pass=$count fail=0"
