# Shell helper sourced by every test script. Resolves the agentctl data
# root the same way common.c::agentctl_root does, and exports convenient
# path variables.
#
# Precedence:
#   1. AGENTCTL_ROOT env
#   2. $XDG_RUNTIME_DIR/agentctl
#   3. /tmp/agentctl-$(id -u)

if [ -n "${AGENTCTL_ROOT:-}" ]; then
    AROOT="$AGENTCTL_ROOT"
elif [ -n "${XDG_RUNTIME_DIR:-}" ]; then
    AROOT="$XDG_RUNTIME_DIR/agentctl"
else
    AROOT="/tmp/agentctl-$(id -u)"
fi

ASOCK="$AROOT/agentd.sock"
APID="$AROOT/agentd.pid"
ALOG="$AROOT/agentd.log"
ALOCK="$AROOT/agentd.lock"
AAGENTS="$AROOT/agents"

export AROOT ASOCK APID ALOG ALOCK AAGENTS
