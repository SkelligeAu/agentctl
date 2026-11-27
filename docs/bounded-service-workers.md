# Bounded service workers

`service` is an explicit restart policy for a single-use worker. After exit 0,
agentd kills the owned cgroup subtree and verifies `populated 0`. It then starts
a fresh process. A clean completion resets consecutive failures and does not
increment `restart_count`. It does not change legacy `always` behavior.
Signals, nonzero exits, and admitted-request timeouts use the existing exponential backoff
and five-short-run crash-loop limit. Service failure-budget exhaustion exits
agentd with status 70 so the outer host service discards the whole boundary.
An operator start clears suppression for legacy policies.

Configure the agent before starting it:

```sh
agentctl set-restart-policy worker service
printf '30000\n' > "$AGENTCTL_ROOT/agents/worker/config/service_timeout_ms"
printf '6000\n' > "$AGENTCTL_ROOT/agents/worker/config/service_request_timeout_ms"
```

Both timeouts are required decimal integers from 1 to 86400000 milliseconds.
These protected config files are host-owned policy. The worker must not have
write access to config. Set `cgroup=on` and finite CPU, memory, and PID limits in
the profile or config. Use Landlock, minimal seccomp, and a host network boundary.
Service mode requires active Linux cgroup v2. Direct CLI execution without
agentd is refused.

`service_timeout_ms` is the idle lifetime from before spawn. Idle expiry kills
and verifies the subtree, then rearms a fresh worker without counting a failure.
Before the first authorised broker inbox FD delivery, agentd consumes a per-run
admission latch and replaces the idle deadline with a full
`service_request_timeout_ms` budget. It uses CLOCK_MONOTONIC and captured config.
Later connections to this worker are denied as `target-busy` (client EACCES).
They cannot extend the deadline. Failed or partial inbox delivery keeps the
latch consumed and sets the deadline to expire immediately. Failed requester
reply also keeps the admission consumed. Nothing retries a delivered request.
Only a fresh worker resets the latch. No worker-written file controls admission.
Poll scheduling observes the remaining deadline; host scheduling and synchronous
startup/broker work can delay observation. Keep the host service bounded too.

agentd holds parent-opened cgroup.kill and cgroup.events descriptors. It does
not obtain cleanup authority from worker-written runtime files. Before every
spawn the cgroup must be empty. On every completion, timeout, stop, or orderly
daemon shutdown it kills the subtree and checks emptiness. Cleanup waits at
most two seconds. A failed kill, failed events read, or populated subtree after
that wait exits agentd with status 70. It never rearms that worker. The outer
host service MUST kill the whole unit on agentd exit (for example systemd
KillMode=control-group). Do not restart agentd with surviving service workers.
Recovery refuses a live service worker whose owned handles were lost.
A service spawn failure stops its desired state; fix the configuration and
start it explicitly. Process failures after successful startup use backoff.

Service workers still receive only their broker capabilities. No new lifecycle
command or supervisor capability is exposed to application ingress. The minimal
seccomp profile now permits memfd_create for anonymous sealed input. It does
not grant filesystem path access.

## Verification

```sh
make -j4
./tests/test_service_supervisor
python3 tests/runtime_regressions.py
python3 tests/service_regressions.py
```

The C unit test models owned descriptors. It checks 25 clean completions,
failure suppression, unchanged `always` accounting, deadline/exit races,
near-idle-limit admission, single-use admission and failed-delivery retirement, and
fail-closed kill and populated-subtree faults. It is not kernel isolation proof.
The service integration suite needs a non-root Linux user with delegated
`/sys/fs/cgroup/agents`. It checks 25 distinct worker processes, descendant
termination on idle timeout, and sealed memfd creation under minimal seccomp.
Run existing `tests/restart_crash_loop.sh` against a test daemon as well.

## Critical host components

For a long-running ingress component, use `restart_policy=never` and write
`yes` to its protected `config/critical` file before start. The default is off.
agentd captures this flag at startup. Any startup failure or process exit,
including exit 0, terminates agentd with status 70. The host unit then kills
all remaining processes and can start a fresh boundary. Recovery also refuses
a surviving critical component. This flag is host policy; do not grant ingress
or application processes write access to config or the agentd control channel.
