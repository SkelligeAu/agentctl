# agentctl

A local capability runtime for Linux. Supervises long-lived processes
on one host, transfers authority between them as file descriptors,
exposes operational state as plain files.

Three things it does:

- **Supervision.** `pidfd` for liveness and signals; `cgroup.kill`
  for subtree teardown; restart policy in a file.
- **IPC.** `AF_UNIX` + `SOCK_SEQPACKET`. One message in, one message
  out. No framing layer to get wrong.
- **Authority.** A small broker in the supervisor issues capabilities
  as file descriptors over `SCM_RIGHTS`. Possession is permission.

Per-user state lives under `$XDG_RUNTIME_DIR/agentctl/agents/<name>/`
(or `/tmp/agentctl-<uid>/agents/<name>/` if `XDG_RUNTIME_DIR` is unset;
`AGENTCTL_ROOT` overrides both). Operators debug with `ls`, `cat`,
`tail -f`, `lsof`, `strace`.

## What this eliminates

Compared to a process supervisor using the Unix primitives most
existing supervisors still rely on — `kill(pid, 0)` for liveness,
`SOCK_STREAM` for local IPC with application-level framing, shared
`/tmp` paths, ad-hoc audit logs — these bug classes are structural
absences in the agentctl architecture rather than things you have to
remember to handle:

| In a supervisor using older primitives | In agentctl |
|---|---|
| `kill(pid, 0)` for liveness; recycled PIDs mislead the supervisor | `pidfd_send_signal(fd, 0)`; the fd binds to the task, not the integer |
| Stops spin the full timeout because zombies still satisfy `kill(pid, 0)` | Inline `waitpid` in the wait loop + `cgroup.kill`; SIGTERM-clean stops in ~60 ms |
| `kill(-pgid, SIGKILL)` races against pgid recycling on subtree termination | `cgroup.kill`: atomic across every task in the cgroup |
| LEN-mismatch on stream IPC wedges the receiver in a partial read | `SOCK_SEQPACKET`: one message or none |
| `fork()` leaks fds the child shouldn't have | `O_CLOEXEC` and `MSG_CMSG_CLOEXEC` are project-wide invariants |
| "Which service had access to what at 14:32" is a multi-log scavenger hunt | Each broker issuance writes a shared 8-hex token to two logs |
| Two users on a shared host accidentally share state or shadow each other's daemon | Per-uid data root with ownership-validated 0700 gate; `flock`-enforced single daemon per root |

Numbers are from the QEMU integration test on Linux 6.6.32. See
`BENCHMARKS.md` for the SEQPACKET vs STREAM matrix.

## Where this is useful

Workloads where these primitives compose well:

**Long-lived worker pools.** Three formatters, two indexers, a queue
consumer. You want crash-restart, per-worker memory caps, and an
inbox protocol that doesn't reinvent itself per worker.

**Local plugin / tool hosts.** An editor or build tool running
named subprocesses across a session. `cgroup.kill` makes "stop this
process and every subprocess it spawned" race-free. `pidfd` makes
"is the language server I started yesterday still mine?" race-free.

**Credential-holding pools.** A pool process holds the credential
and connects out. Workers ask the pool for a connection and get a
ready-to-use socket via `SCM_RIGHTS`. They never see the secret. A
compromised worker exposes one connection.

**Subprocess sandboxing with narrow capabilities.** A formatter that
needs to read one file: open it in the parent, pass the read fd
across. The child gets exactly that fd. No path, no directory
access, no Landlock rule to maintain per invocation.

**Audit-required automation.** Cron-style flows where the operator
must answer "what did this process have access to and when." The
audit token + per-task on-disk record answer it without external
infrastructure.

**Developer infrastructure.** A test runner pool, a local language
server farm, a dev server with helpers — situations where you need
restart-on-crash and structured IPC but don't want to set up systemd
user units, DBus interfaces, or a container runtime for them.

## A worked example

A worker pool that talks to a database without giving the workers the
database password.

The pool process opens N connections on startup. The workers run
under a profile that forbids reading the credential file.

When a worker needs a connection:

```
worker → broker  : VERB request CAP mailbox.send:pool
                ← broker delivers a connected fd to pool's inbox

worker → pool    : VERB connect
                ← pool replies with one DB socket attached via SCM_RIGHTS

worker → DB      : queries flow over the received fd; pool is out of the path
```

The worker never holds the credential. A compromise exposes one
connection, not the password. Revocation is the pool closing its end
of the connection pair; the worker's next read returns EOF. To do
the same thing on top of systemd, you need a service account, socket
activation, possibly a separate proxy service, and a way to revoke a
running session — each part fine, the combination is a project.

The pattern works because the broker delivers the authority (a usable
fd) atomically with the reply that authorizes it. There is no token
to validate, no path to canonicalize, no race between deciding "yes"
and giving the worker what it asked for.

## Why not systemd

systemd is a system manager. Its scope spans PID 1, the boot model,
DBus services, journald, scheduled jobs, user sessions, unit
dependencies. agentctl is one thing: a local runtime where
long-lived processes pass capabilities to each other as fds.

Concrete differences a user sees:

- No DBus dependency. IPC is direct `AF_UNIX` between processes; the
  broker is a per-agent socketpair.
- Authority transfer is a runtime primitive, not a unit-file
  directive. Agents request connected fds during normal operation
  via the broker, not only at unit startup.
- All operational state is a file under the per-user data root
  (`$XDG_RUNTIME_DIR/agentctl/agents/<name>/` by default).
  Inspection is `ls`, `cat`, `lsof`; no `systemctl`, no
  `journalctl --user-unit ...`.
- No service dependency graph. The runtime has no opinion on startup
  order beyond "the target's inbox needs to exist before a
  `mailbox.send:target` request can succeed."
- Linux ≥ 5.14 primitives are required. `pidfd`, `cgroup.kill`,
  `MSG_CMSG_CLOEXEC` are not optional.

systemd is the right tool for general-purpose system management.
agentctl is the right tool when you need three to thirty named
processes on one host and want explicit authority handoff between
them.

## Quickstart

```sh
make
export AGENT_PROFILES_DIR=$(pwd)/profiles
./agentd &
./agentctl create rb --profile worker
./agentctl start  rb --exec $(pwd)/reviewer-agent
printf '+TODO\n+strcpy(a,b);\n' | ./agentctl send rb review
./agentctl tasks rb
./psa | head
./agentctl stop rb
```

`agentctl` with no arguments prints the full command set. The reference
programs under `reviewer-agent.c` and `fanout-agent.c` are around 400
lines each; both speak the wire format directly and serve as the
shortest path from quickstart to "I see how to write one of these."

## Maturity

This is a working POC, not production-deployed:

- QEMU integration test passes end-to-end on Linux 6.6.32.
- Pingpong benchmark verifies SEQPACKET parity with STREAM.
- Broker issues `mailbox.send:<agent>` caps with audit-tokened
  correlation. Delegation, leases, filesystem caps are not built.
- Per-uid hardening: ownership-validated data root + `flock`
  single-daemon-per-root gate. Cross-tenant deployment guide at
  `docs/multi-tenant.md`.
- Broker and IPC parsers have libFuzzer + ASan/UBSan harnesses. CI runs
  native Linux/macOS builds, the Linux regression suite, and fuzz smoke tests.
  Longer fuzz campaigns, KASAN, and syzkaller remain follow-up work.
- macOS compiles and runs for dev only; production semantics depend
  on Linux. See `docs/macos.md`.

Don't deploy in security-sensitive settings without a review you
trust. The `SECURITY.md` threat model is honest about the limits.

## Scope

Not a container runtime. Not a cluster orchestrator. Not a service
mesh. Not a workflow engine. Not a message broker. Not an AI or model
framework. The threat model is **trusted-tenant, hostile-input**:
operators trust their own programs; programs may receive hostile
payloads.

**Cross-tenant** adversarial isolation (different uids on one host)
is supported: per-uid data root with kernel-enforced ownership gate,
single-daemon-per-uid via `flock`. See `docs/multi-tenant.md` for the
host-side deployment story (uid creation, `/proc` `hidepid`, cgroup
delegation, optional netns). **Intra-tenant** adversarial isolation
(agents within one uid distrusting each other) is out of scope; use
namespaces or VMs.

## Build

```sh
make            # Linux or macOS host build
make clean
```

No external dependencies; libc only. `cc -std=c99 -O2`. For the
static Linux binaries used by the QEMU integration test:

```sh
cd kernel/dev && make userland
```

## Layout

```
agentctl.c            CLI
agentd.c              supervisor: pidfd + broker + reconciler
ipc.{c,h}             AF_UNIX transport
broker.{c,h}          capability broker
common.{c,h}          atomic-write, audit, lifecycle helpers, spawn
profiles.{c,h}        profile parser
tasks.{c,h}           per-task on-disk state
enforcement.{c,h}     Landlock + seccomp + cgroup v2
reviewer-agent.c      reference program
fanout-agent.c        reference program: delegating coordinator
psa.c                 ps for supervised processes
profiles/             worker / simple / coordinator
examples/             broker-test, Python reference program
sdk/python/agent.py   Python SDK (stdlib only)
bench/                pingpong benchmark
kernel/               agentfs.ko research artifact (see docs/research.md)
docs/                 deep-dive docs
tests/                security-relevant tests
```

## Docs

- `SECURITY.md` — threat model and limits
- `docs/design-invariants.md` — hard rules the code commits to
- `docs/capabilities.md` — broker architecture and threat analysis
- `docs/multi-tenant.md` — per-uid (cross-tenant) deployment guide
- `docs/macos.md` — dev-loop notes
- `docs/research.md` — `agentfs.ko` (kernel-side experiment)
- `BENCHMARKS.md` — pingpong matrix
- `tests/README.md` — security-relevant test coverage
- `kernel/dev/README.md` — Docker + QEMU dev environment
