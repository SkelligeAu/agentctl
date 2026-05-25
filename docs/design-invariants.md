# Design invariants

An **invariant** in this file is a rule whose violation changes the
runtime model: liveness, atomicity, ordering, identity, or authority.

Current implementation choices, performance tradeoffs, and operator
conventions are documented separately. They may change without
changing the runtime model.

## Enforcement

- Code review prevents intentional drift.
- Executable tests enforce a subset of invariants; see "Required
  tests" at the bottom of this file.
- Inline comments mark the relevant call sites.
- Where no test exists, the invariant is stated here but not verified
  at build time.

## Platform scope

### Hard

- Linux ≥ 5.14 defines production semantics. Every guarantee stated
  elsewhere in this document applies on Linux.
- macOS is development-only. macOS behavior must not define or
  constrain any capability, lifecycle, IPC, or security guarantee.

Following sections do not repeat macOS caveats. Where a Linux
primitive (`SOCK_SEQPACKET`, `pidfd`, `cgroup.kill`,
`MSG_CMSG_CLOEXEC`, `SCM_RIGHTS`, Landlock, seccomp-bpf) is
unavailable on Darwin, the code uses a fallback path; that path is
not a production guarantee.

## IPC

### Hard invariants

- The transport is `AF_UNIX` `SOCK_SEQPACKET`. One `sendmsg` is one
  logical message; one `recvmsg` is one logical message.
- `MSG_TRUNC` on `recvmsg` is fatal. The receiver closes the
  connection, discards the frame, and writes an audit line. The
  oversized frame is never delivered to application code.
- `MSG_CTRUNC` on `recvmsg` is fatal. The receiver closes the
  connection, discards the frame, and writes an audit line. Any
  fds dropped by the kernel during the cmsg truncation are gone.
- Every `recvmsg` allocates `CMSG_SPACE(sizeof(int) * IPC_MAX_FDS)`
  for ancillary data.
- Every `recvmsg` passes `MSG_CMSG_CLOEXEC`. Received fds are
  `O_CLOEXEC` at the syscall boundary.
- Every AF_UNIX socket creation uses `SOCK_CLOEXEC` where the
  platform supports it; otherwise `FD_CLOEXEC` is set via `fcntl`
  before any caller can see the fd.
- The header is ASCII; the payload is opaque bytes. The transport
  never inspects payload.
- No transport-layer userspace buffering. The kernel socket buffer
  is the only queue. There is no sender-side accumulator, no
  application ring buffer, no batching layer.

### Conventions

- Senders use `MSG_DONTWAIT` with bounded retry (3 attempts,
  exponential backoff at 1/5/25 ms), then surface `EAGAIN` to the
  caller. The retry parameters are an implementation choice.
- Callers of `ipc_recv` must close any fds returned in `msg->fds[]`
  they do not intend to consume. The transport does not own
  received-fd lifecycle after delivery.

## Lifecycle

### Hard invariants

- `pidfd` is the production lifecycle identity for supervised
  processes on Linux. Code that signals, polls liveness, or
  reaps for supervisory purposes uses pidfd.
- `pidfd_send_signal` is the only sanctioned signal mechanism in
  production code paths.
- `cgroup.kill` is the only sanctioned mechanism for atomic SIGKILL
  of an entire process subtree when the profile holds cgroup
  ownership.
- Code that busy-waits on a supervised own-child's exit must reap
  inline (`waitpid(..., WNOHANG)`). Without inline reaping, zombies
  satisfy any signal-0 liveness probe and the wait loop spins until
  timeout.
- `agentd` holds at most one pidfd per supervised process.
- PID is display and recovery metadata. The integer pid is used to
  populate `pid` files for `psa`/`inspect` and to seed `pidfd_open`
  during recovery. It is not the runtime authority for lifecycle
  decisions.

### Conventions

- `pidfd_open(pid, 0)` after `fork()` has a race window in the
  microsecond range. v1 accepts this; `clone3(CLONE_PIDFD)` is the
  strict-mode upgrade, not currently used.
- External (recovered) processes are observed via `pidfd_open(pid)`
  after reading the `pid` file at agentd startup. The same race
  window applies. If the pid was reused before agentd's recovery
  scan reads the file, agentd attaches to the wrong process; this is
  a documented limit, not a defended invariant.

## Authority

### Hard invariants

- Broker-mediated authority is represented only by open file
  descriptors. Strings, policy lines, names, agent identifiers,
  and task metadata are not authority.
- `agentd` is the sole broker. Authority is never synthesized by a
  supervised process. The per-agent broker channel at fd 3 is the
  only path to first-issuance.
- The broker is default-deny. An empty policy file, or a policy file
  that does not match the requested capability name, yields a
  `denied` response with no fd.
- The broker does not buffer, store, retry, or replay application
  messages. It transfers fds and writes audit lines.
- Every issuance writes an audit line to `agentd.log` and to the
  requesting agent's `audit.log` carrying the same 8-character hex
  correlation token.

### Limits

Do not assume the above invariants extend beyond these limits:

- Same-uid adversaries are out of scope. Two supervised processes
  running as the same uid can `ptrace`, signal, and connect
  directly to each other's listening sockets, bypassing the broker.
- `ptrace`, `SCM_RIGHTS` forwarding within an application, and
  `fork` without `O_CLOEXEC` discipline can move fds between
  processes that share a uid. The broker has no kernel-level
  mechanism to prevent this.
- Once delivered, an fd cannot be reclaimed from a peer's fd table.
  Revocation of a socket-anchored capability requires the broker to
  close its end of the underlying socket (which propagates EOF on
  next read/write) or the operator to restart the holding process.
  Filesystem-anchored capabilities, when added, will have weaker
  revocation: existing open fds keep working until the holder
  closes them.
- `SO_PEERCRED` on a broker-issued connected fd reports `agentd` as
  the connector (the broker is the process that called `connect`).
  It does not report the requesting agent's pid.

### Conventions

- `mailbox.send:<agent>` capabilities are used short-lived in
  v1: request, send, close. This is a convention enforced by
  application code and SDK documentation, not by the broker or the
  kernel. The broker does not impose a TTL.

## Audit

### Hard invariants

- `agentctl` and `agentd` never rewrite existing audit lines in place
  during normal operation. Lines are appended with `O_WRONLY |
  O_CREAT | O_APPEND` on each open.
- Audit lines are line-oriented ASCII: an RFC3339 UTC timestamp,
  `pid=<n>`, then free-form text, terminated by `\n`.
- Each broker issuance is recorded in `agentd.log` and in the
  requesting agent's `audit.log` with the same 8-character hex
  correlation token.

### Notes

- External rotation, truncation, or deletion of audit files is
  outside the runtime's guarantee. The runtime does not detect or
  recover from external mutation.
- The audit log is not tamper-evident. There is no cryptographic
  signing, no hash chaining, no external integrity check. A process
  with write access to the audit file can modify or remove lines.
- The correlation token is 32 bits drawn from `/dev/urandom`. It is
  sized for human correlation in single-host logs, not for
  adversarial unguessability.

## State tree

### Hard invariants

- The data root is per-user, resolved by `common.c::agentctl_root()`
  in order: `AGENTCTL_ROOT` env override → `$XDG_RUNTIME_DIR/agentctl`
  → `/tmp/agentctl-<uid>`. The root is created 0700 on first use.
- `agentctl_root()` validates ownership and permissions on first
  resolution: `st.st_uid == geteuid()` AND `(st.st_mode & 0077) == 0`.
  A binary that resolves to a foreign-owned or world/group-readable
  root MUST refuse to proceed (`exit(1)` with a stderr message). No
  escape hatch.
- `agentd` holds an exclusive advisory lock
  (`flock(LOCK_EX | LOCK_NB)` on `<root>/agentd.lock`) for its
  entire lifetime. A second `agentd` under the same data root MUST
  observe `EWOULDBLOCK` and refuse to start. The kernel releases
  the lock on any exit (including SIGKILL/OOM); successors can
  acquire it immediately after a crash.
- The agent directory `agentctl_root()/agents/<name>/` is the
  canonical operator interface for per-agent state. Files are owned
  by the running user and 0600 by default.
- Runtime authority and liveness live in `agentd`'s memory and the
  pidfds it holds. Files under `agents/<name>/` are a persisted
  projection of supervisor state, not the source of truth for any
  in-flight decision.

### Live-input files

These files are read by the runtime during normal operation. Edits
take effect on the next runtime read:

- `policy` — broker reads on every issuance request.
- `desired_state`, `enabled` — agentd reads on inotify events and
  during the periodic reconcile scan.
- `exec` — agentd reads when reconciling a `desired_state=running`
  entry that is not currently spawned.

### Display artifacts

- `pid` — last pid as written by the supervisor; used by `psa` and
  `agentctl inspect`. Not authoritative.
- `status` — symbolic state word as last written by the runtime; used
  by display tools. Not authoritative.

### Notes

- The broker reading `policy` on every request is an implementation
  choice. A cache with correct invalidation against operator edits
  is permitted; the current code does not implement one.

## Required tests

Invariants that should be verified by executable tests. The QEMU
integration test (`kernel/dev/share/agentfs-test.sh`) covers some;
the rest are stubs under `tests/`. Coverage is honest: TODO means no
test exists.

| Invariant | Covered? |
|---|---|
| `MSG_TRUNC` causes `ipc_recv` to return `IPC_PROTO_VIOLATION` | Covered: `tests/test_ipc_msg_trunc.c` (socketpair unit test) |
| `MSG_CTRUNC` causes `ipc_recv` to return `IPC_PROTO_VIOLATION` | Covered: `tests/test_ipc_msg_ctrunc.c` (socketpair unit test) |
| Received fds have `FD_CLOEXEC` set | Covered: `tests/test_cloexec.c` (socketpair unit test) |
| Broker default-deny: empty policy → no issuance | Covered: `tests/broker_default_deny.sh` |
| Wildcard policy grants matching caps | Covered: `tests/broker_wildcard.sh` |
| Malformed broker request denied; channel remains open | Covered: `tests/broker_malformed.sh` (uses `broker-fault` in `malformed` mode) |
| `MSG_CTRUNC` on the broker channel closes it | Covered: `tests/broker_msg_ctrunc.sh` (uses `broker-fault` in `many-fds` mode) |
| Policy file alone does not pre-materialize authority | Covered: `tests/policy_not_authority.sh` (uses `broker-fault` in `fdtable` mode) |
| Broker does not retain per-issuance state (no growing fd table) | Covered: `tests/broker_no_state.sh` (agentd fd count stable across 5 issuances) |
| Audit token appears in both `agentd.log` and the requester's `audit.log` | Covered: F4 step in `agentfs-test.sh` |
| Zombie stop path reaps inline; SIGTERM-clean stops do not escalate | Covered: F step in `agentfs-test.sh` (stop ~60 ms) |
| `cgroup.kill` terminates the subtree when cgroup ownership exists | Covered: F3 step in `agentfs-test.sh` |
| Foreign-owned or world-readable data root is refused | Covered: `tests/agentctl_foreign_root.sh` (permission half always-on; uid half sudo-gated) |
| Second `agentd` under the same data root refuses to start | Covered: `tests/agentd_single_instance.sh` |
| Lockfile is released on SIGKILL | Covered: `tests/agentd_lockfile_kill9.sh` |

Run all of the above via `tests/run-all.sh` (with `agentd` running for
the broker tests) or as Step H of the QEMU integration test.

## Change procedure

To change an invariant: update this file first, then change the code.
