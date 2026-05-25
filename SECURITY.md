# Security model

This document states the security model honestly. It is intended to
prevent a reader from inferring stronger isolation than agentctl
actually provides.

agentctl is a **trusted-tenant, hostile-input** process supervisor. It
is not multi-tenant isolation. It is not a sandbox for adversarial
code. It is not a substitute for VMs or user namespaces in scenarios
where mutually distrustful workloads share a host.

## Threat model

### In scope

| Threat | Coverage |
|---|---|
| A supervised process behaves outside the operator's intent due to bugs or misconfiguration | Profile-time seccomp/Landlock + cgroup limits + cap policy gate it |
| A supervised process receives hostile payload bytes from another process or external pipeline | Wire format is opaque to the engine; payload validation is the application's responsibility; sender identity is kernel-verified for direct connections |
| A supervised process exits, crashes, or is killed and must be restarted with clean state | pidfd-rooted lifecycle, cgroup.kill subtree termination, agentd reconciler |
| A supervised process attempts to acquire authority outside its policy | Broker denies; default-deny; one cap = one fd |
| The host operator wants to inspect what authority a process holds at a given moment | `/proc/<pid>/fd/` + agentd audit log + per-agent `audit.log` correlated by 8-hex token |

### Out of scope

| Threat | Why |
|---|---|
| Mutually adversarial processes on the same host | All processes run under the same uid by default; ptrace, signals, `/proc` visibility, and shared filesystem access are not blocked. Use user namespaces, per-process uids, or VMs. |
| Untrusted code execution (e.g., user-supplied scripts evaluated by a supervised process) | The agent's code is the operator's; agentctl does not safely contain code that the operator distrusts. Use Firecracker, gVisor, or a real sandbox. |
| Kernel exploits | Out of scope by construction. seccomp narrows but does not eliminate kernel attack surface. |
| Side channels (cache, timing, Spectre-class) | Not addressed. Use VMs. |
| Privileged escape from a hardened sandbox | Not the design. agentctl is a supervisor, not a containment layer. |
| Supply-chain compromise of supervised programs | Operator's responsibility (signing, IMA, dm-verity). |
| Cross-host or network-borne threats | Single-host project. No network attack surface beyond what agents themselves bind. |

## Trusted components

The Trusted Computing Base for an agentctl deployment is:

1. **The Linux kernel** — and specifically the syscalls used by the
   transport, lifecycle, and enforcement layers: `socketpair`,
   `sendmsg`/`recvmsg` with `SCM_RIGHTS`, `pidfd_open`,
   `pidfd_send_signal`, `landlock_*`, `seccomp`, cgroup v2 ops.
2. **`agentd`** — the supervisor process. **agentd is the trust root.**
   It holds all pidfds, all broker socketpair endpoints, all issued-cap
   sentinel handles. Compromise of agentd is equivalent to compromise
   of every process it supervises.
3. **`agentctl`** — runs in the operator's session under the operator's
   uid. Compromise of `agentctl` is equivalent to operator compromise.
4. **The profile files** in `AGENT_PROFILES_DIR` — read at exec time;
   define the per-process enforcement spec. Write access to these
   files is privileged. Profiles are not hot-reloaded.

If you do not trust the host or its operator, agentctl does not change
your threat model.

## Untrusted inputs

| Input | Treatment |
|---|---|
| Message payloads received over `SOCK_SEQPACKET` (or the macOS STREAM fallback) | Opaque bytes; the engine does not parse them. Application code parses; transport drops malformed frames + closes the connection. |
| `MSG_TRUNC` / `MSG_CTRUNC` from a peer | Protocol violation; receiver closes the connection. Fatal at the connection level, never at the engine level. |
| Filenames in artifact-write paths | Application must validate (no `/`, no `..`). The engine does not. |
| Broker request bytes from a supervised process | Parsed by `broker_parse`; malformed requests denied with a logged audit line. |
| The contents of `/tmp/agents/<name>/policy` | **Privileged input.** The operator (via `agentctl grant`/`deny`) is the only authorized writer. If a supervised process can write to its own policy file, the broker's policy gate is bypassed. Default permissions are 0600 owned by the operator's uid. |

## What the kernel enforces

| Primitive | Guarantee |
|---|---|
| `SO_PEERCRED` (Linux) | The pid/uid/gid captured at `connect()` time on the kernel-side peer. **Not forgeable** by the connector. |
| `SCM_RIGHTS` (Linux) | Atomic fd transfer alongside the message bytes. **Not forgeable**; only the kernel issues fds. |
| `seccomp-bpf` | After `prctl(PR_SET_NO_NEW_PRIVS) + seccomp(SECCOMP_SET_MODE_FILTER)`, the program cannot escape the syscall allowlist. **Immutable for the process's life.** |
| `Landlock` | After ruleset is enforced, path access is restricted per ruleset. **Immutable for the process's life.** |
| `cgroup v2` limits | `memory.max`, `pids.max`, `cpu.max` enforced by the kernel scheduler/OOM killer. |
| `pidfd_send_signal(fd, sig)` | Signals the specific task that `fd` was opened against. **Race-free against PID reuse.** |
| `cgroup.kill` (Linux ≥ 5.14) | SIGKILL every task in the cgroup tree atomically. **Race-free against PID/PGID reuse.** |

## What the kernel does NOT enforce

Things agentctl does not enforce, and that operators must NOT assume:

- **Cross-process isolation by uid.** All supervised processes run as
  the same uid by default. They can ptrace each other, signal each
  other, read each other's `/proc/<pid>/maps`, open each other's
  files (subject to file permissions), and observe each other in
  `ps`. If you need cross-process isolation as a security boundary,
  add user namespaces or per-agent uids — neither is built today.

- **Network egress.** Profiles do not block network access by default.
  A profile may seccomp-deny `socket(AF_INET, ...)` if the operator
  configures it. There is no `network namespace per agent`.

- **Inherited fd discipline beyond `O_CLOEXEC`.** Any fd a supervised
  process spawns into a child (via fork without seccomp-blocking
  `clone`/`fork`) carries forward unless explicitly closed. This is
  Unix; agentctl does not double-enforce.

- **TOCTOU on operator-owned files.** The policy file is read by the
  broker on each request. If the file is replaced atomically between
  reads, the broker uses the latest version. This is intended; do
  not assume any cache.

- **Atomic capability revocation.** Once an fd has been delivered via
  `SCM_RIGHTS`, the receiver controls its own fd table. The broker
  cannot reach into the receiver and close the fd. Revocation
  semantics differ per cap type — see "Revocation limitations" below.

- **Side channels.** Cache attacks, timing attacks, Spectre — none
  addressed.

## Same-uid limitations

All supervised processes share the supervisor's uid by default. This
means an attacker who compromises any one supervised process gains:

- The ability to `ptrace` other supervised processes (same uid).
- The ability to `kill(-1, sig)` other supervised processes.
- Read access to other agent dirs under `/tmp/agents/` (mode 0700, but
  same uid bypasses).
- The ability to connect directly to any agent's `agent.sock`
  (filesystem permissions only).

The broker is a logical gate, not a kernel-enforced one. A
compromised supervised process can still `socket() + connect()` to
any peer's `agent.sock` directly, bypassing the broker — because the
listener socket is in the filesystem and accepts same-uid clients.

To make the broker the *only* path to issuance:

1. Per-agent uids (not built; requires `CAP_SETUID` or
   user-namespace mapping in agentd).
2. Per-agent mount namespaces hiding peer sockets (not built).
3. Or: physically removing peer sockets from the filesystem and using
   only broker-issued connected fds (the "pre-connected pair" model
   in the capability design doc; not built).

Until one of these lands, **the broker provides authoritative audit
and policy gating, not kernel-enforced peer isolation.**

## `SO_PEERCRED` semantics — and how the broker subverts them

`SO_PEERCRED` returns the pid/uid/gid of the process that called
`connect()` at the moment of `connect()`. This is the only
kernel-verified peer identity for `AF_UNIX` sockets.

Subtleties operators must understand:

- **Connector ≠ current sender.** If process A connects to B, then
  `fork`/`execve` into a different program, the post-exec program
  reuses A's fd. B's `SO_PEERCRED` still reports A's original pid.
  Authority is the fd's, not the current sender's getpid().

- **Broker-issued sockets report agentd's pid, not the requester's.**
  When `ba` requests `mailbox.send:bb`, agentd performs the
  `connect()` to bb's listener. bb's accept side reads
  `SO_PEERCRED` and sees `agentd`. The requester's identity must be
  carried by the application's `REPLY-TO` header.

- **`REPLY-TO` is not kernel-authenticated.** Any process holding a
  send fd can put any string in the `REPLY-TO` header. The broker's
  audit log shows which agent it issued the cap to, correlated by
  token. Receivers that need *authenticated* sender identity for
  authorization must consult the audit log (out of band) or wait for
  the broker-proxied caps work (not in v1).

## Revocation limitations

Be honest about what Unix supports:

| Cap class | Revocation behavior |
|---|---|
| Socket-anchored caps (e.g., `mailbox.send`) | Broker closes its sentinel/connection-source → receiver's send returns `EPIPE` on next call. **Real, prompt.** |
| `pidfd` for peer observation | Auto-revokes when the target process exits. **Lifecycle-anchored.** |
| Filesystem caps (when added) | Existing fds keep working until the holder closes them; unlinking the path does not invalidate open fds. **Eventual at best; restart the holder for finality.** |
| Any fd already delivered into a holder's fd table | Receiver controls; broker has no kernel-level mechanism to revoke. **Restart the holder is the only sure revocation.** |

There is **no atomic revocation**. agentctl does not pretend to
provide it. If real-time revocation matters for a deployment, the
correct response is to restart the holding process.

## Confused deputy risks

The broker is the structural confused-deputy risk in agentctl.

| Scenario | Mitigation |
|---|---|
| Process X requests a cap that should only be granted under condition Y | Broker decides per request based on X's policy file. There is no per-request context X can supply that influences the decision; the policy file is the only input. Operators must keep policy minimal. |
| Process X tricks operator into running `agentctl grant X <cap>` | Operator responsibility. The CLI does not verify intent. |
| Process X claims (via `REPLY-TO`) to be a different agent | Receivers that act on `REPLY-TO`-identified senders are trusting a userspace claim. For authorization, use the broker's issuance audit, not `REPLY-TO`. |
| Operator runs `agentctl` while logged in to a session that supervised processes can influence (shell history, command completion, dotfiles) | `agentctl` runs as the operator and inherits the operator's trust. Do not invoke `agentctl` from a context that a supervised process can manipulate. |

## Multiple users on one host

Each user runs an independent agentctl instance under their own uid.
Data root resolution (`common.c::agentctl_root`) chooses, in order:

1. `AGENTCTL_ROOT` env override
2. `$XDG_RUNTIME_DIR/agentctl` (Linux user sessions; systemd manages
   `/run/user/<uid>/` already with the right permissions)
3. `/tmp/agentctl-<uid>` (fallback; macOS dev loop)

The data root is created 0700 on first use. Each user gets their own
`agentd.sock`, `agentd.pid`, `agentd.log`, `agentd.lock`, and
`agents/<name>/` tree.

### Cross-tenant adversarial isolation

The per-uid model is the supported adversarial-isolation boundary
between mutually distrustful tenants on the same host. agentctl
enforces two gates that make this safe:

- **Ownership validation.** Every `agentctl`/`agentd` invocation
  validates the resolved data root before performing any operation:
  `st.st_uid == geteuid()` and `(st.st_mode & 0077) == 0`. A
  misconfigured `AGENTCTL_ROOT` pointing at a foreign-owned or
  world-readable directory aborts with `exit(1)` and a stderr
  message before any file is read or written. There is no escape
  hatch.
- **Single daemon per data root.** `agentd` holds an exclusive
  `flock(LOCK_EX | LOCK_NB)` on `<root>/agentd.lock` for its entire
  lifetime. Two daemons under the same root cannot run
  concurrently. The kernel releases the lock on any exit, including
  `SIGKILL` and OOM, so a crashed prior instance does not lock the
  successor out.

agentd's accept-time `SO_PEERCRED` check rejects cross-uid control
connections at the kernel layer. The broker channel is a socketpair
created at spawn — there is no filesystem path another uid can
discover or bind.

For the operator-side hardening checklist (creating tenant uids,
mounting `/proc` with `hidepid=2`, delegating cgroups,
per-tenant `netns`), see [`docs/multi-tenant.md`](docs/multi-tenant.md).
Those host-level concerns are outside agentctl's scope; agentctl
assumes the operator has done them.

### What cross-tenant adversarial isolation gives you

- Filesystem isolation between tenant data roots (0700 + ownership
  validation).
- Single-daemon-per-tenant guarantee via `flock`.
- Kernel-enforced same-uid acceptance on the control socket.
- With `hidepid=2`: no `/proc` enumeration leak between tenants.
- With cgroup delegation: per-tenant kernel-enforced resource cap.
- With netns: per-tenant network stack.

### What this is NOT

- Adversarial isolation **within** a tenant. Two agents under the
  same tenant uid share that uid: ptrace, signal, same-uid
  filesystem access, /proc/`<pid>` reading are all available. The
  broker is a logical gate inside one uid, not a kernel boundary
  at this layer. Use Firecracker, gVisor, or a real container
  runtime for intra-tenant adversarial isolation. This is the
  locked anti-goal: agentctl is not a container runtime.
- Resistance to kernel exploits or side channels.
- Cross-tenant audit aggregation (centralize via journald or a log
  aggregator if needed).

## Reporting security issues

This is a research/POC codebase. There is no security-response
infrastructure. If you find a security-relevant issue, open a regular
GitHub issue or contact the author directly. Do not deploy this code
in a security-sensitive setting without a security review you trust.
