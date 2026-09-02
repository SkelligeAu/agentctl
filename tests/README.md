# Security-relevant tests

End-to-end + unit-style coverage of the invariants in
`docs/design-invariants.md`. Every test exits 0 on pass, non-zero on
fail, 77 on "skipped on this platform".

## Running

Build everything (`make` at the repo root); start `agentd`; run:

```sh
sh tests/run-all.sh
```

Or via the QEMU integration test:

```sh
cd kernel/dev && make qemu        # Step H runs tests/run-all.sh
```

## Unit tests (C, `socketpair`-based — no `agentd` needed)

| File | Asserts |
|---|---|
| `test_ipc_msg_trunc.c` | `ipc_recv` returns `IPC_PROTO_VIOLATION` when the kernel sets `MSG_TRUNC` on an oversized frame |
| `test_ipc_msg_ctrunc.c` | `ipc_recv` returns `IPC_PROTO_VIOLATION` when the kernel sets `MSG_CTRUNC` because the sender attached more SCM_RIGHTS fds than the recv cmsg buffer holds |
| `test_cloexec.c` | An fd received via SCM_RIGHTS through `ipc_recv` has `FD_CLOEXEC` set (verifies `MSG_CMSG_CLOEXEC` plumbing end-to-end) |

All three are Linux-only and `_exit(77)` on non-Linux platforms.

## Broker drivers (`bash`, exercise a live `agentd`)

| File | Asserts |
|---|---|
| `broker_default_deny.sh` | Empty `policy` → broker emits `denied: not-in-caps` and no fd is delivered |
| `broker_wildcard.sh` | Wildcard issuance works, the target exposes no pathname mailbox, and the receiver observes broker-authenticated sender identity |
| `broker_malformed.sh` | Malformed broker request → `denied: malformed-request` AND the broker channel remains usable for a second request |
| `broker_msg_ctrunc.sh` | A request carrying more SCM_RIGHTS fds than agentd's cmsg buffer holds → agentd closes the channel and logs the protocol violation |
| `policy_not_authority.sh` | A granted policy line does NOT pre-materialize as an open fd in the holder's fd table; only broker issuance does |
| `phase1_authority_boundary.sh` | A Landlock-confined child cannot modify `config/policy`, and an unauthenticated control-socket command is rejected |
| `broker_no_state.sh` | After 5 broker issuances + 5 process exits, agentd's `/proc/<pid>/fd/` count returns to its starting value (broker holds no per-issuance state) |

The broker drivers use `broker-fault` for fault injection. Modes
(`malformed`, `many-fds`, `fdtable`) are selected by writing the mode
name to `/tmp/agents/<name>/broker-fault-mode` before `start`.
Environment variables do not propagate from `agentctl` through `agentd`
to the spawned runtime, so the file-in-cwd convention is used.

## Coverage at a glance

| Invariant from `docs/design-invariants.md` | Test |
|---|---|
| IPC: `MSG_TRUNC` fatal | `test_ipc_msg_trunc` |
| IPC: `MSG_CTRUNC` fatal | `test_ipc_msg_ctrunc` |
| IPC: received fds CLOEXEC | `test_cloexec` |
| Authority: default-deny | `broker_default_deny.sh` |
| Authority: wildcard match | `broker_wildcard.sh` |
| Authority: malformed denied without channel teardown | `broker_malformed.sh` |
| Authority: MSG_CTRUNC on broker channel closes it | `broker_msg_ctrunc.sh` |
| Authority: policy ≠ authority | `policy_not_authority.sh` |
| Authority: no per-issuance state | `broker_no_state.sh` |
| Audit: token correlation across logs | F4 in `agentfs-test.sh` |
| Lifecycle: zombie stop reaps inline | F in `agentfs-test.sh` |
| Lifecycle: `cgroup.kill` subtree termination | F3 in `agentfs-test.sh` |

12 invariants, 12 tests, no TODO.

## What is intentionally not tested

These claims live in the threat model (`SECURITY.md`) and are
documented limitations rather than testable runtime guarantees:

- **Same-uid bypass.** Two processes running as the supervisor's uid
  can `connect()` to each other's listening sockets directly,
  bypassing the broker. This is a property of Unix permissions, not
  an agentctl behavior; a test would assert "this thing we said
  doesn't work, doesn't work."
- **Audit-log tamper-evidence.** The runtime does not provide
  cryptographic integrity for audit logs; a process with write access
  can modify them. Not a runtime guarantee, no test.
- **Audit token unguessability.** 32-bit tokens are sized for
  human-scale correlation, not adversarial unguessability.
- **Fork-leak of inherited fds beyond `O_CLOEXEC` discipline.** A
  supervised process that explicitly `dup2`s a cap fd into a forked
  child can hand it on. That's application behavior, not a
  transport guarantee.
