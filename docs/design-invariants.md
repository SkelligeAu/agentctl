# Design requirements

This document defines required behavior, implementation choices and known limits.
A stated requirement is not proof that every code path meets it.
Tests cover the cases listed below.
See [SECURITY.md](../SECURITY.md) for the deployment model.

## Platforms

Linux 5.14 or later defines the supported process and transport behavior.
Filesystem restrictions require Landlock ABI 3 or later, usually Linux 6.2 or later.
A Linux start that requests Landlock must fail if that restriction cannot be installed.

macOS is for development.
Its fallback paths do not establish Linux security guarantees.

## Message transport

- Linux application channels use `AF_UNIX` `SOCK_SEQPACKET`.
- One send operation produces one message.
- A receiver rejects `MSG_TRUNC` and `MSG_CTRUNC`. It discards the frame and closes the connection.
- Linux descriptor receives use `MSG_CMSG_CLOEXEC`.
- A received descriptor must be close-on-exec before application code receives it.
- A rejected receive closes all descriptors installed by that receive.
- A successful `ipc_recv` transfers descriptor ownership to its caller.
- `read_message` closes ancillary descriptors because its interface cannot return them.
- Socket creation uses `SOCK_CLOEXEC` where available. Otherwise, code sets `FD_CLOEXEC` before exposing the descriptor.
- Headers are ASCII. The payload is byte data and is not interpreted by the transport.
- Duplicate known headers and malformed length values are protocol errors.
- Parsers must reject overlong recognized fields instead of silently truncating them.
- The broker does not maintain an application message queue. Kernel socket buffers provide message storage.

The overlong-field requirement is not met by every legacy C wrapper.
Applications must validate field values before use.

Application receive buffers allow up to `IPC_MAX_FDS` descriptors.
The broker request handler uses its own four-descriptor receive buffer.

Send retries are bounded by `IPC_SEND_RETRIES`.
The configured delays are 1, 5 and 25 milliseconds.
The caller receives an error when retries are exhausted.

Callers must close descriptors they do not use.
Close-on-exec does not prevent descriptor inheritance through `fork`.

## Supervised processes

Use a pidfd to identify a live supervised task on Linux.
Use `pidfd_send_signal` when that handle is available.
PID and process-group operations remain fallback paths.

The supervisor holds at most one pidfd per managed process.
When it waits for its own child to exit, it must reap available zombies.
A signal-zero check alone can treat a zombie as a live process.

Use an owned `cgroup.kill` descriptor for atomic subtree termination when available.
The supervisor opens this handle in the parent.
Cleanup must not obtain cgroup authority from `runtime/enforcement.applied`.

Without an owned cgroup, cleanup uses the process group.
A child that creates another session can survive that fallback.

After a leader exits, the supervisor attempts descendant cleanup before clearing its live process state.
This does not guarantee cleanup of children outside its cgroup or process group.

### Process identity limits

The implementation opens a pidfd after `fork`.
It does not use `clone3(CLONE_PIDFD)`.

Recovery reads a stored PID before opening a pidfd.
The PID can be changed or reused before that open.
A pidfd does not validate the PID file from which its number came.

Direct mode also uses stored PIDs.
Do not treat these recovery and direct-mode paths as equivalent to live supervisor-held process identity.

### Restart policy

Restart delays start at one second and increase to a maximum of 30 seconds.
Five consecutive runs shorter than 30 seconds set `crash-loop`.
The desired state becomes `stopped`.
An explicit operator start clears restart suppression.

## Capability broker

An open descriptor permits use of its channel.
Names, policy entries and task metadata do not provide that access.

`agentd` is the broker for supervised agents.
Descriptor 3 is the private request channel.
An empty or nonmatching policy denies the request without a descriptor.

The broker transfers application endpoints and writes audit records.
It does not buffer, retry or replay application messages.
It retains no application endpoint after transfer.

Inbox delivery and broker replies use nonblocking sends.
A full inbox returns `target-busy`.
An unread broker reply channel is shut down.
Neither case may block the supervisor's event loop.

Rejected broker requests close received descriptors, including those installed before descriptor truncation was reported.

A request and its descriptor-bearing response form one serialized exchange.
Threads and forked children share descriptor 3.
They must hold the process-local lock and the record lock on inherited descriptor 5 for the complete exchange.

Incoming channels use a datagram socket pair on descriptor 4.
Each delivery contains one endpoint and requester metadata.
Datagram boundaries prevent adjacent descriptor deliveries from being combined.

`REPLY-TO` is routing metadata.
It is not authenticated sender identity.
See [capability broker](capabilities.md) for the requester metadata and its limits.

### Capability limits

Same-user hostile processes are outside the isolation model.
The broker does not prevent `ptrace`, signals, `/proc` access or descriptor forwarding.

A delivered descriptor cannot be revoked by the broker.
Close every copy or stop every process that retains one.
Deleting a filesystem pathname does not invalidate an open descriptor.

The normal application sequence is request, send, close.
There is no enforced expiry time.

## Control requests

Partial requests use nonblocking reads.
Each pending request has a 1024-byte buffer and a five-second total deadline.
At most 64 requests can be pending.
A partial unauthenticated request must not block other supervisor events.

The daemon validates the control token at startup and retains it in memory.
Empty or malformed stored tokens prevent startup.
Later file changes do not change the running daemon's accepted token.

## Profile restrictions and limits

Explicit start overrides are written to `config/enforcement.overrides` before the running state is requested.
Restarts retain them.
A start without an override restores that field's profile default.

With cgroup enforcement enabled, configured memory, PID and CPU limits are startup requirements.
Invalid CPU quota syntax or a failed limit write prevents runtime creation.
The applied state records cgroup enforcement as unavailable.

Without configured limits, an unavailable cgroup hierarchy retains the process-group fallback.
Cgroup attachment occurs after `fork`, without a child startup barrier.
The child can execute or fork before attachment.

The minimal seccomp filter permits runtime execution and libc startup calls.
It is not an exec-once policy.
Linux Landlock installation, seccomp installation and exec failures must be returned as start failures.

## Audit records

Normal operation appends audit lines with `O_WRONLY | O_CREAT | O_APPEND`.
It does not rewrite earlier lines.

Each line contains an RFC3339 UTC timestamp, `pid=<n>` and text, followed by a newline.
Each approved capability request records the same eight-character hexadecimal value in both logs:

- `agentd.log`
- The requesting agent's `audit.log`

The value contains 32 random bits from `/dev/urandom`.
It is for log correlation, not authentication.

Audit files have no cryptographic integrity protection.
A process with write access can change or delete them.
External rotation and truncation are not detected or repaired by the runtime.

## State directories

The state root is selected in this order:

1. `AGENTCTL_ROOT`.
2. `$XDG_RUNTIME_DIR/agentctl`.
3. `/tmp/agentctl-<uid>`.

The root is created with mode `0700`.
Its owner must match the effective user ID.
Group and other permission bits must be zero.
A failed owner or permission check terminates the program with an error.

`agentd` holds `flock(LOCK_EX | LOCK_NB)` on `agentd.lock` until exit.
A second daemon under the same root must refuse startup.
The kernel releases the lock after any process exit, including `SIGKILL` and an out-of-memory kill.

Each `agents/<name>/` directory has these subdirectories:

| Directory | Purpose |
|---|---|
| `config/` | Operator and supervisor inputs. |
| `runtime/` | Status and process metadata. |
| `data/` | Runtime working directory and application files. |

Compatibility symlinks expose older top-level paths.
The normal Landlock profile does not grant the child access to that parent directory.
Migration must not move a compatibility symlink into its own target.

Live supervisor state uses in-memory records and open process handles.
Files used for display are not a substitute for those records.
Recovery and direct-mode PID reads remain exceptions with the limits stated above.

### Inputs read during operation

| File | Read point |
|---|---|
| `config/policy` | Each broker request. |
| `config/desired_state` | Relevant inotify events and periodic reconciliation. |
| `config/enabled` | Relevant inotify events and periodic reconciliation. |
| `config/exec` | Reconciliation when the desired state is running and no runtime is active. |

There is no policy cache.
Changing policy affects later requests, not descriptors already delivered.

### Display files

`runtime/pid` records the last stored PID.
`runtime/status` records a symbolic process state.
Display tools use these files.
They do not establish live process identity.

## Tests

| Requirement | Test |
|---|---|
| Reject payload truncation | `tests/test_ipc_msg_trunc.c` |
| Reject descriptor truncation | `tests/test_ipc_msg_ctrunc.c` |
| Close descriptors on receive errors | `tests/test_ipc_fd_cleanup.c` |
| Set close-on-exec on received descriptors | `tests/test_cloexec.c` |
| Validate path components, broker fields, CPU quotas and profile defaults | `tests/test_input_validation.c` |
| Deny requests without policy permission | `tests/broker_default_deny.sh` |
| Match wildcard policy entries | `tests/broker_wildcard.sh` |
| Serialize concurrent broker requests | `tests/broker_concurrency.sh` |
| Deny malformed requests without closing a valid channel | `tests/broker_malformed.sh` |
| Close a truncated broker channel | `tests/broker_msg_ctrunc.sh` |
| Do not create descriptors from policy entries alone | `tests/policy_not_authority.sh` |
| Keep the broker descriptor count stable | `tests/broker_no_state.sh` |
| Refuse an unsafe state root | `tests/agentctl_foreign_root.sh` |
| Refuse a second daemon | `tests/agentd_single_instance.sh` |
| Release the daemon lock after SIGKILL | `tests/agentd_lockfile_kill9.sh` |
| Reject unauthorized control and configuration changes | `tests/phase1_authority_boundary.sh` |
| Suppress a repeated crash loop | `tests/restart_crash_loop.sh` |
| Check supervisor and Python SDK regressions | `tests/runtime_regressions.py` |
| Reject failed configured cgroup limits in a delegated VM | `tests/cgroup_quotas.sh` |

Run `tests/run-all.sh` with a daemon for the broker tests.
The cgroup quota script needs a separate disposable VM.
Some cross-user checks require sudo.

The generated `kernel/dev/share/agentfs-test.sh` has additional QEMU scenarios when present.
Earlier scenarios F, F3 and F4 checked zombie cleanup, subtree termination and audit correlation.
These scenarios are not all run by the userspace suite.
See [test instructions](../tests/README.md).

## Changes to requirements

Update this document before changing a design requirement.
Change the implementation and regression tests with the requirement.
