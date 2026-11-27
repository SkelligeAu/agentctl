# agentfs research module

`agentfs.ko` is research code.
It is not a supported production transport or a security boundary.
The supported userspace transport uses UNIX domain sockets.

## Purpose

The module tests kernel-managed agent names and bounded mailboxes.
It provides:

- A registered name associated with a task.
- Inbox and outbox files containing byte messages.
- A periodic check for tasks that have exited.

The check runs at a two-second interval.
It does not detect exit immediately.

Userspace programs still manage message headers, tasks, profiles, artifacts and restart policies.

## Limits

The userspace supervisor uses pidfds and `SIGCHLD` for process exit handling.
The module uses periodic checks.

Direct UNIX socket connections provide `SO_PEERCRED`.
The module mailbox does not provide the same sender metadata.
A `REPLY-TO` header remains a sender-supplied value.

`SOCK_SEQPACKET` provides message boundaries without an out-of-tree module.
The module adds kernel build, loading and maintenance requirements.

No module fuzzing, KASAN or syzkaller results are recorded here.
Review and test the module before running it outside a disposable VM.
Module loading requires host privileges.
A Docker container does not provide a separate kernel for loading modules.

## Files

| Path | Purpose |
|---|---|
| `kernel/agentfs.c` | Kernel module. |
| `kernel/Makefile` | Module and helper builds. |
| `kernel/agentfs-register.c` | Registration helper. |
| `kernel/agentfs-send.c` | Message writer. |
| `kernel/agentfs-read.c` | Message reader. |
| `kernel/dev/` | Docker build and QEMU test tools. |
| `kernel/dev/share/agentfs-test.sh` | Generated integration script, when present. |

Earlier QEMU scenarios C, D and E exercised the module transport.
Those records do not qualify it for production use.

## Run the experiment

See [kernel development](../kernel/dev/README.md) for prerequisites.

```sh
cd kernel/dev
make module
make qemu
```

The kernel and initramfs must already be built.
A successful test script returns zero.

Keep userspace as the supported transport.
Any proposal to extend the module must identify a requirement that the userspace implementation cannot meet.
See [design invariants](design-invariants.md).
