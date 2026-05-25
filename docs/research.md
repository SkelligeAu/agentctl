# Research artifact: `agentfs.ko`

**Status: research-only. Not for production. Not maintained as a path of
record.** Listed here to keep the kernel-side IPC experiment out of the
main README.

## What it is

A small out-of-tree Linux kernel module that exposes a pseudo-filesystem
at a chosen mount point and pushes three things into the kernel:

- agent identity, bound to a `task_struct` via a `register` file
- per-agent in-kernel mailbox files (one inbox, one outbox)
- lifecycle binding via a 2-second periodic workqueue reaper

The userland POC end-to-end-tested this in QEMU as scenarios C/D/E of
`kernel/dev/share/agentfs-test.sh`.

## Why it is not the recommended substrate

Every problem `agentfs.ko` was meant to solve has been solved better in
userspace, and the kernel artifact carries costs the userspace path
does not:

- **Death detection**: `pidfd` + `SIGCHLD` (userspace) is race-free and
  immediate. The 2 s reaper is strictly worse.
- **Per-message peer identity**: `SO_PEERCRED` (userspace) is
  kernel-verified. The kernel mailbox is opaque; receivers fall back
  to a `REPLY-TO` header (a userspace claim).
- **Atomic message delivery**: `SOCK_SEQPACKET` (userspace) provides
  one-sendmsg-one-recvmsg semantics with no out-of-tree code.
- **Auditability**: the module has had no fuzzing, no KASAN, no
  syzkaller, no security review. Calling its surface a security
  boundary today would be irresponsible.
- **Operational cost**: kernel headers, `CAP_SYS_MODULE` to load, no
  rootless support, no container support, no DKMS, no signing path.

## Files

- `kernel/agentfs.c` — the module (~800 LoC)
- `kernel/Makefile` — out-of-tree build
- `kernel/agentfs-{register,send,read}.c` — userspace probes
- `kernel/dev/` — Docker + QEMU dev environment
- `kernel/dev/share/agentfs-test.sh` — exercises scenarios C/D/E

## If you want to run it

See `kernel/dev/README.md`. The integration test target boots a
QEMU/aarch64 VM with the module loaded and the test script running:

```sh
cd kernel/dev
make module
make qemu
```

Test exit 0 on a clean run.

## Not maintained as a path of record

The architectural direction (locked in
`memory/project_agentctl_invariants.md`) is:

- Userspace `SOCK_SEQPACKET` + `pidfd` + `SCM_RIGHTS` is the production
  substrate.
- `agentfs.ko` exists as a historical experiment in "what would it look
  like to push these primitives into a small kernel surface?" and is
  preserved for reference, not extension.

If a future requirement appears that the userspace path genuinely
cannot satisfy, that's the moment to reopen the kernel-side question —
not before.
