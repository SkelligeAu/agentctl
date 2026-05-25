# macOS dev loop

agentctl compiles and runs on macOS. It is **not a production target**
and does not provide the same guarantees as the Linux build. The
purpose of macOS support is to let developers iterate on the engine
without booting a VM for every change.

## What works on macOS

- `make` builds all binaries (`agentctl`, `agentd`, `reviewer-agent`,
  `fanout-agent`, `psa`, `broker-test`)
- `agentctl create / start / send / stop` direct mode (no `agentd`)
- The Python SDK over the UDS substrate
- The host pingpong benchmark
- Single-process smoke tests

## What doesn't work on macOS

These are by design; the kernel doesn't provide the primitive:

| Linux feature | macOS state |
|---|---|
| `AF_UNIX` `SOCK_SEQPACKET` | Not supported. Falls back to `SOCK_STREAM` with explicit `LEN <n>\n` framing. |
| `pidfd_open` / `pidfd_send_signal` | `ENOSYS`; lifecycle falls back to `kill(pid, 0)` polling and `kill(pid, sig)`. PID-reuse races are not addressed. |
| `cgroup.kill` (v2 subtree termination) | No equivalent. Falls back to `killpg`. |
| Landlock | No equivalent. Profile field is a no-op. |
| seccomp-bpf | No equivalent. Profile field is a no-op. |
| cgroup v2 limits | No equivalent. Profile field is a no-op. |
| `SCM_RIGHTS` with `MSG_CMSG_CLOEXEC` | `MSG_CMSG_CLOEXEC` is missing; the broker requires it, so the broker is Linux-only. |
| Capability broker (`fd 3` channel) | Not exposed on macOS. Broker code paths return `ENOSYS`. |
| `agentd` supervised mode | Has a `killpg` cross-session EPERM edge case after `setsid`; direct mode (no `agentd`) is the recommended dev path. |

## Recommendation

Use macOS for code edits and host smoke tests. For anything touching
lifecycle, broker, IPC semantics, or enforcement, run the QEMU
integration test:

```sh
cd kernel/dev
make qemu
```

The integration test boots a Linux 6.6.32 VM with the static-linked
userland and runs `share/agentfs-test.sh` end-to-end. That's the
authoritative verification surface.

## Invariant

No production semantic is allowed to depend on macOS behavior. If you
find yourself reasoning about "what macOS does here," you are off the
production path. See `docs/design-invariants.md` invariant 34.
