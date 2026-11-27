# macOS development

Use macOS for editing, development builds and local smoke tests.
Linux defines the supported process, transport and security behavior.

## Available development functions

- `make` builds the userspace programs.
- Direct mode supports `agentctl create`, `start`, `send` and `stop`.
- The Python SDK uses UNIX domain sockets.
- The ping-pong benchmark and single-process smoke tests can run locally.

## Linux differences

| Function | macOS behavior |
|---|---|
| Application transport | Uses `SOCK_STREAM` and a `LEN <n>\n` header instead of `SOCK_SEQPACKET`. |
| Process handles | No pidfds. Uses PID-based checks and signals. PID reuse remains a risk. |
| Subtree termination | No `cgroup.kill`. Uses process-group signals. |
| Landlock | Unavailable. |
| seccomp | Unavailable. |
| cgroup resource limits | Unavailable. |
| Received descriptor flags | No `MSG_CMSG_CLOEXEC`. Descriptor flags require a separate operation. |

Broker and supervisor code contains macOS branches.
A successful build does not establish the Linux guarantees.
Direct mode is the recommended path for local development.
Supervisor process-group signaling can fail across sessions.

## Linux verification

Test broker changes, process control, message handling and restrictions on Linux.

The QEMU tools are under `kernel/dev`:

```sh
cd kernel/dev
make qemu
```

Build the kernel, initramfs, module and static userspace programs required by your test.
See [kernel development](../kernel/dev/README.md) for the build targets.

The guest runs `share/agentfs-test.sh` if that executable file is present.
Otherwise, it opens a shell.
The script is generated test material; do not assume it exists in a fresh checkout.

See [design invariants](design-invariants.md) for Linux requirements and known limits.
