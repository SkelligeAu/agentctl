# agentctl

`agentctl` runs named processes on a Linux host and lets them pass file
descriptors to one another through a small capability broker.

It uses the usual UNIX parts: `AF_UNIX`, `SOCK_SEQPACKET`, `SCM_RIGHTS`,
`pidfd`, seccomp, Landlock, and cgroup v2. State is kept in ordinary files.
If something looks wrong, try `ls`, `cat`, `lsof`, or `strace`. The database
administrator has the day off.

This is a process supervisor, not a container runtime. Programs belonging to
the same user are not isolated from each other.

## Requirements

- Linux 5.14 or newer for production semantics
- a C99 compiler and `make`
- cgroup v2 delegation if cgroup limits are enabled

macOS builds are useful for development, but its STREAM transport and missing
Linux enforcement primitives are not equivalent to the Linux runtime.

## Build

```sh
make
```

There are no library dependencies beyond libc.

## First run

```sh
export AGENT_PROFILES_DIR="$PWD/profiles"

./agentd &
./agentctl create rb --profile worker
./agentctl start rb --exec "$PWD/reviewer-agent"

printf '+TODO\n+strcpy(a,b);\n' | ./agentctl send rb review
./agentctl tasks rb
./psa

./agentctl stop rb
```

Run `agentctl` without arguments for the command list.

By default, state is stored in `$XDG_RUNTIME_DIR/agentctl`. If that variable is
unset, `/tmp/agentctl-<uid>` is used. `AGENTCTL_ROOT` overrides both, mostly for
tests and unusual installations.

## How it works

`agentd` owns process lifecycle and the capability broker. Each supervised
process inherits a private broker socket on fd 3. An agent can request a
capability named in its policy file; the current implementation supports
`mailbox.send:<agent>`.

A successful request creates a fresh socketpair. One end goes to the requester
and the other to the target's private inbox. `agentd` keeps neither end. The
kernel transfers the descriptors with `SCM_RIGHTS`, so possession of the fd is
the authority. There is no bearer token pretending to be a file descriptor.

Application messages use a short ASCII header followed by opaque bytes:

```text
VERB review
REPLY-TO coordinator
TASK-ID 20260902T120000Z-0001
LEN 7

payload
```

Linux uses `SOCK_SEQPACKET`: one send is one message. Truncated frames,
truncated ancillary data, duplicate headers, invalid lengths, and oversized
fields are rejected. Received descriptors are marked close-on-exec.

## Supervision

On Linux, `pidfd` is used for liveness and signalling. `cgroup.kill` terminates
an owned process subtree when cgroup support is active. Short-lived crashes get
exponential restart backoff; the fifth consecutive short run is marked as a
crash loop. This is preferable to turning a typo into a heating appliance.

Profiles can apply:

- Landlock filesystem rules
- a minimal seccomp filter
- cgroup memory, process, and CPU limits
- restart and artifact policies

Profiles are read when a process starts. They are not hot-reloaded.

## Security model

The intended boundary is between different UNIX users on one host. Each user
gets a private `0700` state root, and `agentd` checks its ownership before doing
anything. A lock file permits one daemon per root. The control socket also
checks peer credentials and requires a random per-root authentication token.

Agents running as the same uid can still use `ptrace`, signals, `/proc`, and
descriptor forwarding against each other. If they do not trust one another,
give them separate users, namespaces, or virtual machines. No amount of
adjectives in this README changes what the kernel permits.

Other limits worth knowing:

- a delivered fd cannot be revoked from another process; restart the holder
- network egress is not blocked by default
- audit logs are useful, not cryptographically tamper-evident
- direct mode retains cooperative pathname mailboxes
- untrusted executable code needs a real sandbox

Read [SECURITY.md](SECURITY.md) before using this around anything valuable.

## Tests

```sh
make
sh tests/run-all.sh       # expects agentd to be running
```

The full Linux suite is also run in CI. It covers protocol truncation, fd
flags, broker denial and issuance, concurrent requests, authority boundaries,
daemon locking, and restart suppression.

The protocol parsers have libFuzzer harnesses:

```sh
make fuzz
tests/fuzz/fuzz-broker tests/fuzz/corpus/broker -max_total_time=60
tests/fuzz/fuzz-ipc tests/fuzz/corpus/ipc -max_total_time=60
```

`tests/README.md` has the test matrix. QEMU integration support lives under
`kernel/dev` for tests that need real Linux kernel facilities.

## Status

This is a working prototype. It builds on Linux and macOS, passes the Linux
regression suite, and has sanitizer-backed parser fuzzing. It has not had the
independent review, soak testing, packaging, or operational abuse required for
a production release.

Delegation, leases, and filesystem capability issuance are not implemented.
The `agentfs` kernel module is a research artifact, not a second production
path. One production path is already plenty.

Useful reading:

- [design invariants](docs/design-invariants.md)
- [capability broker notes](docs/capabilities.md)
- [multi-user deployment](docs/multi-tenant.md)
- [macOS development notes](docs/macos.md)
- [benchmarks](BENCHMARKS.md)
