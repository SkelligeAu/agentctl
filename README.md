# agentctl

`agentctl` runs named processes on Linux. It starts, monitors and stops them.
A managed process is called an agent.

Agents request communication channels from `agentd`, the supervisor.
The broker checks each request against the agent's policy.
It transfers approved channels as open file descriptors.

Agents under the same UNIX user ID are not isolated from each other.
Read [SECURITY.md](SECURITY.md) before deployment.

## Requirements

- Linux 5.14 or later.
- Landlock ABI 3 or later for filesystem restrictions. This usually requires Linux 6.2 or later.
- A C99 compiler, `make` and libc.
- A delegated cgroup v2 hierarchy for configured resource limits.

A Linux start fails if requested Landlock or seccomp restrictions cannot be installed.
Configured cgroup limits also require successful controller writes.

macOS is supported for development builds.
Its transport and security functions differ from Linux.
Do not use macOS test results to establish Linux security guarantees.

## Build

```sh
make
```

## Run an agent

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

Run `agentctl` without arguments to see the command list.

State is stored in `$XDG_RUNTIME_DIR/agentctl`.
If `XDG_RUNTIME_DIR` is not set, the default is `/tmp/agentctl-<uid>`.
Set `AGENTCTL_ROOT` to use another directory.
The directory must belong to the current user and have no group or other permissions.

## Communication

Each supervised agent receives a private broker channel on file descriptor 3.
It receives incoming channels through file descriptor 4.
File descriptor 5 serializes broker requests from threads and child processes.

The implemented capability is `mailbox.send:<agent>`.
A capability is permission to use an open file descriptor.

For each approved request, `agentd` creates a socket pair.
It sends one end to the requester and the other end to the target.
It uses `SCM_RIGHTS` to transfer the descriptors.
It then closes its copies.

Application messages have an ASCII header and a byte payload:

```text
VERB review
REPLY-TO coordinator
TASK-ID 20260902T120000Z-0001
LEN 7

payload
```

Linux uses `AF_UNIX` with `SOCK_SEQPACKET`.
Each send operation produces one message.
The transport rejects truncated messages, truncated descriptor data, duplicate known headers and invalid length fields.
It marks received descriptors close-on-exec.

The application must validate payload contents.
`REPLY-TO` is a routing field, not proof of sender identity.
See [sender identity](SECURITY.md#sender-identity) for the broker metadata and its limits.

## Process control

On Linux, `agentd` uses pidfds to monitor processes and send signals.
It uses an owned `cgroup.kill` descriptor to terminate a process subtree when available.
Otherwise, it uses the process group.
Children that create another session can survive the process-group fallback.

Restart delays increase after short runs.
The fifth consecutive run shorter than 30 seconds stops automatic restarts.
An explicit start clears this state.

Profiles set filesystem restrictions, seccomp filters and cgroup limits.
They also set dispatch and artifact policies.
The supervisor reads profiles at process start.
Restart the process after a profile change.

CPU quotas use `quota/period`, in microseconds.
Use `max/period` for an explicit unlimited quota.
Invalid values or failed limit writes prevent startup when cgroup limits are configured.

Cgroup attachment and supervisor recovery have known limits.
See [process control limits](SECURITY.md#process-control-limits).

## Security limits

Each UNIX user has a separate state directory.
The directory is created with mode `0700`.
The programs check its owner and permissions before use.
An exclusive lock permits one daemon per state directory.

The control socket checks peer credentials and requires an authentication token.
These checks do not isolate agents that share a UNIX user ID.

Other limits apply:

- An agent can retain or copy a delivered descriptor. The broker cannot revoke it.
- Network connections are not blocked by default.
- Audit files do not have cryptographic integrity protection.
- Direct mode uses pathname mailboxes and requires cooperating processes.
- Do not run code that you do not trust without a separate sandbox.

The host administrator must configure user accounts, cgroup delegation and any required network or process visibility restrictions.

## Tests

Build the programs and start `agentd` before running the suite:

```sh
make
export PATH="$PWD:$PATH"
sh tests/run-all.sh
```

The Linux suite runs in CI.
It tests message parsing, descriptor handling, broker policy, process control, daemon locks and the Python SDK.

Parser fuzz tests require Clang with libFuzzer:

```sh
make fuzz
tests/fuzz/fuzz-broker tests/fuzz/corpus/broker -max_total_time=60
tests/fuzz/fuzz-ipc tests/fuzz/corpus/ipc -max_total_time=60
```

See [tests/README.md](tests/README.md) for test setup and coverage.
Some checks require privileges or kernel functions that are unavailable in a normal Docker container.
The `kernel/dev` directory contains QEMU test tools.

## Project status

This is a prototype.
Do not use it for security-sensitive workloads without a separate review of your deployment.
A successful build or test run is not proof of production readiness.

Capability delegation, leases and filesystem capability issuance are not implemented.
The `agentfs` kernel module is research code.
It is not a supported production transport.

## Reference documents

- [Proposed single-host scheduler](docs/scheduler-spec.md)
- [Design invariants](docs/design-invariants.md)
- [Capability broker](docs/capabilities.md)
- [Multiple-user deployment](docs/multi-tenant.md)
- [macOS development](docs/macos.md)
- [Benchmarks](BENCHMARKS.md)
