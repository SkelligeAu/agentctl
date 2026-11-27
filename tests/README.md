# Tests

The tests check message handling, broker policy, process control and the Python SDK.
See [design requirements](../docs/design-invariants.md) for the required behavior.

Test exit codes are:

- `0`: passed.
- `77`: skipped.
- Any other nonzero value: failed.

A passing summary does not mean that every privileged subcase ran.
Read internal skip messages.

## Run the userspace suite

Build all programs from the repository root:

```sh
make
export PATH="$PWD:$PATH"
export AGENT_PROFILES_DIR="$PWD/profiles"
```

Start `agentd` before running the broker tests.
Use an isolated `AGENTCTL_ROOT` when testing alongside another daemon.

```sh
agentd &
sh tests/run-all.sh
```

The runner reports each test entry and a final summary.
It runs the Python integration cases as one entry.
Those cases create their own daemons and temporary roots.

## C tests

| Source | Check |
|---|---|
| `test_ipc_msg_trunc.c` | Reject an oversized message when `MSG_TRUNC` is set. |
| `test_ipc_msg_ctrunc.c` | Reject truncated descriptor data when `MSG_CTRUNC` is set. |
| `test_ipc_fd_cleanup.c` | Keep descriptor counts stable after valid and rejected receives. |
| `test_cloexec.c` | Set `FD_CLOEXEC` on a received descriptor. |
| `test_input_validation.c` | Reject invalid paths, broker fields and CPU quotas. Initialize unset profile fields. |

The descriptor cleanup test covers malformed headers, truncated messages, truncated descriptor data and empty descriptor-bearing datagrams.
It tests `ipc_recv`, `read_message` and the private inbox receive path.

Linux transport tests return 77 on other platforms.

## Broker tests

These scripts use a running daemon:

| Script | Check |
|---|---|
| `broker_default_deny.sh` | Deny a request without a matching policy entry. |
| `broker_wildcard.sh` | Match wildcard policy and deliver requester metadata without a pathname mailbox. |
| `broker_concurrency.sh` | Match responses to eight concurrent forked requesters. |
| `broker_malformed.sh` | Deny a malformed request and keep the valid broker channel usable. |
| `broker_msg_ctrunc.sh` | Close a broker channel after truncated descriptor data. |
| `policy_not_authority.sh` | Do not create open capabilities from policy entries alone. |
| `broker_no_state.sh` | Restore the daemon descriptor count after five issuances and process exits. |

`broker-fault` provides the `malformed`, `many-fds` and `fdtable` modes.
Set its mode through the file used by the test in the agent's data directory.
The default root is not the older `/tmp/agents` path.

The runtime inherits the daemon's environment, not the later CLI command's environment.
Tests use data files to select runtime behavior.

## State and process control tests

| Script | Check |
|---|---|
| `agentctl_foreign_root.sh` | Refuse unsafe root permissions and, when permitted, a foreign owner. |
| `agentd_single_instance.sh` | Refuse a second daemon under one root. |
| `agentd_lockfile_kill9.sh` | Release the daemon lock after SIGKILL. |
| `phase1_authority_boundary.sh` | Reject a confined child's configuration write and unauthenticated control request. |
| `restart_crash_loop.sh` | Suppress five consecutive short runs with restart backoff. |

The foreign-owner subcase needs sudo.
It reports an internal skip when sudo is unavailable.

## Supervisor and Python SDK regressions

```sh
python3 tests/runtime_regressions.py
```

The file contains 20 Linux integration tests.
Each test uses a separate daemon and temporary root.

The cases check:

- Full inboxes and unread broker replies do not block the supervisor.
- Cleanup terminates children in the leader's process group.
- Rejected broker messages do not leak descriptors.
- A Python agent uses its private inbox and exchanges messages with the C runtime.
- Landlock prevents control-token truncation but permits writes to the agent's data.
- The daemon rejects malformed stored tokens and retains its validated token in memory.
- Forged cgroup records cannot redirect cleanup writes during exit, stop or CLI kill.
- The minimal seccomp profile starts the runtime. The supplied simple profile processes a review.
- Runtime execution errors reach the CLI.
- A partial control request does not block another request or extend its total deadline.
- Explicit enforcement overrides survive runtime restart.
- Python artifact writes reject invalid names and do not follow destination symlinks.
- Layout migration preserves a compatibility symlink whose target is not yet present.
- Invalid CPU quotas prevent runtime execution.
- An explicit CPU limit cannot fall back when the cgroup hierarchy is unavailable.

The tests require Python 3 and `tests/runtime-regression`, built by `make`.
Filesystem restriction cases require Landlock ABI 3 or later.
The Python test group returns 77 on macOS.

## Real cgroup tests

```sh
sh tests/cgroup_quotas.sh
```

Run this script only in a disposable Linux VM with a writable, delegated cgroup v2 hierarchy.
Its root fixture must first start `agentd` as the unprivileged `reviewer` user.
Set `AGENTCTL_ROOT` and `AGENT_PROFILES_DIR`.

Install the test executables at these paths:

| Path | Build |
|---|---|
| `/opt/agentctl` | CLI from the tested source. |
| `/opt/runtime-regression` | Statically linked `tests/runtime-regression`. |

`AGENTCTL_TEST_CLI` and `AGENTCTL_TEST_RUNTIME` can override those paths.

The script runs ten negative cases.
They include malformed and oversized quotas, a kernel-rejected numeric quota and denied writes to CPU, memory and PID controls.
Each case checks a failed CLI start, unavailable enforcement, no runtime PID and no execution marker.

The script changes permissions on uniquely named test cgroups.
It is not part of the normal userspace suite.
A read-only Docker cgroup mount cannot run these checks.

## Parser fuzz tests

Clang and libFuzzer are required:

```sh
make fuzz
tests/fuzz/fuzz-broker tests/fuzz/corpus/broker -max_total_time=60
tests/fuzz/fuzz-ipc tests/fuzz/corpus/ipc -max_total_time=60
```

The targets use AddressSanitizer and UndefinedBehaviorSanitizer.
The IPC target exposes the production parser through a fuzz-build-only wrapper.
Normal binaries do not export that wrapper.

Seed inputs include valid and malformed messages.
They also include length headers and payloads.
A passing fuzz run does not prove that the parsers have no defects.

## QEMU integration

The tools under [kernel/dev](../kernel/dev/README.md) build and boot a Linux guest.

```sh
cd kernel/dev
make qemu
```

The guest runs `share/agentfs-test.sh` when that executable script is present.
Earlier scripts used Step H for the userspace suite.
Check the installed script and guest dependencies before relying on that step.
The current Python tests need Python in the guest.
Do not assume a minimal initramfs contains it.

## Limits

The suite does not establish isolation between hostile processes with the same user ID.
It does not provide cryptographic audit integrity or unguessable audit correlation values.
It does not prevent applications from forwarding descriptors to other processes.

Process-group cleanup tests do not establish cgroup containment.
Cgroup tests do not clear the post-fork attachment race or validate supervisor recovery.
See [SECURITY.md](../SECURITY.md).
