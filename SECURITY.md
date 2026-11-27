# Security model

Use `agentctl` only with programs that the operator trusts.
Those programs can receive untrusted input.
The application must validate that input.

`agentctl` is a process supervisor.
It does not safely isolate hostile programs that share a UNIX user ID.
Use a separate sandbox when you must run code that you do not trust.

## Scope

The supervisor provides these controls:

- It checks capability requests against an operator-controlled policy.
- It applies requested Landlock and seccomp restrictions.
- It configures cgroup limits when enabled.
- It monitors processes and applies restart policies.
- It records process events and approved capability requests.

These controls do not replace application checks.
They do not protect against kernel exploits, side channels or compromised program dependencies.
The operator is responsible for the host, installed programs and profile files.

Network security depends on the programs and the host configuration.
Agents can open network connections unless another control prevents them.

## Trusted components

The following components must be trusted:

- The Linux kernel and its file descriptor, socket, pidfd, Landlock, seccomp and cgroup functions.
- `agentd`, which holds process handles and the private broker and delivery channels.
- `agentctl`, which runs with the operator's permissions.
- Profile files and per-agent configuration files.

An attacker who controls `agentd` can control its supervised processes.
An attacker who controls the operator's session can issue operator commands.

Do not run operator commands from a shell environment that an agent can change.
Keep profile and configuration files under operator control.
Grant only the capabilities that each agent needs.

## State directory and UNIX users

The programs select the state directory in this order:

1. `AGENTCTL_ROOT`, if set.
2. `$XDG_RUNTIME_DIR/agentctl`, if `XDG_RUNTIME_DIR` is set.
3. `/tmp/agentctl-<uid>`.

The directory is created with mode `0700`.
Its owner must match the program's effective user ID.
Group and other permission bits must be zero.
The program refuses a directory that fails these checks.

Each state directory contains its own control socket, PID file, log, lock file and agent directories.
`agentd` holds an exclusive lock on `agentd.lock` until it exits.
The kernel releases this lock after normal exit, `SIGKILL` or an out-of-memory kill.

Use separate UNIX accounts for users who do not trust each other.
UNIX file permissions restrict access between those accounts.
The directory checks do not provide containers, network namespaces or a separate kernel.

The host administrator must configure cgroup delegation and process visibility.
Options such as `hidepid=2` and network namespaces require host setup.
See [multiple-user deployment](docs/multi-tenant.md).

## Agents with the same user ID

Agents normally run with the supervisor's UNIX user ID.
That user ID does not separate the agents.

Subject to host restrictions, a process with the same user ID can:

- Send signals to other processes.
- Inspect or change another process through `ptrace` or `/proc`.
- Access files permitted to that user.
- Copy or forward open file descriptors.

Landlock and seccomp restrict specific operations.
They do not establish complete isolation between hostile programs under one user ID.

Supervised agents use private socket channels instead of pathname mailboxes.
This removes the pathname mailbox connection path.
It does not prevent descriptor forwarding, process inspection or signals.

Direct mode has no persistent broker.
It retains pathname mailboxes and requires cooperating processes.

## Control socket

Control requests require a random token stored in `<root>/agentd.token`.
The file is outside the directories readable by a normally Landlock-restricted agent.

At startup, the daemon checks the token file's type, owner, permissions and contents.
The token must contain 64 lowercase hexadecimal characters.
A final newline is permitted.
An empty or malformed token prevents daemon startup.

The daemon retains the accepted token in memory.
Changing the file does not change the running daemon's token.
Restart the daemon after an operator changes the token.

The control socket also checks peer credentials.
It accepts the daemon's user ID or root.
The request must still pass token authentication.

Partial requests use nonblocking reads and a five-second total deadline.
A partial request does not stop the supervisor from processing other events.

The token is not protection against a same-user attacker who can inspect the operator or bypass filesystem restrictions.

## Capability requests

The implemented capability is `mailbox.send:<agent>`.

An empty policy denies capability requests.
The broker checks the requester's policy file on each request.
A policy change affects later requests.
It does not invalidate descriptors already delivered.

For an approved request, the broker creates a socket pair.
It sends one end to the requester and the other end to the target.
It keeps neither end after transfer.

Access to the descriptor permits use of the channel.
A capability name or message header does not provide that access.

The broker cannot revoke a delivered descriptor.
Close every copy to remove access.
Stop all processes that hold a copy if necessary.
Restarting only the leader is insufficient when a child retains the descriptor.

Capability delegation, leases and filesystem capability issuance are not implemented.
If filesystem capabilities are added, deleting a pathname will not invalidate an open descriptor.

## Sender identity

On a direct connection, `SO_PEERCRED` reports the credentials recorded when the connection was created.
It does not identify the current writer after another process inherits or receives the descriptor.

Broker-created socket pairs do not identify the requester through connector credentials.
The broker sends the requester agent name, runtime PID and user ID through the target's private delivery channel.
The C library exposes the agent name as `peer_id_t.authenticated_name`.

Use this broker metadata when the application needs the requester agent identity.
It identifies the agent that received the channel.
It does not prove which process currently holds or writes to that channel.

`REPLY-TO` is supplied by the sender.
Do not use it to authorize a request.
The broker log records capability issuance, not each message sent through an issued channel.

## Message and descriptor handling

Linux uses `AF_UNIX` `SOCK_SEQPACKET`.
One send operation produces one message.
Application payloads are byte data.
The transport does not interpret their contents.

The transport rejects truncated messages and truncated descriptor data.
It also rejects duplicate known headers and invalid length fields.
Applications must validate field values and payloads before use.

Received descriptors are marked close-on-exec.
A rejected receive closes the descriptors installed by that receive.
After a successful `ipc_recv`, the caller owns the returned descriptors.
The older `read_message` interface closes ancillary descriptors because it cannot return them.

Task IDs and artifact names must be single path components.
Task APIs reject traversal, hidden names and oversized names.
Python artifact writes do not follow an existing destination symlink.

A child process can inherit descriptors through `fork`.
Close-on-exec does not prevent that inheritance.
The application must close descriptors that its children do not need.

## Filesystem and syscall restrictions

Linux filesystem restrictions require Landlock ABI 3 or later.
This ABI can restrict file truncation.
It usually requires Linux 6.2 or later.

The normal profile grants read access to `config/`.
It grants write access to the agent's `data/` and `runtime/` directories.
Explicit filesystem grants can extend this access.

A requested Landlock or seccomp policy that cannot be installed prevents Linux runtime startup.
macOS does not provide these Linux controls.

The minimal seccomp filter is installed before runtime execution.
It permits `exec` and the libc startup calls.
It does not limit execution to one program.
Use Landlock rules to restrict executable paths.

No profile blocks network access by default.
The current minimal filter permits socket calls.
The host must provide any required network restrictions.

Programs inherit the daemon's environment.
Filesystem restrictions do not remove secrets already present in that environment.
Do not start the daemon with environment values that its agents must not receive.

## Resource limits

With cgroup enforcement enabled, configured memory, PID and CPU limits must be written successfully before runtime startup.
An invalid CPU quota or a failed controller write returns a startup error.
The applied state records cgroup enforcement as unavailable.

CPU quotas use `quota/period`, in microseconds.
Use `max/period` for an explicit unlimited quota.
Quota values must be valid decimal numbers or `max`.
The kernel also checks the requested quota and period.

If no limits are configured, unavailable cgroups retain the process-group fallback.

The current cgroup path is `/sys/fs/cgroup/agents/<name>`.
A private state directory does not create a private cgroup hierarchy.
The host administrator must provide the required delegation.

## Process control limits

For a supervised process, a pidfd identifies the task opened by the supervisor.
Signals through that pidfd do not target a later process that reuses the PID.

When available, the supervisor retains a parent-opened `cgroup.kill` descriptor.
It checks for cgroup v2 and does not follow a final symlink.
Cleanup and CLI kill do not take cgroup authority from the child-writable `enforcement.applied` file.

Writing `cgroup.kill` terminates processes in that cgroup and its descendants.
The process-group fallback cannot terminate children that create another session.

Cgroup attachment occurs after `fork`. The child waits on a startup pipe before
it applies runtime settings or executes the runtime. The parent releases this
gate only after attachment succeeds. Active cgroup enforcement also requires a
parent-owned kill descriptor. A failed attachment refuses startup. Startup
failure attempts cleanup through that descriptor as well as the process group.

The Linux fixture checks runtime-entry membership and refusal on attachment
failure. Parent death while the gate is closed has not yet been fault-injected.
A failed cgroup kill still needs an outer host watchdog; this change does not
turn cleanup errors into a guarantee that no process survives.

Supervisor recovery starts from a PID stored on disk.
That PID can be changed or reused before the supervisor opens a pidfd.
Opening a pidfd does not validate the original PID file.
Recovered processes also lack the retained cgroup handle from the original supervisor.
Do not assume recovery provides the same process identity or subtree control as a new supervised start.

Restart delays increase after short runs.
The fifth consecutive run shorter than 30 seconds sets `crash-loop` and stops automatic restarts.
An explicit start clears this state.

## Audit records

The daemon writes process events and capability issuance records.
Each approved capability request has an eight-character hexadecimal correlation value.
The daemon log and requesting agent's log use the same value.

This 32-bit value links log entries.
It is not an authentication secret.

Audit files have no cryptographic signatures or integrity checks.
A process with write access can change or delete them.
Collect logs outside the agent's writable directories if a deployment needs independent records.
Central collection across users requires separate host setup.

## Reporting security issues

This is a prototype.
There is no dedicated security response service.
Report an issue through GitHub or contact the author directly.

Do not use this code for security-sensitive workloads without a separate review of the deployment.

## Timed broker acquisition

`ipc_connect_timeout(target, timeout_ms)` bounds broker acquisition, including
thread and process lock waits. The supported timeout is 1–60000 milliseconds.
It requires the inherited supervisor channel and never falls back to a socket
pathname. An in-flight timeout shuts down that channel so a late descriptor
cannot become a later request's response. Restart the runtime before reuse.
A timeout while waiting for the lock does not cancel another caller's exchange.
This API does not supply a task deadline or terminate the runtime.

The broker remains trusted. Malformed broker-response descriptor handling is
not fully qualified by the timeout tests. Production isolation must include the
supervisor inside the outer boundary and enforce task cleanup outside it.
