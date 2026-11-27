# Capability broker

This document describes the implemented broker and the requirements for proposed extensions.
See [SECURITY.md](../SECURITY.md) for deployment limits.

A capability is an open file descriptor.
A policy entry permits a request.
The policy entry itself is not a capability.

## Private channels

Each supervised agent receives these descriptors:

| Descriptor | Purpose |
|---|---|
| 3 | Broker requests and responses. |
| 4 | Incoming application channels and requester metadata. |
| 5 | Lock used to serialize broker exchanges. |

The parent keeps its broker endpoint in `struct managed.broker_fd`.
The child endpoint is copied to descriptor 3 before `exec`.
Its close-on-exec flag is cleared so the runtime receives it.

The supervisor polls broker endpoints.
Readable data calls `broker_handle_event`.
See `common.c::spawn_agent_runtime_owned` and `agentd.c::broker_handle_event`.

Descriptor 3 is shared by threads and forked children.
`ipc_connect` holds a process-local lock and a POSIX record lock on descriptor 5.
Both locks cover the request and the descriptor-bearing response.
Code that bypasses `ipc_connect` must provide the same serialization.

## Broker protocol

Linux uses `SOCK_SEQPACKET`.
Each broker frame contains ASCII headers and a final blank line.
The maximum frame size is `BROKER_MSG_MAX`, or 512 bytes.

| Direction | Header bytes | Descriptor data |
|---|---|---|
| Request | `VERB request\nCAP <name>\n[TASK-ID <id>]\n[REASON <text>]\n\n` | None. |
| Approved | `VERB issued\nCAP <name>\nTOKEN <8-hex>\n\n` | One descriptor through `SCM_RIGHTS`. |
| Denied | `VERB denied\nCAP <name>\nREASON <text>\n\n` | None. |

The approved response transfers the descriptor with its header.
There is no separate descriptor handshake.

## Request handling

The implemented capability is `mailbox.send:<target>`.

1. The requester writes a request on descriptor 3.
2. The supervisor receives it with `MSG_CMSG_CLOEXEC` and space for four received descriptors.
3. The supervisor closes any received descriptors. Requests do not support delegation.
4. Truncated frames or descriptor data cause the supervisor to close the broker channel.
5. `broker_parse` checks the headers.
6. The supervisor reads the requester's `config/policy`.
7. `broker_policy_check` checks the capability against `allow <pattern>` entries.
8. An approved request creates a new application socket pair.
9. The target receives one endpoint and requester metadata through descriptor 4.
10. The requester receives the other endpoint in the broker response.
11. The supervisor closes its application endpoint copies and records the approved request.

Policy matching supports exact names and a trailing `*` wildcard.
An empty policy denies requests.

Application messages then pass directly between the agents.
The supervisor does not receive, store or replay them.

## Full channels and denied requests

Broker replies and inbox deliveries use nonblocking sends.
A full inbox returns `target-busy`.
A broker reply that cannot be sent closes the broker channel.
The supervisor does not queue these replies.

Current denial reasons include:

| Reason | Meaning |
|---|---|
| `malformed-request` | The broker parser rejected the request. |
| `not-in-caps` | No policy entry permits the requested capability. |
| `no-listener` | The target has no live private inbox. |
| `target-busy` | The target's inbox is full. |
| `unknown-cap-kind` | The broker cannot create that capability type. |
| An errno description | A system call failed during channel creation or transfer. |

A denied response carries no descriptor.
The supervisor records denials in its log and the requesting agent's log.
The requester must handle the error.

## Audit correlation

Each approved request gets an eight-character hexadecimal value from `broker_make_token`.
The response and both audit logs contain this value.

Example daemon entry:

```text
broker issued cap=mailbox.send:bb to=ba token=46ee4952
```

Example requester entry:

```text
broker issued cap=mailbox.send:bb token=46ee4952 target=bb
```

The value contains 32 random bits from `/dev/urandom`.
Use it to match log entries.
Do not use it as an authentication secret.

## Sender identity

The supervisor associates a private broker channel with a managed agent.
It uses that association to select the requester's policy.

Application socket pairs are created by the supervisor.
Their socket credentials do not identify the requester.
The supervisor supplies the requester agent name, runtime PID and user ID with the receiver endpoint.

The C library exposes the agent name as `peer_id_t.authenticated_name`.
Use this metadata when the application needs the requester agent identity.
Do not substitute the sender's `REPLY-TO` value.

Metadata identifies the agent that received the channel.
It does not identify every process that later inherits or receives the descriptor.
Audit records show channel issuance, not each application message.

## Security limits

The broker applies the requester's policy.
It does not verify the operator's intent when the operator grants a capability.
Keep policy files and the operator's shell environment outside agent control.

Agents under the same UNIX user ID are not isolated.
Process inspection, signals and descriptor forwarding remain possible, subject to host restrictions.

The broker cannot revoke a delivered descriptor.
Changing policy only prevents later requests.
Close every copy or stop every process that holds a copy.
Restarting only a leader is insufficient if its children retain descriptors.

The normal application sequence is request, send, close.
The broker does not enforce a lifetime or expiry time.

## Requirements for proposed extensions

The following functions are not implemented.

### Delegation

Before adding broker-supported delegation:

1. Add a per-agent `delegation=enabled` setting. The default must be disabled.
2. Define a `delegate` request with the recipient and source capability.
3. Record the source and delegated tokens, including their relationship.
4. Test that a disabled agent cannot delegate through the broker.
5. Define whether delegation can continue through more agents.
6. Test correlation between the delegated capability and its original issuance.

These controls would apply to broker requests.
They would not prevent direct descriptor forwarding by same-user processes.

### Leases

Before adding expiry times:

1. Define creation, renewal and expiry, including who closes each endpoint.
2. Define enforcement through the existing poll loop or a retained endpoint. Do not add a background timer thread.
3. Record the lease duration and a separate expiry event.
4. Test that an expired socket lease returns `EPIPE` on later use.
5. Define what happens to messages already queued in the kernel.

### Capability discovery

An agent-facing discovery API is not planned.
Operators can inspect `/proc/<pid>/fd/` and the supervisor log.

### Filesystem capabilities

Before adding a capability such as `artifact.write`:

1. Define the descriptor type and permitted operations.
2. Define and test filename restrictions, including traversal and hidden names.
   Reject `..`, `/` and leading `.` in filenames.
3. State that deleting a pathname does not invalidate open descriptors.
4. Test malicious filenames and define how all descriptor copies are closed.

### Persistent application channels

Before adding persistent channels:

1. Identify a workload that cannot use request, send, close.
2. Measure the cost of repeated broker requests for that workload.
3. Define how access ends without relying only on a leader restart.
