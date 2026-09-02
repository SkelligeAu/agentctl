# Capability broker — design + threat analysis

Companion to `SECURITY.md` and `docs/design-invariants.md`. This file
documents how the v1 broker actually works, what it guarantees, and
what it explicitly does not.

## Architecture

A capability in agentctl is an open file descriptor. Possession is
permission. The broker is the only path to first-issuance.

Each process spawned under `agentd` receives a per-agent
`SOCK_SEQPACKET` broker channel at fd 3:

```
agentd                       supervised process
  │                                  │
  ├─── socketpair (broker channel) ──┤
  │      sv[0] held by agentd        │     sv[1] → child fd 3
  │      (struct managed.broker_fd)  │     (BROKER_FD_SLOT)
  │                                  │
  └── poll(POLLIN) in main loop ─────┘
```

The agent end (`sv[1]`) is dup2'd to fd 3 in the child before
`execl()`. The `FD_CLOEXEC` bit is cleared so the fd survives exec.
agentd holds `sv[0]` in `struct managed::broker_fd`. agentd's main
poll loop watches every live broker fd; `POLLIN` triggers
`broker_handle_event`.

Construction is in `common.c::spawn_agent_runtime`; handler is in
`agentd.c::broker_handle_event`.

fd 3 is a shared request/response channel. Supervised runtimes also inherit
an unlinked regular-file descriptor at fd 5. `ipc_connect` holds an in-process
lock plus a POSIX record lock on fd 5 across the complete exchange. This
prevents threads or forked descendants from consuming one another's
`SCM_RIGHTS` response. Code bypassing `ipc_connect` must provide equivalent
serialization.

## Wire format

| Direction | Header bytes | Ancillary |
|---|---|---|
| Request (agent → agentd) | `VERB request\nCAP <name>\n[TASK-ID <id>]\n[REASON <text>]\n\n` | (none) |
| Issued (agentd → agent) | `VERB issued\nCAP <name>\nTOKEN <8-hex>\n\n` | 1 fd in `SCM_RIGHTS` |
| Denied (agentd → agent) | `VERB denied\nCAP <name>\nREASON <text>\n\n` | (none) |

ASCII headers; one frame per `sendmsg`/`recvmsg`. Max frame size is
`BROKER_MSG_MAX` (512 bytes from `broker.h`). The fd accompanying an
`issued` response is delivered atomically with the header bytes; no
separate handshake is required.

## Issuance path

For the v1 cap `mailbox.send:<target>`:

1. Process X writes the request bytes on fd 3.
2. agentd's `poll()` returns POLLIN for X's `broker_fd`.
3. `broker_handle_event` calls `recvmsg` with
   `CMSG_SPACE(sizeof(int) * 4)` for cmsg + `MSG_CMSG_CLOEXEC`.
4. If `msg_flags & (MSG_TRUNC | MSG_CTRUNC)` is set, the channel is
   closed and an audit line is emitted.
5. `broker_parse` validates the header; malformed → `denied:
   malformed-request`.
6. agentd reads X's `<root>/agents/X/config/policy` and extracts `allow
   <pattern>` lines.
7. `broker_policy_check` matches the requested cap name against the
   pattern list (exact or `<prefix>*` wildcard-suffix). Empty pattern
   list → deny.
8. On allow, agentd creates a fresh socketpair. It transfers the receiver end,
   plus authenticated requester metadata, over the target's inherited fd 4
   inbox channel.
9. An 8-hex token is generated from `/dev/urandom`.
10. agentd `sendmsg`s the `issued` response with the requester end in
    `SCM_RIGHTS`.
11. agentd closes its own copy of the connected fd immediately.
12. Both `agentd.log` and X's `audit.log` record the issuance with
    the token.
13. X's subsequent `sendmsg` on the issued fd goes agent-to-agent;
    agentd is not in the data path.

## Audit correlation

Every issuance produces an 8-character hex token (`broker_make_token`).
The token is included in:

- `agentd.log` (single source of truth for broker events): `broker
  issued cap=mailbox.send:bb to=ba token=46ee4952 target=bb`
- Requesting agent's `audit.log`: `broker issued cap=mailbox.send:bb
  token=46ee4952 target=bb`

The token is intentionally non-cryptographic — 32 bits is sufficient
for human-scale operational correlation in a single-host log, not for
adversarial unguessability. If a future deployment requires
adversarial-unguessable tokens (e.g., to gate token-bearer access),
that's a separate design.

## Denial behavior

Every denied request produces a `denied` response with a `REASON`
field. Current reasons:

- `malformed-request` — broker_parse failed
- `not-in-caps` — cap name didn't match any allow pattern
- `no-listener` — target has no live inherited inbox channel
- `unknown-cap-kind` — request matched policy but isn't a cap kind
  the v1 broker knows how to issue
- `<errno-string>` — kernel-level failure during issuance

Denials are logged in `agentd.log` AND the requesting agent's
`audit.log`. The agent receives the `denied` frame and is free to
log/handle as it sees fit.

The denial path does **not** carry an fd. It does not allocate
sentinel objects in agentd. A flood of denial-eligible requests is
cheap to handle.

## Threat analysis

### Identity vs authority

Two distinct things. Conflating them is the most common operator
mistake.

| Concept | Where it lives | How it's verified |
|---|---|---|
| Identity | The pid/uid of the connecting peer | `SO_PEERCRED` on the kernel side |
| Authority | An open fd in the holder's fd table | Possession |

Identity is what `SO_PEERCRED` tells you. Authority is what your
fd table holds. The broker uses identity (the agent's pid, via the
broker channel's kernel-verified peer creds) to decide what
authority to issue. After issuance, authority transfers — the fd
the receiver gains does not carry the original requester's
identity.

### `SO_PEERCRED` through the broker

When the broker connects to the target's listener on the
requester's behalf:

```
ba (requester)        agentd                bb (target)
  │   request           │                       │
  │ ──────────────────► │                       │
  │                     │   connect()           │
  │                     │ ────────────────────► │
  │                     │                       │   bb's accept() returns;
  │                     │                       │   SO_PEERCRED on the
  │                     │                       │   accepted fd reports
  │                     │                       │   AGENTD's pid (not ba's).
  │   issued + fd       │                       │
  │ ◄────────────────── │                       │
  │                     │                       │
  │  send via issued fd ───────────────────────►│
  │                     │                       │   bb receives the
  │                     │                       │   message with requester
  │                     │                       │   identity authenticated
  │                     │                       │   by inbox metadata.
```

Receivers use the metadata delivered by agentd with the fd for requester
identity. `REPLY-TO` remains an unauthenticated routing claim and must not
override `peer_id_t.authenticated_name` for authorization.

### Confused deputy

The broker is the structural confused-deputy risk. Mitigations
operationalized in v1:

| Scenario | What v1 does |
|---|---|
| Process X requests a cap it shouldn't have | Policy gate (default-deny) + audit |
| Process X attempts to make the broker do work on a third party's behalf | Broker reads only X's policy; per-channel kernel-verified identity ensures the broker can't be tricked about who is asking |
| Operator runs `agentctl grant X <cap>` while X manipulates the operator's environment | Out of scope; the CLI runs as the operator |
| Process X sends `REPLY-TO ba` while not being ba | Receiver authorizes against broker-authenticated peer metadata, not the header |

### Why `REPLY-TO` is not kernel-authenticated identity

The `REPLY-TO` header in the wire format is a string the sender
writes. The kernel does not verify it. The broker's audit log
records which agent received the cap (by broker-channel identity,
which IS kernel-verified). The application running on the receiver
side is free to consult the audit log out-of-band if it needs to
verify that a specific incoming `REPLY-TO=ba` corresponds to an
actual cap issued to `ba` recently.

Authorization decisions on the receiver side should not be made on
`REPLY-TO` alone. Receivers either accept the cap's mere arrival as
authorization (sender's possession of the fd is sufficient), or
they consult the audit log. There is no third option.

### Same-uid limitation

Daemon-supervised agents expose no pathname mailbox: application channels are
socketpairs minted by agentd. A same-UID adversary may still use `ptrace`,
`/proc`, signals, or fd forwarding to cross the boundary. If that assumption
breaks,
escalate to per-agent uids or namespaces.

### Revocation

There is no kernel-level revocation of an fd already delivered. The
broker can:

- Stop issuing new caps to a holder (immediate).
- Close its own copy of any socket-anchored cap (immediate but only
  affects future operations; in-flight sendmsg already in the kernel
  buffer will still deliver).
- Restart the holder via agentd (the hammer; clean revocation).

Filesystem caps, when added, will have weaker revocation
(documented in the design doc).

## Future requirements before adding delegation or leases

These were considered for v1 and deferred. Each requires meeting
specific prerequisites before being added:

### Delegation (A delegates a cap to B)

Required before adding:

1. A per-agent profile bit `delegation=enabled` (default off).
2. A `delegate` verb in the broker wire format with explicit
   recipient and source-cap parameters.
3. An audit trail that records the source token and the delegated
   token, with a parent-child relationship in `agentd.log`.
4. A test demonstrating that an agent without
   `delegation=enabled` cannot perform a delegation regardless of
   what it sends on its broker channel.
5. A documented argument for why the delegation primitive doesn't
   silently grow into a multi-hop chain (A → B → C → ...).
6. A test demonstrating that a delegated cap can be audit-correlated
   to the original issuance.

Without all six, delegation is not added.

### Lease semantics (caps with expiry)

Required before adding:

1. An explicit lifecycle model (lease, renewal, expiry, who closes
   what when expiry fires).
2. A demonstration that lease enforcement does not require a
   background timer thread in agentd (the broker's poll loop is
   the only timer permitted; or close the sentinel).
3. An audit format that records the lease duration and a separate
   expiry event.
4. A test demonstrating an expired socket-anchored lease returns
   `EPIPE` on next use.
5. A documented answer to "what happens to in-flight messages when
   a lease expires" (kernel-buffered messages already in flight
   should not be a concern; the application is).

Without all five, leases are not added.

### Cap discovery / introspection (agent queries its own caps)

Not planned. Operators use `/proc/<pid>/fd/` and agentd's audit
log. Adding an introspection API invites reflection-based attacks
and incentivizes cap squatting. The decision is to keep this
path closed.

### Filesystem caps (`artifact.write` as a pre-exec dirfd)

Required before adding:

1. A precise spec of what the cap fd authorizes (dirfd + Landlock
   rule, or just dirfd, or O_PATH + open-on-demand).
2. Filename validation policy (no `..`, no `/`, no leading `.`,
   etc.) documented and tested.
3. A clear statement of revocation behavior: filesystem caps are
   eventually-revoked because existing fds keep working; document
   that the operator must restart the holder for finality.
4. Tests for path-traversal attempts via crafted filenames.

### Persistent peer sockets

Required before adding:

1. A documented reason why the short-lived
   `request → send → close` model is insufficient.
2. A measurement showing that the cost of repeated broker
   round-trips is the bottleneck for a real workload.
3. A revocation story that does not require restarting the holder
   (because persistent sockets imply the operator wants
   long-running authority).

Without (1) and (2), the deferred decision stands.
