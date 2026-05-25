# `agentfs` — minimal kernel-backed agent identity + mailbox

> **Honest disclaimer.** This module was written on macOS, where Linux
> kernel modules cannot be compiled or run. The helpers
> (`agentfs-register`/`-send`/`-read`) compile clean on macOS. The kernel
> module follows standard Linux 6.6+ conventions but has **not been
> compiled, loaded, or stressed by me**. Read it as a careful first draft;
> review with a kernel developer before running on a machine you care
> about.

## Scope

This is the first thing in the project to live in **ring 0**. The point is
to test the hypothesis that **three things — and only three things — about
an agent are worth pushing into the kernel:**

1. **Identity.** "I am the agent named `reviewer`" — a name bound to a
   `task_struct` that the kernel can authoritatively report.
2. **A mailbox.** An opaque, pollable, bounded byte-message queue per
   agent. Userspace writers enqueue, the registered runtime reads.
3. **Lifecycle binding.** When the owning task exits, the kernel knows
   *immediately*. The mailbox flushes, blocked readers wake, the status
   flips to `dead`.

Everything else still lives in userspace:

| In kernel (this module) | In userspace (existing repo) |
|---|---|
| `register` file → bind name to current task_struct | profiles, configs, caps semantics, task objects, artifacts, memory modes |
| `/agents/<name>/inbox` (opaque bytes) | VERB/LEN/REPLY-TO/TASK-ID framing |
| Status (`running`/`dead`), pid, owner, stats | reconciler (`agentd`), restart policies, enforcement (Landlock/seccomp/cgroup) |

The kernel **does not** parse any semantic protocol. It does not know what
"review" or "ping" mean. It treats every `write()` to an `inbox` as an
opaque blob, and every `read()` as one such blob dequeued.

> *Kernel should govern. Runtime should think.*

## Mount layout

```
/mnt/agentfs/
  register              # 0200, write only — write your agent's name here
  agents/
    <name>/             # created on registration
      pid               # text: owning task pid
      owner             # text: "uid=N gid=M"
      status            # text: "running" | "dead"
      stats             # text: per-mailbox queue depth / bytes / processed
      inbox             # 0600, read/write/poll, opaque byte messages
      outbox            # 0600, same shape as inbox
```

## Build + load

The kernel half needs a Linux host with matching kernel headers. The
helpers build anywhere with a C99 compiler.

```
# On Linux (with kernel-headers / linux-headers installed):
make                           # builds module + helpers
sudo insmod agentfs.ko
sudo mkdir -p /mnt/agentfs
sudo mount -t agentfs none /mnt/agentfs
```

`Makefile` switches behaviour based on `uname -s`: on non-Linux it builds
the helpers only and prints a skip notice.

## Demo

```
$ ./agentfs-register reviewer &
[1] 12345
agentfs: registered 'reviewer' pid=12345
agentfs: sleeping; signal me to unregister

$ ls /mnt/agentfs/agents/reviewer
inbox  outbox  owner  pid  stats  status

$ cat /mnt/agentfs/agents/reviewer/pid
12345
$ cat /mnt/agentfs/agents/reviewer/status
running

$ echo "hello" | ./agentfs-send reviewer
sent 6 bytes to reviewer

$ ./agentfs-read reviewer
hello

$ cat /mnt/agentfs/agents/reviewer/stats
inbox_messages=0
inbox_bytes=0
inbox_processed=1
outbox_messages=0
outbox_bytes=0
outbox_processed=0

$ kill 12345
$ cat /mnt/agentfs/agents/reviewer/status
dead
```

Or with `poll(2)`-style blocking:

```
# Terminal A: agent runtime
./agentfs-register reviewer
# (separate process opens inbox and reads in a loop)

# Terminal B
./agentfs-read reviewer        # blocks until message arrives

# Terminal C
echo "ping" | ./agentfs-send reviewer
# Terminal B unblocks immediately and prints "ping"
```

## Design

### Locking model

Two mutex layers, no spinlocks (no atomic-context callers):

- **`g_agents_lock`** (module-global mutex) — protects the agent list. Held
  while iterating, adding, or removing.
- **`agent->lock`** (per-agent mutex) — protects both mailboxes and the
  `dead` flag. Held during enqueue, dequeue, drain, status read. Never
  held across `copy_to_user`/`copy_from_user` — the message is dequeued
  under the lock, then copied out unlocked.

`messages_processed` is `atomic64_t` so the stats file doesn't need the
mutex for that counter.

### Memory model

- Per-message buffer = `struct agent_message { size_t len; char data[]; }`
  allocated via `kmalloc(struct_size(...), GFP_KERNEL)`.
- Per-mailbox queue is bounded by `AGENTFS_MAX_QUEUE_BYTES` (8 MiB) and
  `AGENTFS_MAX_QUEUE_MSGS` (1024). Writes past either limit return
  `-ENOSPC`.
- Per-message size is bounded by `AGENTFS_MAX_MESSAGE` (1 MiB). Larger
  writes return `-EMSGSIZE`.

### Lifecycle model

Registration calls `task_work_add(current, &a->exit_work, TWA_NONE)`.
When the owning task exits, the kernel walks its task_work list as part of
`do_exit()` and invokes our callback. The callback:

1. Acquires `agent->lock`.
2. Sets `a->dead = true`.
3. Drains both mailboxes (frees queued messages).
4. Releases the lock.
5. Wakes all waiters on both `readq`s.
6. Drops the `task_struct` reference.

**The agent struct stays in the tree** after the owner dies — the
directory entries and files remain visible, status reads return `dead`,
and reads on a drained inbox return 0 (EOF). This matches the spec's "OR
marked stale" allowance. Module unload removes everything.

### Race-safe cleanup at module unload

`agentfs_exit` is what runs when the user `rmmod`s. Because every file_op
sets `.owner = THIS_MODULE`, rmmod is blocked while files are open, so we
know there are no in-flight readers/writers when we get here. The
remaining concern is **the exit callback racing with us:**

- We acquire `agent->lock`.
- If `dead` is already `true`, the callback ran — it already freed
  messages and dropped the task ref, so we just `kfree(a)`.
- If `dead` is `false`, we call `task_work_cancel()`. A non-NULL return
  means we yanked the callback before it ran and still own the task ref.
  NULL means it either never armed or is mid-execution.
- We drain messages, drop the task ref iff we own it, set `dead = true`,
  release the lock, wake waiters (no-op now), and `kfree(a)`.

### Poll / select / epoll

Each mailbox has its own `wait_queue_head_t readq`. `poll_wait` registers
the calling task on it. The returned mask is:

- `EPOLLIN | EPOLLRDNORM` if the queue is non-empty
- `EPOLLOUT | EPOLLWRNORM` if the queue has room
- `EPOLLHUP` if the agent is dead

This means `epoll` over many mailboxes works without polling — readers
wake when a writer enqueues, dead-detection wakes everything.

### Userspace responsibilities — what the kernel does *not* know

The kernel sees only `read()` and `write()` calls with opaque payloads.
It does not parse:

- `VERB review` / `LEN 247` / `TASK-ID ...` / `REPLY-TO ...`
- task lifecycle (`queued → running → completed`)
- profiles, configs, restart policies, caps semantics, enforcement
- artifacts, memory modes, planners

All of that stays in the userspace runtime (`reviewer-agent`,
`fanout-agent`, `agentd`, `agentctl`). The kernel only provides:

1. A stable identity (name → process)
2. A datagram-shaped buffer (read/write/poll/blocking)
3. Death detection (`status` flips, readers get EOF, `EPOLLHUP` fires)

## What this is *not*

- **Not a sandbox.** Filesystem permissions on `/mnt/agentfs/` are the
  only access control. For real isolation use Landlock + seccomp +
  cgroup v2 (the existing userspace layer).
- **Not a security boundary.** The mailbox is opaque-bytes; if a peer
  with write access misbehaves, the kernel doesn't help. Audit it
  via existing userspace tooling.
- **Not an orchestrator.** No tasks, no scheduling, no DAGs, no policy.
- **Not a database.** Messages are FIFO byte payloads; the kernel keeps
  no record once a message is dequeued.
- **Not an "AI in the kernel" project.** The kernel still has zero
  knowledge of models, prompts, embeddings, or planners.

## Known caveats / first-draft limitations

- **Not run-tested.** I built this on macOS. It should compile on
  Linux 6.6+ but I have not verified.
- **Re-registration of dead agents is refused.** Once an agent is in the
  tree, the name is taken until module unload. (Easier rule for v1;
  spec explicitly allowed either choice.)
- **`task_work_add` can fail** if the registering task is itself in the
  middle of exiting. The module warns via `pr_warn` and leaves the agent
  status as `running` forever in that pathological case.
- **`rmmod` requires `umount` first.** Active mounts hold no module ref,
  but open files on them do. Standard pseudo-fs convention.
- **No re-registration of the same name.** A name that was once
  registered stays in the tree (showing `dead`) until module unload.

## Code map

| File | Role |
|---|---|
| `agentfs.c` | The LKM (filesystem registration, super_block, file_ops, lifecycle hook). |
| `Makefile` | Builds the module via kbuild on Linux; builds helpers everywhere. |
| `agentfs-register.c` | Userspace: `write()` a name, then `pause()` until killed. |
| `agentfs-send.c` | Userspace: copy stdin into one `write()` call on `inbox`. |
| `agentfs-read.c` | Userspace: one `read()` from `inbox` to stdout. |

## How this maps from the existing userspace POC

| Userspace concept | Kernel analogue (this module) |
|---|---|
| `/tmp/agents/<name>/pid` | `/mnt/agentfs/agents/<name>/pid` |
| `/tmp/agents/<name>/status` (file written by runtime) | `/mnt/agentfs/agents/<name>/status` (kernel-derived) |
| `agent.sock` (UDS, peer creds) | `inbox` + `outbox` (queues, kernel-known owner) |
| `audit_log()` lines | `dmesg` (`pr_info` traces) |
| `agentd` reconciler watching files via inotify | (future) a kernel-side notifier or a thin userspace consumer of `EPOLLHUP` |

The existing userspace POC keeps working — `agentfs` is parallel
infrastructure for testing the kernel-worthiness of just these three
primitives. Userspace runtimes that already exist (`reviewer-agent` etc.)
can be ported to read/write `/mnt/agentfs/agents/<name>/inbox` instead of
the UDS in a small future commit, but that is **not done in this phase**.
