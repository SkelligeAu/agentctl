# agentfs kernel module

`agentfs` is an experimental Linux filesystem module for agent registration and byte-message queues.
It is not a supported production transport.
Load it only in a disposable test VM.

The module does not parse task messages or enforce broker policy.
Userspace programs manage tasks, profiles, artifacts and restart decisions.
See [research status](../docs/research.md).

## Filesystem layout

```text
/mnt/agentfs/
  register
  agents/
    <name>/
      pid
      owner
      status
      stats
      inbox
      outbox
```

| File | Contents or operation |
|---|---|
| `register` | Write an agent name. The registering task becomes its owner. Mode 0200. |
| `pid` | Owner task PID. |
| `owner` | User and group IDs as `uid=N gid=M`. |
| `status` | `running` or `dead`. |
| `stats` | Queue depth, byte count and processed-message counters. |
| `inbox` | Read, write and poll a byte-message queue. Mode 0600. |
| `outbox` | A second queue with the same interface. Mode 0600. |

The module associates a name with a referenced `task_struct`.
This records the owner, not the identity of each writer.

## Build and load

Run the module in a test guest with matching Linux kernel headers.
Run these commands from `kernel/`:

```sh
make
sudo insmod agentfs.ko
sudo mkdir -p /mnt/agentfs
sudo mount -t agentfs none /mnt/agentfs
```

On Linux, `make` builds the module and helper programs.
On other hosts, it builds only the helpers.
The helpers require a C99 compiler and POSIX functions.

For the supplied Docker and QEMU procedure, see [kernel development](dev/README.md).
Do not load the module inside the Docker build container.
A container shares its host's kernel.

## Register and send a message

Keep the registration process alive while testing:

```sh
./agentfs-register reviewer &
owner=$!

ls /mnt/agentfs/agents/reviewer
cat /mnt/agentfs/agents/reviewer/pid
cat /mnt/agentfs/agents/reviewer/status

printf 'hello\n' | ./agentfs-send reviewer
./agentfs-read reviewer
cat /mnt/agentfs/agents/reviewer/stats

kill "$owner"
```

The read helper prints `hello`.
Before owner exit, the status is `running`.
The periodic exit check later changes it to `dead`.

A read on an empty live mailbox blocks unless `O_NONBLOCK` is set.
To test blocking, run the read helper in one terminal and the send helper in another.

Writing a name with `echo` registers the task that performs the write.
If that task exits immediately, the registration will not remain live.
Use `agentfs-register` for a persistent test owner.

## Queue limits

| Limit | Value | Error when exceeded |
|---|---|---|
| One message | `AGENTFS_MAX_MESSAGE`: 1 MiB. | `EMSGSIZE` |
| Queued bytes per mailbox | `AGENTFS_MAX_QUEUE_BYTES`: 8 MiB. | `ENOSPC` |
| Queued messages per mailbox | `AGENTFS_MAX_QUEUE_MSGS`: 1024. | `ENOSPC` |

Each message uses a `struct agent_message` with a variable-length byte buffer.
Allocation uses `kmalloc(struct_size(...), GFP_KERNEL)`.

A successful write enqueues one message.
A read removes one message.
If the caller's buffer is smaller than the message, the read returns only the bytes that fit.
The remaining bytes are discarded.
Use a sufficiently large receive buffer.

The module does not retain messages after they are read or drained.

## Locks and counters

`g_agents_lock` protects the global agent list.
Each agent's mutex protects its mailboxes and `dead` flag.

The read path removes the message under the mutex.
It releases the mutex before `copy_to_user`.
The write path performs `copy_from_user` before acquiring the mutex.

Processed-message counters use `atomic64_t`.

## Owner exit and name reuse

A delayed work item checks owners at a two-second interval.
It uses `pid_alive` to find owners whose tasks have been released.
Exit detection is not immediate.

For an exited owner, the worker:

1. Marks the agent dead.
2. Drains the inbox and outbox.
3. Wakes blocked readers.
4. Releases the owner task reference.

A dead, drained mailbox returns zero from read.
The directory remains visible.

Registration refuses a name while its previous owner is alive.
After owner exit, registration can reuse the entry.
It replaces owner metadata, clears queues and resets processed-message counters.

The implementation uses a workqueue, not a `task_work_add` exit callback.

## Polling

Each mailbox has a read wait queue.
`poll_wait` registers the caller.

| Mask | Condition |
|---|---|
| `EPOLLIN | EPOLLRDNORM` | A message is queued. |
| `EPOLLOUT | EPOLLWRNORM` | The live mailbox has queue capacity. |
| `EPOLLHUP` | The owner has been marked dead. |

Writes wake readers.
The exit worker wakes readers when it marks an owner dead.

## Module removal

Stop helper processes and close mailbox files before removal:

```sh
sudo umount /mnt/agentfs
sudo rmmod agentfs
```

The file operations hold module references while files are open.
During module exit, `cancel_delayed_work_sync` stops the exit worker.
The module then unregisters the filesystem, drains queues, releases task references and frees agent records.
It destroys the workqueue last.

Do not treat this description as proof that all module cleanup races have been tested.

## Security and application responsibilities

Filesystem permissions control access to mailbox files.
The module does not provide a sandbox or isolate hostile writers.
The normal userspace restrictions also do not establish complete isolation between hostile same-user programs.

The module does not interpret `VERB`, `LEN`, `TASK-ID` or `REPLY-TO`.
Applications must validate their messages.
A mailbox does not authenticate each message sender.

The module does not manage task state, schedules, profiles, capability policy, artifacts or model operations.
Kernel log messages are not a replacement for the supervisor's audit records.

## Source files

| File | Purpose |
|---|---|
| `agentfs.c` | Filesystem registration, mailbox operations and owner exit checks. |
| `Makefile` | Module build and userspace helpers. |
| `agentfs-register.c` | Register a name and wait for a signal. |
| `agentfs-send.c` | Copy standard input into one inbox write. |
| `agentfs-read.c` | Copy one inbox read to standard output. |

The userspace socket transport remains the supported implementation.
Experimental agentfs transport code must be tested separately.
