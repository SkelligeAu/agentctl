#ifndef AGENTCTL_COMMON_H
#define AGENTCTL_COMMON_H

#if !defined(_POSIX_C_SOURCE)
#  define _POSIX_C_SOURCE 200809L
#endif
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#  define _DARWIN_C_SOURCE 1
#endif

#include <sys/types.h>
#include <signal.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>

#define MAX_NAME          64
#define MAX_VERB          64
#define MAX_HEADER_LINE   256
#define MAX_PAYLOAD       (1u << 20)   /* 1 MiB */
#define MAX_PATHBUF       4096
#define AUDIT_TAIL_LINES  20
#define BROKER_FD_SLOT     3
#define INBOX_FD_SLOT      4
#define BROKER_LOCK_FD_SLOT 5

#if defined(__GNUC__) || defined(__clang__)
#  define PRINTF_FMT(a,b) __attribute__((format(printf,(a),(b))))
#else
#  define PRINTF_FMT(a,b)
#endif

/* Per-user data root resolution (lazy, cached). Precedence:
 *   1. AGENTCTL_ROOT env var (explicit override)
 *   2. $XDG_RUNTIME_DIR/agentctl  (Linux user sessions)
 *   3. /tmp/agentctl-<uid>        (fallback; works on macOS dev loop)
 * The directory is created (0700) on first call. */
const char *agentctl_root(void);

/* The agents/ subdirectory under agentctl_root. Replaces the old hardcoded
 * `/tmp/agents` path. Lazy, cached. */
const char *agent_root(void);

/* Daemon-level file paths under agentctl_root. Lazy, cached. */
const char *agentd_sock_path(void);
const char *agentd_pid_path(void);
const char *agentd_log_path(void);
const char *agentd_token_path(void);

/* Acquire an exclusive lockfile at <agentctl_root>/agentd.lock to enforce
 * one daemon per data root. Returns an open fd which the caller MUST keep
 * open for the daemon's lifetime; the kernel releases the flock on any
 * exit (including SIGKILL/OOM). Returns -1 with errno set; specifically
 * EWOULDBLOCK when another daemon already holds the lock. */
int  agentctl_root_lock(void);

/* Re-validate that the cached data root is owned 0700 by the current
 * effective uid. Same checks as the implicit gate in agentctl_root()
 * (which calls this on first resolution and exits the process on
 * mismatch). Exposed for callers wanting a defence-in-depth re-check
 * before a security-sensitive operation. Returns 0 on success; on
 * mismatch, prints to stderr and returns -1. */
int  agentctl_root_validate_ownership(void);

/* Back-compat macro so existing call sites that use AGENT_ROOT as a
 * `const char *` (snprintf format args, opendir, ensure_dir) keep working. */
#define AGENT_ROOT  agent_root()

/* Name + path helpers. Each agent has operator config/, runtime metadata/,
 * and agent-writable data/. agent_path routes known leaves to the canonical
 * class and defaults application-specific leaves to data/. */
int  validate_name(const char *name);
int  ensure_dir(const char *path, mode_t mode);
int  agent_dir(char *out, size_t n, const char *name);
int  agent_config_dir(char *out, size_t n, const char *name);
int  agent_runtime_dir(char *out, size_t n, const char *name);
int  agent_data_dir(char *out, size_t n, const char *name);
int  agent_path(char *out, size_t n, const char *name, const char *leaf);
int  agent_ensure_layout(const char *name);

/* IO helpers */
ssize_t read_all(int fd, void *buf, size_t n);              /* retries EINTR */
ssize_t write_all(int fd, const void *buf, size_t n);       /* retries EINTR */
int     read_line_fd(int fd, char *out, size_t n);          /* NO EINTR retry; 0 ok, -1 err/EOF */
int     read_small_file(const char *path, char *out, size_t n, size_t *out_len);
int     atomic_write_file(const char *path, const void *buf, size_t n, mode_t mode);
int     append_file(const char *path, const void *buf, size_t n, mode_t mode);

/* Agent state */
int  write_status(const char *name, const char *status);
int  read_pid_file(const char *name, pid_t *pid);
int  audit_log(const char *name, const char *fmt, ...) PRINTF_FMT(2,3);

/* Inbox message protocol */
#define MAX_TASK_ID_INLINE 32  /* must match tasks.h::MAX_TASK_ID */
typedef struct {
    char   verb[MAX_VERB];
    size_t payload_len;
    char   reply_to[MAX_NAME];           /* "" if absent */
    char   task_id[MAX_TASK_ID_INLINE];  /* "" if absent (correlation id) */
} agent_msg_hdr;

/* Reads one full message from fd; payload_buf must hold MAX_PAYLOAD bytes.
 * Returns 0 on success, -1 on error (errno set; EINTR from read_line_fd propagates). */
int read_message(int fd, agent_msg_hdr *hdr, void *payload_buf);

/* ---------- transport substrate selection ---------- */

/* An agent's IPC substrate is one of:
 *   TRANSPORT_UDS     — <root>/agents/<name>/agent.sock (existing default)
 *   TRANSPORT_AGENTFS — /<mount>/agents/<name>/inbox (kernel mailbox)
 *
 * Per-agent on-disk record: <root>/agents/<name>/transport. Format:
 *   "uds\n"                      → TRANSPORT_UDS
 *   "agentfs /mnt/agentfs\n"     → TRANSPORT_AGENTFS, mount="/mnt/agentfs"
 *   (absent file)                → TRANSPORT_UDS (default)
 *
 * The kernel does not parse the wire protocol — both transports carry the
 * same framed VERB/LEN/REPLY-TO/TASK-ID payload. The only thing that
 * differs is the bytes-to-fd mechanism. */
typedef enum {
    TRANSPORT_UDS = 0,
    TRANSPORT_AGENTFS
} transport_t;

typedef struct {
    transport_t kind;
    char mount[MAX_PATHBUF];   /* used only when kind == TRANSPORT_AGENTFS */
} transport_cfg_t;

int transport_resolve(const char *agent, transport_cfg_t *out);
int transport_write  (const char *agent, transport_t kind, const char *mount);

/* Symbolic name (for inspect / psa). */
const char *transport_name(transport_t k);

/* ---------- agentfs-backed substrate primitives ---------- */

/* Open the agentfs server-side endpoint for `agent`. Writes the agent name
 * to <mount>/register (which binds the current task_struct), then opens
 * <mount>/agents/<agent>/inbox O_RDWR. Returns the inbox fd, or -1. */
int agentfs_listen(const char *agent, const char *mount);

/* Read one framed message from an agentfs inbox fd. Parses the in-buffer
 * VERB/LEN/[REPLY-TO]/[TASK-ID]/blank/payload. payload_buf must hold
 * MAX_PAYLOAD bytes. Returns 0 on success, -1 on error (errno set). */
int agentfs_recv(int inbox_fd, agent_msg_hdr *hdr, void *payload_buf);

/* Open <mount>/agents/<target>/inbox O_WRONLY and write one framed
 * message. Returns 0 on success, -1 on error, -2 if no such inbox. */
int agentfs_send(const char *mount, const char *target,
                 const char *verb, const char *reply_to, const char *task_id,
                 const void *payload, size_t len);

/* ---------- UDS-based A2A IPC ---------- */

/* Peer identity as reported by the kernel for an AF_UNIX peer. */
typedef struct {
    pid_t pid;
    uid_t uid;
    gid_t gid;
    char authenticated_name[MAX_NAME]; /* broker-authenticated, else "" */
} peer_id_t;

/* Return inherited fd 4 under agentd, or build a legacy pathname listener in
 * direct mode. */
int  create_server_socket(const char *name);

/* Request a broker-minted connection via fd 3 under agentd; direct mode falls
 * back to the legacy pathname listener. */
int  connect_agent(const char *target);

/* Accept one client; capture peer creds; install a recv timeout.
 * Returns client fd, or -1 on accept error (errno set; EINTR may propagate). */
int  accept_client(int server_fd, peer_id_t *peer);

/* Read peer credentials (pid/uid/gid) from an AF_UNIX peer.
 * On macOS, pid may be reported as 0 if LOCAL_PEERPID is unavailable. */
int  get_peer_creds(int fd, peer_id_t *out);

/* Walk <root>/agents/ and return the agent name whose pid file matches `pid`.
 * Returns 0 on match (out filled), -1 if no agent owns that pid. */
int  resolve_agent_by_pid(pid_t pid, char *out, size_t n);

/* Receiver-side deny check. Returns 1 if `sender_name` is denied by any
 * "deny recv:<name>" or "deny recv:*" rule in caps_text. Default-open. */
int  recv_is_denied(const char *caps_text, const char *sender_name);

/* Write a framed VERB/LEN/payload message to a connected fd. */
int  send_framed_message(int fd, const char *verb,
                         const void *payload, size_t len);

/* Same as send_framed_message but also emits optional REPLY-TO and TASK-ID
 * headers if the corresponding strings are non-NULL and non-empty. */
int  send_framed_message_ex(int fd, const char *verb,
                            const char *reply_to, const char *task_id,
                            const void *payload, size_t len);

/* Connect + send + close. -2 if no server. */
int  send_to_agent(const char *target, const char *verb,
                   const void *payload, size_t len);

/* Connect + send with optional headers + close. -2 if no server. */
int  send_to_agent_ex(const char *target, const char *verb,
                      const char *reply_to, const char *task_id,
                      const void *payload, size_t len);

/* Signal flags. Handlers set; main loop reads + clears. Async-signal-safe. */
extern volatile sig_atomic_t shutdown_flag;
extern volatile sig_atomic_t reload_flag;
extern volatile sig_atomic_t snapshot_flag;
extern volatile sig_atomic_t rotate_flag;

/* Runtime helpers. Call once at startup. */
void runtime_init(void);              /* records start time */
void runtime_install_signals(void);   /* TERM/INT/HUP/USR1/USR2/PIPE */

/* Signal actions — call from main loop, NOT from signal context. */
int do_reload(const char *name);                                /* SIGHUP */
int do_rotate_artifacts(const char *name);                      /* SIGUSR2 */
int snapshot_state(const char *name, const char *extra_fields); /* SIGUSR1 */

/* Read/write a single-line per-agent setting file. read trims trailing
 * whitespace; write appends a newline atomically. Returns 0 on success. */
int read_agent_setting (const char *agent, const char *leaf,
                        char *out, size_t n);
int write_agent_setting(const char *agent, const char *leaf, const char *value);

/* Parse a `limits` file (KEY=VALUE; KEY ∈ CPU|AS|NOFILE|FSIZE) and apply via
 * setrlimit. Unknown keys silently ignored. Used by the supervisor in the
 * child after chdir, before exec. */
void apply_limits_from_file(const char *path);

/* Spawn a runtime under a supervisor convention. Forks, applies enforcement
 * + limits + argv[0]="agent:<name>", waits briefly for the runtime to flip
 * status off "starting". Returns 0 on success and stores the child pid in
 * out_pid; -1 on error (errno set). cwd / inheritance for the child:
 *   - setsid, chdir(<root>/agents/<name>/data), redirect stdio to audit.log
 *   - apply limits from the operator-controlled config/limits
 *   - enforcement_child_apply
 *   - execl(runtime_path, "agent:<name>", name, NULL)
 * fs_override / sc_override / cg_override use the same -1=profile-default,
 * 0=off, 1=on convention as agentctl's CLI flags. */
/* If `out_broker_fd` is non-NULL, a SOCK_SEQPACKET (Linux) or SOCK_STREAM
 * (macOS) socketpair is created; the child's end is dup2'd to fd 3 in the
 * spawned runtime (BROKER_FD_SLOT); the parent end is stored in *out_broker_fd
 * for the caller (agentd) to read broker requests from. The receiver inbox
 * channel uses SOCK_DGRAM so each SCM_RIGHTS delivery retains boundaries.
 * Pass NULL to skip. */
int spawn_agent_runtime(const char *name, const char *runtime_path,
                        const char *supervisor_label,
                        int fs_override, int sc_override, int cg_override,
                        pid_t *out_pid,
                        int *out_broker_fd,
                        int *out_inbox_fd);

/* Misc */
int refuse_root(void);
int run_alive(pid_t pid);

/* ---------- pidfd-based lifecycle (Linux production path) ----------
 *
 * Linux is the production target. macOS is dev-loop only and these helpers
 * all return -1 with errno=ENOSYS there; callers should fall back to the
 * pid-based primitives (run_alive / kill) when -1/ENOSYS is returned.
 *
 * Spawn path: v1 uses fork + pidfd_open(child) in the parent. There is a
 * micro-race window (microseconds) between fork() returning and the parent
 * calling pidfd_open(); if the child dies and its pid is reused before
 * pidfd_open runs, the pidfd refers to a different process. clone3(CLONE_PIDFD)
 * eliminates this race and is reserved for a future strict mode. */

/* Open a pidfd for `pid`. Returns fd ≥ 0 on success; -1 on error (errno set);
 * -1 with errno=ESRCH when the process is already gone. Always -1 on non-Linux. */
int  lifecycle_pidfd_open(pid_t pid);

/* Liveness probe anchored to a pidfd via signal 0.
 * Returns 1 alive, 0 dead (process exited), -1 on other error.
 * pidfd < 0 returns -1, errno=EBADF (caller may fall back to run_alive). */
int  lifecycle_pidfd_alive(int pidfd);

/* Send `sig` to the process *leader* identified by `pidfd`. Race-free against
 * PID reuse. Returns 0 on success, -1 on error (errno set; ESRCH = gone). */
int  lifecycle_pidfd_signal(int pidfd, int sig);

/* Send `sig` to the process *group* identified by `pgid`. Wraps killpg().
 * Documented limitation: pgid is a kernel-recycled identifier, so there is
 * a small race window if `pgid` was reused between the leader's exit and
 * this call. Prefer lifecycle_cgroup_kill() for cgroup-active profiles. */
int  lifecycle_signal_group(pid_t pgid, int sig);

/* Atomic SIGKILL of an entire cgroup v2 subtree via `<cgroup_path>/cgroup.kill`
 * (kernel ≥ 5.14). Race-immune to PID/PGID reuse: the kernel signals every
 * task currently in the cgroup tree at the moment of the write. Returns 0 on
 * success, -1 on error (errno set; ENOENT means cgroup.kill is unsupported or
 * the cgroup is gone — caller should fall back to lifecycle_signal_group).
 * Always -1 with errno=ENOSYS on non-Linux. Note: only SIGKILL — there is no
 * cgroup-native SIGTERM; graceful shutdown still uses pidfd+killpg. */
int  lifecycle_cgroup_kill(const char *cgroup_path);

#endif
