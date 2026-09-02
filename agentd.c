/* agentd — reconciling supervisor for agent processes.
 *
 * Owns:
 *   - forking the runtime
 *   - SIGCHLD harvesting + restart-on-failure
 *   - lifecycle transitions (desired_state on disk ↔ live process)
 *   - the <root>/agentd.sock control channel
 *
 * Does NOT own state. The filesystem under <root>/agents/ is canonical;
 * agentd reads it on startup, reconciles, and writes back lifecycle markers
 * (status, restart_count, supervisor=agentd, audit lines). If agentd dies,
 * the agents keep running (reparented to init/launchd); a restarted agentd
 * picks them back up via the same per-agent files. */

#include "broker.h"
#include "common.h"
#include "enforcement.h"
#include "profiles.h"
#include "tasks.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#  include <sys/inotify.h>
#endif

#if !defined(MSG_CMSG_CLOEXEC)
#  define MSG_CMSG_CLOEXEC 0
#endif
#if !defined(MSG_NOSIGNAL)
#  define MSG_NOSIGNAL 0
#endif

/* These macros expand to function calls that resolve the path on first use
 * against the per-user data root (see common.c::agentctl_root). */
#define AGENTD_SOCK (agentd_sock_path())
#define AGENTD_PID  (agentd_pid_path())
#define AGENTD_LOG  (agentd_log_path())
#define MAX_MANAGED 32
#define RECONCILE_INTERVAL_SEC 5      /* fallback polling cadence (no inotify) */
#define INOTIFY_SAFETY_SEC     60     /* belt-and-braces full rescan with inotify */
#define RESTART_STABLE_SEC     30
#define RESTART_BACKOFF_MAX_SEC 30
#define RESTART_BURST_LIMIT    5

/* ---------- per-agent state in agentd ---------- */

enum restart_policy { POLICY_NEVER = 0, POLICY_ON_FAILURE, POLICY_ALWAYS };

struct managed {
    int     used;
    char    name[MAX_NAME];
    pid_t   pid;                  /* 0 if not running; otherwise our child */
    int     pidfd;                /* -1 unless we hold a pidfd for `pid` (Linux only) */
    int     broker_fd;            /* -1 unless agentd's end of broker socketpair */
    int     inbox_fd;             /* -1 unless agentd's receiver-delivery channel */
    int     restart_count;
    int     consecutive_failures;
    time_t  last_started_at;
    time_t  next_restart_at;
    int     external;             /* 1 if we observed it but didn't spawn it */
};

static struct managed g_agents[MAX_MANAGED];

static volatile sig_atomic_t g_shutdown = 0;
static volatile sig_atomic_t g_sigchld  = 0;
static int g_self_pipe[2] = { -1, -1 };

#if defined(__linux__)
/* inotify state (Linux only). */
static int g_inotify_fd = -1;
static int g_root_wd    = -1;
struct wd_slot { int wd; char name[MAX_NAME]; };
static struct wd_slot g_watches[MAX_MANAGED];
#endif

/* ---------- daemon log ---------- */

static void daemon_log(const char *fmt, ...)
{
    char line[512];
    time_t t = time(NULL);
    struct tm tm;
    gmtime_r(&t, &tm);
    int p = snprintf(line, sizeof(line),
                     "%04d-%02d-%02dT%02d:%02d:%02dZ pid=%ld ",
                     tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                     tm.tm_hour, tm.tm_min, tm.tm_sec, (long)getpid());
    if (p < 0) return;
    va_list ap;
    va_start(ap, fmt);
    int q = vsnprintf(line + p, sizeof(line) - (size_t)p, fmt, ap);
    va_end(ap);
    if (q < 0) return;
    size_t total = (size_t)p + (size_t)q;
    if (total >= sizeof(line) - 1) total = sizeof(line) - 2;
    line[total] = '\n';
    int fd = open(AGENTD_LOG, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd != -1) { (void)!write(fd, line, total + 1); close(fd); }
}

/* ---------- slot helpers ---------- */

static struct managed *find_by_name(const char *name)
{
    for (int i = 0; i < MAX_MANAGED; i++)
        if (g_agents[i].used && strcmp(g_agents[i].name, name) == 0)
            return &g_agents[i];
    return NULL;
}

static struct managed *find_by_pid(pid_t pid)
{
    if (pid <= 0) return NULL;
    for (int i = 0; i < MAX_MANAGED; i++)
        if (g_agents[i].used && g_agents[i].pid == pid)
            return &g_agents[i];
    return NULL;
}

static struct managed *alloc_slot(const char *name)
{
    struct managed *m = find_by_name(name);
    if (m) return m;
    for (int i = 0; i < MAX_MANAGED; i++) {
        if (!g_agents[i].used) {
            memset(&g_agents[i], 0, sizeof(g_agents[i]));
            g_agents[i].used = 1;
            g_agents[i].pidfd = -1;
            g_agents[i].broker_fd = -1;
            g_agents[i].inbox_fd = -1;
            snprintf(g_agents[i].name, sizeof(g_agents[i].name), "%s", name);
            return &g_agents[i];
        }
    }
    return NULL;
}

/* Clear the running-process bookkeeping for `m` (pid + pidfd + broker_fd).
 * Slot stays in use so restart logic can keep its name and restart_count. */
static void clear_runtime_state(struct managed *m)
{
    if (!m) return;
    if (m->pidfd >= 0)     { close(m->pidfd);     m->pidfd = -1; }
    if (m->broker_fd >= 0) { close(m->broker_fd); m->broker_fd = -1; }
    if (m->inbox_fd >= 0)  { close(m->inbox_fd);  m->inbox_fd = -1; }
    m->pid = 0;
}

static void release_slot(struct managed *m)
{
    if (!m) return;
    if (m->pidfd >= 0)     { close(m->pidfd);     m->pidfd = -1; }
    if (m->broker_fd >= 0) { close(m->broker_fd); m->broker_fd = -1; }
    if (m->inbox_fd >= 0)  { close(m->inbox_fd);  m->inbox_fd = -1; }
    memset(m, 0, sizeof(*m));
}

/* ---------- per-agent settings ---------- */

static int load_enabled(const char *name)
{
    char v[16];
    if (read_agent_setting(name, "enabled", v, sizeof(v)) != 0) return 1; /* default yes */
    return (strcmp(v, "yes") == 0);
}

static int load_desired_running(const char *name)
{
    char v[16];
    if (read_agent_setting(name, "desired_state", v, sizeof(v)) != 0) return 0;
    return (strcmp(v, "running") == 0);
}

static enum restart_policy load_policy(const char *name)
{
    char v[32];
    if (read_agent_setting(name, "restart_policy", v, sizeof(v)) != 0)
        return POLICY_ON_FAILURE;
    if (strcmp(v, "never")  == 0) return POLICY_NEVER;
    if (strcmp(v, "always") == 0) return POLICY_ALWAYS;
    return POLICY_ON_FAILURE;
}

static int load_runtime_path(const char *name, char *out, size_t n)
{
    /* New canonical name is `exec`; fall back to legacy `runtime` for
     * one release. */
    if (read_agent_setting(name, "exec", out, n) == 0) return 0;
    return read_agent_setting(name, "runtime", out, n);
}

static void persist_restart_count(struct managed *m)
{
    char b[16];
    snprintf(b, sizeof(b), "%d", m->restart_count);
    write_agent_setting(m->name, "restart_count", b);
}

/* ---------- start / stop a managed agent ---------- */

/* Spawn a runtime, tag it as managed by agentd. Returns 0 on success. */
static int spawn_agent(struct managed *m)
{
    char runtime_path[MAX_PATHBUF];
    if (load_runtime_path(m->name, runtime_path, sizeof(runtime_path)) != 0) {
        daemon_log("start %s: no runtime file", m->name);
        audit_log(m->name, "agentd: cannot start (no runtime file)");
        return -1;
    }
    pid_t pid = 0;
    int broker_fd = -1, inbox_fd = -1;
    if (spawn_agent_runtime(m->name, runtime_path, "agentd",
                            -1, -1, -1, &pid, &broker_fd, &inbox_fd) != 0) {
        daemon_log("start %s: spawn failed: %s", m->name, strerror(errno));
        audit_log(m->name, "agentd: spawn failed: %s", strerror(errno));
        return -1;
    }
    m->pid = pid;
    m->external = 0;
    m->last_started_at = time(NULL);
    m->next_restart_at = 0;
    /* Acquire a pidfd race-free against PID reuse. v1: fork + pidfd_open;
     * micro-race window between fork() and this open is acceptable per the
     * lifecycle invariant. clone3(CLONE_PIDFD) is the strict-mode upgrade. */
    m->pidfd = lifecycle_pidfd_open(pid);
    if (m->pidfd < 0 && errno != ENOSYS) {
        /* Linux but the open failed — most likely the child already exited.
         * Log it; reap_zombies will catch up via SIGCHLD. */
        daemon_log("pidfd_open(%ld) for %s: %s",
                   (long)pid, m->name, strerror(errno));
    }
    /* Hold the agentd-side end of the broker socketpair; runtime got fd 3. */
    m->broker_fd = broker_fd;
    m->inbox_fd = inbox_fd;
    daemon_log("started %s pid=%ld pidfd=%d broker_fd=%d inbox_fd=%d",
               m->name, (long)pid, m->pidfd, m->broker_fd, m->inbox_fd);
    return 0;
}

/* Liveness via pidfd (race-free against PID reuse) when available, else the
 * legacy kill(pid,0) probe. Returns 1 alive, 0 dead. */
static int agent_alive(struct managed *m)
{
    if (!m || m->pid <= 0) return 0;
    if (m->pidfd >= 0) {
        int r = lifecycle_pidfd_alive(m->pidfd);
        if (r >= 0) return r;
        /* Fall through to pid-based check if pidfd path errored. */
    }
    return run_alive(m->pid);
}

/* Forward decl: stop_agent drains zombies inline (own children only become
 * reapable after waitpid()) so the liveness probe doesn't spin on a zombie. */
static void reap_zombies(void);

/* Stop a managed agent. Send SIGTERM to the leader via pidfd (race-free),
 * then to the rest of the process group via killpg() for any forked children
 * (cgroup.kill is the planned upgrade for cgroup-active profiles).
 * Poll for exit, escalate to SIGKILL. */
static int stop_agent(struct managed *m, int timeout_ms)
{
    if (m->pid <= 0 || !agent_alive(m)) {
        clear_runtime_state(m);
        return 0;
    }
    /* Leader first (pidfd path is race-free even if pid was recycled). */
    if (m->pidfd >= 0) {
        if (lifecycle_pidfd_signal(m->pidfd, SIGTERM) == -1 && errno != ESRCH) {
            daemon_log("stop %s: pidfd SIGTERM: %s", m->name, strerror(errno));
        }
    } else {
        if (kill(m->pid, SIGTERM) == -1 && errno != ESRCH) {
            daemon_log("stop %s: kill -TERM: %s", m->name, strerror(errno));
        }
    }
    /* Rest of the process group. Small race window if pgid was recycled;
     * documented limitation, see project_agentctl_invariants. */
    if (lifecycle_signal_group(m->pid, SIGTERM) == -1 && errno != ESRCH) {
        daemon_log("stop %s: killpg -TERM: %s", m->name, strerror(errno));
    }
    audit_log(m->name, "agentd: SIGTERM sent");
    int slept = 0;
    while (slept < timeout_ms) {
        /* agentd is the parent of own children, so exits don't free the
         * process table entry until we waitpid(). Drain inline so the
         * liveness probe (kill(0) / pidfd_send_signal(0)) sees the exit
         * rather than spinning on a zombie. Safe to call: reap_zombies()
         * honours desired_state=stopped and won't restart this agent. */
        reap_zombies();
        if (!agent_alive(m)) { clear_runtime_state(m); return 0; }
        struct timespec ts = { 0, 50L * 1000L * 1000L };
        nanosleep(&ts, NULL);
        slept += 50;
    }
    daemon_log("stop %s: still alive after %dms; SIGKILL", m->name, timeout_ms);
    /* Prefer cgroup.kill — atomic subtree SIGKILL, race-immune to PID/PGID
     * reuse — when the profile has cgroup ownership and the cgroup exists.
     * Fall back to pidfd+killpg otherwise. */
    enforcement_state_t es;
    int used_cgroup = 0;
    if (enforcement_read_state(m->name, &es) == 0 &&
        es.cgroup_status == ENF_STATUS_ACTIVE && es.cgroup_path[0]) {
        if (lifecycle_cgroup_kill(es.cgroup_path) == 0) {
            audit_log(m->name, "agentd: cgroup.kill atomic subtree SIGKILL "
                      "path=%s", es.cgroup_path);
            used_cgroup = 1;
        } else {
            audit_log(m->name, "agentd: cgroup.kill failed (%s); "
                      "falling back to pidfd+killpg", strerror(errno));
        }
    }
    if (!used_cgroup) {
        if (m->pidfd >= 0) (void)lifecycle_pidfd_signal(m->pidfd, SIGKILL);
        else               (void)kill(m->pid, SIGKILL);
        (void)lifecycle_signal_group(m->pid, SIGKILL);
    }
    audit_log(m->name, "agentd: SIGKILL after stop timeout");
    return 0;
}

/* ---------- reap + restart ---------- */

static void reap_zombies(void)
{
    for (;;) {
        int status = 0;
        pid_t pid = waitpid(-1, &status, WNOHANG);
        if (pid <= 0) break;
        struct managed *m = find_by_pid(pid);
        if (!m) continue;
        time_t now = time(NULL);
        time_t uptime = m->last_started_at > 0 ? now - m->last_started_at : 0;
        clear_runtime_state(m);
        int code = 0;
        int signum = 0;
        if      (WIFEXITED(status))   code   = WEXITSTATUS(status);
        else if (WIFSIGNALED(status)) signum = WTERMSIG(status);
        if (signum) {
            audit_log(m->name, "runtime crashed signal=%d", signum);
            daemon_log("%s crashed signal=%d", m->name, signum);
        } else {
            audit_log(m->name, "runtime exited status=%d", code);
            daemon_log("%s exited status=%d", m->name, code);
        }
        write_status(m->name, signum ? "crashed" : (code == 0 ? "stopped" : "failed"));

        if (!load_enabled(m->name) || !load_desired_running(m->name)) {
            daemon_log("%s not restarted (disabled or stopped)", m->name);
            continue;
        }
        enum restart_policy p = load_policy(m->name);
        int should = 0;
        if (p == POLICY_ALWAYS) should = 1;
        else if (p == POLICY_ON_FAILURE && (signum || code != 0)) should = 1;
        if (!should) {
            audit_log(m->name, "no restart (policy=%s)",
                      p == POLICY_NEVER ? "never" : "on-failure");
            /* Reconciliation treats desired_state=running as an instruction
             * to start a missing process. Persist the terminal decision or a
             * clean one-shot runtime would be relaunched on the next scan. */
            write_agent_setting(m->name, "desired_state", "stopped");
            continue;
        }
        if (uptime >= RESTART_STABLE_SEC) m->consecutive_failures = 0;
        m->consecutive_failures++;
        m->restart_count++;
        persist_restart_count(m);
        if (m->consecutive_failures >= RESTART_BURST_LIMIT) {
            audit_log(m->name,
                      "restart suppressed crash-loop failures=%d window=%ds",
                      m->consecutive_failures, RESTART_STABLE_SEC);
            daemon_log("%s restart suppressed after %d short runs",
                       m->name, m->consecutive_failures);
            write_status(m->name, "crash-loop");
            write_agent_setting(m->name, "desired_state", "stopped");
            m->next_restart_at = 0;
            continue;
        }
        int shift = m->consecutive_failures - 1;
        int delay = shift >= 5 ? RESTART_BACKOFF_MAX_SEC : (1 << shift);
        if (delay > RESTART_BACKOFF_MAX_SEC) delay = RESTART_BACKOFF_MAX_SEC;
        m->next_restart_at = now + delay;
        audit_log(m->name,
                  "restart scheduled policy=%s delay=%ds failure=%d",
                  p == POLICY_ALWAYS ? "always" : "on-failure", delay,
                  m->consecutive_failures);
    }
}

/* ---------- reconciliation ---------- */

static void scan_disk_agents(void (*cb)(const char *name, void *ud), void *ud)
{
    DIR *d = opendir(AGENT_ROOT);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        if (validate_name(e->d_name) != 0) continue;
        char path[MAX_PATHBUF];
        if (snprintf(path, sizeof(path), "%s/%s", AGENT_ROOT, e->d_name)
                >= (int)sizeof(path)) continue;
        struct stat st;
        if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        cb(e->d_name, ud);
    }
    closedir(d);
}

static void recover_cb_(const char *name, void *ud)
{
    (void)ud;
    pid_t pid;
    int has_pid = (read_pid_file(name, &pid) == 0);
    int alive   = has_pid && run_alive(pid);
    if (alive) {
        struct managed *m = alloc_slot(name);
        if (!m) return;
        m->pid      = pid;
        m->external = 1;
        /* Anchor identity via pidfd. Documented race: the pid we just read
         * from disk may have been reused before pidfd_open runs. If so, we
         * end up pointing at a different process; this corner is acceptable
         * per the v1 lifecycle invariant (agentd-restart-with-live-agents is
         * not a supported v1 use case anyway). */
        m->pidfd = lifecycle_pidfd_open(pid);
        char rc[16];
        if (read_agent_setting(name, "restart_count", rc, sizeof(rc)) == 0)
            m->restart_count = atoi(rc);
        daemon_log("recovered running agent %s pid=%ld pidfd=%d (external)",
                   name, (long)pid, m->pidfd);
        audit_log(name, "agentd: recovered running pid=%ld", (long)pid);
        return;
    }
    if (has_pid && !alive) {
        char p[MAX_PATHBUF];
        if (agent_path(p, sizeof(p), name, "pid") == 0) {
            (void)unlink(p);
            daemon_log("removed stale pid file for %s", name);
            audit_log(name, "agentd: stale pid file removed");
        }
    }
    /* If desired_state=running and enabled, start. */
    if (load_enabled(name) && load_desired_running(name)) {
        struct managed *m = alloc_slot(name);
        if (!m) return;
        daemon_log("restarting %s (recovery)", name);
        audit_log(name, "agentd: restarting (recovery)");
        if (spawn_agent(m) != 0) release_slot(m);
    }
}

static void reconcile_cb_(const char *name, void *ud)
{
    (void)ud;
    int enabled = load_enabled(name);
    int desire  = load_desired_running(name);
    struct managed *m = find_by_name(name);

    /* External liveness check (no waitpid for non-children). Uses pidfd
     * when held — race-free against PID reuse. */
    if (m && m->external && m->pid > 0 && !agent_alive(m)) {
        audit_log(name, "agentd: external pid %ld is gone", (long)m->pid);
        write_status(name, "stopped");
        clear_runtime_state(m);
        m->external = 0;
    }

    int alive = (m && m->pid > 0 && agent_alive(m));

    if (enabled && desire && !alive) {
        if (!m) m = alloc_slot(name);
        if (m) {
            time_t now = time(NULL);
            if (m->next_restart_at > now) return;
            audit_log(name, "agentd: reconcile -> start");
            if (spawn_agent(m) != 0) {
                audit_log(name, "agentd: restart spawn failed");
                m->next_restart_at = now + 1;
            } else if (m->restart_count > 0) {
                audit_log(name, "restarted pid=%ld restart_count=%d",
                          (long)m->pid, m->restart_count);
            }
        }
        return;
    }
    if (alive && (!enabled || !desire)) {
        audit_log(name, "agentd: reconcile -> stop");
        (void)stop_agent(m, 2000);
        return;
    }
}

/* Bound poll by the earliest scheduled restart so inotify-enabled systems do
 * not defer backoff expiry until the 60-second safety scan. */
static int scheduled_restart_timeout_ms(int fallback_ms)
{
    time_t now = time(NULL);
    int best = fallback_ms;
    for (int i = 0; i < MAX_MANAGED; i++) {
        struct managed *m = &g_agents[i];
        if (!m->used || m->pid > 0 || m->next_restart_at <= 0) continue;
        long ms = (long)(m->next_restart_at - now) * 1000L;
        if (ms < 0) ms = 0;
        if (ms < best) best = (int)ms;
    }
    return best;
}

static int scheduled_restart_due(void)
{
    time_t now = time(NULL);
    for (int i = 0; i < MAX_MANAGED; i++)
        if (g_agents[i].used && g_agents[i].pid <= 0 &&
            g_agents[i].next_restart_at > 0 &&
            g_agents[i].next_restart_at <= now)
            return 1;
    return 0;
}

/* ---------- capability broker (v1) ----------
 *
 * Per-agent broker channel handler. Reads one request from m->broker_fd,
 * checks the requester's config/policy file for an `allow`
 * pattern matching the requested cap name, and either issues the cap fd
 * via SCM_RIGHTS or sends a denial.
 *
 * v1 supports exactly one cap kind: mailbox.send:<target>. The broker
 * mints a socketpair, delivers one end plus authenticated requester metadata
 * to the target over fd 4, hands the other end to the requester, and closes
 * its copies. All subsequent traffic on that fd
 * flows agent-to-agent without going through agentd. The broker NEVER
 * buffers, stores, retries, or replays application messages — it only
 * transfers authority. */

static int load_allow_patterns(const char *agent_name,
                               char *workbuf, size_t workcap,
                               const char *patterns[], int max_patterns)
{
    char caps_path[MAX_PATHBUF];
    if (agent_path(caps_path, sizeof(caps_path), agent_name, "policy") != 0) return 0;
    char caps_text[8192];
    if (read_small_file(caps_path, caps_text, sizeof(caps_text), NULL) != 0) return 0;
    size_t tlen = strlen(caps_text);
    if (tlen >= workcap) tlen = workcap - 1;
    memcpy(workbuf, caps_text, tlen);
    workbuf[tlen] = '\0';

    int n = 0;
    char *line = workbuf;
    while (*line && n < max_patterns) {
        char *eol = strchr(line, '\n');
        if (eol) *eol = '\0';
        while (*line == ' ' || *line == '\t') line++;
        if (strncmp(line, "allow ", 6) == 0) {
            char *p = line + 6;
            while (*p == ' ' || *p == '\t') p++;
            size_t plen = strlen(p);
            while (plen > 0 && (p[plen - 1] == ' ' || p[plen - 1] == '\t'))
                p[--plen] = '\0';
            if (*p) patterns[n++] = p;
        }
        if (!eol) break;
        line = eol + 1;
    }
    return n;
}

/* Send a small reply on the broker channel. fd_or_neg < 0 = no SCM_RIGHTS. */
static int broker_reply(int chan_fd, const char *bytes, size_t len, int fd_or_neg)
{
    struct iovec iov = { .iov_base = (void *)bytes, .iov_len = len };
    struct msghdr mh;
    memset(&mh, 0, sizeof(mh));
    mh.msg_iov    = &iov;
    mh.msg_iovlen = 1;
    char cmsg[CMSG_SPACE(sizeof(int))];
    if (fd_or_neg >= 0) {
        mh.msg_control    = cmsg;
        mh.msg_controllen = sizeof(cmsg);
        struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
        c->cmsg_level = SOL_SOCKET;
        c->cmsg_type  = SCM_RIGHTS;
        c->cmsg_len   = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(c), &fd_or_neg, sizeof(int));
    }
    ssize_t n;
    do { n = sendmsg(chan_fd, &mh, MSG_NOSIGNAL); }
    while (n < 0 && errno == EINTR);
    return (n < 0) ? -1 : 0;
}

static int issue_mailbox_channel(const char *sender, pid_t sender_pid,
                                 uid_t sender_uid, const char *target,
                                 int *out_sender_fd)
{
    struct managed *dst = find_by_name(target);
    if (!dst || dst->pid <= 0 || dst->inbox_fd < 0 || !agent_alive(dst)) {
        errno = ENOENT; return -2;
    }
    int stype =
#if defined(__linux__)
        SOCK_SEQPACKET;
#else
        SOCK_STREAM;
#endif
    int sv[2];
    if (socketpair(AF_UNIX, stype, 0, sv) != 0) return -1;
    for (int i = 0; i < 2; i++) {
        int fl = fcntl(sv[i], F_GETFD);
        if (fl != -1) (void)fcntl(sv[i], F_SETFD, fl | FD_CLOEXEC);
    }
    char meta[256];
    int ml = snprintf(meta, sizeof(meta), "SENDER %s\nPID %ld\nUID %ld\n\n",
                      sender, (long)sender_pid, (long)sender_uid);
    struct iovec iov = { .iov_base = meta, .iov_len = (size_t)ml };
    char control[CMSG_SPACE(sizeof(int))];
    struct msghdr mh;
    memset(&mh, 0, sizeof(mh));
    mh.msg_iov = &iov; mh.msg_iovlen = 1;
    mh.msg_control = control; mh.msg_controllen = sizeof(control);
    struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
    c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &sv[1], sizeof(int));
    ssize_t n;
    do { n = sendmsg(dst->inbox_fd, &mh, MSG_NOSIGNAL); } while (n < 0 && errno == EINTR);
    close(sv[1]);
    if (n < 0) { int saved = errno; close(sv[0]); errno = saved; return -1; }
    *out_sender_fd = sv[0];
    return 0;
}

static void broker_handle_event(struct managed *m)
{
    char buf[BROKER_MSG_MAX + 1];
    char cmsg[CMSG_SPACE(sizeof(int) * 4)];
    struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) - 1 };
    struct msghdr mh;
    memset(&mh, 0, sizeof(mh));
    mh.msg_iov     = &iov;
    mh.msg_iovlen  = 1;
    mh.msg_control = cmsg;
    mh.msg_controllen = sizeof(cmsg);

    ssize_t n;
    do { n = recvmsg(m->broker_fd, &mh, MSG_CMSG_CLOEXEC); }
    while (n < 0 && errno == EINTR);
    if (n <= 0) {
        /* EOF or error: agent closed broker channel or died. Drop the fd. */
        close(m->broker_fd); m->broker_fd = -1;
        return;
    }
    if (mh.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
        daemon_log("broker %s: oversized or cmsg-truncated; closing channel",
                   m->name);
        audit_log(m->name, "broker protocol violation (truncated); channel closed");
        close(m->broker_fd); m->broker_fd = -1;
        return;
    }
    /* Defensively close any inbound fds — v1 doesn't accept delegation. */
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&mh); c; c = CMSG_NXTHDR(&mh, c)) {
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS) {
            size_t nfd = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
            int *fds = (int *)CMSG_DATA(c);
            for (size_t k = 0; k < nfd; k++) close(fds[k]);
        }
    }

    broker_msg_t req;
    if (broker_parse(buf, (size_t)n, &req) != 0 ||
        req.verb != BROKER_VERB_REQUEST) {
        char resp[BROKER_MSG_MAX];
        int rl = broker_format_denied(resp, sizeof(resp), "?", "malformed-request");
        if (rl > 0) (void)broker_reply(m->broker_fd, resp, (size_t)rl, -1);
        daemon_log("broker %s: malformed request", m->name);
        audit_log(m->name, "broker malformed request from agent");
        return;
    }

    /* Policy check: read requester's caps file. */
    char workbuf[8192];
    const char *patterns[32];
    int n_patterns = load_allow_patterns(m->name, workbuf, sizeof(workbuf),
                                         patterns, 32);
    int allowed = broker_policy_check(req.cap, patterns, n_patterns);
    if (!allowed) {
        char resp[BROKER_MSG_MAX];
        int rl = broker_format_denied(resp, sizeof(resp), req.cap, "not-in-caps");
        if (rl > 0) (void)broker_reply(m->broker_fd, resp, (size_t)rl, -1);
        daemon_log("broker denied cap=%s to=%s reason=not-in-caps",
                   req.cap, m->name);
        audit_log(m->name, "broker denied cap=%s reason=not-in-caps", req.cap);
        return;
    }

    /* Dispatch by cap kind. v1: mailbox.send:<target> only. */
    if (strncmp(req.cap, "mailbox.send:", 13) == 0) {
        const char *target = req.cap + 13;
        int cap_fd = -1;
        int issue_rc = issue_mailbox_channel(m->name, m->pid, getuid(),
                                             target, &cap_fd);
        if (issue_rc < 0) {
            const char *reason = (issue_rc == -2) ? "no-listener" : strerror(errno);
            char resp[BROKER_MSG_MAX];
            int rl = broker_format_denied(resp, sizeof(resp), req.cap, reason);
            if (rl > 0) (void)broker_reply(m->broker_fd, resp, (size_t)rl, -1);
            daemon_log("broker denied cap=%s to=%s reason=%s",
                       req.cap, m->name, reason);
            audit_log(m->name, "broker denied cap=%s reason=%s", req.cap, reason);
            return;
        }
        char token[BROKER_TOKEN_LEN + 1];
        broker_make_token(token);
        char resp[BROKER_MSG_MAX];
        int rl = broker_format_issued(resp, sizeof(resp), req.cap, token);
        if (rl <= 0) { close(cap_fd); return; }
        int rc = broker_reply(m->broker_fd, resp, (size_t)rl, cap_fd);
        close(cap_fd);   /* broker's own copy; receiver got their own via SCM_RIGHTS */
        if (rc != 0) {
            daemon_log("broker %s: response sendmsg failed: %s",
                       m->name, strerror(errno));
            return;
        }
        daemon_log("broker issued cap=%s to=%s token=%s", req.cap, m->name, token);
        audit_log(m->name, "broker issued cap=%s token=%s target=%s",
                  req.cap, token, target);
        return;
    }

    /* Unknown cap kind. */
    char resp[BROKER_MSG_MAX];
    int rl = broker_format_denied(resp, sizeof(resp), req.cap, "unknown-cap-kind");
    if (rl > 0) (void)broker_reply(m->broker_fd, resp, (size_t)rl, -1);
    daemon_log("broker denied cap=%s to=%s reason=unknown-cap-kind",
               req.cap, m->name);
    audit_log(m->name, "broker denied cap=%s reason=unknown-cap-kind", req.cap);
}

/* ---------- inotify (Linux) ----------
 * Watch <root>/agents/ for new/removed agent dirs; watch each agent dir for
 * IN_MOVED_TO/IN_CREATE/IN_CLOSE_WRITE on its settings files. On any event
 * we just call reconcile_cb_() for the affected agent — the same logic the
 * periodic scan runs, but driven by file events instead of a 5s timer. */

#if defined(__linux__)
static void inotify_add_agent(const char *name)
{
    if (g_inotify_fd == -1) return;
    char path[MAX_PATHBUF];
    if (agent_ensure_layout(name) != 0 ||
        agent_config_dir(path, sizeof(path), name) != 0) return;
    for (int i = 0; i < MAX_MANAGED; i++) {
        if (g_watches[i].wd != 0 && strcmp(g_watches[i].name, name) == 0) return;
    }
    int wd = inotify_add_watch(g_inotify_fd, path,
                               IN_MOVED_TO | IN_CLOSE_WRITE | IN_CREATE |
                               IN_DELETE_SELF | IN_MOVE_SELF);
    if (wd == -1) {
        daemon_log("inotify add %s: %s", path, strerror(errno));
        return;
    }
    for (int i = 0; i < MAX_MANAGED; i++) {
        if (g_watches[i].wd == 0) {
            g_watches[i].wd = wd;
            snprintf(g_watches[i].name, sizeof(g_watches[i].name), "%s", name);
            return;
        }
    }
}

static const char *inotify_lookup_wd(int wd)
{
    for (int i = 0; i < MAX_MANAGED; i++)
        if (g_watches[i].wd == wd) return g_watches[i].name;
    return NULL;
}

static void inotify_release_wd(int wd)
{
    for (int i = 0; i < MAX_MANAGED; i++) {
        if (g_watches[i].wd == wd) {
            g_watches[i].wd = 0;
            g_watches[i].name[0] = '\0';
            return;
        }
    }
}

static int inotify_setup_linux(void)
{
    g_inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (g_inotify_fd == -1) {
        daemon_log("inotify_init1: %s (falling back to periodic scan)",
                   strerror(errno));
        return -1;
    }
    g_root_wd = inotify_add_watch(g_inotify_fd, AGENT_ROOT,
                                  IN_CREATE | IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM);
    if (g_root_wd == -1) {
        daemon_log("inotify watch %s: %s", AGENT_ROOT, strerror(errno));
        close(g_inotify_fd);
        g_inotify_fd = -1;
        return -1;
    }
    DIR *d = opendir(AGENT_ROOT);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (e->d_name[0] == '.') continue;
            if (validate_name(e->d_name) != 0) continue;
            inotify_add_agent(e->d_name);
        }
        closedir(d);
    }
    daemon_log("inotify active (root_wd=%d)", g_root_wd);
    return 0;
}

static void inotify_drain(void)
{
    if (g_inotify_fd == -1) return;
    char buf[8192] __attribute__((aligned(8)));
    for (;;) {
        ssize_t r = read(g_inotify_fd, buf, sizeof(buf));
        if (r <= 0) {
            if (r < 0 && errno == EINTR) continue;
            if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            break;
        }
        size_t off = 0;
        while (off + sizeof(struct inotify_event) <= (size_t)r) {
            struct inotify_event *ev = (struct inotify_event *)(buf + off);
            off += sizeof(*ev) + ev->len;
            if (off > (size_t)r) break;

            if (ev->mask & IN_Q_OVERFLOW) {
                daemon_log("inotify queue overflow; full rescan");
                scan_disk_agents(reconcile_cb_, NULL);
                continue;
            }

            if (ev->wd == g_root_wd) {
                if (ev->len == 0) continue;
                if (validate_name(ev->name) != 0) continue;
                if (ev->mask & (IN_CREATE | IN_MOVED_TO)) {
                    inotify_add_agent(ev->name);
                    reconcile_cb_(ev->name, NULL);
                } else if (ev->mask & (IN_DELETE | IN_MOVED_FROM)) {
                    struct managed *m = find_by_name(ev->name);
                    if (m && m->pid <= 0) release_slot(m);
                }
                continue;
            }

            const char *name = inotify_lookup_wd(ev->wd);
            if (!name) continue;

            if (ev->mask & (IN_IGNORED | IN_DELETE_SELF | IN_MOVE_SELF)) {
                struct managed *m = find_by_name(name);
                inotify_release_wd(ev->wd);
                if (m && m->pid <= 0) release_slot(m);
                continue;
            }

            /* Only react to settings files. Audit-log churn etc. is ignored. */
            if (ev->len > 0 &&
                (strcmp(ev->name, "desired_state") == 0 ||
                 strcmp(ev->name, "enabled") == 0 ||
                 strcmp(ev->name, "exec") == 0)) {
                reconcile_cb_(name, NULL);
            }
        }
    }
}
#endif  /* __linux__ */

/* ---------- control socket ---------- */

static int handle_cmd_start(const char *name, char *resp, size_t n)
{
    if (validate_name(name) != 0) {
        snprintf(resp, n, "ERROR invalid name"); return 1;
    }
    char dir[MAX_PATHBUF];
    if (agent_dir(dir, sizeof(dir), name) != 0) {
        snprintf(resp, n, "ERROR invalid name"); return 1;
    }
    struct stat st;
    if (stat(dir, &st) != 0) {
        snprintf(resp, n, "ERROR no such agent"); return 1;
    }
    write_agent_setting(name, "desired_state", "running");
    if (load_enabled(name) == 0)
        write_agent_setting(name, "enabled", "yes");
    struct managed *m = alloc_slot(name);
    if (!m) { snprintf(resp, n, "ERROR slots full"); return 1; }
    if (m->pid > 0 && agent_alive(m)) {
        snprintf(resp, n, "OK already running pid=%ld", (long)m->pid);
        return 0;
    }
    /* An explicit operator start clears crash-loop suppression state. */
    m->consecutive_failures = 0;
    m->next_restart_at = 0;
    if (spawn_agent(m) != 0) {
        snprintf(resp, n, "ERROR spawn failed: %s", strerror(errno));
        return 1;
    }
    snprintf(resp, n, "OK started pid=%ld", (long)m->pid);
    return 0;
}

static int handle_cmd_stop(const char *name, char *resp, size_t n)
{
    if (validate_name(name) != 0) {
        snprintf(resp, n, "ERROR invalid name"); return 1;
    }
    char dir[MAX_PATHBUF];
    if (agent_dir(dir, sizeof(dir), name) != 0 || access(dir, F_OK) != 0) {
        snprintf(resp, n, "ERROR no such agent"); return 1;
    }
    write_agent_setting(name, "desired_state", "stopped");
    struct managed *m = find_by_name(name);
    if (!m) {
        snprintf(resp, n, "OK no live process"); return 0;
    }
    (void)stop_agent(m, 2000);
    release_slot(m);
    snprintf(resp, n, "OK stopped");
    return 0;
}

static int handle_cmd_restart(const char *name, char *resp, size_t n)
{
    char tmp[256];
    if (handle_cmd_stop(name, tmp, sizeof(tmp)) != 0) {
        snprintf(resp, n, "%s", tmp); return 1;
    }
    return handle_cmd_start(name, resp, n);
}

static int handle_cmd_reload(const char *name, char *resp, size_t n)
{
    if (validate_name(name) != 0) {
        snprintf(resp, n, "ERROR invalid name"); return 1;
    }
    struct managed *m = find_by_name(name);
    if (!m || m->pid <= 0) {
        snprintf(resp, n, "ERROR not running"); return 1;
    }
    int sig_rc = (m->pidfd >= 0)
                    ? lifecycle_pidfd_signal(m->pidfd, SIGHUP)
                    : kill(m->pid, SIGHUP);
    if (sig_rc != 0) {
        snprintf(resp, n, "ERROR signal: %s", strerror(errno));
        return 1;
    }
    audit_log(name, "agentd: SIGHUP sent (reload)");
    snprintf(resp, n, "OK reloaded");
    return 0;
}

static int handle_cmd_status(const char *name, char *resp, size_t n)
{
    if (validate_name(name) != 0) {
        snprintf(resp, n, "ERROR invalid name"); return 1;
    }
    struct managed *m = find_by_name(name);
    pid_t pid_disk = 0;
    int alive = 0;
    if (read_pid_file(name, &pid_disk) == 0) alive = run_alive(pid_disk);
    char desired[16] = "stopped";
    (void)read_agent_setting(name, "desired_state", desired, sizeof(desired));
    int restarts = m ? m->restart_count : 0;
    snprintf(resp, n, "OK desired=%s actual=%s pid=%ld restarts=%d",
             desired, alive ? "running" : "stopped",
             (long)(alive ? pid_disk : 0), restarts);
    return 0;
}

static int handle_command(const char *line, char *resp, size_t n)
{
    while (*line == ' ' || *line == '\t') line++;
    char verb[32]; size_t i = 0;
    while (i < sizeof(verb) - 1 && line[i] && line[i] != ' ' && line[i] != '\t') {
        verb[i] = line[i]; i++;
    }
    verb[i] = '\0';
    while (line[i] == ' ' || line[i] == '\t') i++;
    const char *arg = line + i;

    if (strcmp(verb, "start")    == 0) return handle_cmd_start(arg, resp, n);
    if (strcmp(verb, "stop")     == 0) return handle_cmd_stop(arg, resp, n);
    if (strcmp(verb, "restart")  == 0) return handle_cmd_restart(arg, resp, n);
    if (strcmp(verb, "reload")   == 0) return handle_cmd_reload(arg, resp, n);
    if (strcmp(verb, "status")   == 0) return handle_cmd_status(arg, resp, n);
    if (strcmp(verb, "shutdown") == 0) {
        snprintf(resp, n, "OK shutting down");
        g_shutdown = 1;
        return 0;
    }
    if (strcmp(verb, "kick") == 0) {
        /* "Reconcile now." agentctl uses this on macOS (no inotify) so it
         * doesn't have to wait for the 5s polling cadence. On Linux this is
         * harmless — inotify has already triggered, reconcile_cb_ is
         * idempotent. */
        if (*arg) {
            if (validate_name(arg) == 0) reconcile_cb_(arg, NULL);
        } else {
            scan_disk_agents(reconcile_cb_, NULL);
        }
        snprintf(resp, n, "OK kicked");
        return 0;
    }
    snprintf(resp, n, "ERROR unknown verb '%s'", verb);
    return 1;
}

/* Read one line from the client, dispatch, write response, close. */
static void serve_one_connection(int srv)
{
    int fd = accept(srv, NULL, NULL);
    if (fd == -1) return;
    int f = fcntl(fd, F_GETFD); if (f != -1) fcntl(fd, F_SETFD, f | FD_CLOEXEC);
    struct timeval tv = { 5, 0 };
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    /* Same-uid only. */
    peer_id_t peer;
    if (get_peer_creds(fd, &peer) == 0 && peer.uid != 0 && peer.uid != getuid()) {
        const char *m = "ERROR forbidden uid\n";
        (void)!write(fd, m, strlen(m));
        close(fd);
        return;
    }

    char line[1024];
    size_t off = 0;
    while (off + 1 < sizeof(line)) {
        ssize_t r = read(fd, line + off, sizeof(line) - 1 - off);
        if (r == -1) {
            if (errno == EINTR) continue;
            break;
        }
        if (r == 0) break;
        off += (size_t)r;
        if (memchr(line, '\n', off)) break;
    }
    if (off == 0) { close(fd); return; }
    line[off] = '\0';
    char *nl = strchr(line, '\n');
    if (nl) *nl = '\0';

    char resp[512];
    char expected[129];
    if (read_small_file(agentd_token_path(), expected, sizeof(expected), NULL) != 0) {
        snprintf(resp, sizeof(resp), "ERROR control authentication unavailable");
    } else {
        expected[strcspn(expected, "\r\n")] = '\0';
        const char *command = line;
        int authenticated = 0;
        if (strncmp(command, "AUTH ", 5) == 0) {
            const char *presented = command + 5;
            const char *space = strchr(presented, ' ');
            if (space && (size_t)(space - presented) == strlen(expected) &&
                memcmp(presented, expected, strlen(expected)) == 0) {
                authenticated = 1;
                command = space + 1;
            }
        }
        if (!authenticated) snprintf(resp, sizeof(resp), "ERROR unauthorized");
        else if (strncmp(command, "issue ", 6) == 0) {
            const char *target = command + 6;
            int capfd = -1;
            if (validate_name(target) != 0 ||
                issue_mailbox_channel("operator", peer.pid, peer.uid,
                                      target, &capfd) != 0) {
                snprintf(resp, sizeof(resp), "ERROR no-listener");
            } else {
                static const char ok[] = "OK issued\n";
                (void)broker_reply(fd, ok, sizeof(ok) - 1, capfd);
                close(capfd); close(fd); return;
            }
        } else (void)handle_command(command, resp, sizeof(resp));
    }
    size_t rl = strlen(resp);
    if (rl < sizeof(resp) - 1) { resp[rl++] = '\n'; resp[rl] = '\0'; }
    (void)!write_all(fd, resp, rl);
    close(fd);
}

/* ---------- signals + main loop ---------- */

static void on_signal(int sig)
{
    char c;
    if (sig == SIGCHLD) { g_sigchld  = 1; c = 'c'; }
    else                { g_shutdown = 1; c = 't'; }
    if (g_self_pipe[1] != -1) (void)!write(g_self_pipe[1], &c, 1);
}

static int setup_signals(void)
{
    if (pipe(g_self_pipe) != 0) return -1;
    int f = fcntl(g_self_pipe[1], F_GETFL);
    if (f != -1) fcntl(g_self_pipe[1], F_SETFL, f | O_NONBLOCK);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = on_signal;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGCHLD, &sa, NULL);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
    return 0;
}

static int bind_control_socket(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) return -1;
    int f = fcntl(fd, F_GETFD); if (f != -1) fcntl(fd, F_SETFD, f | FD_CLOEXEC);
    struct sockaddr_un a;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    snprintf(a.sun_path, sizeof(a.sun_path), "%s", AGENTD_SOCK);
    /* Try the bind first. We hold the flock so no live daemon owns this
     * socket; an EADDRINUSE here means a stale unix-socket file from a
     * prior crash. Unlink and retry. */
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        if (errno == EADDRINUSE) {
            (void)unlink(AGENTD_SOCK);
            if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
                int saved = errno; close(fd); errno = saved; return -1;
            }
        } else {
            int saved = errno; close(fd); errno = saved; return -1;
        }
    }
    (void)chmod(AGENTD_SOCK, 0600);
    if (listen(fd, 8) != 0) {
        int saved = errno; close(fd); errno = saved; return -1;
    }
    return fd;
}

static void write_pid_file(void)
{
    char buf[32];
    int n = snprintf(buf, sizeof(buf), "%ld\n", (long)getpid());
    if (n > 0) atomic_write_file(AGENTD_PID, buf, (size_t)n, 0600);
}

static int ensure_control_token(void)
{
    const char *path = agentd_token_path();
    struct stat st;
    if (lstat(path, &st) == 0) {
        if (!S_ISREG(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 0077)) {
            errno = EACCES;
            return -1;
        }
        return 0;
    }
    if (errno != ENOENT) return -1;
    unsigned char raw[32];
    int rfd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (rfd == -1) return -1;
    ssize_t got = read_all(rfd, raw, sizeof(raw));
    int saved = errno;
    close(rfd);
    if (got != (ssize_t)sizeof(raw)) { errno = saved ? saved : EIO; return -1; }
    static const char hex[] = "0123456789abcdef";
    char token[65];
    for (size_t i = 0; i < sizeof(raw); i++) {
        token[i * 2] = hex[raw[i] >> 4];
        token[i * 2 + 1] = hex[raw[i] & 15];
    }
    token[64] = '\n';
    return atomic_write_file(path, token, sizeof(token), 0600);
}

int main(int argc, char **argv)
{
    (void)argv;
    if (refuse_root() != 0) return 1;
    if (argc > 1) {
        fputs("usage: agentd (no args; runs in foreground)\n", stderr);
        return 2;
    }

    /* Single-daemon-per-data-root gate: hold an exclusive flock for the
     * full lifetime of this process. The kernel releases the lock on any
     * exit, including SIGKILL/OOM, so a crashed prior instance does not
     * leave us locked out. lock_fd is intentionally never closed. */
    int lock_fd = agentctl_root_lock();
    if (lock_fd == -1) {
        if (errno == EWOULDBLOCK) {
            fprintf(stderr,
                    "agentd: another instance is already running "
                    "under %s (lockfile held)\n", agentctl_root());
        } else {
            fprintf(stderr, "agentd: cannot acquire lockfile: %s\n",
                    strerror(errno));
        }
        return 1;
    }
    (void)lock_fd;  /* held until process exit; kernel releases the flock. */
    if (ensure_control_token() != 0) {
        fprintf(stderr, "agentd: control token: %s\n", strerror(errno));
        return 1;
    }

    if (setup_signals() != 0) {
        fprintf(stderr, "agentd: signals: %s\n", strerror(errno));
        return 1;
    }
    int srv = bind_control_socket();
    if (srv == -1) {
        fprintf(stderr, "agentd: bind: %s\n", strerror(errno));
        return 1;
    }
    write_pid_file();
    daemon_log("agentd started pid=%ld", (long)getpid());
    fprintf(stderr, "agentd listening on %s (pid=%ld)\n",
            AGENTD_SOCK, (long)getpid());

    /* Make sure the agent root exists so opendir() does not fail. */
    (void)ensure_dir(AGENT_ROOT, 0700);

    int inotify_ok = 0;
#if defined(__linux__)
    inotify_ok = (inotify_setup_linux() == 0);
#endif

    /* Recovery scan. */
    scan_disk_agents(recover_cb_, NULL);

    while (!g_shutdown) {
        /* Fixed-tier pollfds: control socket, self-pipe, optional inotify;
         * then one slot per managed agent's pidfd, then one per broker_fd.
         * Bounded by 3 + 2*MAX_MANAGED. */
        struct pollfd pfd[3 + 2 * MAX_MANAGED];
        int pidfd_pfd_idx[MAX_MANAGED];
        int broker_pfd_idx[MAX_MANAGED];
        for (int i = 0; i < MAX_MANAGED; i++) {
            pidfd_pfd_idx[i]  = -1;
            broker_pfd_idx[i] = -1;
        }

        int npfd = 0;
        int srv_idx = npfd;
        pfd[npfd].fd = srv;            pfd[npfd].events = POLLIN; pfd[npfd].revents = 0; npfd++;
        int sp_idx = npfd;
        pfd[npfd].fd = g_self_pipe[0]; pfd[npfd].events = POLLIN; pfd[npfd].revents = 0; npfd++;
#if defined(__linux__)
        int in_idx = -1;
        if (inotify_ok) {
            in_idx = npfd;
            pfd[npfd].fd = g_inotify_fd;
            pfd[npfd].events = POLLIN;
            pfd[npfd].revents = 0;
            npfd++;
        }
#endif
        /* Watch every live pidfd. POLLIN fires when the process exits. */
        for (int i = 0; i < MAX_MANAGED; i++) {
            if (!g_agents[i].used || g_agents[i].pidfd < 0) continue;
            pidfd_pfd_idx[i] = npfd;
            pfd[npfd].fd = g_agents[i].pidfd;
            pfd[npfd].events = POLLIN;
            pfd[npfd].revents = 0;
            npfd++;
        }
        /* Watch every live broker channel. POLLIN = pending request. */
        for (int i = 0; i < MAX_MANAGED; i++) {
            if (!g_agents[i].used || g_agents[i].broker_fd < 0) continue;
            broker_pfd_idx[i] = npfd;
            pfd[npfd].fd = g_agents[i].broker_fd;
            pfd[npfd].events = POLLIN;
            pfd[npfd].revents = 0;
            npfd++;
        }

        int timeout_ms = inotify_ok ? INOTIFY_SAFETY_SEC * 1000
                                    : RECONCILE_INTERVAL_SEC * 1000;
        timeout_ms = scheduled_restart_timeout_ms(timeout_ms);
        int pr = poll(pfd, (nfds_t)npfd, timeout_ms);
        if (pr == -1) {
            if (errno == EINTR) continue;
            daemon_log("poll: %s", strerror(errno));
            break;
        }
        if (pfd[sp_idx].revents & POLLIN) {
            char drain[64];
            (void)!read(g_self_pipe[0], drain, sizeof(drain));
        }
        /* SIGCHLD path: authoritative for own children. Reaps + restarts +
         * closes pidfds. After this, own-child slots have pidfd == -1. */
        if (g_sigchld) { g_sigchld = 0; reap_zombies(); }
        if (pfd[srv_idx].revents & POLLIN) serve_one_connection(srv);
#if defined(__linux__)
        if (in_idx >= 0 && (pfd[in_idx].revents & POLLIN)) inotify_drain();
#endif

        /* pidfd POLLIN: process exited. For own children, reap_zombies
         * already cleaned up (m->pidfd < 0 now) so we skip. For external
         * agents we have no waitpid path, so do the cleanup here. */
        for (int i = 0; i < MAX_MANAGED; i++) {
            int idx = pidfd_pfd_idx[i];
            if (idx < 0) continue;
            if (!(pfd[idx].revents & POLLIN)) continue;
            struct managed *m = &g_agents[i];
            if (m->pidfd < 0) continue;  /* reap_zombies got here first */
            if (!m->external) continue;  /* own child handled via SIGCHLD */
            audit_log(m->name, "agentd: external pid %ld exited (pidfd)",
                      (long)m->pid);
            daemon_log("external %s pid=%ld exited", m->name, (long)m->pid);
            write_status(m->name, "stopped");
            clear_runtime_state(m);
            m->external = 0;
        }

        /* Broker channels: serve one request per channel that fired. The
         * handler is synchronous (no userspace queuing per invariants). */
        for (int i = 0; i < MAX_MANAGED; i++) {
            int idx = broker_pfd_idx[i];
            if (idx < 0) continue;
            if (!(pfd[idx].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            struct managed *m = &g_agents[i];
            if (m->broker_fd < 0) continue;
            broker_handle_event(m);
        }

        /* Periodic reconcile:
         *   - no inotify  → on every wake (5s ticks)
         *   - with inotify → only when poll timed out (60s safety net) */
        if (!inotify_ok || pr == 0 || scheduled_restart_due()) {
            scan_disk_agents(reconcile_cb_, NULL);
        }
    }

    daemon_log("agentd shutting down");
    fprintf(stderr, "agentd shutting down\n");
#if defined(__linux__)
    if (g_inotify_fd != -1) close(g_inotify_fd);
#endif
    close(srv);
    (void)unlink(AGENTD_SOCK);
    (void)unlink(AGENTD_PID);
    return 0;
}
