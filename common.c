#include "common.h"
#include "enforcement.h"
#include "ipc.h"
#include "profiles.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

int validate_name(const char *name)
{
    if (!name) return -1;
    size_t n = strlen(name);
    if (n == 0 || n > MAX_NAME) return -1;
    if (name[0] == '.' || name[0] == '-') return -1;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)name[i];
        if (!(isalnum(c) || c == '_' || c == '-' || c == '.'))
            return -1;
    }
    return 0;
}

int ensure_dir(const char *path, mode_t mode)
{
    if (mkdir(path, mode) == 0) return 0;
    if (errno == EEXIST) {
        struct stat st;
        if (stat(path, &st) != 0) return -1;
        if (!S_ISDIR(st.st_mode)) { errno = ENOTDIR; return -1; }
        return 0;
    }
    return -1;
}

/* ---------- per-user data root resolution ----------
 *
 * Resolves once on first call and caches in a static buffer. Order:
 *
 *   1. AGENTCTL_ROOT env (explicit; used by tests and unusual deployments)
 *   2. $XDG_RUNTIME_DIR/agentctl (Linux user sessions; systemd manages it)
 *   3. /tmp/agentctl-<uid> (fallback; works on macOS dev loop)
 *
 * The root is created 0700 on first call, then validated:
 *   - must be a directory
 *   - st_uid must equal geteuid()
 *   - st_mode & 0077 must be zero (no group/world bits)
 * A mismatch prints to stderr and exits the process. This is the cross-
 * tenant adversarial-isolation gate: a misconfigured AGENTCTL_ROOT
 * cannot silently make this binary read or write into another uid's
 * data root. There is no escape hatch. */

static int validate_root_ownership_path(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        fprintf(stderr, "agentctl: cannot stat data root %s: %s\n",
                path, strerror(errno));
        return -1;
    }
    if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr,
                "agentctl: data root %s is not a directory; refusing\n",
                path);
        return -1;
    }
    if (st.st_uid != geteuid()) {
        fprintf(stderr,
                "agentctl: data root %s is owned by uid %u, "
                "not yours (%u); refusing\n",
                path, (unsigned)st.st_uid, (unsigned)geteuid());
        return -1;
    }
    if (st.st_mode & 0077) {
        fprintf(stderr,
                "agentctl: data root %s has insecure permissions %04o "
                "(expect 0700); refusing\n",
                path, (unsigned)(st.st_mode & 07777));
        return -1;
    }
    return 0;
}

const char *agentctl_root(void)
{
    static char path[MAX_PATHBUF];
    static int initialized = 0;
    if (initialized) return path;
    const char *override = getenv("AGENTCTL_ROOT");
    int written;
    if (override && *override) {
        written = snprintf(path, sizeof(path), "%s", override);
    } else {
        const char *xdg = getenv("XDG_RUNTIME_DIR");
        if (xdg && *xdg) {
            written = snprintf(path, sizeof(path), "%s/agentctl", xdg);
        } else {
            written = snprintf(path, sizeof(path), "/tmp/agentctl-%u",
                               (unsigned)getuid());
        }
    }
    if (written < 0 || (size_t)written >= sizeof(path)) {
        fputs("agentctl: data root path is too long; refusing\n", stderr);
        exit(1);
    }
    if (ensure_dir(path, 0700) != 0) {
        fprintf(stderr, "agentctl: cannot create data root %s: %s\n",
                path, strerror(errno));
        exit(1);
    }
    if (validate_root_ownership_path(path) != 0) {
        /* helper printed the diagnostic; refuse to proceed. */
        exit(1);
    }
    initialized = 1;
    return path;
}

static void root_child_path(char *out, size_t n, const char *leaf)
{
    int written = snprintf(out, n, "%s/%s", agentctl_root(), leaf);
    if (written < 0 || (size_t)written >= n) {
        fprintf(stderr, "agentctl: data root path for %s is too long; refusing\n",
                leaf);
        exit(1);
    }
}

int agentctl_root_validate_ownership(void)
{
    /* Re-stats the cached root for defence-in-depth callers.
     * Does not exit on mismatch — returns -1 so the caller chooses. */
    return validate_root_ownership_path(agentctl_root());
}

int agentctl_root_lock(void)
{
    char path[MAX_PATHBUF];
    int n = snprintf(path, sizeof(path), "%s/agentd.lock",
                     agentctl_root());
    if (n < 0 || (size_t)n >= sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd == -1) return -1;
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;  /* EWOULDBLOCK = another daemon holds the lock */
        return -1;
    }
    /* Stamp the pid for human debuggability (lsof <root>/agentd.lock
     * shows the holder's pid). The kernel-held flock is the authority. */
    (void)ftruncate(fd, 0);
    char buf[32];
    int w = snprintf(buf, sizeof(buf), "%ld\n", (long)getpid());
    if (w > 0) (void)!write(fd, buf, (size_t)w);
    return fd;
}

const char *agent_root(void)
{
    static char path[MAX_PATHBUF];
    static int initialized = 0;
    if (initialized) return path;
    root_child_path(path, sizeof(path), "agents");
    if (ensure_dir(path, 0700) != 0) {
        fprintf(stderr, "agentctl: cannot create agent root %s: %s\n",
                path, strerror(errno));
        exit(1);
    }
    initialized = 1;
    return path;
}

const char *agentd_sock_path(void)
{
    static char path[MAX_PATHBUF];
    static int initialized = 0;
    if (initialized) return path;
    root_child_path(path, sizeof(path), "agentd.sock");
    initialized = 1;
    return path;
}

const char *agentd_pid_path(void)
{
    static char path[MAX_PATHBUF];
    static int initialized = 0;
    if (initialized) return path;
    root_child_path(path, sizeof(path), "agentd.pid");
    initialized = 1;
    return path;
}

const char *agentd_log_path(void)
{
    static char path[MAX_PATHBUF];
    static int initialized = 0;
    if (initialized) return path;
    root_child_path(path, sizeof(path), "agentd.log");
    initialized = 1;
    return path;
}

const char *agentd_token_path(void)
{
    static char path[MAX_PATHBUF];
    static int initialized = 0;
    if (initialized) return path;
    root_child_path(path, sizeof(path), "agentd.token");
    initialized = 1;
    return path;
}

int agent_dir(char *out, size_t n, const char *name)
{
    if (validate_name(name) != 0) { errno = EINVAL; return -1; }
    int r = snprintf(out, n, "%s/%s", AGENT_ROOT, name);
    if (r < 0 || (size_t)r >= n) { errno = ENAMETOOLONG; return -1; }
    return 0;
}

static int agent_subdir(char *out, size_t n, const char *name, const char *subdir)
{
    if (validate_name(name) != 0) { errno = EINVAL; return -1; }
    int r = snprintf(out, n, "%s/%s/%s", AGENT_ROOT, name, subdir);
    if (r < 0 || (size_t)r >= n) { errno = ENAMETOOLONG; return -1; }
    return 0;
}

int agent_config_dir(char *out, size_t n, const char *name)
{
    return agent_subdir(out, n, name, "config");
}

int agent_runtime_dir(char *out, size_t n, const char *name)
{
    return agent_subdir(out, n, name, "runtime");
}

int agent_data_dir(char *out, size_t n, const char *name)
{
    return agent_subdir(out, n, name, "data");
}

static const char *leaf_class(const char *leaf)
{
    static const char *const config_leaves[] = {
        "goal", "policy", "limits", "profile", "config", "exec", "runtime",
        "desired_state", "enabled", "restart_policy", "transport", NULL
    };
    static const char *const runtime_leaves[] = {
        "pid", "status", "supervisor", "restart_count",
        "enforcement.req", "enforcement.applied", NULL
    };
    if (!leaf) return "data";
    for (int i = 0; config_leaves[i]; i++)
        if (strcmp(leaf, config_leaves[i]) == 0) return "config";
    for (int i = 0; runtime_leaves[i]; i++)
        if (strcmp(leaf, runtime_leaves[i]) == 0) return "runtime";
    return "data";
}

static void ensure_legacy_link(const char *base, const char *leaf, const char *klass)
{
    if (!leaf || strchr(leaf, '/')) return;
    char oldp[MAX_PATHBUF], target[MAX_PATHBUF];
    int a = snprintf(oldp, sizeof(oldp), "%s/%s", base, leaf);
    int b = snprintf(target, sizeof(target), "%s/%s", klass, leaf);
    if (a < 0 || b < 0 || (size_t)a >= sizeof(oldp) || (size_t)b >= sizeof(target))
        return;
    struct stat st;
    if (lstat(oldp, &st) != 0 && errno == ENOENT) (void)symlink(target, oldp);
}

int agent_ensure_layout(const char *name)
{
    char base[MAX_PATHBUF], config[MAX_PATHBUF], runtime[MAX_PATHBUF], data[MAX_PATHBUF];
    if (agent_dir(base, sizeof(base), name) != 0 ||
        agent_config_dir(config, sizeof(config), name) != 0 ||
        agent_runtime_dir(runtime, sizeof(runtime), name) != 0 ||
        agent_data_dir(data, sizeof(data), name) != 0) return -1;
    struct stat st;
    if (stat(base, &st) != 0) return -1;
    if (!S_ISDIR(st.st_mode)) { errno = ENOTDIR; return -1; }
    if (ensure_dir(config, 0700) != 0 || ensure_dir(runtime, 0700) != 0 ||
        ensure_dir(data, 0700) != 0) return -1;

    DIR *d = opendir(base);
    if (!d) return -1;
    struct dirent *e;
    int rc = 0;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.' || strcmp(e->d_name, "config") == 0 ||
            strcmp(e->d_name, "runtime") == 0 || strcmp(e->d_name, "data") == 0)
            continue;
        char oldp[MAX_PATHBUF], newp[MAX_PATHBUF];
        const char *klass = leaf_class(e->d_name);
        int a = snprintf(oldp, sizeof(oldp), "%s/%s", base, e->d_name);
        int b = snprintf(newp, sizeof(newp), "%s/%s/%s", base, klass, e->d_name);
        if (a < 0 || b < 0 || (size_t)a >= sizeof(oldp) || (size_t)b >= sizeof(newp)) {
            rc = -1; errno = ENAMETOOLONG; break;
        }
        if (lstat(newp, &st) != 0) {
            if (errno != ENOENT || rename(oldp, newp) != 0) { rc = -1; break; }
        }
        ensure_legacy_link(base, e->d_name, klass);
    }
    int saved = errno;
    closedir(d);
    errno = saved;
    return rc;
}

int agent_path(char *out, size_t n, const char *name, const char *leaf)
{
    if (validate_name(name) != 0) { errno = EINVAL; return -1; }
    char base[MAX_PATHBUF];
    if (agent_dir(base, sizeof(base), name) != 0) return -1;
    char config_dir[MAX_PATHBUF];
    struct stat st;
    if (agent_config_dir(config_dir, sizeof(config_dir), name) != 0) return -1;
    if (stat(config_dir, &st) != 0 && errno == ENOENT &&
        agent_ensure_layout(name) != 0) return -1;
    const char *klass = leaf_class(leaf);
    int r = snprintf(out, n, "%s/%s/%s", base, klass, leaf);
    if (r < 0 || (size_t)r >= n) { errno = ENAMETOOLONG; return -1; }
    ensure_legacy_link(base, leaf, klass);
    return 0;
}

ssize_t read_all(int fd, void *buf, size_t n)
{
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(fd, (char *)buf + off, n - off);
        if (r == -1) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return (ssize_t)off;
        off += (size_t)r;
    }
    return (ssize_t)off;
}

ssize_t write_all(int fd, const void *buf, size_t n)
{
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, (const char *)buf + off, n - off);
        if (w == -1) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)w;
    }
    return (ssize_t)off;
}

int read_line_fd(int fd, char *out, size_t n)
{
    if (n == 0) { errno = EINVAL; return -1; }
    size_t i = 0;
    while (i + 1 < n) {
        char c;
        ssize_t r = read(fd, &c, 1);
        if (r == -1) return -1;          /* EINTR propagates */
        if (r == 0) { errno = 0; return -1; }
        if (c == '\n') { out[i] = '\0'; return 0; }
        out[i++] = c;
    }
    errno = EMSGSIZE;
    return -1;
}

int read_small_file(const char *path, char *out, size_t n, size_t *out_len)
{
    if (n == 0) { errno = EINVAL; return -1; }
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd == -1) return -1;
    ssize_t r = read_all(fd, out, n - 1);
    int saved = errno;
    close(fd);
    if (r == -1) { errno = saved; return -1; }
    out[r] = '\0';
    if (out_len) *out_len = (size_t)r;
    return 0;
}

int atomic_write_file(const char *path, const void *buf, size_t n, mode_t mode)
{
    char tmp[MAX_PATHBUF];
    int r = snprintf(tmp, sizeof(tmp), "%s.tmp.XXXXXX", path);
    if (r < 0 || (size_t)r >= sizeof(tmp)) { errno = ENAMETOOLONG; return -1; }
    int fd = mkstemp(tmp);
    if (fd == -1) return -1;
    int flags = fcntl(fd, F_GETFD);
    if (flags == -1 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == -1 ||
        fchmod(fd, mode) == -1) {
        int saved = errno;
        close(fd);
        unlink(tmp);
        errno = saved;
        return -1;
    }
    if (write_all(fd, buf, n) == -1) {
        int saved = errno;
        close(fd); unlink(tmp);
        errno = saved;
        return -1;
    }
    if (close(fd) == -1) {
        int saved = errno;
        unlink(tmp);
        errno = saved;
        return -1;
    }
    if (rename(tmp, path) == -1) {
        int saved = errno;
        unlink(tmp);
        errno = saved;
        return -1;
    }
    return 0;
}

int append_file(const char *path, const void *buf, size_t n, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, mode);
    if (fd == -1) return -1;
    if (write_all(fd, buf, n) == -1) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    if (close(fd) == -1) return -1;
    return 0;
}

int write_status(const char *name, const char *status)
{
    char path[MAX_PATHBUF];
    if (agent_path(path, sizeof(path), name, "status") != 0) return -1;
    size_t len = strlen(status);
    char buf[64];
    if (len + 2 > sizeof(buf)) { errno = EINVAL; return -1; }
    memcpy(buf, status, len);
    buf[len] = '\n';
    return atomic_write_file(path, buf, len + 1, 0600);
}

int read_pid_file(const char *name, pid_t *out)
{
    char path[MAX_PATHBUF];
    if (agent_path(path, sizeof(path), name, "pid") != 0) return -1;
    char buf[32];
    if (read_small_file(path, buf, sizeof(buf), NULL) != 0) return -1;
    char *end;
    errno = 0;
    long v = strtol(buf, &end, 10);
    while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n') end++;
    if (errno != 0 || end == buf || *end != '\0' || v <= 0 || v > INT_MAX) {
        errno = EINVAL;
        return -1;
    }
    *out = (pid_t)v;
    return 0;
}

int audit_log(const char *name, const char *fmt, ...)
{
    char path[MAX_PATHBUF];
    if (agent_path(path, sizeof(path), name, "audit.log") != 0) return -1;
    char line[1024];
    time_t t = time(NULL);
    struct tm tm;
    gmtime_r(&t, &tm);
    int p = snprintf(line, sizeof(line),
                     "%04d-%02d-%02dT%02d:%02d:%02dZ pid=%ld ",
                     tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                     tm.tm_hour, tm.tm_min, tm.tm_sec, (long)getpid());
    if (p < 0 || (size_t)p >= sizeof(line)) return -1;
    va_list ap;
    va_start(ap, fmt);
    int q = vsnprintf(line + p, sizeof(line) - (size_t)p, fmt, ap);
    va_end(ap);
    if (q < 0) return -1;
    size_t total = (size_t)p + (size_t)q;
    if (total >= sizeof(line) - 1) total = sizeof(line) - 2;
    line[total] = '\n';
    return append_file(path, line, total + 1, 0600);
}

/* Thin wrapper around ipc_recv that copies fields into the legacy
 * agent_msg_hdr struct + caller-owned payload buffer. New code should use
 * ipc_recv directly. */
int read_message(int fd, agent_msg_hdr *hdr, void *payload_buf)
{
    char *buf = malloc(IPC_BUF_CAP);
    if (!buf) return -1;
    ipc_msg_t msg;
    int r = ipc_recv(fd, buf, IPC_BUF_CAP, &msg);
    if (r != IPC_OK) {
        int saved = errno;
        free(buf);
        if (r == IPC_PROTO_VIOLATION) errno = EPROTO;
        else if (r == IPC_PEER_GONE)  errno = ECONNRESET;
        else errno = saved;
        return -1;
    }
    memset(hdr, 0, sizeof(*hdr));
    if (msg.verb)     snprintf(hdr->verb,     sizeof(hdr->verb),     "%s", msg.verb);
    if (msg.reply_to) snprintf(hdr->reply_to, sizeof(hdr->reply_to), "%s", msg.reply_to);
    if (msg.task_id)  snprintf(hdr->task_id,  sizeof(hdr->task_id),  "%s", msg.task_id);
    hdr->payload_len = msg.payload_len;
    if (msg.payload && msg.payload_len > 0)
        memcpy(payload_buf, msg.payload, msg.payload_len);
    free(buf);
    return 0;
}

/* ---------- AF_UNIX IPC + peer credentials ---------- */

#include <sys/socket.h>
#include <sys/un.h>
#if defined(__APPLE__)
#  include <sys/ucred.h>
#endif

/* Thin wrappers delegating to ipc.c. See top of file. */

int create_server_socket(const char *name)
{
    return ipc_listen(name);
}

int connect_agent(const char *target)
{
    if (validate_name(target) != 0) { errno = EINVAL; return -1; }
    int r = ipc_connect(target);
    if (r == IPC_PEER_GONE) return -2;
    return r;  /* fd or -1 */
}

int accept_client(int server_fd, peer_id_t *peer)
{
    return ipc_accept(server_fd, peer);
}

int get_peer_creds(int fd, peer_id_t *out)
{
    if (!out) { errno = EINVAL; return -1; }
    memset(out, 0, sizeof(*out));
#if defined(__linux__)
    struct ucred uc;
    socklen_t len = sizeof(uc);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &uc, &len) != 0) return -1;
    out->pid = uc.pid;
    out->uid = uc.uid;
    out->gid = uc.gid;
    return 0;
#elif defined(__APPLE__)
    uid_t uid = 0;
    gid_t gid = 0;
    if (getpeereid(fd, &uid, &gid) != 0) return -1;
    out->uid = uid;
    out->gid = gid;
    /* macOS LOCAL_PEERPID requires the socket to still be in ESTABLISHED;
     * once the peer FINs (close), the option returns ENOTCONN. Callers that
     * want pid to be available must keep the connection open past their
     * write (see send_to_agent: shutdown(SHUT_WR) + drain). Linux's
     * SO_PEERCRED snapshots at connect-time and doesn't need this. */
    pid_t pid = 0;
    socklen_t plen = sizeof(pid);
    int r = getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &plen);
    if (r == 0 && pid > 0) {
        out->pid = pid;
    }
    return 0;
#else
    (void)fd;
    errno = ENOTSUP;
    return -1;
#endif
}

int resolve_agent_by_pid(pid_t pid, char *out, size_t n)
{
    if (pid <= 0 || !out || n == 0) { errno = EINVAL; return -1; }
    DIR *d = opendir(AGENT_ROOT);
    if (!d) return -1;
    int found = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        if (validate_name(e->d_name) != 0) continue;
        pid_t p;
        if (read_pid_file(e->d_name, &p) != 0) continue;
        if (p == pid) {
            size_t l = strlen(e->d_name);
            if (l >= n) l = n - 1;
            memcpy(out, e->d_name, l);
            out[l] = '\0';
            found = 1;
            break;
        }
    }
    closedir(d);
    return found ? 0 : -1;
}

int recv_is_denied(const char *caps_text, const char *sender_name)
{
    if (!caps_text || !sender_name || !*sender_name) return 0;
    size_t snlen = strlen(sender_name);
    const char *p = caps_text;
    while (*p) {
        const char *eol = strchr(p, '\n');
        size_t llen = eol ? (size_t)(eol - p) : strlen(p);
        const char *line = p;
        while (llen > 0 && (*line == ' ' || *line == '\t')) { line++; llen--; }
        if (llen > 9 && strncmp(line, "deny recv:", 10) == 0) {
            const char *t = line + 10;
            size_t tl = llen - 10;
            while (tl > 0 && (t[tl-1] == ' ' || t[tl-1] == '\t')) tl--;
            if (tl == 1 && t[0] == '*') return 1;
            if (tl == snlen && memcmp(t, sender_name, tl) == 0) return 1;
        }
        if (!eol) break;
        p = eol + 1;
    }
    return 0;
}

/* Thin wrappers delegating to ipc.c. Wire-format choice (SEQPACKET on Linux,
 * STREAM + LEN on macOS) is hidden inside ipc.c; callers see only the legacy
 * agent_msg_hdr / send_framed_message_ex API. Internal-only — new code should
 * use the ipc_* API directly. */

int send_framed_message_ex(int fd, const char *verb,
                           const char *reply_to, const char *task_id,
                           const void *payload, size_t len)
{
    if (len > MAX_PAYLOAD) { errno = EMSGSIZE; return -1; }
    if (!verb || !*verb || strlen(verb) >= MAX_VERB) { errno = EINVAL; return -1; }
    ipc_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.verb        = verb;
    msg.reply_to    = (reply_to && *reply_to) ? reply_to : "";
    msg.task_id     = (task_id  && *task_id)  ? task_id  : "";
    msg.payload     = payload;
    msg.payload_len = len;
    int r = ipc_send(fd, &msg);
    if (r == IPC_OK) return 0;
    return -1;
}

int send_framed_message(int fd, const char *verb,
                        const void *payload, size_t len)
{
    return send_framed_message_ex(fd, verb, NULL, NULL, payload, len);
}

/* UDS send path; agentfs has its own. Delegates to ipc_send_oneshot which
 * handles the macOS LOCAL_PEERPID half-close + drain dance internally. */
static int send_to_agent_uds(const char *target, const char *verb,
                              const char *reply_to, const char *task_id,
                              const void *payload, size_t len)
{
    int r = ipc_send_oneshot(target, verb, reply_to, task_id, payload, len);
    if (r == IPC_OK)         return 0;
    if (r == IPC_PEER_GONE)  return -2;
    return -1;
}

int send_to_agent_ex(const char *target, const char *verb,
                     const char *reply_to, const char *task_id,
                     const void *payload, size_t len)
{
    /* Look up the target's transport per-call so hybrid (some agents on
     * UDS, some on agentfs) "just works". */
    transport_cfg_t tcfg;
    if (transport_resolve(target, &tcfg) == 0 &&
        tcfg.kind == TRANSPORT_AGENTFS) {
        return agentfs_send(tcfg.mount, target, verb, reply_to, task_id,
                            payload, len);
    }
    return send_to_agent_uds(target, verb, reply_to, task_id, payload, len);
}

int send_to_agent(const char *target, const char *verb,
                  const void *payload, size_t len)
{
    return send_to_agent_ex(target, verb, NULL, NULL, payload, len);
}

/* ---------- transport substrate ---------- */

const char *transport_name(transport_t k)
{
    return (k == TRANSPORT_AGENTFS) ? "agentfs" : "uds";
}

int transport_resolve(const char *agent, transport_cfg_t *out)
{
    memset(out, 0, sizeof(*out));
    out->kind = TRANSPORT_UDS;
    char path[MAX_PATHBUF];
    if (agent_path(path, sizeof(path), agent, "transport") != 0) return -1;
    char buf[256];
    if (read_small_file(path, buf, sizeof(buf), NULL) != 0) return 0;  /* default UDS */
    /* trim trailing whitespace */
    size_t l = strlen(buf);
    while (l > 0 && (buf[l-1] == '\n' || buf[l-1] == '\r' ||
                     buf[l-1] == ' '  || buf[l-1] == '\t')) buf[--l] = '\0';
    if (strncmp(buf, "agentfs", 7) == 0) {
        out->kind = TRANSPORT_AGENTFS;
        const char *p = buf + 7;
        while (*p == ' ' || *p == '\t') p++;
        if (*p) snprintf(out->mount, sizeof(out->mount), "%s", p);
        else    snprintf(out->mount, sizeof(out->mount), "/mnt/agentfs");
    }
    return 0;
}

int transport_write(const char *agent, transport_t kind, const char *mount)
{
    char path[MAX_PATHBUF];
    if (agent_path(path, sizeof(path), agent, "transport") != 0) return -1;
    char buf[256];
    int n;
    if (kind == TRANSPORT_AGENTFS) {
        n = snprintf(buf, sizeof(buf), "agentfs %s\n",
                     (mount && *mount) ? mount : "/mnt/agentfs");
    } else {
        n = snprintf(buf, sizeof(buf), "uds\n");
    }
    if (n < 0 || (size_t)n >= sizeof(buf)) { errno = ENAMETOOLONG; return -1; }
    return atomic_write_file(path, buf, (size_t)n, 0600);
}

/* ---------- agentfs-backed substrate ---------- */

int agentfs_listen(const char *agent, const char *mount)
{
    char path[MAX_PATHBUF];
    int n = snprintf(path, sizeof(path), "%s/register",
                     (mount && *mount) ? mount : "/mnt/agentfs");
    if (n < 0 || (size_t)n >= sizeof(path)) { errno = ENAMETOOLONG; return -1; }
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd == -1) return -1;
    size_t l = strlen(agent);
    if (write_all(fd, agent, l) == -1) {
        int saved = errno; close(fd); errno = saved; return -1;
    }
    close(fd);

    /* Confirm registration by opening our inbox. O_RDWR keeps the kernel
     * happy on either side of the queue. */
    n = snprintf(path, sizeof(path), "%s/agents/%s/inbox",
                 (mount && *mount) ? mount : "/mnt/agentfs", agent);
    if (n < 0 || (size_t)n >= sizeof(path)) { errno = ENAMETOOLONG; return -1; }
    int inbox = open(path, O_RDWR | O_CLOEXEC);
    return inbox;
}

/* In-memory parser, mirrors read_message()'s state machine but on a buffer.
 * agentfs hands us the full message in one read(), no per-byte FIFO games. */
static int parse_framed_in_buf(const char *buf, size_t buflen,
                                agent_msg_hdr *hdr, void *payload_buf)
{
    memset(hdr, 0, sizeof(*hdr));
    size_t pos = 0;

    /* First line must be VERB <name>\n */
    const char *nl = memchr(buf + pos, '\n', buflen - pos);
    if (!nl) { errno = EPROTO; return -1; }
    size_t linelen = (size_t)(nl - (buf + pos));
    if (linelen < 5 || memcmp(buf + pos, "VERB ", 5) != 0) {
        errno = EPROTO; return -1;
    }
    size_t vstart = pos + 5;
    while (vstart < pos + linelen && buf[vstart] == ' ') vstart++;
    size_t vlen = pos + linelen - vstart;
    if (vlen == 0 || vlen >= MAX_VERB) { errno = EPROTO; return -1; }
    memcpy(hdr->verb, buf + vstart, vlen);
    hdr->verb[vlen] = '\0';
    pos += linelen + 1;

    int got_len = 0;
    for (;;) {
        if (pos > buflen) { errno = EPROTO; return -1; }
        nl = memchr(buf + pos, '\n', buflen - pos);
        if (!nl) { errno = EPROTO; return -1; }
        linelen = (size_t)(nl - (buf + pos));
        if (linelen == 0) { pos += 1; break; }  /* blank → header done */

        if (linelen >= 4 && memcmp(buf + pos, "LEN ", 4) == 0) {
            char num[32];
            size_t nlen = linelen - 4;
            if (nlen >= sizeof(num)) { errno = EPROTO; return -1; }
            memcpy(num, buf + pos + 4, nlen);
            num[nlen] = '\0';
            char *end;
            errno = 0;
            long n = strtol(num, &end, 10);
            if (errno != 0 || n < 0 || (size_t)n > MAX_PAYLOAD) {
                errno = EPROTO; return -1;
            }
            hdr->payload_len = (size_t)n;
            got_len = 1;
        } else if (linelen >= 9 && memcmp(buf + pos, "REPLY-TO ", 9) == 0) {
            size_t vl = linelen - 9;
            while (vl > 0 && buf[pos + 9] == ' ') { /* leading space — rare */ vl--; }
            if (vl < sizeof(hdr->reply_to)) {
                memcpy(hdr->reply_to, buf + pos + 9, vl);
                hdr->reply_to[vl] = '\0';
            }
        } else if (linelen >= 8 && memcmp(buf + pos, "TASK-ID ", 8) == 0) {
            size_t vl = linelen - 8;
            if (vl < sizeof(hdr->task_id)) {
                memcpy(hdr->task_id, buf + pos + 8, vl);
                hdr->task_id[vl] = '\0';
            }
        }
        /* unknown headers ignored */
        pos += linelen + 1;
    }
    if (!got_len) { errno = EPROTO; return -1; }

    /* Payload is the remainder; the message should be exactly header + payload */
    if (buflen - pos < hdr->payload_len) { errno = EPROTO; return -1; }
    if (hdr->payload_len > 0)
        memcpy(payload_buf, buf + pos, hdr->payload_len);
    return 0;
}

int agentfs_recv(int inbox_fd, agent_msg_hdr *hdr, void *payload_buf)
{
    /* Buffer big enough for the worst-case framed message: payload + a few
     * KiB of header. Heap so we don't stack-blow at MAX_PAYLOAD = 1 MiB. */
    size_t cap = MAX_PAYLOAD + 4096;
    char *buf = malloc(cap);
    if (!buf) return -1;
    ssize_t n = read(inbox_fd, buf, cap);
    if (n <= 0) {
        int saved = errno;
        free(buf);
        errno = (n == 0) ? 0 : saved;
        return -1;
    }
    int r = parse_framed_in_buf(buf, (size_t)n, hdr, payload_buf);
    free(buf);
    return r;
}

int agentfs_send(const char *mount, const char *target,
                 const char *verb, const char *reply_to, const char *task_id,
                 const void *payload, size_t len)
{
    if (!mount || !*mount) mount = "/mnt/agentfs";
    if (validate_name(target) != 0) { errno = EINVAL; return -1; }
    if (len > MAX_PAYLOAD) { errno = EMSGSIZE; return -1; }
    size_t vlen = strlen(verb);
    if (vlen == 0 || vlen >= MAX_VERB) { errno = EINVAL; return -1; }

    /* Each agentfs write() is one full message (datagram-shaped). Build the
     * entire framed bytes in one buffer and write it atomically. */
    size_t cap = MAX_PAYLOAD + 4096;
    char *buf = malloc(cap);
    if (!buf) return -1;

    size_t off = 0;
    int w;
#define H_APP(...) do { \
    w = snprintf(buf + off, cap - off, __VA_ARGS__); \
    if (w < 0 || (size_t)w >= cap - off) { free(buf); errno = EOVERFLOW; return -1; } \
    off += (size_t)w; \
} while (0)
    H_APP("VERB %s\n", verb);
    H_APP("LEN %zu\n", len);
    if (reply_to && *reply_to) H_APP("REPLY-TO %s\n", reply_to);
    if (task_id && *task_id)   H_APP("TASK-ID %s\n", task_id);
    H_APP("\n");
#undef H_APP
    if (off + len > cap) { free(buf); errno = EOVERFLOW; return -1; }
    if (len > 0) memcpy(buf + off, payload, len);
    off += len;

    char path[MAX_PATHBUF];
    int n = snprintf(path, sizeof(path), "%s/agents/%s/inbox", mount, target);
    if (n < 0 || (size_t)n >= sizeof(path)) {
        free(buf); errno = ENAMETOOLONG; return -1;
    }
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd == -1) {
        int saved = errno;
        free(buf);
        if (saved == ENOENT) { errno = saved; return -2; }
        errno = saved;
        return -1;
    }
    ssize_t wr = write(fd, buf, off);
    int saved = errno;
    close(fd);
    free(buf);
    if (wr < 0) { errno = saved; return -1; }
    if ((size_t)wr != off) { errno = EIO; return -1; }
    return 0;
}

/* ---------- signal flags + runtime lifecycle ---------- */

volatile sig_atomic_t shutdown_flag = 0;
volatile sig_atomic_t reload_flag   = 0;
volatile sig_atomic_t snapshot_flag = 0;
volatile sig_atomic_t rotate_flag   = 0;

static time_t runtime_start_time = 0;

static void on_term(int sig) { (void)sig; shutdown_flag = 1; }
static void on_hup(int sig)  { (void)sig; reload_flag = 1; }
static void on_usr1(int sig) { (void)sig; snapshot_flag = 1; }
static void on_usr2(int sig) { (void)sig; rotate_flag = 1; }

void runtime_init(void)
{
    runtime_start_time = time(NULL);
}

void runtime_install_signals(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;  /* no SA_RESTART → blocking reads break with EINTR */

    sa.sa_handler = on_term;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);

    sa.sa_handler = on_hup;
    sigaction(SIGHUP, &sa, NULL);

    sa.sa_handler = on_usr1;
    sigaction(SIGUSR1, &sa, NULL);

    sa.sa_handler = on_usr2;
    sigaction(SIGUSR2, &sa, NULL);

    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
}

int do_reload(const char *name)
{
    /* Both shipped runtimes re-read caps per message; reload is currently a
     * no-op beyond audit. Runtimes that cache config should hook here. */
    audit_log(name, "SIGHUP: reload acknowledged");
    return 0;
}

int do_rotate_artifacts(const char *name)
{
    char base[MAX_PATHBUF];
    if (agent_dir(base, sizeof(base), name) != 0) return -1;
    char dir[MAX_PATHBUF];
    if (agent_path(dir, sizeof(dir), name, "artifacts") != 0) return -1;

    time_t t = time(NULL);
    struct tm tm; gmtime_r(&t, &tm);
    char newdir[MAX_PATHBUF];
    int n = snprintf(newdir, sizeof(newdir),
                     "%s/artifacts.%04d%02d%02dT%02d%02d%02dZ",
                     base,
                     tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                     tm.tm_hour, tm.tm_min, tm.tm_sec);
    if (n < 0 || (size_t)n >= sizeof(newdir)) { errno = ENAMETOOLONG; return -1; }

    if (rename(dir, newdir) != 0) {
        audit_log(name, "SIGUSR2: rotate failed: %s", strerror(errno));
        return -1;
    }
    if (mkdir(dir, 0700) != 0) {
        audit_log(name, "SIGUSR2: mkdir new artifacts/ failed: %s", strerror(errno));
        return -1;
    }
    audit_log(name, "SIGUSR2: artifacts rotated -> %s", newdir);
    return 0;
}

int snapshot_state(const char *name, const char *extra_fields)
{
    char path[MAX_PATHBUF];
    if (agent_path(path, sizeof(path), name, "outbox/state.snapshot") != 0)
        return -1;

    char status[64] = "?";
    {
        char sp[MAX_PATHBUF];
        char sb[64];
        if (agent_path(sp, sizeof(sp), name, "status") == 0 &&
            read_small_file(sp, sb, sizeof(sb), NULL) == 0) {
            size_t i = 0;
            while (i < sizeof(status) - 1 && sb[i] && sb[i] != '\n') {
                status[i] = sb[i]; i++;
            }
            status[i] = '\0';
        }
    }

    time_t now = time(NULL);
    struct tm tm; gmtime_r(&runtime_start_time, &tm);
    char started_at[32];
    if (strftime(started_at, sizeof(started_at), "%Y-%m-%dT%H:%M:%SZ", &tm) == 0)
        return -1;

    char buf[4096];
    size_t off = 0;
    int w;
#define APP(...) do { \
    w = snprintf(buf + off, sizeof(buf) - off, __VA_ARGS__); \
    if (w < 0 || (size_t)w >= sizeof(buf) - off) return -1; \
    off += (size_t)w; \
} while (0)
    APP("agent: %s\n", name);
    APP("pid: %ld\n", (long)getpid());
    APP("ppid: %ld\n", (long)getppid());
    APP("status: %s\n", status);
    APP("started_at: %s\n", started_at);
    APP("uptime_sec: %ld\n", (long)(now - runtime_start_time));
#undef APP
    if (extra_fields && *extra_fields) {
        size_t el = strlen(extra_fields);
        if (off + el >= sizeof(buf)) return -1;
        memcpy(buf + off, extra_fields, el);
        off += el;
    }

    int r = atomic_write_file(path, buf, off, 0600);
    if (r == 0) audit_log(name, "SIGUSR1: state snapshot -> outbox/state.snapshot");
    else        audit_log(name, "SIGUSR1: snapshot failed: %s", strerror(errno));
    return r;
}

/* ---------- ---------- */

/* ---------- per-agent settings (single-line text files) ---------- */

int read_agent_setting(const char *agent, const char *leaf,
                       char *out, size_t n)
{
    if (n == 0) { errno = EINVAL; return -1; }
    char path[MAX_PATHBUF];
    if (agent_path(path, sizeof(path), agent, leaf) != 0) return -1;
    char buf[256];
    if (read_small_file(path, buf, sizeof(buf), NULL) != 0) return -1;
    /* Take the first line, trim trailing whitespace. */
    char *nl = strchr(buf, '\n');
    if (nl) *nl = '\0';
    size_t l = strlen(buf);
    while (l > 0 && (buf[l-1] == ' ' || buf[l-1] == '\t' || buf[l-1] == '\r'))
        buf[--l] = '\0';
    if (l + 1 > n) { errno = ENAMETOOLONG; return -1; }
    memcpy(out, buf, l + 1);
    return 0;
}

int write_agent_setting(const char *agent, const char *leaf, const char *value)
{
    char path[MAX_PATHBUF];
    if (agent_path(path, sizeof(path), agent, leaf) != 0) return -1;
    size_t vl = value ? strlen(value) : 0;
    char buf[512];
    if (vl + 2 > sizeof(buf)) { errno = E2BIG; return -1; }
    if (vl > 0) memcpy(buf, value, vl);
    buf[vl] = '\n';
    return atomic_write_file(path, buf, vl + 1, 0600);
}

/* ---------- setrlimit applier (moved from agentctl) ---------- */

#include <sys/resource.h>

void apply_limits_from_file(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd == -1) return;
    char buf[1024];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return;
    buf[n] = '\0';

    char *p = buf;
    while (*p) {
        char *eol = strchr(p, '\n');
        if (eol) *eol = '\0';
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '#') goto next;
        char *eq = strchr(p, '=');
        if (eq) {
            *eq = '\0';
            char *key = p;
            char *val = eq + 1;
            char *end;
            errno = 0;
            long long v = strtoll(val, &end, 10);
            if (errno == 0 && v >= 0) {
                struct rlimit lim = { (rlim_t)v, (rlim_t)v };
                int which = -1;
                if      (strcmp(key, "CPU")    == 0) which = RLIMIT_CPU;
                else if (strcmp(key, "AS")     == 0) which = RLIMIT_AS;
                else if (strcmp(key, "NOFILE") == 0) which = RLIMIT_NOFILE;
                else if (strcmp(key, "FSIZE")  == 0) which = RLIMIT_FSIZE;
                if (which >= 0) (void)setrlimit(which, &lim);
            }
        }
    next:
        if (!eol) break;
        p = eol + 1;
    }
}

/* ---------- spawn_agent_runtime ---------- */

static void export_profiles_dir_once(void)
{
    if (getenv("AGENT_PROFILES_DIR")) return;
    char cwd[MAX_PATHBUF];
    if (!getcwd(cwd, sizeof(cwd))) return;
    char prof_dir[MAX_PATHBUF];
    int n = snprintf(prof_dir, sizeof(prof_dir), "%s/profiles", cwd);
    if (n > 0 && (size_t)n < sizeof(prof_dir) &&
        access(prof_dir, R_OK | X_OK) == 0) {
        setenv("AGENT_PROFILES_DIR", prof_dir, 0);
    }
}

int spawn_agent_runtime(const char *name, const char *runtime_path,
                        const char *supervisor_label,
                        int fs_override, int sc_override, int cg_override,
                        pid_t *out_pid,
                        int *out_broker_fd,
                        int *out_inbox_fd)
{
    if (out_broker_fd) *out_broker_fd = -1;
    if (out_inbox_fd) *out_inbox_fd = -1;
    if (validate_name(name) != 0) { errno = EINVAL; return -1; }
    char dir[MAX_PATHBUF], data_dir[MAX_PATHBUF], runtime_dir[MAX_PATHBUF];
    if (agent_dir(dir, sizeof(dir), name) != 0 ||
        agent_ensure_layout(name) != 0 ||
        agent_data_dir(data_dir, sizeof(data_dir), name) != 0 ||
        agent_runtime_dir(runtime_dir, sizeof(runtime_dir), name) != 0) return -1;
    struct stat st;
    if (stat(dir, &st) != 0) return -1;

    char runtime_abs[MAX_PATHBUF];
    if (realpath(runtime_path, runtime_abs) == NULL) return -1;
    if (access(runtime_abs, X_OK) != 0) { errno = EACCES; return -1; }

    char audit_path[MAX_PATHBUF];
    if (agent_path(audit_path, sizeof(audit_path), name, "audit.log") != 0)
        return -1;
    int audit_fd = open(audit_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);

    write_agent_setting(name, "supervisor", supervisor_label ? supervisor_label : "direct");
    write_status(name, "starting");

    export_profiles_dir_once();

    /* Resolve enforcement spec. */
    profile_cfg_t pcfg;
    profile_load_for_agent(name, &pcfg);
    enforcement_spec_t spec;
    memset(&spec, 0, sizeof(spec));
    int fs_on = (fs_override >= 0) ? fs_override : pcfg.enforce_fs;
    int sc_on = (sc_override >= 0) ? sc_override : pcfg.seccomp;
    int cg_on = (cg_override >= 0) ? cg_override : pcfg.cgroup;
    spec.fs_mode   = fs_on ? ENFORCE_FS_LANDLOCK : ENFORCE_FS_OFF;
    spec.sc_mode   = sc_on ? SECCOMP_MINIMAL    : SECCOMP_OFF;
    spec.cgroup_on = cg_on;
    spec.cg_memory_max = pcfg.cgroup_memory_max;
    spec.cg_pids_max   = pcfg.cgroup_pids_max;
    snprintf(spec.cg_cpu_max, sizeof(spec.cg_cpu_max), "%s", pcfg.cgroup_cpu_max);

    enforcement_write_req(name, &spec);
    enforcement_state_t enf;
    enforcement_parent_setup(name, &spec, &enf);

    audit_log(name, "%s: enforcement requested fs=%s seccomp=%s cgroup=%s",
              supervisor_label ? supervisor_label : "direct",
              enforce_fs_name(spec.fs_mode),
              seccomp_mode_name(spec.sc_mode),
              spec.cgroup_on ? "on" : "off");
    if (enf.cgroup_status == ENF_STATUS_ACTIVE)
        audit_log(name, "cgroup active path=%s", enf.cgroup_path);
    else if (enf.cgroup_status == ENF_STATUS_UNAVAILABLE)
        audit_log(name, "cgroup unavailable: %s",
                  enf.reason[0] ? enf.reason : "?");

    /* Optional broker channel: SOCK_SEQPACKET on Linux, STREAM on macOS.
     * sv[0] is the agentd-side end (kept by parent); sv[1] becomes fd 3 in
     * the child via dup2 (with O_CLOEXEC cleared so it survives exec). */
    int broker_sv[2] = { -1, -1 };
    int broker_lock_fd = -1;
    if (out_broker_fd) {
        int stype =
#if defined(__linux__)
            SOCK_SEQPACKET;
#else
            SOCK_STREAM;   /* SOCK_SEQPACKET unavailable on AF_UNIX on Darwin */
#endif
#if defined(SOCK_CLOEXEC)
        int rc = socketpair(AF_UNIX, stype | SOCK_CLOEXEC, 0, broker_sv);
#else
        int rc = socketpair(AF_UNIX, stype, 0, broker_sv);
        if (rc == 0) {
            int f0 = fcntl(broker_sv[0], F_GETFD);
            if (f0 != -1) fcntl(broker_sv[0], F_SETFD, f0 | FD_CLOEXEC);
            int f1 = fcntl(broker_sv[1], F_GETFD);
            if (f1 != -1) fcntl(broker_sv[1], F_SETFD, f1 | FD_CLOEXEC);
        }
#endif
        if (rc != 0) {
            int saved = errno;
            if (audit_fd != -1) close(audit_fd);
            errno = saved;
            return -1;
        }
        char lock_path[MAX_PATHBUF];
        if (snprintf(lock_path, sizeof(lock_path), "%s/broker.lock", runtime_dir)
                >= (int)sizeof(lock_path) ||
            (broker_lock_fd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600)) < 0) {
            int saved = errno;
            close(broker_sv[0]); close(broker_sv[1]);
            if (audit_fd != -1) close(audit_fd);
            errno = saved;
            return -1;
        }
        /* The descriptor, not this pathname, is the synchronization
         * authority. Removing the name also prevents runtime code from
         * opening an independent lock description. */
        (void)unlink(lock_path);
    }

    int inbox_sv[2] = { -1, -1 };
    if (out_inbox_fd) {
        /* Inbox delivery carries one fd plus fixed metadata per datagram.
         * Datagram boundaries are required even on Darwin: SOCK_STREAM can
         * coalesce consecutive SCM_RIGHTS deliveries into one recvmsg. */
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, inbox_sv) != 0) {
            int saved = errno;
            if (broker_sv[0] >= 0) { close(broker_sv[0]); close(broker_sv[1]); }
            if (broker_lock_fd >= 0) close(broker_lock_fd);
            if (audit_fd != -1) close(audit_fd);
            errno = saved; return -1;
        }
        for (int i = 0; i < 2; i++) {
            int fl = fcntl(inbox_sv[i], F_GETFD);
            if (fl != -1) (void)fcntl(inbox_sv[i], F_SETFD, fl | FD_CLOEXEC);
        }
    }

    pid_t pid = fork();
    if (pid < 0) {
        int saved = errno;
        if (audit_fd != -1) close(audit_fd);
        if (broker_sv[0] >= 0) { close(broker_sv[0]); close(broker_sv[1]); }
        if (inbox_sv[0] >= 0) { close(inbox_sv[0]); close(inbox_sv[1]); }
        if (broker_lock_fd >= 0) close(broker_lock_fd);
        errno = saved;
        return -1;
    }
    if (pid == 0) {
        /* child */
        if (setsid() == -1) _exit(127);
        if (chdir(data_dir) == -1) _exit(127);
        int devnull = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (devnull != -1) { dup2(devnull, 0); close(devnull); }
        if (audit_fd != -1) { dup2(audit_fd, 1); dup2(audit_fd, 2); close(audit_fd); }
        /* Broker channel: dup2 sv[1] → fd 3 (BROKER_FD_SLOT) and clear
         * O_CLOEXEC so it survives execl. Close the parent-end copy. */
        if (broker_sv[1] >= 0) {
            close(broker_sv[0]);
            if (dup2(broker_sv[1], 3) != 3) _exit(127);
            int fl = fcntl(3, F_GETFD);
            if (fl != -1) fcntl(3, F_SETFD, fl & ~FD_CLOEXEC);
            if (broker_sv[1] != 3) close(broker_sv[1]);
        }
        if (inbox_sv[1] >= 0) {
            close(inbox_sv[0]);
            if (dup2(inbox_sv[1], INBOX_FD_SLOT) != INBOX_FD_SLOT) _exit(127);
            int fl = fcntl(INBOX_FD_SLOT, F_GETFD);
            if (fl != -1) fcntl(INBOX_FD_SLOT, F_SETFD, fl & ~FD_CLOEXEC);
            if (inbox_sv[1] != INBOX_FD_SLOT) close(inbox_sv[1]);
            (void)setenv("AGENTCTL_INBOX_FD", "4", 1);
        }
        if (broker_lock_fd >= 0) {
            if (dup2(broker_lock_fd, BROKER_LOCK_FD_SLOT) != BROKER_LOCK_FD_SLOT)
                _exit(127);
            int fl = fcntl(BROKER_LOCK_FD_SLOT, F_GETFD);
            if (fl != -1)
                fcntl(BROKER_LOCK_FD_SLOT, F_SETFD, fl & ~FD_CLOEXEC);
            if (broker_lock_fd != BROKER_LOCK_FD_SLOT) close(broker_lock_fd);
            (void)setenv("AGENTCTL_BROKER_LOCK_FD", "5", 1);
        }
        char limits_path[MAX_PATHBUF];
        if (agent_path(limits_path, sizeof(limits_path), name, "limits") == 0)
            apply_limits_from_file(limits_path);
        (void)enforcement_child_apply(name, runtime_abs, &spec, &enf);
        char argv0[MAX_NAME + 16];
        int an = snprintf(argv0, sizeof(argv0), "agent:%s", name);
        if (an < 0 || (size_t)an >= sizeof(argv0)) _exit(127);
        execl(runtime_abs, argv0, name, (char *)NULL);
        char exec_error[256];
        int exec_error_len = snprintf(
            exec_error, sizeof(exec_error),
            "spawn_agent_runtime: execl %s failed: %s\n",
            runtime_abs, strerror(errno)
        );
        if (exec_error_len > 0)
            (void)!write(2, exec_error, (size_t)exec_error_len);
        _exit(127);
    }
    /* parent */
    if (audit_fd != -1) close(audit_fd);
    if (broker_sv[0] >= 0) {
        close(broker_sv[1]);          /* child's end stays in the child */
        *out_broker_fd = broker_sv[0];
    }
    if (inbox_sv[0] >= 0) {
        close(inbox_sv[1]);
        *out_inbox_fd = inbox_sv[0];
    }
    if (broker_lock_fd >= 0) close(broker_lock_fd);

    char pidbuf[32];
    int rl = snprintf(pidbuf, sizeof(pidbuf), "%ld\n", (long)pid);
    if (rl < 0 || (size_t)rl >= sizeof(pidbuf)) return -1;
    char pid_path[MAX_PATHBUF];
    if (agent_path(pid_path, sizeof(pid_path), name, "pid") != 0) return -1;
    if (atomic_write_file(pid_path, pidbuf, (size_t)rl, 0600) != 0) return -1;

    (void)enforcement_parent_attach_pid(&enf, pid);
    audit_log(name, "%s forked pid=%ld pgid=%ld runtime=%s",
              supervisor_label ? supervisor_label : "direct",
              (long)pid, (long)pid, runtime_abs);

    /* Persist runtime path for future restarts. */
    write_agent_setting(name, "exec", runtime_path);

    /* Wait briefly for status to flip off "starting". */
    char status_path[MAX_PATHBUF];
    if (agent_path(status_path, sizeof(status_path), name, "status") == 0) {
        for (int i = 0; i < 40; i++) {
            char sbuf[64];
            if (read_small_file(status_path, sbuf, sizeof(sbuf), NULL) == 0) {
                char *nl = strchr(sbuf, '\n');
                if (nl) *nl = '\0';
                if (strcmp(sbuf, "starting") != 0 &&
                    strcmp(sbuf, "created")  != 0) break;
            }
            if (!run_alive(pid)) break;
            struct timespec ts = { 0, 50L * 1000L * 1000L };
            nanosleep(&ts, NULL);
        }
    }

    if (out_pid) *out_pid = pid;
    return 0;
}

/* ---------- ---------- */

int refuse_root(void)
{
    if (geteuid() == 0) {
        /* In a contained sandbox (QEMU initramfs, test fixtures) the only
         * uid available is 0. Escape hatch: AGENT_ALLOW_ROOT=1. */
        const char *override = getenv("AGENT_ALLOW_ROOT");
        if (override && override[0] == '1' && override[1] == '\0') return 0;
        fprintf(stderr, "agentctl: refusing to run as root "
                "(set AGENT_ALLOW_ROOT=1 to override; intended for sandboxes only)\n");
        return -1;
    }
    return 0;
}

int run_alive(pid_t pid)
{
    if (pid <= 0) return 0;
    if (kill(pid, 0) == 0) return 1;
    if (errno == EPERM) return 1;  /* exists but we can't signal it */
    return 0;
}

/* ---------- pidfd lifecycle helpers (Linux only) ----------
 *
 * Use syscall() directly rather than the glibc wrapper so the build doesn't
 * require glibc ≥ 2.36. The syscall numbers are stable on every architecture
 * that has the generic syscall table (x86_64, aarch64, arm, riscv, etc.);
 * they were introduced together in kernel 5.3 (September 2019). */

#if defined(__linux__)
#  include <sys/syscall.h>
#  ifndef SYS_pidfd_open
#    define SYS_pidfd_open 434
#  endif
#  ifndef SYS_pidfd_send_signal
#    define SYS_pidfd_send_signal 424
#  endif
#endif

int lifecycle_pidfd_open(pid_t pid)
{
#if defined(__linux__)
    long r = syscall(SYS_pidfd_open, (long)pid, 0L);
    if (r < 0) return -1;
    return (int)r;
#else
    (void)pid;
    errno = ENOSYS;
    return -1;
#endif
}

int lifecycle_pidfd_alive(int pidfd)
{
    if (pidfd < 0) { errno = EBADF; return -1; }
#if defined(__linux__)
    if (syscall(SYS_pidfd_send_signal,
                (long)pidfd, 0L, (long)NULL, 0L) == 0) return 1;
    if (errno == ESRCH) return 0;
    return -1;
#else
    errno = ENOSYS;
    return -1;
#endif
}

int lifecycle_pidfd_signal(int pidfd, int sig)
{
    if (pidfd < 0) { errno = EBADF; return -1; }
#if defined(__linux__)
    if (syscall(SYS_pidfd_send_signal,
                (long)pidfd, (long)sig, (long)NULL, 0L) == 0) return 0;
    return -1;
#else
    (void)sig;
    errno = ENOSYS;
    return -1;
#endif
}

int lifecycle_signal_group(pid_t pgid, int sig)
{
    return killpg(pgid, sig);
}

int lifecycle_cgroup_kill(const char *cgroup_path)
{
#if defined(__linux__)
    if (!cgroup_path || !*cgroup_path) { errno = EINVAL; return -1; }
    char path[MAX_PATHBUF];
    int n = snprintf(path, sizeof(path), "%s/cgroup.kill", cgroup_path);
    if (n < 0 || (size_t)n >= sizeof(path)) { errno = ENAMETOOLONG; return -1; }
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd == -1) return -1;  /* ENOENT = unsupported / cgroup gone */
    ssize_t w = write(fd, "1\n", 2);
    int saved = errno;
    close(fd);
    if (w < 0) { errno = saved; return -1; }
    return 0;
#else
    (void)cgroup_path;
    errno = ENOSYS;
    return -1;
#endif
}
