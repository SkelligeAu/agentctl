/*
 * ipc.c — canonical IPC transport. See ipc.h for invariants.
 *
 * Linux:  SOCK_SEQPACKET. One sendmsg / one recvmsg per message.
 * macOS:  SOCK_STREAM + LEN framing (Darwin AF_UNIX lacks SOCK_SEQPACKET).
 *         Dev-loop only; macOS is non-production per the invariants.
 *
 * No userspace queues. No connection pool. No retries beyond bounded
 * EAGAIN. The kernel socket buffer is the queue.
 */

#include "ipc.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#if defined(__APPLE__)
#  include <sys/ucred.h>
#endif

/* fd 3 is shared by every thread and forked descendant of a supervised
 * runtime. A process-local guard serializes threads; the inherited regular
 * fd 5 supplies a POSIX record lock that serializes distinct processes. */
static volatile int g_broker_thread_lock = 0;

static int broker_exchange_lock(void)
{
    const char *marker = getenv("AGENTCTL_BROKER_LOCK_FD");
    if (!marker || strcmp(marker, "5") != 0 ||
        fcntl(BROKER_LOCK_FD_SLOT, F_GETFD) < 0) {
        errno = EPROTO;
        return -1;
    }
    while (__sync_lock_test_and_set(&g_broker_thread_lock, 1)) {
        struct timespec ts = { 0, 1000L * 1000L };
        nanosleep(&ts, NULL);
    }
    struct flock lk;
    memset(&lk, 0, sizeof(lk));
    lk.l_type = F_WRLCK;
    lk.l_whence = SEEK_SET;
    int rc;
    do { rc = fcntl(BROKER_LOCK_FD_SLOT, F_SETLKW, &lk); }
    while (rc < 0 && errno == EINTR);
    if (rc < 0) __sync_lock_release(&g_broker_thread_lock);
    return rc;
}

static void broker_exchange_unlock(void)
{
    struct flock lk;
    memset(&lk, 0, sizeof(lk));
    lk.l_type = F_UNLCK;
    lk.l_whence = SEEK_SET;
    (void)fcntl(BROKER_LOCK_FD_SLOT, F_SETLK, &lk);
    __sync_lock_release(&g_broker_thread_lock);
}

/* Per-platform socket type. */
#if defined(__linux__)
#  define IPC_SOCK_TYPE SOCK_SEQPACKET
#  define IPC_WIRE_LEN  0   /* SEQPACKET: no LEN header; size is recvmsg() */
#else
#  define IPC_SOCK_TYPE SOCK_STREAM
#  define IPC_WIRE_LEN  1   /* STREAM: explicit LEN header for framing */
#endif

/* SOCK_CLOEXEC isn't on Darwin; we set FD_CLOEXEC via fcntl after socket(). */
#if !defined(SOCK_CLOEXEC)
#  define SOCK_CLOEXEC 0
#endif
#if !defined(SOCK_NONBLOCK)
#  define SOCK_NONBLOCK 0
#endif
#if !defined(MSG_CMSG_CLOEXEC)
#  define MSG_CMSG_CLOEXEC 0
#endif

static int set_cloexec(int fd)
{
    int f = fcntl(fd, F_GETFD);
    if (f == -1) return -1;
    return fcntl(fd, F_SETFD, f | FD_CLOEXEC);
}

static int set_nonblock(int fd)
{
    int f = fcntl(fd, F_GETFL);
    if (f == -1) return -1;
    return fcntl(fd, F_SETFL, f | O_NONBLOCK);
}

/* ----------------------------------------------------------------
 * Path construction
 * ---------------------------------------------------------------- */

static int sock_path_for(const char *agent_name, char *out, size_t n)
{
    return agent_path(out, n, agent_name, "agent.sock");
}

/* ----------------------------------------------------------------
 * Listener / accept / connect
 * ---------------------------------------------------------------- */

int ipc_listen(const char *agent_name)
{
    /* agentd-supervised runtimes receive a private capability-delivery
     * channel at fd 4. No pathname mailbox is created in that mode. */
    const char *inherited = getenv("AGENTCTL_INBOX_FD");
    if (inherited && strcmp(inherited, "4") == 0 &&
        fcntl(INBOX_FD_SLOT, F_GETFD) != -1) return INBOX_FD_SLOT;
    char path[MAX_PATHBUF];
    if (sock_path_for(agent_name, path, sizeof(path)) != 0) return -1;
    (void)unlink(path);

    int fd = socket(AF_UNIX, IPC_SOCK_TYPE | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd == -1) return -1;
    set_cloexec(fd);
    set_nonblock(fd);  /* belt-and-braces for platforms ignoring SOCK_NONBLOCK */

    struct sockaddr_un a;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    size_t path_len = strlen(path);
    if (path_len >= sizeof(a.sun_path)) { close(fd); errno = ENAMETOOLONG; return -1; }
    memcpy(a.sun_path, path, path_len + 1);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        int e = errno; close(fd); errno = e; return -1;
    }
    (void)chmod(path, 0600);
    if (listen(fd, 8) != 0) {
        int e = errno; close(fd); errno = e; return -1;
    }

    /* Size kernel buffers to comfortably hold one max-size message in each
     * direction, plus header headroom. The hard cap is per the invariants;
     * SO_*BUF setsockopt typically grants at most the requested value. */
    int sz = (int)IPC_BUF_CAP;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));

    return fd;
}

static int read_peer_creds(int fd, peer_id_t *out)
{
    memset(out, 0, sizeof(*out));
#if defined(__linux__)
    struct ucred uc;
    socklen_t l = sizeof(uc);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &uc, &l) == 0) {
        out->pid = uc.pid;
        out->uid = uc.uid;
        out->gid = uc.gid;
        return 0;
    }
    return -1;
#elif defined(__APPLE__)
    /* getpeereid → uid/gid; LOCAL_PEERPID → pid (best-effort, may be 0). */
    if (getpeereid(fd, &out->uid, &out->gid) != 0) return -1;
    pid_t pid = 0;
    socklen_t l = sizeof(pid);
    if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &l) == 0)
        out->pid = pid;
    return 0;
#else
    (void)fd;
    return 0;
#endif
}

int ipc_accept(int server_fd, peer_id_t *out_peer)
{
    if (server_fd == INBOX_FD_SLOT) {
        char meta[256];
        char control[CMSG_SPACE(sizeof(int))];
        struct iovec iov = { .iov_base = meta, .iov_len = sizeof(meta) - 1 };
        struct msghdr mh;
        memset(&mh, 0, sizeof(mh));
        mh.msg_iov = &iov; mh.msg_iovlen = 1;
        mh.msg_control = control; mh.msg_controllen = sizeof(control);
        ssize_t n;
        do { n = recvmsg(server_fd, &mh, MSG_CMSG_CLOEXEC); } while (n < 0 && errno == EINTR);
        if (n <= 0 || (mh.msg_flags & (MSG_TRUNC | MSG_CTRUNC))) {
            /* EOF on the inherited delivery channel means agentd is gone.
             * Convert it to the normal runtime shutdown signal so callers do
             * not spin forever polling a permanently readable EOF. */
            if (n == 0) {
                shutdown_flag = 1;
                errno = EINTR;
            }
            else if (n > 0) errno = EPROTO;
            return -1;
        }
        int issued = -1;
        for (struct cmsghdr *c = CMSG_FIRSTHDR(&mh); c; c = CMSG_NXTHDR(&mh, c))
            if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS) {
                memcpy(&issued, CMSG_DATA(c), sizeof(issued)); break;
            }
        if (issued < 0) { errno = EPROTO; return -1; }
        set_cloexec(issued);
        meta[n] = '\0';
        if (out_peer) {
            memset(out_peer, 0, sizeof(*out_peer));
            char sender[MAX_NAME] = "";
            long pid = 0, uid = 0;
            (void)sscanf(meta, "SENDER %63s\nPID %ld\nUID %ld", sender, &pid, &uid);
            snprintf(out_peer->authenticated_name,
                     sizeof(out_peer->authenticated_name), "%s", sender);
            out_peer->pid = (pid_t)pid;
            out_peer->uid = (uid_t)uid;
        }
        struct timeval tv = { 30, 0 };
        (void)setsockopt(issued, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        return issued;
    }
    int cfd;
    do {
        cfd = accept(server_fd, NULL, NULL);
    } while (cfd == -1 && errno == EINTR);
    if (cfd == -1) return -1;
    set_cloexec(cfd);
    if (out_peer) (void)read_peer_creds(cfd, out_peer);
    /* 30 s recv safety so a wedged peer can't pin us forever. */
    struct timeval tv = { 30, 0 };
    (void)setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return cfd;
}

int ipc_connect(const char *target)
{
    /* Supervised runtimes never know a mailbox pathname. Acquire a fresh
     * connected capability through their inherited broker channel. */
    int broker_type = 0; socklen_t broker_type_len = sizeof(broker_type);
    if (fcntl(BROKER_FD_SLOT, F_GETFD) != -1 &&
        getsockopt(BROKER_FD_SLOT, SOL_SOCKET, SO_TYPE,
                   &broker_type, &broker_type_len) == 0) {
        if (validate_name(target) != 0) { errno = EINVAL; return IPC_ERR; }
        if (broker_exchange_lock() != 0) return IPC_ERR;
        char req[256];
        int rn = snprintf(req, sizeof(req),
                          "VERB request\nCAP mailbox.send:%s\nREASON libagentctl\n\n",
                          target);
        if (rn <= 0 || send(BROKER_FD_SLOT, req, (size_t)rn, 0) < 0) {
            broker_exchange_unlock();
            return IPC_ERR;
        }
        char resp[512], control[CMSG_SPACE(sizeof(int))];
        struct iovec iov = { .iov_base = resp, .iov_len = sizeof(resp) };
        struct msghdr mh;
        memset(&mh, 0, sizeof(mh)); mh.msg_iov = &iov; mh.msg_iovlen = 1;
        mh.msg_control = control; mh.msg_controllen = sizeof(control);
        ssize_t got;
        do { got = recvmsg(BROKER_FD_SLOT, &mh, MSG_CMSG_CLOEXEC); }
        while (got < 0 && errno == EINTR);
        if (got <= 0) { broker_exchange_unlock(); return IPC_ERR; }
        int issued = -1;
        for (struct cmsghdr *c = CMSG_FIRSTHDR(&mh); c; c = CMSG_NXTHDR(&mh, c))
            if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS) {
                memcpy(&issued, CMSG_DATA(c), sizeof(issued)); break;
            }
        if (issued < 0) {
            broker_exchange_unlock();
            errno = EACCES;
            return IPC_ERR;
        }
        set_cloexec(issued);
        broker_exchange_unlock();
        return issued;
    }
    char path[MAX_PATHBUF];
    if (sock_path_for(target, path, sizeof(path)) != 0) return IPC_ERR;
    int fd = socket(AF_UNIX, IPC_SOCK_TYPE | SOCK_CLOEXEC, 0);
    if (fd == -1) return IPC_ERR;
    set_cloexec(fd);

    struct sockaddr_un a;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    size_t path_len = strlen(path);
    if (path_len >= sizeof(a.sun_path)) { close(fd); errno = ENAMETOOLONG; return -1; }
    memcpy(a.sun_path, path, path_len + 1);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        int e = errno; close(fd);
        if (e == ENOENT || e == ECONNREFUSED) return IPC_PEER_GONE;
        errno = e; return IPC_ERR;
    }
    /* Leave fd in blocking mode; ipc_send uses MSG_DONTWAIT per-call so
     * callers can read replies normally without juggling fd flags. */
    return fd;
}

void ipc_close_listener(int server_fd, const char *agent_name)
{
    if (server_fd >= 0) close(server_fd);
    if (agent_name && server_fd != INBOX_FD_SLOT) {
        char path[MAX_PATHBUF];
        if (sock_path_for(agent_name, path, sizeof(path)) == 0)
            (void)unlink(path);
    }
}

/* ----------------------------------------------------------------
 * Header building (shared between send and oneshot)
 * ---------------------------------------------------------------- */

static int build_header(const ipc_msg_t *msg, char *out, size_t cap, size_t *out_len)
{
    if (!msg->verb || !*msg->verb) { errno = EINVAL; return -1; }
    size_t pos = 0;
    int n;

#define APPEND(...) do { \
    n = snprintf(out + pos, cap - pos, __VA_ARGS__); \
    if (n < 0 || (size_t)n >= cap - pos) { errno = EOVERFLOW; return -1; } \
    pos += (size_t)n; \
} while (0)

    APPEND("VERB %s\n", msg->verb);
#if IPC_WIRE_LEN
    APPEND("LEN %zu\n", msg->payload_len);
#endif
    if (msg->reply_to && *msg->reply_to) APPEND("REPLY-TO %s\n", msg->reply_to);
    if (msg->task_id  && *msg->task_id)  APPEND("TASK-ID %s\n",  msg->task_id);
    if (pos + 1 >= cap) { errno = EOVERFLOW; return -1; }
    out[pos++] = '\n';  /* blank separator */
#undef APPEND
    *out_len = pos;
    return 0;
}

/* ----------------------------------------------------------------
 * Send
 * ---------------------------------------------------------------- */

#if defined(__linux__)
/* SEQPACKET: one sendmsg with header + payload as iovec. Atomic. */
static int ipc_send_linux(int fd, const ipc_msg_t *msg)
{
    char hdr[IPC_HEADER_HEADROOM];
    size_t hlen;
    if (build_header(msg, hdr, sizeof(hdr), &hlen) != 0) return IPC_ERR;
    if (msg->payload_len > IPC_MSG_HARD_CAP) {
        errno = EMSGSIZE; return IPC_ERR;
    }

    struct iovec iov[2];
    int niov = 1;
    iov[0].iov_base = hdr;
    iov[0].iov_len  = hlen;
    if (msg->payload_len > 0) {
        iov[1].iov_base = (void *)msg->payload;
        iov[1].iov_len  = msg->payload_len;
        niov = 2;
    }
    struct msghdr mh;
    memset(&mh, 0, sizeof(mh));
    mh.msg_iov    = iov;
    mh.msg_iovlen = (size_t)niov;

    /* SCM_RIGHTS: attach caller-provided fds via cmsg. Used by the
     * capability broker (broker.c) to deliver issued cap fds. */
    char cmsg_buf[CMSG_SPACE(sizeof(int) * IPC_MAX_FDS)];
    if (msg->n_fds > 0) {
        if (msg->n_fds > IPC_MAX_FDS) { errno = EINVAL; return IPC_ERR; }
        size_t fdbytes = sizeof(int) * (size_t)msg->n_fds;
        mh.msg_control    = cmsg_buf;
        mh.msg_controllen = CMSG_SPACE(fdbytes);
        struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
        c->cmsg_level = SOL_SOCKET;
        c->cmsg_type  = SCM_RIGHTS;
        c->cmsg_len   = CMSG_LEN(fdbytes);
        memcpy(CMSG_DATA(c), msg->fds, fdbytes);
    }

    static const int backoff_us[] = IPC_SEND_BACKOFF_US;
    /* MSG_DONTWAIT makes the send per-call non-blocking without touching
     * fcntl flags — caller's fd state is preserved for any post-send read. */
    for (int attempt = 0; attempt <= IPC_SEND_RETRIES; attempt++) {
        ssize_t n;
        do { n = sendmsg(fd, &mh, MSG_NOSIGNAL | MSG_DONTWAIT); }
        while (n < 0 && errno == EINTR);
        if (n >= 0) return IPC_OK;
        if (errno == EPIPE || errno == ECONNRESET) return IPC_PEER_GONE;
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
            if (attempt < IPC_SEND_RETRIES) {
                struct timespec ts = {
                    0, (long)backoff_us[attempt] * 1000L
                };
                nanosleep(&ts, NULL);
                continue;
            }
        }
        return IPC_ERR;
    }
    return IPC_ERR;
}
#endif

#if defined(__APPLE__)
/* STREAM: header + payload as two sends. send() with MSG_DONTWAIT to keep
 * the call per-call non-blocking without touching fcntl flags (callers
 * may want to read replies on the same fd, so the fd stays blocking). */
static int write_all_retry(int fd, const void *buf, size_t n)
{
    const char *p = buf;
    static const int backoff_us[] = IPC_SEND_BACKOFF_US;
    while (n > 0) {
        ssize_t w;
        int attempt = 0;
        for (;;) {
            do { w = send(fd, p, n, MSG_DONTWAIT
#  ifdef MSG_NOSIGNAL
                          | MSG_NOSIGNAL
#  endif
                 ); } while (w == -1 && errno == EINTR);
            if (w >= 0) break;
            if (errno == EPIPE || errno == ECONNRESET) return IPC_PEER_GONE;
            if ((errno == EAGAIN || errno == EWOULDBLOCK) && attempt < IPC_SEND_RETRIES) {
                struct timespec ts = { 0, (long)backoff_us[attempt] * 1000L };
                nanosleep(&ts, NULL);
                attempt++;
                continue;
            }
            return IPC_ERR;
        }
        p += w; n -= (size_t)w;
    }
    return IPC_OK;
}

static int ipc_send_macos(int fd, const ipc_msg_t *msg)
{
    char hdr[IPC_HEADER_HEADROOM];
    size_t hlen;
    if (build_header(msg, hdr, sizeof(hdr), &hlen) != 0) return IPC_ERR;
    if (msg->payload_len > IPC_MSG_HARD_CAP) {
        errno = EMSGSIZE; return IPC_ERR;
    }
    int r = write_all_retry(fd, hdr, hlen);
    if (r != IPC_OK) return r;
    if (msg->payload_len > 0)
        return write_all_retry(fd, msg->payload, msg->payload_len);
    return IPC_OK;
}
#endif

int ipc_send(int fd, const ipc_msg_t *msg)
{
#if defined(__linux__)
    return ipc_send_linux(fd, msg);
#else
    return ipc_send_macos(fd, msg);
#endif
}

/* ----------------------------------------------------------------
 * Recv
 * ---------------------------------------------------------------- */

/* In-place parser: locates header/payload split, NUL-terminates header
 * field values inside `buf`, populates `out`. On STREAM, `total_len`
 * equals header_len + payload_len (already framed by the caller). */
static int parse_inplace(char *buf, size_t total_len, ipc_msg_t *out)
{
    /* Find the blank-line separator "\n\n". */
    char *sep = NULL;
    for (size_t i = 0; i + 1 < total_len; i++) {
        if (buf[i] == '\n' && buf[i + 1] == '\n') { sep = buf + i; break; }
    }
    if (!sep) return -1;
    size_t header_len = (size_t)(sep - buf);
    char *payload_start = sep + 2;
    size_t payload_avail = total_len - (header_len + 2);

    /* Do NOT reset n_fds / fds here. The Linux cmsg walk in ipc_recv
     * runs BEFORE parse_inplace and populates these fields; the parser
     * must not clobber them. ipc_recv's caller initializes them on
     * non-Linux paths where SCM_RIGHTS does not apply. */
    out->verb = NULL;
    out->reply_to = "";
    out->task_id = "";
    out->payload = NULL;
    out->payload_len = 0;

    size_t explicit_len = (size_t)-1;
    unsigned seen = 0;
    enum { SEEN_VERB = 1u, SEEN_LEN = 2u, SEEN_REPLY = 4u,
           SEEN_TASK = 8u };
    char *p = buf;
    char *end = buf + header_len;
    while (p < end) {
        char *eol = memchr(p, '\n', (size_t)(end - p));
        if (!eol) eol = end;
        *eol = '\0';
        size_t llen = (size_t)(eol - p);
        if (llen >= 5 && memcmp(p, "VERB ", 5) == 0) {
            if (seen & SEEN_VERB) return -1;
            const char *v = p + 5;
            while (*v == ' ') v++;
            if (!*v) return -1;
            out->verb = v;
            seen |= SEEN_VERB;
        } else if (llen >= 4 && memcmp(p, "LEN ", 4) == 0) {
            if (seen & SEEN_LEN) return -1;
            const char *v = p + 4;
            while (*v == ' ') v++;
            char *endp; errno = 0;
            long n = strtol(v, &endp, 10);
            if (errno != 0 || endp == v || *endp != '\0' || n < 0 ||
                (size_t)n > IPC_MSG_HARD_CAP) return -1;
            explicit_len = (size_t)n;
            seen |= SEEN_LEN;
        } else if (llen >= 9 && memcmp(p, "REPLY-TO ", 9) == 0) {
            if (seen & SEEN_REPLY) return -1;
            const char *v = p + 9;
            while (*v == ' ') v++;
            out->reply_to = v;
            seen |= SEEN_REPLY;
        } else if (llen >= 8 && memcmp(p, "TASK-ID ", 8) == 0) {
            if (seen & SEEN_TASK) return -1;
            const char *v = p + 8;
            while (*v == ' ') v++;
            out->task_id = v;
            seen |= SEEN_TASK;
        }
        /* Unknown headers ignored — forward-compat. */
        p = eol + 1;
    }
    if (!out->verb) return -1;

    if (explicit_len != (size_t)-1) {
        if (explicit_len > payload_avail) return -1;
        out->payload_len = explicit_len;
    } else {
        out->payload_len = payload_avail;
    }
    if (out->payload_len > 0) out->payload = payload_start;
    return 0;
}

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
int ipc_parse_for_fuzz(char *buf, size_t len, ipc_msg_t *out_msg)
{
    return parse_inplace(buf, len, out_msg);
}
#endif

#if defined(__APPLE__)
/* macOS STREAM: read header byte-by-byte until blank line, parse LEN, read
 * payload. Fills `buf` so the same in-place parser can run. */
static int recv_stream_into(int fd, char *buf, size_t bufcap, size_t *out_total)
{
    size_t pos = 0;
    size_t line_start = 0;
    int got_blank = 0;
    while (!got_blank) {
        if (pos + 1 >= bufcap) { errno = EOVERFLOW; return IPC_PROTO_VIOLATION; }
        char c;
        ssize_t r;
        do { r = read(fd, &c, 1); } while (r == -1 && errno == EINTR);
        if (r == 0) return (pos == 0) ? IPC_PEER_GONE : IPC_PROTO_VIOLATION;
        if (r < 0)  return IPC_ERR;
        buf[pos++] = c;
        if (c == '\n') {
            if (pos - line_start == 1) got_blank = 1;
            line_start = pos;
        }
    }
    /* Header complete. Parse LEN to know payload size. */
    size_t need = (size_t)-1;
    for (size_t i = 0; i + 4 <= pos; i++) {
        if (memcmp(buf + i, "LEN ", 4) == 0 &&
            (i == 0 || buf[i - 1] == '\n')) {
            char nb[32]; size_t k = 0;
            for (size_t j = i + 4; j < pos && buf[j] != '\n' && k < sizeof(nb) - 1; j++)
                nb[k++] = buf[j];
            nb[k] = '\0';
            char *endp; errno = 0;
            long n = strtol(nb, &endp, 10);
            if (errno != 0 || endp == nb || *endp != '\0' || n < 0 ||
                (size_t)n > IPC_MSG_HARD_CAP) return IPC_PROTO_VIOLATION;
            need = (size_t)n;
            break;
        }
    }
    if (need == (size_t)-1) return IPC_PROTO_VIOLATION;
    if (pos + need > bufcap) { errno = EOVERFLOW; return IPC_PROTO_VIOLATION; }
    while (need > 0) {
        ssize_t r;
        do { r = read(fd, buf + pos, need); } while (r == -1 && errno == EINTR);
        if (r == 0) return IPC_PROTO_VIOLATION;
        if (r < 0)  return IPC_ERR;
        pos += (size_t)r;
        need -= (size_t)r;
    }
    *out_total = pos;
    return IPC_OK;
}
#endif

int ipc_recv(int fd, void *buf, size_t bufcap, ipc_msg_t *out_msg)
{
    if (!buf || bufcap < IPC_MSG_DEFAULT_CAP) { errno = EINVAL; return IPC_ERR; }
    size_t total = 0;

#if defined(__linux__)
    /* Always allocate cmsg space and check MSG_CTRUNC — invariant. */
    char cmsg[CMSG_SPACE(sizeof(int) * IPC_MAX_FDS)];
    struct iovec iov = { .iov_base = buf, .iov_len = bufcap };
    struct msghdr mh;
    memset(&mh, 0, sizeof(mh));
    mh.msg_iov     = &iov;
    mh.msg_iovlen  = 1;
    mh.msg_control = cmsg;
    mh.msg_controllen = sizeof(cmsg);

    ssize_t n;
    do { n = recvmsg(fd, &mh, MSG_CMSG_CLOEXEC); } while (n < 0 && errno == EINTR);
    if (n == 0) return IPC_PEER_GONE;
    if (n < 0)  return IPC_ERR;
    if (mh.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
        /* MSG_TRUNC: oversized message. MSG_CTRUNC: cmsg overflow.
         * Both are protocol violations; caller must close the fd. */
        return IPC_PROTO_VIOLATION;
    }
    total = (size_t)n;

    /* Walk cmsgs and collect any fds (SCM_RIGHTS). */
    out_msg->n_fds = 0;
    for (struct cmsghdr *cm = CMSG_FIRSTHDR(&mh); cm; cm = CMSG_NXTHDR(&mh, cm)) {
        if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS) {
            size_t nfd = (cm->cmsg_len - CMSG_LEN(0)) / sizeof(int);
            if ((size_t)out_msg->n_fds + nfd > IPC_MAX_FDS) {
                int *got = (int *)CMSG_DATA(cm);
                for (size_t i = 0; i < nfd; i++) close(got[i]);
                return IPC_PROTO_VIOLATION;
            }
            memcpy(&out_msg->fds[out_msg->n_fds], CMSG_DATA(cm),
                   nfd * sizeof(int));
            out_msg->n_fds += (int)nfd;
        }
    }
#else
    int r = recv_stream_into(fd, (char *)buf, bufcap, &total);
    if (r != IPC_OK) return r;
    out_msg->n_fds = 0;
#endif

    /* Parse in place. Also re-reads peer creds defensively (cheap on Linux). */
    if (parse_inplace((char *)buf, total, out_msg) != 0)
        return IPC_PROTO_VIOLATION;
    (void)read_peer_creds(fd, &out_msg->peer);
    return IPC_OK;
}

/* ----------------------------------------------------------------
 * One-shot send (connect + send + close, with macOS peer-creds dance)
 * ---------------------------------------------------------------- */

int ipc_send_oneshot(const char *target,
                     const char *verb,
                     const char *reply_to,
                     const char *task_id,
                     const void *payload,
                     size_t      payload_len)
{
    if (payload_len > IPC_MSG_HARD_CAP) { errno = EMSGSIZE; return IPC_ERR; }
    int fd = ipc_connect(target);
    if (fd == IPC_PEER_GONE) return IPC_PEER_GONE;
    if (fd < 0)              return IPC_ERR;

    ipc_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.verb = verb;
    msg.reply_to = reply_to ? reply_to : "";
    msg.task_id  = task_id  ? task_id  : "";
    msg.payload  = payload;
    msg.payload_len = payload_len;

    int rc = ipc_send(fd, &msg);

#if defined(__APPLE__)
    /* macOS LOCAL_PEERPID is queried on the server side and requires that the
     * client has half-closed and the server has drained — otherwise pid may
     * read as 0. Harmless on Linux but we restrict to the macOS branch. 1 s
     * safety cap. */
    if (rc == IPC_OK) {
        (void)shutdown(fd, SHUT_WR);
        struct timeval tv = { 1, 0 };
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        char trash[64];
        ssize_t n;
        do { n = read(fd, trash, sizeof(trash)); } while (n > 0);
    }
#endif

    int saved = errno;
    close(fd);
    errno = saved;
    return rc;
}
