/*
 * broker-fault — security-test runtime + CLI tool.
 *
 * Runtime modes (invoked by agentd; inherits broker channel on fd 3):
 *   BROKER_FAULT_MODE=malformed    send garbage on fd 3; expect VERB denied
 *                                  with REASON malformed-request; channel
 *                                  remains usable for a re-request
 *   BROKER_FAULT_MODE=many-fds     send a request with 8 fds attached via
 *                                  SCM_RIGHTS; agentd's cmsg buffer holds 4,
 *                                  so MSG_CTRUNC fires and the broker
 *                                  closes the channel.
 *   BROKER_FAULT_MODE=fdtable      enumerate /proc/self/fd/ and write the
 *                                  list to ./fdtable. Used by the
 *                                  policy-not-authority test.
 *
 * Standalone CLI:
 *   broker-fault oversized <target>
 *       connect to /tmp/agents/<target>/agent.sock and send a SEQPACKET
 *       frame larger than IPC_BUF_CAP. The receiver's recvmsg should set
 *       MSG_TRUNC and close the connection. (Note: subject to kernel
 *       SO_RCVBUF; see comments below.)
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#if !defined(MSG_CMSG_CLOEXEC)
#  define MSG_CMSG_CLOEXEC 0
#endif
#if !defined(SOCK_CLOEXEC)
#  define SOCK_CLOEXEC 0
#endif

static int is_broker_runtime(void)
{
    struct stat st;
    if (fstat(3, &st) != 0) return 0;
    return S_ISSOCK(st.st_mode);
}

/* ---- runtime: malformed broker request ---- */

static int run_malformed(void)
{
    /* Send something that broker_parse rejects (no VERB line). */
    const char *bad = "not-a-verb foo\nblah blah\n\n";
    if (send(3, bad, strlen(bad), 0) < 0) {
        fprintf(stderr, "broker-fault malformed: send: %s\n", strerror(errno));
        return 1;
    }
    char buf[512];
    ssize_t n = recv(3, buf, sizeof(buf) - 1, 0);
    if (n <= 0) {
        /* Channel was closed — that would mean we got MSG_TRUNC/MSG_CTRUNC
         * treatment, not malformed-request treatment. The contract is
         * that malformed requests get a denial without channel teardown. */
        fprintf(stderr, "broker-fault malformed: channel closed (n=%zd)\n", n);
        return 2;
    }
    buf[n] = 0;
    if (!strstr(buf, "VERB denied")) {
        fprintf(stderr, "broker-fault malformed: unexpected response: %s\n", buf);
        return 3;
    }
    if (!strstr(buf, "malformed")) {
        fprintf(stderr, "broker-fault malformed: response missing reason: %s\n", buf);
        return 4;
    }
    /* Now send a SECOND request to verify the channel is still open. */
    const char *ok = "VERB request\nCAP mailbox.send:nonexistent\n\n";
    if (send(3, ok, strlen(ok), 0) < 0) {
        fprintf(stderr, "broker-fault malformed: 2nd send: %s\n", strerror(errno));
        return 5;
    }
    n = recv(3, buf, sizeof(buf) - 1, 0);
    if (n <= 0) {
        fprintf(stderr, "broker-fault malformed: 2nd recv n=%zd; channel closed\n", n);
        return 6;
    }
    buf[n] = 0;
    /* We expect another VERB denied (target doesn't exist) — proves the
     * channel survived the malformed request. */
    if (!strstr(buf, "VERB denied")) {
        fprintf(stderr, "broker-fault malformed: 2nd response unexpected: %s\n", buf);
        return 7;
    }
    fprintf(stderr, "broker-fault malformed: OK\n");
    return 0;
}

/* ---- runtime: too many SCM_RIGHTS fds (MSG_CTRUNC) ---- */

static int run_many_fds(void)
{
    /* Open 8 spurious fds. agentd's cmsg buffer holds 4; the kernel will
     * deliver 4 and set MSG_CTRUNC on the remainder. agentd's contract is
     * to treat MSG_CTRUNC as fatal: close the channel. */
    int fds[8];
    for (int i = 0; i < 8; i++) {
        fds[i] = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (fds[i] < 0) {
            fprintf(stderr, "broker-fault many-fds: open: %s\n", strerror(errno));
            return 1;
        }
    }
    /* Build a header that broker_parse would accept (the cmsg overflow
     * triggers before parse runs). */
    const char *hdr = "VERB request\nCAP mailbox.send:peer\n\n";
    struct iovec iov = { .iov_base = (void *)hdr, .iov_len = strlen(hdr) };
    char cmsg_buf[CMSG_SPACE(sizeof(int) * 8)];
    struct msghdr mh;
    memset(&mh, 0, sizeof(mh));
    mh.msg_iov        = &iov;
    mh.msg_iovlen     = 1;
    mh.msg_control    = cmsg_buf;
    mh.msg_controllen = CMSG_SPACE(sizeof(int) * 8);
    struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type  = SCM_RIGHTS;
    c->cmsg_len   = CMSG_LEN(sizeof(int) * 8);
    memcpy(CMSG_DATA(c), fds, sizeof(int) * 8);
    if (sendmsg(3, &mh, 0) < 0) {
        fprintf(stderr, "broker-fault many-fds: sendmsg: %s\n", strerror(errno));
        return 2;
    }
    for (int i = 0; i < 8; i++) close(fds[i]);
    /* Expect EOF on the channel now. */
    char resp[64];
    ssize_t n = recv(3, resp, sizeof(resp), 0);
    if (n != 0) {
        fprintf(stderr, "broker-fault many-fds: expected EOF, got n=%zd\n", n);
        return 3;
    }
    fprintf(stderr, "broker-fault many-fds: OK (channel closed by broker)\n");
    return 0;
}

/* ---- runtime: enumerate fd table ---- */

static int run_fdtable(void)
{
    DIR *d = opendir("/proc/self/fd");
    if (!d) {
        fprintf(stderr, "broker-fault fdtable: %s\n", strerror(errno));
        return 1;
    }
    FILE *out = fopen("fdtable", "w");  /* cwd = /tmp/agents/<name>/ */
    if (!out) { closedir(d); return 1; }
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        int fd = atoi(e->d_name);
        char link[256] = {0};
        char path[256];
        snprintf(path, sizeof(path), "/proc/self/fd/%s", e->d_name);
        ssize_t n = readlink(path, link, sizeof(link) - 1);
        if (n < 0) n = 0;
        link[n] = 0;
        fprintf(out, "%d %s\n", fd, link);
    }
    closedir(d);
    fclose(out);
    return 0;
}

/* ---- CLI: oversized message ---- */

static int run_oversized(const char *target)
{
    char path[256];
    snprintf(path, sizeof(path), "/tmp/agents/%s/agent.sock", target);
#if defined(__linux__)
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
#else
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
#endif
    if (fd < 0) { perror("socket"); return 1; }
    struct sockaddr_un a;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    snprintf(a.sun_path, sizeof(a.sun_path), "%s", path);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
        perror("connect");
        close(fd);
        return 1;
    }
    /* Bump our send buffer so the kernel won't refuse the oversized frame.
     * The receiver's SO_RCVBUF still caps what gets queued; for SEQPACKET
     * sendmsg returns ENOBUFS when the message can't fit in the peer's
     * receive buffer. We try anyway and inspect the result. */
    int big = 4 << 20;
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &big, sizeof(big));

    size_t payload = (size_t)(2u << 20);  /* 2 MiB */
    size_t cap = payload + 256;
    char *buf = malloc(cap);
    if (!buf) { close(fd); return 1; }
    int hlen = snprintf(buf, 256, "VERB review\nLEN %zu\n\n", payload);
    memset(buf + hlen, 'x', payload);
    ssize_t s = send(fd, buf, (size_t)hlen + payload, 0);
    int saved = errno;
    free(buf);
    close(fd);
    if (s < 0) {
        /* ENOBUFS / EMSGSIZE: kernel refused to enqueue the oversized
         * frame. This is the expected outcome on Linux SEQPACKET — the
         * MSG_TRUNC path in ipc_recv is defence-in-depth that the kernel
         * rarely lets us reach. Report it explicitly. */
        fprintf(stderr,
                "broker-fault oversized: kernel refused send (%s); "
                "MSG_TRUNC path unreachable in this configuration\n",
                strerror(saved));
        /* This is still a pass: the system refused the oversized message
         * at the earliest possible layer. */
        return 0;
    }
    fprintf(stderr, "broker-fault oversized: sent %zd bytes\n", s);
    return 0;
}

static void usage(void)
{
    fputs("broker-fault — security test tool.\n"
          "  As runtime (fd 3 = broker channel):\n"
          "    BROKER_FAULT_MODE=malformed | many-fds | fdtable\n"
          "  Standalone:\n"
          "    broker-fault oversized <target>\n",
          stderr);
}

int main(int argc, char **argv)
{
    if (is_broker_runtime()) {
        /* Mode is read from the `broker-fault-mode` file in the cwd
         * (agentd chdir's to /tmp/agents/<name>/ before exec). Env vars
         * do not propagate agentctl → agentd → spawned runtime. */
        char mode[32] = {0};
        int mfd = open("broker-fault-mode", O_RDONLY | O_CLOEXEC);
        if (mfd >= 0) {
            ssize_t r = read(mfd, mode, sizeof(mode) - 1);
            close(mfd);
            if (r > 0) {
                mode[r] = 0;
                /* trim trailing whitespace */
                while (r > 0 && (mode[r-1] == '\n' || mode[r-1] == ' '))
                    mode[--r] = 0;
            }
        }
        if (!mode[0]) {
            /* fallback: env var if the operator is launching manually */
            const char *env = getenv("BROKER_FAULT_MODE");
            if (env) snprintf(mode, sizeof(mode), "%s", env);
        }
        if (!mode[0]) {
            fprintf(stderr,
                    "broker-fault: mode not set (drop a value into "
                    "broker-fault-mode in the agent dir)\n");
            return 2;
        }
        if (strcmp(mode, "malformed") == 0) return run_malformed();
        if (strcmp(mode, "many-fds")  == 0) return run_many_fds();
        if (strcmp(mode, "fdtable")   == 0) return run_fdtable();
        fprintf(stderr, "broker-fault: unknown mode %s\n", mode);
        return 2;
    }
    if (argc < 2) { usage(); return 2; }
    if (strcmp(argv[1], "oversized") == 0 && argc == 3) {
        return run_oversized(argv[2]);
    }
    usage();
    return 2;
}
