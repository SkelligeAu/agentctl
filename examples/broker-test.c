/*
 * broker-test — minimal runtime that exercises the v1 capability broker.
 *
 * Invoked by agentctl as: broker-test <name>. Reads BROKER_TARGET from the
 * environment, requests mailbox.send:<target> from agentd over fd 3,
 * receives the connected fd via SCM_RIGHTS, sends one "hello" message,
 * closes the fd, exits 0.
 *
 * No application-level retries, no buffering. The broker only transfers
 * authority; the message flows agent-to-agent directly.
 */

#include "common.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#if !defined(MSG_CMSG_CLOEXEC)
#  define MSG_CMSG_CLOEXEC 0
#endif

#define BROKER_FD 3

static int request_and_recv(const char *target, int *out_fd, char *out_token, size_t tcap)
{
    char req[256];
    int rn = snprintf(req, sizeof(req),
                      "VERB request\nCAP mailbox.send:%s\nREASON F4-test\n\n",
                      target);
    if (rn <= 0) return -1;
    if (send(BROKER_FD, req, (size_t)rn, 0) < 0) {
        perror("broker request send");
        return -1;
    }

    char buf[512];
    char cmsg[CMSG_SPACE(sizeof(int))];
    struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) - 1 };
    struct msghdr mh;
    memset(&mh, 0, sizeof(mh));
    mh.msg_iov     = &iov;
    mh.msg_iovlen  = 1;
    mh.msg_control = cmsg;
    mh.msg_controllen = sizeof(cmsg);

    ssize_t n;
    do { n = recvmsg(BROKER_FD, &mh, MSG_CMSG_CLOEXEC); }
    while (n < 0 && errno == EINTR);
    if (n <= 0) {
        perror("broker recvmsg");
        return -1;
    }
    buf[n] = '\0';

    /* Look up the fd in cmsg, and the token in the header text. */
    int issued = -1;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&mh); c; c = CMSG_NXTHDR(&mh, c)) {
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS) {
            memcpy(&issued, CMSG_DATA(c), sizeof(int));
            break;
        }
    }
    out_token[0] = '\0';
    char *tok = strstr(buf, "TOKEN ");
    if (tok) {
        tok += 6;
        size_t k = 0;
        while (*tok && *tok != '\n' && k < tcap - 1) out_token[k++] = *tok++;
        out_token[k] = '\0';
    }
    if (issued < 0) {
        fprintf(stderr, "broker denied or no fd in response: %s\n", buf);
        return -1;
    }
    *out_fd = issued;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "broker-test: missing <name>\n"); return 2; }
    const char *self = argv[1];
    write_status(self, "idle");
    /* Target is read from `broker-target` in the cwd (agentd chdirs to
     * /tmp/agents/<name>/ before exec). Falls back to BROKER_TARGET env. */
    char target_buf[64] = {0};
    const char *target = NULL;
    int tfd = open("broker-target", O_RDONLY | O_CLOEXEC);
    if (tfd >= 0) {
        ssize_t r = read(tfd, target_buf, sizeof(target_buf) - 1);
        close(tfd);
        if (r > 0) {
            target_buf[r] = '\0';
            /* trim trailing whitespace */
            while (r > 0 && (target_buf[r - 1] == '\n' || target_buf[r - 1] == ' '))
                target_buf[--r] = '\0';
            if (target_buf[0]) target = target_buf;
        }
    }
    if (!target) target = getenv("BROKER_TARGET");
    if (!target || !*target) {
        fprintf(stderr,
                "broker-test: target required (broker-target file or BROKER_TARGET env)\n");
        return 2;
    }

    int issued_fd = -1;
    char token[32] = {0};
    if (request_and_recv(target, &issued_fd, token, sizeof(token)) != 0) {
        fprintf(stderr, "broker-test: cap acquisition failed\n");
        return 1;
    }
    fprintf(stderr, "broker-test: got cap fd=%d token=%s\n", issued_fd, token);

    /* Use the canonical framing helper: Linux uses one SEQPACKET record;
     * Darwin's development transport adds the required LEN header. */
    char payload[128];
    int pn = snprintf(payload, sizeof(payload), "hi from %s\n", self);
    if (pn <= 0 || (size_t)pn >= sizeof(payload)) {
        close(issued_fd);
        return 1;
    }
    if (send_framed_message_ex(issued_fd, "hello", self, "broker-f4",
                               payload, (size_t)pn) < 0) {
        perror("send on issued fd");
        close(issued_fd);
        return 1;
    }

    /* Short-lived cap per the locked invariant: close immediately. */
    close(issued_fd);
    close(BROKER_FD);
    fprintf(stderr, "broker-test: done\n");
    return 0;
}
