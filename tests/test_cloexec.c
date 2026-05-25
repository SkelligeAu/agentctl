/*
 * Unit test: fds received via SCM_RIGHTS have FD_CLOEXEC set when the
 * receiver passes MSG_CMSG_CLOEXEC to recvmsg. agentctl's ipc_recv
 * passes MSG_CMSG_CLOEXEC unconditionally.
 *
 * Strategy: socketpair; parent sends a pipe fd via SCM_RIGHTS; child
 * receives via ipc_recv; verifies F_GETFD shows FD_CLOEXEC.
 *
 * Linux-only (relies on MSG_CMSG_CLOEXEC).
 */

#include "ipc.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#if !defined(__linux__)
int main(void) { fprintf(stderr, "skip: linux-only\n"); return 77; }
#else

int main(void)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) != 0) {
        perror("socketpair"); return 1;
    }
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }
    if (pid == 0) {
        close(sv[0]);
        char *buf = malloc(IPC_BUF_CAP);
        if (!buf) _exit(1);
        ipc_msg_t msg;
        int r = ipc_recv(sv[1], buf, IPC_BUF_CAP, &msg);
        free(buf);
        if (r != IPC_OK) {
            fprintf(stderr, "child: ipc_recv = %d\n", r); _exit(2);
        }
        if (msg.n_fds < 1) {
            fprintf(stderr, "child: no fds received\n"); _exit(3);
        }
        int rx = msg.fds[0];
        int flags = fcntl(rx, F_GETFD);
        if (flags < 0) {
            fprintf(stderr, "child: fcntl: %s\n", strerror(errno)); _exit(4);
        }
        if (!(flags & FD_CLOEXEC)) {
            fprintf(stderr, "child: fd %d does NOT have FD_CLOEXEC (flags=0x%x)\n",
                    rx, flags);
            _exit(5);
        }
        /* Close received fds and exit clean. */
        for (int i = 0; i < msg.n_fds; i++) close(msg.fds[i]);
        close(sv[1]);
        _exit(0);
    }
    /* parent: open a pipe and send one end via SCM_RIGHTS. */
    close(sv[1]);
    int pipefd[2];
    if (pipe(pipefd) != 0) { perror("pipe"); kill(pid, SIGKILL); return 1; }
    const char *hdr = "VERB ping\n\n";
    struct iovec iov = { .iov_base = (void *)hdr, .iov_len = strlen(hdr) };
    char cmsg_buf[CMSG_SPACE(sizeof(int))];
    struct msghdr mh;
    memset(&mh, 0, sizeof(mh));
    mh.msg_iov        = &iov;
    mh.msg_iovlen     = 1;
    mh.msg_control    = cmsg_buf;
    mh.msg_controllen = sizeof(cmsg_buf);
    struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type  = SCM_RIGHTS;
    c->cmsg_len   = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &pipefd[0], sizeof(int));
    ssize_t s = sendmsg(sv[0], &mh, 0);
    int saved = errno;
    close(pipefd[0]); close(pipefd[1]); close(sv[0]);
    if (s < 0) {
        fprintf(stderr, "parent: sendmsg: %s\n", strerror(saved));
        kill(pid, SIGKILL); waitpid(pid, NULL, 0); return 1;
    }
    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        fprintf(stderr, "PASS: received fd has FD_CLOEXEC set\n");
        return 0;
    }
    fprintf(stderr, "FAIL: child exit %d\n",
            WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 1;
}

#endif /* __linux__ */
