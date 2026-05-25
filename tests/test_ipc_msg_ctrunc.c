/*
 * Unit test: ipc_recv returns IPC_PROTO_VIOLATION when MSG_CTRUNC fires.
 *
 * Strategy: socketpair(AF_UNIX, SOCK_SEQPACKET); parent sends a small
 * frame with IPC_MAX_FDS+1 fds in SCM_RIGHTS. ipc_recv allocates
 * CMSG_SPACE(sizeof(int) * IPC_MAX_FDS); the extra fd triggers
 * MSG_CTRUNC; ipc_recv returns IPC_PROTO_VIOLATION.
 *
 * Linux-only (SOCK_SEQPACKET + SCM_RIGHTS).
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
        /* On MSG_CTRUNC, the kernel closes the dropped fds itself;
         * fds that fit (IPC_MAX_FDS of them) may be present in msg->fds
         * — close them defensively if returned. */
        if (r == IPC_OK) {
            for (int i = 0; i < msg.n_fds; i++) close(msg.fds[i]);
        }
        free(buf);
        close(sv[1]);
        if (r == IPC_PROTO_VIOLATION) _exit(0);
        fprintf(stderr, "child: ipc_recv returned %d (expected %d)\n",
                r, IPC_PROTO_VIOLATION);
        _exit(2);
    }
    /* parent: send a valid small frame with IPC_MAX_FDS+1 fds. */
    close(sv[1]);
    int n_send = IPC_MAX_FDS + 4;
    int *fds = calloc((size_t)n_send, sizeof(int));
    for (int i = 0; i < n_send; i++) {
        fds[i] = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (fds[i] < 0) {
            fprintf(stderr, "open /dev/null: %s\n", strerror(errno));
            kill(pid, SIGKILL); waitpid(pid, NULL, 0); return 1;
        }
    }
    const char *hdr = "VERB ping\n\n";
    struct iovec iov = { .iov_base = (void *)hdr, .iov_len = strlen(hdr) };
    size_t cmsg_sz = CMSG_SPACE(sizeof(int) * (size_t)n_send);
    char *cmsg_buf = calloc(1, cmsg_sz);
    struct msghdr mh;
    memset(&mh, 0, sizeof(mh));
    mh.msg_iov        = &iov;
    mh.msg_iovlen     = 1;
    mh.msg_control    = cmsg_buf;
    mh.msg_controllen = cmsg_sz;
    struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type  = SCM_RIGHTS;
    c->cmsg_len   = CMSG_LEN(sizeof(int) * (size_t)n_send);
    memcpy(CMSG_DATA(c), fds, sizeof(int) * (size_t)n_send);
    ssize_t s = sendmsg(sv[0], &mh, 0);
    if (s < 0) {
        fprintf(stderr, "parent: sendmsg: %s\n", strerror(errno));
        for (int i = 0; i < n_send; i++) close(fds[i]);
        free(fds); free(cmsg_buf);
        kill(pid, SIGKILL); waitpid(pid, NULL, 0); return 1;
    }
    for (int i = 0; i < n_send; i++) close(fds[i]);
    free(fds); free(cmsg_buf);
    close(sv[0]);
    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        fprintf(stderr, "PASS: ipc_recv returned IPC_PROTO_VIOLATION on MSG_CTRUNC\n");
        return 0;
    }
    fprintf(stderr, "FAIL: child exit %d\n",
            WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 1;
}

#endif /* __linux__ */
