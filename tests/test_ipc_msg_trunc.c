/*
 * Unit test: ipc_recv returns IPC_PROTO_VIOLATION when MSG_TRUNC fires.
 *
 * Strategy: socketpair(AF_UNIX, SOCK_SEQPACKET); parent sends a frame
 * larger than the child's recv buffer; child calls ipc_recv with a small
 * buffer; expect IPC_PROTO_VIOLATION.
 *
 * Linux-only (SOCK_SEQPACKET). exits 0 on pass, non-zero on fail.
 */

#include "ipc.h"

#include <errno.h>
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
        perror("socketpair");
        return 1;
    }
    /* Bump both buffers so the kernel queues the oversized frame for us
     * to recv with a deliberately-small recv iov. */
    int big = 4 << 20;
    setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &big, sizeof(big));
    setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &big, sizeof(big));

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }
    if (pid == 0) {
        /* child: recv with a SMALL ipc buffer; should return PROTO_VIOLATION */
        close(sv[0]);
        char *buf = malloc(IPC_MSG_DEFAULT_CAP);
        if (!buf) _exit(1);
        ipc_msg_t msg;
        int r = ipc_recv(sv[1], buf, IPC_MSG_DEFAULT_CAP, &msg);
        free(buf);
        close(sv[1]);
        if (r == IPC_PROTO_VIOLATION) _exit(0);
        fprintf(stderr, "child: ipc_recv returned %d (expected %d)\n",
                r, IPC_PROTO_VIOLATION);
        _exit(2);
    }
    /* parent: send a frame larger than the child's recv buffer. */
    close(sv[1]);
    size_t payload = IPC_MSG_DEFAULT_CAP + 4096;
    size_t cap = payload + 256;
    char *frame = malloc(cap);
    if (!frame) { kill(pid, SIGKILL); return 1; }
    int hlen = snprintf(frame, 256, "VERB review\nLEN %zu\n\n", payload);
    memset(frame + hlen, 'x', payload);
    ssize_t s = send(sv[0], frame, (size_t)hlen + payload, 0);
    if (s < 0) {
        fprintf(stderr, "parent: send: %s (kernel refused; skip)\n",
                strerror(errno));
        free(frame);
        close(sv[0]);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return 77;
    }
    free(frame);
    close(sv[0]);
    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        fprintf(stderr, "PASS: ipc_recv returned IPC_PROTO_VIOLATION on MSG_TRUNC\n");
        return 0;
    }
    fprintf(stderr, "FAIL: child exit %d\n",
            WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 1;
}

#endif /* __linux__ */
