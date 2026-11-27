#include "common.h"
#include "ipc.h"
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#if !defined(__linux__)
int main(void) { return 77; }
#else
static int descriptor_count(void)
{
    DIR *d = opendir("/proc/self/fd");
    if (!d) return -1;
    int count = 0;
    struct dirent *e;
    while ((e = readdir(d))) if (e->d_name[0] != '.') count++;
    closedir(d);
    return count;
}

int main(void)
{
    /* Valid and malformed frames; ancillary and payload truncation; empty
     * datagrams with rights. Check both the low-level and legacy APIs. */
    int before = descriptor_count();
    if (before < 0) return 1;
    for (int wrapper = 0; wrapper < 2; wrapper++) {
        for (int mode = 0; mode < 5; mode++) {
            for (int repeat = 0; repeat < 16; repeat++) {
                int sv[2];
                if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) != 0) return 1;
                int nfds = mode == 2 ? IPC_MAX_FDS + 4 : 1;
                int descriptors[IPC_MAX_FDS + 4];
                for (int i = 0; i < nfds; i++) {
                    descriptors[i] = open("/dev/null", O_RDONLY);
                    if (descriptors[i] < 0) return 1;
                }
                char *data = calloc(1, IPC_BUF_CAP + 1024);
                if (!data) return 1;
                strcpy(data, mode == 1 ? "malformed\n\n" : "VERB ping\n\n");
                size_t length = mode == 4 ? 0 : strlen(data);
                if (mode == 3) length = IPC_MSG_DEFAULT_CAP + 1024;
                struct iovec io = { data, length };
                char control[CMSG_SPACE(sizeof(descriptors))];
                memset(control, 0, sizeof(control));
                struct msghdr mh = {0};
                mh.msg_iov = &io; mh.msg_iovlen = 1;
                mh.msg_control = control;
                mh.msg_controllen = CMSG_SPACE(sizeof(int) * (size_t)nfds);
                struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
                c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS;
                c->cmsg_len = CMSG_LEN(sizeof(int) * (size_t)nfds);
                memcpy(CMSG_DATA(c), descriptors, sizeof(int) * (size_t)nfds);
                /* The oversized case needs a larger sender buffer. */
                int size = 4 * IPC_BUF_CAP;
                setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
                if (sendmsg(sv[0], &mh, 0) < 0) { perror("sendmsg"); return 1; }
                for (int i = 0; i < nfds; i++) close(descriptors[i]);
                int rc;
                if (wrapper) {
                    agent_msg_hdr header;
                    rc = read_message(sv[1], &header, data);
                    /* This wrapper has a large fixed receive buffer, so
                     * mode 3 is a valid payload rather than truncation. */
                    if ((mode == 0 || mode == 3) != (rc == 0)) return 1;
                } else {
                    ipc_msg_t msg;
                    rc = ipc_recv(sv[1], data, IPC_MSG_DEFAULT_CAP, &msg);
                    if (mode == 0) {
                        if (rc != IPC_OK || msg.n_fds != 1) return 1;
                        close(msg.fds[0]);
                    } else if (rc == IPC_OK || msg.n_fds != 0) return 1;
                }
                free(data); close(sv[0]); close(sv[1]);
                if (descriptor_count() != before) {
                    fprintf(stderr, "FD leak: wrapper=%d mode=%d\n", wrapper, mode);
                    return 1;
                }
            }
        }
    }
    /* The private delivery channel has the same cleanup obligation. A
     * one-fd cmsg buffer can hold two fds due to alignment padding. */
    for (int mode = 0; mode < 4; mode++) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) return 1;
        if (sv[1] != INBOX_FD_SLOT) {
            fprintf(stderr, "test requires the receiver in fd 4\n"); return 1;
        }
        int fd = open("/dev/null", O_RDONLY);
        if (fd < 0) return 1;
        int fds[8]; for (int i = 0; i < 8; i++) fds[i] = fd;
        int nfds = mode == 0 ? 2 : mode == 1 ? 8 : 1;
        char meta[512]; memset(meta, 'x', sizeof(meta));
        struct iovec io = { meta, mode == 2 ? sizeof(meta) : mode == 3 ? 0 : 16 };
        char control[CMSG_SPACE(sizeof(fds))]; memset(control, 0, sizeof(control));
        struct msghdr mh = {0};
        mh.msg_iov = &io; mh.msg_iovlen = 1; mh.msg_control = control;
        mh.msg_controllen = CMSG_SPACE(sizeof(int) * (size_t)nfds);
        struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
        c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = CMSG_LEN(sizeof(int) * (size_t)nfds);
        memcpy(CMSG_DATA(c), fds, sizeof(int) * (size_t)nfds);
        if (sendmsg(sv[0], &mh, 0) < 0) return 1;
        close(fd);
        if (ipc_accept(sv[1], NULL) != -1) return 1;
        close(sv[0]); close(sv[1]);
        if (descriptor_count() != before) {
            fprintf(stderr, "FD leak in private inbox: mode=%d\n", mode); return 1;
        }
    }
    puts("PASS: received descriptors have one owner on every receive path");
    return 0;
}
#endif
