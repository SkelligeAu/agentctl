#include "common.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/mman.h>
#endif

static void marker(const char *name, const char *value)
{
    FILE *f = fopen(name, "w");
    if (!f) exit(2);
    fprintf(f, "%s\n", value);
    fclose(f);
}

static int acquire(void)
{
    const char *r = "VERB request\nCAP mailbox.send:sink\n\n";
    if (send(3, r, strlen(r), 0) < 0) return -1;
    char b[512], control[CMSG_SPACE(sizeof(int))];
    struct iovec io = { b, sizeof(b) - 1 };
    struct msghdr m = {0};
    m.msg_iov = &io; m.msg_iovlen = 1;
    m.msg_control = control; m.msg_controllen = sizeof(control);
    ssize_t n = recvmsg(3, &m, 0);
    if (n <= 0) return -1;
    b[n] = 0;
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    int fd = -1;
    if (c && c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS)
        memcpy(&fd, CMSG_DATA(c), sizeof(fd));
    if (fd < 0 && strstr(b, "target-busy")) marker("busy", "yes");
    return fd;
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    char mode[32] = "";
    FILE *f = fopen("mode", "r");
    if (f) { (void)fscanf(f, "%31s", mode); fclose(f); }
    write_status(argv[1], "idle");
    if (!strcmp(mode, "service-clean")) {
        f = fopen("completions", "a");
        if (!f) return 3;
        fprintf(f, "%ld\n", (long)getpid());
        fclose(f);
        return 0;
    } else if (!strcmp(mode, "service-memfd")) {
#ifdef __linux__
        int fd = memfd_create("sealed-input", MFD_CLOEXEC | MFD_ALLOW_SEALING);
        if (fd < 0 || write(fd, "test", 4) != 4 ||
            fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) != 0)
            return 3;
        close(fd);
        marker("memfd-ready", "sealed");
#else
        return 3;
#endif
    } else if (!strcmp(mode, "security-file-grant")) {
        char path[MAX_PATHBUF];
        int fd = open("/dev/null", O_WRONLY);
        if (fd < 0 || write(fd, "x", 1) != 1) return 4;
        close(fd);
        snprintf(path, sizeof(path), "%s/allowed-file", agentctl_root());
        fd = open(path, O_WRONLY | O_TRUNC);
        if (fd < 0 || write(fd, "ok", 2) != 2) return 4;
        close(fd);
        snprintf(path, sizeof(path), "%s/denied-file", agentctl_root());
        fd = open(path, O_WRONLY | O_TRUNC);
        if (fd >= 0) { close(fd); return 4; }
        marker("security-ready", "yes");
    } else if (!strcmp(mode, "security-truncate")) {
        char path[MAX_PATHBUF], result[64];
        snprintf(path, sizeof(path), "%s/agentd.token", agentctl_root());
        int rc = truncate(path, 0);
        snprintf(result, sizeof(result), "%d %d", rc, rc < 0 ? errno : 0);
        marker("truncate-result", result);
        /* The same writable rights must still work for ordinary data. */
        marker("truncate-data", "test");
        if (truncate("truncate-data", 0) != 0) return 3;
        marker("security-ready", "yes");
    } else if (!strncmp(mode, "security-forge", 14)) {
        char path[MAX_PATHBUF], target[MAX_PATHBUF], record[2 * MAX_PATHBUF];
        snprintf(target, sizeof(target), "%s/outside/victim", agentctl_root());
        if (symlink(target, "cgroup.kill") != 0) return 3;
        snprintf(path, sizeof(path), "%s/agents/%s/data", agentctl_root(), argv[1]);
        snprintf(record, sizeof(record), "cgroup_status=active\ncgroup_path=%s\n", path);
        char state[MAX_PATHBUF];
        if (agent_path(state, sizeof(state), argv[1], "enforcement.applied") != 0 ||
            atomic_write_file(state, record, strlen(record), 0600) != 0) return 3;
        if (!strcmp(mode, "security-forge-stop")) signal(SIGTERM, SIG_IGN);
        marker("security-ready", "yes");
        if (!strcmp(mode, "security-forge-exit")) return 0;
    } else if (!strcmp(mode, "security-minimal")) {
        marker("security-ready", "executed");
    } else if (!strcmp(mode, "descendants")) {
        int ready[2];
        if (pipe(ready) != 0) return 2;
        pid_t child = fork();
        if (child < 0) return 2;
        if (!child) {
            close(ready[0]);
            signal(SIGTERM, SIG_IGN);
            (void)!write(ready[1], "x", 1);
            close(ready[1]);
            for (;;) pause();
        }
        close(ready[1]);
        char byte;
        (void)!read(ready[0], &byte, 1);
        close(ready[0]);
        char pid[32]; snprintf(pid, sizeof(pid), "%ld", (long)child);
        marker("child.pid", pid);
    } else if (!strcmp(mode, "leak")) {
        int fds[8];
        for (int i = 0; i < 8; i++) fds[i] = open("mode", O_RDONLY);
        char *r = "VERB request\nCAP mailbox.send:sink\n\n";
        struct iovec io = { r, strlen(r) };
        char control[CMSG_SPACE(sizeof(fds))];
        memset(control, 0, sizeof(control));
        struct msghdr m = {0};
        m.msg_iov = &io; m.msg_iovlen = 1;
        m.msg_control = control; m.msg_controllen = sizeof(control);
        struct cmsghdr *c = CMSG_FIRSTHDR(&m);
        c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = CMSG_LEN(sizeof(fds));
        memcpy(CMSG_DATA(c), fds, sizeof(fds));
        if (sendmsg(3, &m, 0) < 0) return 2;
        for (int i = 0; i < 8; i++) close(fds[i]);
        char b[32];
        if (recv(3, b, sizeof(b), 0) != 0) return 3;
        return 0;
    } else if (!strcmp(mode, "flood")) {
        for (int i = 0; i < 10000; i++) {
            int fd = acquire();
            if (fd < 0) break;
            close(fd);
        }
    } else if (!strcmp(mode, "unread-replies")) {
        const char *r = "VERB request\nCAP mailbox.send:absent\n\n";
        time_t deadline = time(NULL) + 10;
        while (time(NULL) < deadline) {
            if (send(3, r, strlen(r), MSG_DONTWAIT | MSG_NOSIGNAL) < 0) {
                if (errno == EPIPE || errno == ECONNRESET) {
                    marker("disconnected", "yes");
                    break;
                }
                if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                    return 3;
                struct timespec delay = { 0, 1000000 };
                nanosleep(&delay, NULL);
            }
        }
    }
    for (;;) pause();
}
