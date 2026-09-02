#include "common.h"
#include "ipc.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define WORKERS 8

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    const char *self = argv[1];
    char target_buf[MAX_NAME] = {0};
    int tfd = open("broker-target", O_RDONLY | O_CLOEXEC);
    if (tfd < 0) return 2;
    ssize_t nr = read(tfd, target_buf, sizeof(target_buf) - 1);
    close(tfd);
    if (nr <= 0) return 2;
    target_buf[strcspn(target_buf, "\r\n ")] = '\0';
    const char *target = target_buf;
    write_status(self, "idle");

    for (int i = 0; i < WORKERS; i++) {
        pid_t pid = fork();
        if (pid < 0) return 1;
        if (pid == 0) {
            int fd = ipc_connect(target);
            if (fd < 0) _exit(10);
            close(fd);
            _exit(0);
        }
    }
    int failed = 0;
    for (int i = 0; i < WORKERS; i++) {
        int status = 0;
        if (wait(&status) < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
            failed++;
    }
    return failed ? 1 : 0;
}
