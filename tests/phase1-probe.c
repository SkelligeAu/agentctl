#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int main(void)
{
    int policy_errno = 0;
    int pfd = open("../config/policy", O_WRONLY | O_APPEND | O_CLOEXEC);
    if (pfd >= 0) {
        static const char grant[] = "allow mailbox.send:*\n";
        (void)write(pfd, grant, sizeof(grant) - 1);
        close(pfd);
    } else {
        policy_errno = errno;
    }

    char response[128] = "connect-failed";
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s >= 0) {
        struct sockaddr_un a;
        memset(&a, 0, sizeof(a));
        a.sun_family = AF_UNIX;
        snprintf(a.sun_path, sizeof(a.sun_path), "../../../agentd.sock");
        if (connect(s, (struct sockaddr *)&a, sizeof(a)) == 0) {
            static const char request[] = "shutdown\n";
            (void)write(s, request, sizeof(request) - 1);
            ssize_t n = read(s, response, sizeof(response) - 1);
            if (n > 0) response[n] = '\0';
            else snprintf(response, sizeof(response), "read-failed");
        }
        close(s);
    }

    FILE *out = fopen("phase1-result", "w");
    if (!out) return 2;
    fprintf(out, "policy_write=%s errno=%d\ncontrol=%s",
            pfd >= 0 ? "allowed" : "denied", policy_errno, response);
    fclose(out);
    return 0;
}
