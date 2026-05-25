/* agentfs-register <name>
 *
 * Write <name> to /mnt/agentfs/register, then sleep until signalled so the
 * owning task_struct stays alive and the agent's status remains "running".
 *
 * Ctrl-C / SIGTERM → process exits → kernel task_work fires → agent dead.
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0;
static void on_signal(int s) { (void)s; g_stop = 1; }

int main(int argc, char **argv)
{
	const char *mount = "/mnt/agentfs";
	const char *name;
	char path[256];
	int fd;
	ssize_t w;

	if (argc < 2) {
		fprintf(stderr, "usage: %s <name> [mount=/mnt/agentfs]\n", argv[0]);
		return 2;
	}
	name = argv[1];
	if (argc >= 3) mount = argv[2];

	if (snprintf(path, sizeof(path), "%s/register", mount) >= (int)sizeof(path)) {
		fprintf(stderr, "mount path too long\n");
		return 1;
	}
	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "open %s: %s\n", path, strerror(errno));
		return 1;
	}
	w = write(fd, name, strlen(name));
	if (w < 0) {
		fprintf(stderr, "write: %s\n", strerror(errno));
		close(fd);
		return 1;
	}
	close(fd);

	printf("agentfs: registered '%s' pid=%ld\n", name, (long)getpid());
	printf("agentfs: sleeping; signal me to unregister\n");

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_signal;
	sigaction(SIGINT,  &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGHUP,  &sa, NULL);

	while (!g_stop) pause();
	printf("agentfs: exiting; owner task_struct will trigger cleanup\n");
	return 0;
}
