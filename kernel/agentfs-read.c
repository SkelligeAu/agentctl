/* agentfs-read <name> [--nonblock] [mount=/mnt/agentfs]
 *
 * read() one message from /mnt/agentfs/agents/<name>/inbox and print it to
 * stdout. One read = one message (the kernel's mailbox is datagram-shaped).
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define READ_BUF (1U << 20)

int main(int argc, char **argv)
{
	const char *mount = "/mnt/agentfs";
	const char *name = NULL;
	int nonblock = 0;
	char path[256];
	char *buf;
	ssize_t r;
	int fd;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--nonblock") == 0)      nonblock = 1;
		else if (strncmp(argv[i], "mount=", 6) == 0) mount = argv[i] + 6;
		else if (!name)                              name  = argv[i];
		else {
			fprintf(stderr, "usage: %s <name> [--nonblock]\n", argv[0]);
			return 2;
		}
	}
	if (!name) {
		fprintf(stderr, "usage: %s <name> [--nonblock]\n", argv[0]);
		return 2;
	}

	if (snprintf(path, sizeof(path), "%s/agents/%s/inbox", mount, name)
	    >= (int)sizeof(path)) {
		fprintf(stderr, "path too long\n"); return 1;
	}
	int flags = O_RDONLY | O_CLOEXEC | (nonblock ? O_NONBLOCK : 0);
	fd = open(path, flags);
	if (fd < 0) {
		fprintf(stderr, "open %s: %s\n", path, strerror(errno));
		return 1;
	}
	buf = malloc(READ_BUF);
	if (!buf) { perror("malloc"); close(fd); return 1; }
	for (;;) {
		r = read(fd, buf, READ_BUF);
		if (r < 0) {
			if (errno == EINTR) continue;
			fprintf(stderr, "read: %s\n", strerror(errno));
			free(buf); close(fd); return 1;
		}
		break;
	}
	close(fd);
	if (r == 0) {
		fprintf(stderr, "(EOF — agent dead or queue drained)\n");
		free(buf);
		return 0;
	}
	if (write(1, buf, (size_t)r) < 0) perror("write stdout");
	free(buf);
	return 0;
}
