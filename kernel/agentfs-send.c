/* agentfs-send <name> [mount=/mnt/agentfs]
 *
 * Read up to 1 MiB from stdin and write() it as one message into the named
 * agent's inbox. Whatever bytes the kernel takes in a single write() call
 * become one message; we read stdin into a bounded buffer first, then write
 * exactly once so the framing is consistent.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_PAYLOAD (1U << 20)

int main(int argc, char **argv)
{
	const char *mount = "/mnt/agentfs";
	const char *name;
	char path[256];
	char *buf;
	size_t got = 0;
	ssize_t w;
	int fd;

	if (argc < 2) {
		fprintf(stderr, "usage: %s <name> [mount=/mnt/agentfs]\n", argv[0]);
		return 2;
	}
	name  = argv[1];
	if (argc >= 3) mount = argv[2];

	buf = malloc(MAX_PAYLOAD);
	if (!buf) { perror("malloc"); return 1; }

	while (got < MAX_PAYLOAD) {
		ssize_t r = read(0, buf + got, MAX_PAYLOAD - got);
		if (r < 0) {
			if (errno == EINTR) continue;
			perror("read stdin");
			free(buf); return 1;
		}
		if (r == 0) break;
		got += (size_t)r;
	}
	if (got == MAX_PAYLOAD) {
		char extra;
		ssize_t r = read(0, &extra, 1);
		if (r > 0) {
			fprintf(stderr, "send: payload exceeds %u bytes\n", MAX_PAYLOAD);
			free(buf); return 1;
		}
	}

	if (snprintf(path, sizeof(path), "%s/agents/%s/inbox", mount, name)
	    >= (int)sizeof(path)) {
		fprintf(stderr, "path too long\n"); free(buf); return 1;
	}
	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "open %s: %s\n", path, strerror(errno));
		free(buf); return 1;
	}
	w = write(fd, buf, got);
	if (w < 0) {
		fprintf(stderr, "write: %s\n", strerror(errno));
		close(fd); free(buf); return 1;
	}
	close(fd);
	fprintf(stderr, "sent %zd bytes to %s\n", w, name);
	free(buf);
	return 0;
}
