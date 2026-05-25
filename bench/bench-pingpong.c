/*
 * bench-pingpong — measure local IPC RTT for SOCK_STREAM vs SOCK_SEQPACKET.
 *
 * Forks a child, exchanges N round-trip messages over a socketpair, prints
 * percentile latencies. Single binary, no external deps. Intended to run
 * inside the kdev Linux container or any Linux env.
 *
 * Usage:
 *   bench-pingpong --type {stream|seqpacket} --size BYTES --count N
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static ssize_t write_all(int fd, const void *buf, size_t n)
{
    const char *p = buf;
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        p += w; n -= (size_t)w;
    }
    return 0;
}

static ssize_t read_all(int fd, void *buf, size_t n)
{
    char *p = buf;
    while (n > 0) {
        ssize_t r = read(fd, p, n);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) return -1;
        p += r; n -= (size_t)r;
    }
    return 0;
}

/* Server child: loop forever (until SIGTERM), echo back what was sent.
 * For SEQPACKET, one recv = one message; for STREAM, must read_all. */
static int child_loop(int fd, int sock_type, size_t msg_size)
{
    char *buf = malloc(msg_size);
    if (!buf) return 1;
    for (;;) {
        if (sock_type == SOCK_SEQPACKET) {
            ssize_t n = recv(fd, buf, msg_size, 0);
            if (n <= 0) break;
            if (send(fd, buf, (size_t)n, 0) < 0) break;
        } else {
            if (read_all(fd, buf, msg_size) != 0) break;
            if (write_all(fd, buf, msg_size) != 0) break;
        }
    }
    free(buf);
    return 0;
}

int main(int argc, char **argv)
{
    const char *type_str = "seqpacket";
    size_t msg_size = 128;
    int count = 100000;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--type") && i + 1 < argc) type_str = argv[++i];
        else if (!strcmp(argv[i], "--size") && i + 1 < argc) msg_size = (size_t)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--count") && i + 1 < argc) count = atoi(argv[++i]);
        else {
            fprintf(stderr, "usage: %s --type {stream|seqpacket} --size BYTES --count N\n",
                    argv[0]);
            return 2;
        }
    }
    int sock_type;
    if (!strcmp(type_str, "stream"))    sock_type = SOCK_STREAM;
    else if (!strcmp(type_str, "seqpacket")) sock_type = SOCK_SEQPACKET;
    else { fprintf(stderr, "bad --type\n"); return 2; }

    int sv[2];
    if (socketpair(AF_UNIX, sock_type, 0, sv) != 0) {
        fprintf(stderr, "socketpair(%s): %s\n", type_str, strerror(errno));
        return 1;
    }
    /* Grow the kernel buffers so 64 KiB messages fit without blocking. */
    int sz = 2 * 1024 * 1024;
    for (int k = 0; k < 2; k++) {
        (void)setsockopt(sv[k], SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
        (void)setsockopt(sv[k], SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
    }

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }
    if (pid == 0) {
        close(sv[0]);
        int r = child_loop(sv[1], sock_type, msg_size);
        close(sv[1]);
        _exit(r);
    }
    close(sv[1]);
    int parent_fd = sv[0];

    char *snd = malloc(msg_size);
    char *rcv = malloc(msg_size);
    if (!snd || !rcv) { perror("malloc"); return 1; }
    memset(snd, 'x', msg_size);

    uint64_t *rtts = calloc((size_t)count, sizeof(uint64_t));
    if (!rtts) { perror("calloc"); return 1; }

    /* Warmup */
    for (int i = 0; i < 100; i++) {
        if (sock_type == SOCK_SEQPACKET) {
            if (send(parent_fd, snd, msg_size, 0) < 0) { perror("warmup send"); return 1; }
            if (recv(parent_fd, rcv, msg_size, 0) < 0) { perror("warmup recv"); return 1; }
        } else {
            if (write_all(parent_fd, snd, msg_size) != 0) { perror("warmup write"); return 1; }
            if (read_all(parent_fd, rcv, msg_size) != 0)  { perror("warmup read");  return 1; }
        }
    }

    /* Measurement loop. */
    uint64_t t_start = now_ns();
    for (int i = 0; i < count; i++) {
        uint64_t t0 = now_ns();
        if (sock_type == SOCK_SEQPACKET) {
            if (send(parent_fd, snd, msg_size, 0) < 0) { perror("send"); return 1; }
            if (recv(parent_fd, rcv, msg_size, 0) < 0) { perror("recv"); return 1; }
        } else {
            if (write_all(parent_fd, snd, msg_size) != 0) { perror("write"); return 1; }
            if (read_all(parent_fd, rcv, msg_size) != 0)  { perror("read"); return 1; }
        }
        rtts[i] = now_ns() - t0;
    }
    uint64_t t_end = now_ns();

    /* Shut down child. */
    close(parent_fd);
    int status;
    waitpid(pid, &status, 0);

    /* Percentiles. */
    qsort(rtts, (size_t)count, sizeof(uint64_t), cmp_u64);
    uint64_t p50 = rtts[count / 2];
    uint64_t p99 = rtts[(int)((double)count * 0.99)];
    uint64_t p999 = rtts[(int)((double)count * 0.999)];
    uint64_t total_ns = t_end - t_start;
    double per_msg_us = (double)total_ns / 1000.0 / (double)count;
    double throughput = (double)count / ((double)total_ns / 1.0e9);
    double mbps = throughput * (double)msg_size / (1024.0 * 1024.0);

    printf("type=%-9s size=%-6zu count=%-6d "
           "p50=%.2fµs p99=%.2fµs p99.9=%.2fµs "
           "mean=%.2fµs thrpt=%.0f msg/s (%.1f MiB/s)\n",
           type_str, msg_size, count,
           (double)p50 / 1000.0, (double)p99 / 1000.0, (double)p999 / 1000.0,
           per_msg_us, throughput, mbps);

    free(snd); free(rcv); free(rtts);
    return 0;
}
