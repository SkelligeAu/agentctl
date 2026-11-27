# IPC benchmark

The ping-pong benchmark compares `SOCK_STREAM` and `SOCK_SEQPACKET` for agentctl message sizes.
It does not compare gRPC, ZeroMQ, Redis or named pipes.

## Tool

`bench/bench-pingpong.c` creates a socket pair and forks a child.
The child returns the bytes it receives.
After a warmup period, the parent measures round-trip time for the requested iteration count.

```text
Usage: bench-pingpong --type {stream|seqpacket} --size BYTES --count N
```

## Build

The following command builds a static Linux executable.
It requires the `kdev:latest` image from [kernel/dev](kernel/dev/README.md).

```sh
docker run --rm -v "$(pwd):/work" -w /work kdev:latest \
    gcc -O2 -static -o bench/bench-pingpong bench/bench-pingpong.c
```

## Recorded results

These results used 100,000 iterations on ARM64 in an OrbStack Linux VM.
They are recorded measurements, not results from the current checkout.

| Size | Transport | p50 | p99 | p99.9 | Mean | Throughput |
|---|---|---|---|---|---|---|
| 128 B | STREAM | 1.29 µs | 2.38 µs | 10.71 µs | 1.33 µs | 752k/s |
| 128 B | SEQPACKET | 1.00 µs | 1.46 µs | 7.38 µs | 1.05 µs | 953k/s |
| 4 KiB | STREAM | 1.29 µs | 2.50 µs | 9.42 µs | 1.49 µs | 672k/s |
| 4 KiB | SEQPACKET | 1.21 µs | 1.71 µs | 8.25 µs | 1.26 µs | 793k/s |
| 64 KiB | STREAM | 6.42 µs | 12.12 µs | 18.79 µs | 6.70 µs | 149k/s |
| 64 KiB | SEQPACKET | 6.21 µs | 8.92 µs | 18.08 µs | 6.35 µs | 157k/s |

In this run, SEQPACKET reduced p99 latency by 26–39%.
Throughput increased at each tested size.
The results met the migration targets: p50 within 10% of STREAM and p99 at least 20% lower.

The run did not record syscall counts or CPU counters.
It did not use `strace -c` or `perf stat -e migrations,cache-misses`.
The latency results alone do not establish the cause of the difference.
