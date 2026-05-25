# Kernel-module development environment

> **Why this exists.** Building and testing kernel modules without
> trashing the host requires (a) a build environment with the right
> toolchain, (b) a kernel source tree to build against, (c) a VM you can
> safely crash. This directory gives you all three in one `make qemu`.
>
> **Docker is *only* for building.** The container holds the toolchain,
> the kernel source, the helpers. Module loading happens inside a QEMU VM
> that runs *inside* the container (or on the host if you'd rather).
> Loading custom kernel modules in a container is a category error — the
> container shares the *host's* kernel and you'd be modifying it.

## What's here

```
kernel/dev/
  Dockerfile             ──  build/dev image (Ubuntu 24.04 + toolchain + QEMU + busybox)
  docker-compose.yml     ──  optional, mirrors the Makefile's `make shell`
  Makefile               ──  high-level workflow targets (image / kernel / qemu / gdb)
  README.md              ──  this file
  .clangd                ──  LSP config for editing kernel headers
  .gitignore             ──  excludes src/, share/, build artefacts

  bin/
    fetch-kernel.sh      ──  curl + tar a kernel.org release
    build-kernel.sh      ──  configure + build bzImage + modules_prepare
    build-rootfs.sh      ──  pack a busybox initramfs
    qemu-run.sh          ──  launch QEMU with 9p sharing /work into /mnt/share

  qemu/
    kernel.config        ──  config fragment merged onto x86_64 defconfig
    init.sh              ──  PID 1 inside the VM; mounts 9p, drops to shell

  examples/hello/        ──  canonical hello-world module (build pipeline smoke test)

  src/                   ──  generated: linux-X.Y.Z/ kernel source (gitignored)
  share/                 ──  generated: vmlinuz, initramfs.cpio.gz, *.ko (gitignored)
```

The directory layout mirrors how a kernel developer actually works:
**`src/` = source you don't own**, **`share/` = build output**, **`bin/` =
the muscle memory commands**, **`qemu/` = config that follows the
project**. Nothing is hidden behind abstractions you can't grep.

## End-to-end demo

Fresh checkout, macOS or Linux host, Docker installed:

```
cd kernel/dev/
make image              # ~3 min   build the container image
make fetch-kernel       # ~30 s    download linux-6.6.32.tar.xz, extract
make kernel             # ~5-15 min  configure + build (ccache helps reruns)
make rootfs             # ~2 s     pack busybox initramfs
make module             # ~10 s    build /work/kernel/agentfs.ko
make hello              # ~5 s     build the hello-world example
make qemu               # boots the VM, drops you to a shell
```

Inside the VM:

```
# Smoke test the pipeline first:
insmod /mnt/share/hello.ko
dmesg | tail -3
# hello: loaded
rmmod hello

# Then the real thing:
insmod /mnt/share/agentfs.ko
mkdir -p /mnt/agentfs
mount -t agentfs none /mnt/agentfs
ls /mnt/agentfs
# agents/  register

# Register an agent (we don't have agentfs-register inside busybox; use the
# kernel-facing interface directly):
echo reviewer > /mnt/agentfs/register
ls /mnt/agentfs/agents/reviewer
# inbox  outbox  owner  pid  stats  status
cat /mnt/agentfs/agents/reviewer/pid
cat /mnt/agentfs/agents/reviewer/status
echo "hello" > /mnt/agentfs/agents/reviewer/inbox
cat /mnt/agentfs/agents/reviewer/inbox

poweroff -f             # or Ctrl-A, x
```

## How the pieces talk

```
  host                                  container (kdev)
  ─────                                 ─────────────────
  Docker Desktop / Linux ──── kernel/ ──┬──→ /work        (bind mount, r/w)
                                        │
                                        ├──→ src/         kernel source
                                        ├──→ share/       vmlinuz, *.ko, initramfs
                                        │
                                        │   ┌────────────────────── QEMU ────────────┐
                                        │   │  guest kernel = share/vmlinuz          │
                                        │   │  initramfs    = share/initramfs.cpio.gz│
                                        │   │  -virtfs share=path=share/             │
                                        │   │     ▶ guest mounts as /mnt/share       │
                                        │   │       (9p over virtio)                 │
                                        └─→ │       guest insmod /mnt/share/*.ko     │
                                            └────────────────────────────────────────┘
```

`/mnt/share` inside the VM **is** the host's `kernel/dev/share/` directory.
Drop a `.ko` into `share/` on the host, it's instantly available to the
VM. Edit `kernel/agentfs.c`, run `make module`, the new `agentfs.ko`
appears.

## Why each component

| Piece | Why |
|---|---|
| **Ubuntu 24.04 base** | Modern enough that `make defconfig` + recent kernels just build. Debian Bookworm works equally well; swap the `FROM` line. |
| **gcc + clang + lld** | The kernel still defaults to gcc but parts (and increasingly all of it) build with clang. Having both lets you flip with `CC=clang LLVM=1`. |
| **bc / bison / flex** | Required by the kernel's build for `Kbuild` parsing, kconfig, and timeconst.bc. The kernel build will fail in confusing ways without them. |
| **libssl-dev / libelf-dev** | `libssl` for signing-related tooling; `libelf` for `pahole` + module loading. |
| **dwarves (`pahole`)** | Generates BTF info (`CONFIG_DEBUG_INFO_BTF`). Needed for any BPF work and for some recent kernel features. |
| **kmod** | `insmod`/`modprobe`/`depmod` for working with `.ko` files outside the VM if you need to. |
| **cpio / rsync** | Initramfs packing (cpio) and source-tree copying without surprises (rsync). |
| **qemu-system-x86 / qemu-utils** | The kernel runs here. Anything that goes wrong crashes the VM, not your host. |
| **busybox-static** | Tiny single-binary userland for the initramfs. We just symlink commands at it. |
| **ccache** | Kernels rebuild a lot. ccache turns a 10-minute incremental build into 30 seconds. The Dockerfile prepends `/usr/lib/ccache` to PATH so plain `gcc` becomes the cached variant. |
| **bear** | Generates `compile_commands.json` by intercepting compiler invocations. Required for clangd to understand kernel sources. |
| **gdb** | The host-side gdb attaches to QEMU on `:1234` and reads `vmlinux` for symbols. See "Debugging" below. |

## Editor support (clangd / VSCode / Neovim)

1. After `make kernel`, run `make compile-db`. This re-runs the module
   build under `bear`, producing `kernel/compile_commands.json`.
2. Open `kernel/agentfs.c` in any clangd-capable editor (VSCode + the C/C++
   extension, Neovim with `nvim-lspconfig` + `clangd`, Helix, Zed, …).
3. The `kernel/dev/.clangd` file adds the kernel-build defines and strips
   gcc-only flags clang doesn't recognise. Without it, every `#include`
   looks broken.

```
# typical neovim config snippet
require'lspconfig'.clangd.setup{
  cmd = {"clangd", "--header-insertion=never"},
}
```

## Debugging — gdb attached to a paused VM

```
# terminal 1 (inside kernel/dev/)
make gdb            # boots QEMU with -s -S, so it freezes at first instruction

# terminal 2
make gdb-attach     # connects gdb to :1234, loads src/linux-<ver>/vmlinux
(gdb) b agentfs_init
Breakpoint 1 at 0xffffffff...
(gdb) c
Continuing.

# back in terminal 1, the VM has booted; do this:
insmod /mnt/share/agentfs.ko
# gdb in terminal 2 hits the breakpoint
```

**Why `nokaslr`?** Kernel address-space randomisation moves every kernel
address each boot, so the symbols in `vmlinux` won't line up with where
the code actually is. `qemu-run.sh` adds `nokaslr` to the command line by
default. Remove it for production builds.

**Module symbols** (for debugging `agentfs.ko` itself, not the kernel):

```
(gdb) add-symbol-file /work/kernel/agentfs.ko <load address>
```

Get the load address from `cat /sys/module/agentfs/sections/.text` inside
the VM after `insmod`.

## Debugging — kgdb over serial (the heavy weapon)

For kgdb you boot with `kgdbwait` in the command line; kernel waits for a
gdb attach over the serial port before continuing init.

```
# edit qemu/init.sh append line to add:  kgdboc=ttyS1,115200 kgdbwait
# add a second serial in qemu-run.sh:    -serial pty
# QEMU prints something like  /dev/pts/3
# then: gdb vmlinux ; (gdb) set serial baud 115200 ; (gdb) target remote /dev/pts/3
```

In practice for an LKM POC, attaching gdb to QEMU's gdbstub on `:1234` is
much simpler than kgdb-over-serial — and that's what `make gdb` gives you.
Reach for kgdb only when you're debugging early boot (before gdbstub is
usable).

## Performance — KVM vs TCG

| Host | What runs | Speed |
|---|---|---|
| Linux with `/dev/kvm` exposed to the container | KVM (hardware virt) | native |
| macOS via Docker Desktop | TCG (software emulation, no nested virt) | ~10-20× slower |
| Linux without `/dev/kvm` (rare) | TCG | as above |

Pass `--kvm` to `bin/qemu-run.sh` (or set it in your own wrapper) to
enable KVM where available. On macOS you can alternatively install QEMU
via Homebrew on the host and run it there with `accel=hvf` for fast
emulation — at the cost of moving QEMU outside the dev image.

## Common pitfalls

| Symptom | Cause | Fix |
|---|---|---|
| `insmod: ERROR: could not insert module ...: Invalid module format` | Module built against a different kernel version than the one QEMU is running | Always `make kernel` (or `make fetch-kernel kernel`) before `make module`. Module `vermagic` must match. |
| `ld: cannot find -lelf` / `ld: cannot find -lssl` | Missing dev headers on a host build | Use the container. Or `apt install libelf-dev libssl-dev`. |
| QEMU boots but you see nothing | No serial console kernel built / no `console=ttyS0` in cmdline | The provided `kernel.config` and `qemu-run.sh` cover both. If you modified them, check both still set the console to ttyS0. |
| QEMU exits immediately with `init not found` | initramfs missing `/init` or it's not executable | `bin/build-rootfs.sh` chmods it; re-run `make rootfs` after editing `qemu/init.sh`. |
| `mount: agentfs: unknown filesystem type` inside the VM | Tried to mount before `insmod` | `insmod` registers the type; then `mount -t agentfs`. |
| `rmmod: ERROR: ... Resource temporarily unavailable` | Open files on the agentfs mount | `umount` first; reap any `agentfs-register` processes. |
| gdb says "Remote 'g' packet reply is too long" | Mismatch between QEMU CPU type and gdb arch | Use `qemu64` (already default) and `set arch i386:x86-64:intel` in gdb. |
| Files on host owned by root after Docker run | Image built with default UID, not yours | Rebuild: `make image` runs `docker build --build-arg UID=$(id -u) --build-arg GID=$(id -g)`. |
| `bear` fails / `compile_commands.json` empty | Underlying `make` failed | Run `make module` standalone first; fix that, then `make compile-db`. |
| 9p mount fails with `cannot open access=...` | host path doesn't exist or container can't see it | The Makefile mounts `kernel/dev/share/` — make sure it exists (it's created by `make rootfs`). |
| Builds are dog slow even on rebuilds | ccache not picking up | `echo $PATH` inside the container should show `/usr/lib/ccache:...` first. `ccache -s` shows hit rate. |

## Going further

This setup intentionally stops at "build + test one module in one VM."
Things you might add later, none of which I included to keep the surface
small:

- **netboot for multi-machine tests** — TFTP/PXE inside docker-compose;
  useful for testing module interactions across two VMs.
- **Coccinelle / smatch / sparse** — static analysers the kernel devs
  actually use. `apt install coccinelle sparse smatch`.
- **lockdep / KASAN / KMSAN / UBSAN** — set in `qemu/kernel.config` for
  the next kernel build. Slow but catches real bugs.
- **GDB python scripts that ship with the kernel** — `make scripts_gdb`
  generates `vmlinux-gdb.py`. `(gdb) source vmlinux-gdb.py` then
  `(gdb) lx-dmesg`, `(gdb) lx-lsmod`, etc.
- **A second module, vmtest-style** — building two modules and loading
  them in dependency order. Just add another `obj-m` target.
- **CI** — the same Dockerfile + `make module` works in any container
  CI. The QEMU step is harder to put in CI (needs `/dev/kvm` for speed
  or you pay TCG cost).

## What this is not

- Not a Kubernetes-based test harness. Add one if you scale to hundreds
  of kernels, not before.
- Not a devcontainer. VSCode's devcontainer.json adds a layer of
  indirection on top of the Dockerfile; you can wrap this in one
  trivially if you want, but the indirection isn't needed.
- Not a yocto / buildroot environment. We build an initramfs with
  busybox-static because that's the smallest thing that boots. If you
  need a real rootfs, swap `bin/build-rootfs.sh` for a `debootstrap` call.
- Not a sandbox for *running* kernel modules. **Don't `insmod` anything
  inside the container.** The container shares the host's kernel.
