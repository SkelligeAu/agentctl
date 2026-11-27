# Kernel development and QEMU tests

Docker provides the build tools.
QEMU runs the test kernel and module in a guest VM.

Do not run `insmod` inside the Docker container.
The container shares its host's kernel.
Use the QEMU guest for module loading and crash tests.

The `agentfs` module is research code.
See [research status](../../docs/research.md).

## Files

```text
kernel/dev/
  Dockerfile
  docker-compose.yml
  Makefile
  .clangd
  bin/
    fetch-kernel.sh
    build-kernel.sh
    build-rootfs.sh
    qemu-run.sh
  qemu/
    kernel.config
    init.sh
  examples/hello/
  src/
  share/
```

`src/` contains downloaded kernel source and build output.
`share/` contains the guest kernel, initramfs and copied test files.
These directories contain generated files and are excluded from version control.

The Makefile mounts the repository at `/work` in the container.
The standard QEMU command exposes `share/` as writable `/mnt/share` in the guest.
Guest writes there change the host's `kernel/dev/share/` directory.
This configuration is not a VM with no host filesystem access.

## Build the test environment

From a checkout with Docker available:

```sh
cd kernel/dev
make image
make fetch-kernel
make kernel
make rootfs
make module
make hello
make qemu
```

The default kernel version is 6.6.32.
Use `KERNEL_VERSION` to select another version.

The kernel script builds the host architecture.
ARM64 uses the `Image` target.
x86-64 uses `bzImage`.
Both are copied to `share/vmlinuz`.

The root filesystem script packs an Alpine minirootfs as `share/initramfs.cpio.gz`.
Its `/init` mounts proc, sysfs, device files, temporary storage, cgroup v2 and the 9p share.

If an executable `share/agentfs-test.sh` exists, the guest runs it and powers off.
Otherwise, it opens a shell.
Use this target to request a shell explicitly:

```sh
make qemu-shell
```

## Load the modules in the guest

Check the hello module first:

```sh
insmod /mnt/share/hello.ko
dmesg | tail -3
rmmod hello
```

Load agentfs and mount it:

```sh
insmod /mnt/share/agentfs.ko
mkdir -p /mnt/agentfs
mount -t agentfs none /mnt/agentfs
ls /mnt/agentfs
```

The filesystem contains `agents/` and `register`.
Use the registration helper to keep an owner task alive.
A short-lived `echo` command does not create a persistent owner.

Build and copy the helpers before using them in the guest:

```sh
# On the host, from kernel/dev:
make helpers

# In the guest:
/mnt/share/agentfs-register reviewer &
printf 'hello\n' | /mnt/share/agentfs-send reviewer
/mnt/share/agentfs-read reviewer
```

The send helper reads standard input.
Use another terminal or a pipe when testing a blocked reader.
See [module instructions](../README.md) for a complete message example.

Exit the guest with:

```sh
poweroff -f
```

Ctrl-A, then x also exits QEMU.

## Build the userspace supervisor

```sh
make userland
```

This target performs a clean static Linux build in the mounted repository.
It replaces host build outputs with Linux executables.
Rebuild with the host compiler before using those binaries on macOS.

The target copies selected programs, profiles and tests into `share/userland/`.
Check that all programs required by the selected guest test are present.
The target does not install every current test dependency.
In particular, the Python integration tests need Python in the guest.

See [test instructions](../../tests/README.md).

## Build tools

| Tools | Purpose |
|---|---|
| GCC, Clang and LLD | Compile and link kernel and userspace code. |
| bc, Bison and Flex | Kernel configuration and generated build files. |
| libssl-dev and libelf-dev | Headers and libraries required by kernel build tools. |
| dwarves and pahole | BTF generation when enabled in the kernel configuration. |
| kmod | Module inspection and loading tools. Load test modules only in the guest. |
| cpio and rsync | Initramfs packing and file copying. |
| QEMU | Run x86-64 or ARM64 guests. |
| busybox-static | A small userspace utility binary available in the build image. |
| ccache | Reuse compiler results between builds. |
| bear | Record compiler commands for clangd. |
| GDB | Debug the guest kernel through QEMU. |

The image uses Ubuntu 24.04.
It creates a development user with the host UID and GID supplied by `make image`.
The ccache directory is `kernel/dev/.ccache`.
Use `ccache -s` inside the container to inspect cache use.

## Editor configuration

After a kernel build, generate the compiler database:

```sh
make compile-db
```

This runs the module build under `bear`.
It writes `kernel/compile_commands.json`.

Use a clangd-capable editor.
`kernel/dev/.clangd` adds kernel build definitions and removes unsupported GCC options.

Example Neovim configuration:

```lua
require'lspconfig'.clangd.setup{
  cmd = {"clangd", "--header-insertion=never"},
}
```

## GDB through QEMU

In terminal 1, from `kernel/dev`:

```sh
make gdb
```

QEMU starts paused with its GDB endpoint on port 1234.

In terminal 2, on x86-64:

```sh
make gdb-attach
```

The supplied attach target sets an x86-64 architecture.
For ARM64, use an ARM64-capable GDB without that x86 setting:

```sh
gdb -ex 'target remote :1234' src/linux-6.6.32/vmlinux
```

Set a kernel breakpoint and continue:

```text
(gdb) b start_kernel
(gdb) c
```

Load `agentfs.ko` in the guest after it boots.
Add the module symbols before setting breakpoints in its functions.

For module symbols, obtain the text address in the guest:

```sh
cat /sys/module/agentfs/sections/.text
```

Then load symbols in GDB:

```text
(gdb) add-symbol-file /work/kernel/agentfs.ko <load address>
```

The QEMU script adds `nokaslr` to keep kernel addresses stable for debugging.
Do not copy this debugging setting into a production kernel configuration.

## Serial KGDB

Serial KGDB is an optional configuration.
The normal `make gdb` target uses QEMU's GDB endpoint instead.

For an x86 serial setup, add `kgdboc=ttyS1,115200 kgdbwait` to the guest kernel command line.
Add a second serial port with `-serial pty` in `qemu-run.sh`.
Use the PTY path printed by QEMU:

```text
(gdb) set serial baud 115200
(gdb) target remote /dev/pts/3
```

The PTY path and serial device must match the actual configuration.

## Acceleration

QEMU uses software emulation by default.
Pass `--kvm` to `bin/qemu-run.sh` to request KVM.
The container must also have access to `/dev/kvm`.
The standard Makefile does not expose that device automatically.
The Compose file contains a commented device mapping.

Without KVM, the script uses software emulation.
Build and test times depend on the host and guest workload.

## Real cgroup tests

A writable cgroup v2 mount and delegated controllers are required.
CPU quota tests also require `CONFIG_CFS_BANDWIDTH=y`.
The supplied kernel fragment does not enable that setting explicitly.
Check the resulting kernel configuration before running CPU quota tests.

The guest administrator must create the delegated hierarchy.
Run the supervisor and workloads as an unprivileged user within it.
Do not use a writable host cgroup mount as a substitute for an isolated test guest.

See `tests/cgroup_quotas.sh` and the [test instructions](../../tests/README.md).
Check the test's result marker, not only QEMU's exit code.
A guest can report test failure and still power off normally.

## Common failures

| Symptom | Check |
|---|---|
| Invalid module format | Match the module build to the booted kernel and its `vermagic`. |
| Missing `-lelf` or `-lssl` | Use the build image or install the matching development libraries. |
| No console output | Check the kernel console and command line. x86 uses `ttyS0`; ARM64 uses `ttyAMA0`. |
| Init not found | Rebuild the initramfs and confirm executable `/init` is present. |
| Unknown agentfs filesystem | Load the module before mounting it. |
| Module removal fails | Stop helpers, close files and unmount agentfs before `rmmod`. |
| GDB register packet error | Match GDB's architecture to the QEMU guest. |
| Host files become root-owned | Rebuild the image with the correct host UID and GID. |
| Empty compiler database | Fix the module build before running `make compile-db`. |
| 9p mount failure | Confirm `share/` exists and is visible to the container. |
| Repeated slow builds | Check `/usr/lib/ccache` in PATH and inspect `ccache -s`. |

Optional checks include sparse, smatch, Coccinelle, lockdep and kernel sanitizers.
They are not automatically run by these targets.
