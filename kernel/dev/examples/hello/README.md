# Hello kernel module

Use this module to check the kernel build and QEMU loading procedure.

Run these commands from `kernel/dev`:

```sh
make image
make fetch-kernel
make kernel
make rootfs
make hello
make qemu
```

If an executable integration script is present, the guest runs it and powers off.
Use `make qemu-shell` when you need an interactive guest shell.

In the guest:

```sh
insmod /mnt/share/hello.ko
dmesg | tail -3
# Expected: hello: loaded

rmmod hello
dmesg | tail -3
# Expected: hello: unloaded

poweroff -f
```

You can also exit QEMU with Ctrl-A, then x.
Load this module only in the test guest, not in the Docker container.
