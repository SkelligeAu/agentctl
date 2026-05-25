# hello — smallest possible out-of-tree module

If this builds and loads, the whole pipeline (Docker image → kernel tree →
kbuild → QEMU → insmod) is healthy. Use it as your smoke test before
debugging anything fancier.

```
# from kernel/dev/
make image
make fetch-kernel       # downloads + extracts linux-<ver>.tar.xz
make kernel             # configures + builds; ~5–15 min depending on host
make rootfs             # tiny busybox initramfs
make hello              # builds hello.ko, copies it into share/
make qemu               # boots the VM

# inside the VM (autostarts at /init):
insmod /mnt/share/hello.ko
dmesg | tail -3
# -> hello: loaded
rmmod hello
dmesg | tail -3
# -> hello: unloaded
poweroff -f             # or Ctrl-A, x
```
