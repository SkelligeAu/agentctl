#!/bin/sh
# PID 1 inside the QEMU VM. Mounts essential filesystems, sets up the 9p
# share, prints a banner, drops into a shell.

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

exec >/dev/console 2>&1

mount -t proc     none /proc
mount -t sysfs    none /sys
mount -t devtmpfs none /dev
mount -t tmpfs    none /tmp
# cgroup v2 — required for the agentctl cgroup-active profile + cgroup.kill.
# Silent if the kernel was built without CONFIG_CGROUPS; in that case the
# code falls back to pidfd+killpg.
mkdir -p /sys/fs/cgroup
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null || true
hostname kvm

# /mnt/share is the host's kernel/dev/share/ directory, mounted r/w.
mount -t 9p -o trans=virtio,version=9p2000.L share /mnt/share \
    || echo "(9p mount failed — no /mnt/share)"

# If a test script was dropped into the share, run it and power off.
# Otherwise drop to an interactive shell.
if [ -x /mnt/share/agentfs-test.sh ]; then
    echo "================ running /mnt/share/agentfs-test.sh ================"
    /mnt/share/agentfs-test.sh
    rc=$?
    echo "================ test exit=$rc ================"
    poweroff -f
fi

cat <<'BANNER'

================================================================
 agentfs QEMU sandbox

 Modules:
   ls /mnt/share/*.ko
   insmod /mnt/share/hello.ko          # smoke test
   insmod /mnt/share/agentfs.ko        # the real module
   mkdir -p /mnt/agentfs
   mount -t agentfs none /mnt/agentfs
   ls /mnt/agentfs

 Logs:
   dmesg | tail -20

 Quit:
   poweroff -f      (or Ctrl-A, x)

================================================================

BANNER

exec setsid /bin/sh -c 'exec /bin/sh </dev/console >/dev/console 2>&1'
