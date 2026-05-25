#!/usr/bin/env bash
# Boot a kernel + initramfs in QEMU, sharing /work into the VM via 9p.
# Inside the VM the share appears at /mnt/share.
#
# Flags:
#   --paused      add -s -S so QEMU waits for gdb on :1234
#   --kvm         pass through /dev/kvm if present (Linux host only)
#
# Exit QEMU with Ctrl-A then x (this is the default -serial mon:stdio key).
set -euo pipefail

V="${1:-${KERNEL_VERSION:-6.6.32}}"; shift || true
PAUSED=0
KVM=0
for arg in "$@"; do
    case "$arg" in
        --paused) PAUSED=1 ;;
        --kvm)    KVM=1 ;;
        *) echo "unknown flag $arg"; exit 2 ;;
    esac
done

HERE=$(cd "$(dirname "$0")"/.. && pwd)
KERNEL="$HERE/share/vmlinuz"
INITRD="$HERE/share/initramfs.cpio.gz"
SHARE_DIR="$HERE/share"

[[ -f "$KERNEL" ]] || { echo "missing $KERNEL — run 'make kernel'"; exit 1; }
[[ -f "$INITRD" ]] || { echo "missing $INITRD — run 'make rootfs'"; exit 1; }

ARCH_HOST=$(uname -m)
case "$ARCH_HOST" in
    x86_64)
        QEMU=qemu-system-x86_64
        MACHINE=(-machine pc)
        CONSOLE="ttyS0"
        DEFAULT_CPU="qemu64"
        KVM_CPU="host"
        ;;
    aarch64|arm64)
        QEMU=qemu-system-aarch64
        MACHINE=(-machine virt)
        CONSOLE="ttyAMA0"
        DEFAULT_CPU="max"
        KVM_CPU="host"
        ;;
    *)
        echo "unsupported arch: $ARCH_HOST"; exit 1
        ;;
esac
echo ">>> arch=$ARCH_HOST qemu=$QEMU"

ACCEL=()
if [[ $KVM -eq 1 && -e /dev/kvm ]]; then
    ACCEL=(-enable-kvm -cpu "$KVM_CPU")
    echo ">>> KVM acceleration on"
else
    ACCEL=(-cpu "$DEFAULT_CPU")
    echo ">>> TCG (software) acceleration — slow but portable"
fi

PAUSE_FLAGS=()
if [[ $PAUSED -eq 1 ]]; then
    PAUSE_FLAGS=(-s -S)
    echo ">>> QEMU paused: connect gdb to :1234 (use 'make gdb-attach')"
fi

# nokaslr makes kernel addresses match vmlinux for gdb.
# lsm= activates Landlock in the runtime LSM stack — the kernel must
# also have CONFIG_SECURITY_LANDLOCK=y (see qemu/kernel.config).
APPEND="console=$CONSOLE nokaslr panic=1 lsm=landlock,lockdown,yama,bpf"

set -x
exec "$QEMU" \
    "${ACCEL[@]}" \
    "${MACHINE[@]}" \
    -kernel "$KERNEL" \
    -initrd "$INITRD" \
    -append "$APPEND" \
    -nographic \
    -serial mon:stdio \
    -m 512M -smp 2 \
    -virtfs local,id=share,path="$SHARE_DIR",mount_tag=share,security_model=none \
    "${PAUSE_FLAGS[@]}"
