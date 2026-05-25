#!/usr/bin/env bash
# Build a minimal Alpine initramfs (~5-8 MB) for the QEMU guest.
# Extracts alpine-minirootfs into share/initramfs/, installs our /init,
# packs as cpio.gz. Caches the upstream tarball under share/cache/.
#
# Mounts proc/sys/dev/cgroup2 and the host's /work via 9p at /mnt/share
# (see qemu/init.sh). Runs /mnt/share/agentfs-test.sh if present and
# powers off; otherwise drops to an interactive shell.
set -euo pipefail

HERE=$(cd "$(dirname "$0")"/.. && pwd)
ROOTFS=$HERE/share/initramfs
SHARE=$HERE/share
INIT_SRC=$HERE/qemu/init.sh
CACHE=$SHARE/cache

ALPINE_BRANCH="${ALPINE_BRANCH:-v3.20}"
ALPINE_RELEASE="${ALPINE_RELEASE:-3.20.3}"

HOST_ARCH=$(uname -m)
case "$HOST_ARCH" in
    aarch64|arm64) ALPINE_ARCH=aarch64 ;;
    x86_64)        ALPINE_ARCH=x86_64  ;;
    *) echo "unsupported arch: $HOST_ARCH" >&2; exit 1 ;;
esac

TARBALL="alpine-minirootfs-${ALPINE_RELEASE}-${ALPINE_ARCH}.tar.gz"
URL="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_BRANCH}/releases/${ALPINE_ARCH}/${TARBALL}"

mkdir -p "$CACHE"
if [ ! -f "$CACHE/$TARBALL" ]; then
    echo ">>> fetching $URL"
    curl -fsSL "$URL" -o "$CACHE/$TARBALL.tmp"
    mv "$CACHE/$TARBALL.tmp" "$CACHE/$TARBALL"
fi

rm -rf "$ROOTFS"
mkdir -p "$ROOTFS"
tar -xzf "$CACHE/$TARBALL" -C "$ROOTFS"

# Mount points expected by qemu/init.sh.
mkdir -p "$ROOTFS"/{proc,sys,dev,tmp,mnt/share,mnt/agentfs}

# /init: kernel runs this first. Overwrites any provided by minirootfs.
cp "$INIT_SRC" "$ROOTFS/init"
chmod +x "$ROOTFS/init"

# Pack
(
    cd "$ROOTFS"
    find . -print0 | cpio --null -ov --format=newc 2>/dev/null | gzip -9 > "$SHARE/initramfs.cpio.gz"
)

echo ">>> wrote $SHARE/initramfs.cpio.gz ($(du -h $SHARE/initramfs.cpio.gz | cut -f1)), alpine $ALPINE_RELEASE/$ALPINE_ARCH"
