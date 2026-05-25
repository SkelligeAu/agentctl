#!/usr/bin/env bash
# Configure + build a kernel that we can run under QEMU and load modules
# into. Native-arch build: aarch64 host → Image, x86_64 host → bzImage.
# Both end up at share/vmlinuz (we keep the same output name across arches).
set -euo pipefail

V="${1:-${KERNEL_VERSION:-6.6.32}}"
HERE=$(cd "$(dirname "$0")"/.. && pwd)
SRC="$HERE/src/linux-$V"
FRAGMENT="$HERE/qemu/kernel.config"
SHARE="$HERE/share"

[[ -d "$SRC" ]] || { echo "missing $SRC; run 'make fetch-kernel'"; exit 1; }
[[ -f "$FRAGMENT" ]] || { echo "missing $FRAGMENT"; exit 1; }

ARCH_HOST=$(uname -m)
case "$ARCH_HOST" in
    x86_64)
        IMG_TARGET=bzImage
        IMG_PATH="arch/x86/boot/bzImage"
        ;;
    aarch64|arm64)
        IMG_TARGET=Image
        IMG_PATH="arch/arm64/boot/Image"
        ;;
    *)
        echo "unsupported arch: $ARCH_HOST"; exit 1
        ;;
esac
echo ">>> arch=$ARCH_HOST target=$IMG_TARGET"

cd "$SRC"
if [[ ! -f .config ]]; then
    echo ">>> generating defconfig"
    make defconfig
fi
echo ">>> merging fragment from $FRAGMENT"
./scripts/kconfig/merge_config.sh -m .config "$FRAGMENT"
make olddefconfig

# Two ceilings to dodge on Docker-for-Mac / OrbStack:
#   (1) nofile — kernel builds open thousands of fds; the docker run
#       wrapper sets --ulimit nofile=1048576, this just belt-and-braces it.
#   (2) memory — each cc1 can use ~1–2 GiB; on a 12 GiB VM, j>4 OOMs
#       fixdep with "Cannot allocate memory". Override with KJOBS=N if
#       you have more headroom.
ulimit -n 65536 2>/dev/null || true
NPROC=$(nproc)
KJOBS_DEFAULT=2
KJOBS=${KJOBS:-$KJOBS_DEFAULT}
[[ "$KJOBS" -gt "$NPROC" ]] && KJOBS=$NPROC
echo ">>> building (j=$KJOBS, host has $NPROC cpus)"
NPROC=$KJOBS

# Trim the defconfig module set. Out-of-tree modules just need Module.symvers
# (a list of exported kernel symbols + their CRCs). Building the full
# defconfig module set is gigabytes and many minutes of compile time we
# don't need. These knobs flip the biggest module-producing subsystems off.
# (Done via a temp fragment merge so the user can still hand-edit .config.)
cat > /tmp/agentfs-min.config <<'EOF'
# CONFIG_DRM is not set
# CONFIG_SOUND is not set
# CONFIG_NETFILTER is not set
# CONFIG_INFINIBAND is not set
# CONFIG_USB is not set
# CONFIG_BT is not set
# CONFIG_WIRELESS is not set
# CONFIG_HAMRADIO is not set
# CONFIG_RFKILL is not set
# CONFIG_GPU is not set
# CONFIG_INPUT_TOUCHSCREEN is not set
EOF
./scripts/kconfig/merge_config.sh -m .config /tmp/agentfs-min.config || true
make olddefconfig
make -j"$NPROC" "$IMG_TARGET"
# `make modules` populates Module.symvers, which out-of-tree modpost
# needs to resolve kernel-exported symbols. `modules_prepare` alone is
# not enough.
make -j"$NPROC" modules

mkdir -p "$SHARE"
cp "$SRC/$IMG_PATH" "$SHARE/vmlinuz"
echo ">>> done"
echo "    $IMG_TARGET -> $SHARE/vmlinuz"
echo "    vmlinux    -> $SRC/vmlinux (for gdb)"
