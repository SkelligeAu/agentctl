#!/usr/bin/env bash
# Download + extract a Linux kernel tarball into src/linux-<ver>/.
# Runs INSIDE the container.
set -euo pipefail

V="${1:-${KERNEL_VERSION:-6.6.32}}"
MAJOR="${V%%.*}"
URL="https://cdn.kernel.org/pub/linux/kernel/v${MAJOR}.x/linux-${V}.tar.xz"

mkdir -p src
cd src
if [[ -d "linux-$V" ]]; then
    echo ">>> already extracted: src/linux-$V"
    exit 0
fi

echo ">>> fetching $URL"
curl --fail --location --progress-bar -O "$URL"
echo ">>> extracting"
tar xJf "linux-$V.tar.xz"
rm "linux-$V.tar.xz"
echo ">>> source ready at src/linux-$V"
