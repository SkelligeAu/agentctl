# Linux kernel-module development image.
#
# Image scope:
#   - everything needed to BUILD an out-of-tree LKM
#   - everything needed to BUILD an upstream Linux kernel
#   - QEMU for testing the resulting module without touching the host
#
# Image scope is intentionally NOT:
#   - kernel runtime isolation (you don't load modules in containers)
#   - any agentfs-specific code (image is project-agnostic)

FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

# --- toolchain + kernel build deps ------------------------------------
# Full list from the user request, plus a few obviously useful neighbours.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc clang lld make \
    bc bison flex \
    libssl-dev libelf-dev \
    dwarves \
    kmod cpio rsync \
    git gdb vim tmux less \
    python3 python3-pip \
    ca-certificates curl xz-utils \
    ccache bear \
    qemu-system-x86 qemu-system-arm qemu-utils \
    busybox-static \
    fakeroot sudo \
 && rm -rf /var/lib/apt/lists/*

# --- non-root user --------------------------------------------------
# Volume mounts inherit the container's UID; running as UID 0 would leave
# all your source files owned by root on the host. We build the image with
# UID/GID args matching the invoking user so the mount semantics are clean.
ARG UID=1000
ARG GID=1000
RUN if getent group $GID >/dev/null 2>&1; then \
        groupmod -n dev "$(getent group $GID | cut -d: -f1)"; \
    else \
        groupadd -g $GID dev; \
    fi \
 && if getent passwd $UID >/dev/null 2>&1; then \
        usermod -l dev -d /home/dev -m -g $GID "$(getent passwd $UID | cut -d: -f1)"; \
    else \
        useradd -m -u $UID -g $GID -s /bin/bash dev; \
    fi \
 && echo 'dev ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/dev

USER dev
WORKDIR /work

# ccache lives in the project tree so it survives `docker rm` and is per-checkout.
ENV PATH=/usr/lib/ccache:$PATH
ENV CCACHE_DIR=/work/kernel/dev/.ccache

CMD ["/bin/bash"]
