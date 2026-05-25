# High-level workflow.
#
#   make image          build the kdev container image
#   make shell          drop into a shell inside the container (project at /work)
#   make fetch-kernel   download linux-<KERNEL_VERSION>.tar.xz, extract to src/
#   make kernel         configure + build the kernel (bzImage + modules_prepare)
#   make rootfs         build a minimal Alpine initramfs (~5-8 MB)
#   make module         build the real agentfs.ko against src/linux-<v>/
#   make hello          build the hello-world example
#   make compile-db     regenerate compile_commands.json (clangd)
#   make qemu           boot the built kernel under QEMU with /work shared
#   make qemu-shell     boot QEMU into an interactive /bin/sh (skips agentfs-test)
#   make gdb            launch QEMU paused for `make gdb-attach`
#   make gdb-attach     attach gdb to a paused QEMU
#   make clean          remove built kernel + rootfs + image
#
# Most targets just invoke `bin/<x>.sh` inside the container so the host
# (macOS, your distro, whatever) doesn't need any kernel tooling itself.

SHELL := /bin/bash
IMG   := kdev:latest

# Project root — the repo, mounted into the container at /work.
PROJECT_ROOT := $(abspath $(CURDIR)/../..)

KERNEL_VERSION ?= 6.6.32
KERNEL_DIR     := src/linux-$(KERNEL_VERSION)

DOCKER ?= docker
# -it for interactive (`make shell`, `make qemu`, `make gdb-attach`).
# Non-interactive targets drop -it so they work from CI / piped builds.
# --ulimit nofile= because kernel builds open thousands of fds in parallel
# and Docker on macOS otherwise hits the host's tight default ceiling.
DOCKER_ENV = -e KERNEL_VERSION=$(KERNEL_VERSION) \
             --ulimit nofile=1048576:1048576 \
             -v $(PROJECT_ROOT):/work \
             -w /work/kernel/dev \
             $(IMG)
RUN     = $(DOCKER) run --rm $(DOCKER_ENV)
RUN_TTY = $(DOCKER) run --rm -it $(DOCKER_ENV)

help:
	@awk 'BEGIN{FS=":.*?## "} /^[a-zA-Z_-]+:.*?## /{printf "  %-15s %s\n",$$1,$$2}' $(MAKEFILE_LIST) \
	  || grep -E '^[a-zA-Z_-]+:' $(MAKEFILE_LIST) | sed 's/:.*//' | sort -u | awk '{print "  "$$0}'

image: ## build the kdev container image
	$(DOCKER) build --build-arg UID=$$(id -u) --build-arg GID=$$(id -g) -t $(IMG) .

shell: image ## interactive shell in the container, project mounted at /work
	$(RUN_TTY) bash

fetch-kernel: image ## download + extract linux-$(KERNEL_VERSION).tar.xz
	$(RUN) bash bin/fetch-kernel.sh $(KERNEL_VERSION)

kernel: image $(KERNEL_DIR) ## configure + build the kernel
	$(RUN) bash bin/build-kernel.sh $(KERNEL_VERSION)

$(KERNEL_DIR):
	$(MAKE) fetch-kernel

rootfs: image ## build a minimal Alpine initramfs (~5-8 MB)
	$(RUN) bash bin/build-rootfs.sh

module: image $(KERNEL_DIR) ## build agentfs.ko against the in-tree kernel
	$(RUN) make -C /work/kernel KDIR=/work/kernel/dev/$(KERNEL_DIR) module
	# Copy into the shared dir QEMU will mount via 9p.
	cp $(PROJECT_ROOT)/kernel/agentfs.ko share/ 2>/dev/null || true

helpers: image ## build the userspace probes (static Linux ELF for the guest)
	# -static so they run in our busybox-only initramfs (no glibc loader).
	$(RUN) make -C /work/kernel helpers LDFLAGS=-static
	cp $(PROJECT_ROOT)/kernel/agentfs-register \
	   $(PROJECT_ROOT)/kernel/agentfs-send \
	   $(PROJECT_ROOT)/kernel/agentfs-read \
	   share/ 2>/dev/null || true

userland: image ## build the agentctl userspace stack statically for the guest
	# Force a clean build in the container; the host's macOS objects are
	# Mach-O and would link in spurious places. -static handles the missing
	# glibc loader inside the busybox initramfs.
	$(RUN) sh -c 'cd /work && make clean && make LDFLAGS=-static'
	mkdir -p share/userland
	cp $(PROJECT_ROOT)/agentctl \
	   $(PROJECT_ROOT)/agentd \
	   $(PROJECT_ROOT)/reviewer-agent \
	   $(PROJECT_ROOT)/fanout-agent \
	   $(PROJECT_ROOT)/psa \
	   $(PROJECT_ROOT)/broker-test \
	   $(PROJECT_ROOT)/broker-fault \
	   share/userland/ 2>/dev/null || true
	# Profiles are read by the runtimes; bring them along.
	rm -rf share/userland/profiles
	cp -r $(PROJECT_ROOT)/profiles share/userland/profiles
	# Tests directory: unit tests + bash drivers + run-all.sh
	rm -rf share/userland/tests
	mkdir -p share/userland/tests
	cp $(PROJECT_ROOT)/tests/test_ipc_msg_trunc \
	   $(PROJECT_ROOT)/tests/test_ipc_msg_ctrunc \
	   $(PROJECT_ROOT)/tests/test_cloexec \
	   $(PROJECT_ROOT)/tests/*.sh \
	   share/userland/tests/ 2>/dev/null || true
	chmod +x share/userland/tests/*.sh
	file share/userland/agentctl | head -1

hello: image $(KERNEL_DIR) ## build the hello-world example
	$(RUN) make -C /work/kernel/dev/examples/hello \
	  KDIR=/work/kernel/dev/$(KERNEL_DIR)
	cp examples/hello/hello.ko share/ 2>/dev/null || true

compile-db: image $(KERNEL_DIR) ## (re)generate compile_commands.json for clangd
	$(RUN) bash -c 'cd /work/kernel && \
	  bear --output /work/kernel/compile_commands.json -- \
	  make KDIR=/work/kernel/dev/$(KERNEL_DIR) module'

qemu: image kernel rootfs ## boot QEMU with /work shared via 9p
	mkdir -p share
	$(RUN_TTY) bash bin/qemu-run.sh $(KERNEL_VERSION)

qemu-shell: image kernel rootfs ## boot QEMU into an interactive shell (skips agentfs-test.sh)
	@mkdir -p share
	@bash -c 'trap "mv -f share/.agentfs-test.sh.bak share/agentfs-test.sh 2>/dev/null || true" EXIT; \
	  [ -f share/agentfs-test.sh ] && mv share/agentfs-test.sh share/.agentfs-test.sh.bak; \
	  $(RUN_TTY) bash bin/qemu-run.sh $(KERNEL_VERSION)'

# Paused mode: QEMU sits on -s -S waiting for gdb on :1234 in the container.
gdb: image kernel rootfs ## boot QEMU paused, waiting for gdb on :1234
	mkdir -p share
	$(RUN_TTY) bash bin/qemu-run.sh $(KERNEL_VERSION) --paused

gdb-attach: image ## attach gdb to a paused QEMU (run in a second terminal)
	$(RUN_TTY) gdb -ex 'set arch i386:x86-64:intel' \
	           -ex 'target remote :1234' \
	           /work/kernel/dev/$(KERNEL_DIR)/vmlinux

clean: ## remove builds + image
	rm -rf src share/initramfs share/vmlinuz \
	       share/agentfs.ko share/hello.ko \
	       .ccache compile_commands.json
	-$(DOCKER) image rm $(IMG)

.PHONY: help image shell fetch-kernel kernel rootfs module hello compile-db qemu gdb gdb-attach clean
