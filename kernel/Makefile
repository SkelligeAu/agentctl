# Builds:
#   - agentfs.ko  (Linux only, via the host's kbuild tree)
#   - agentfs-register / agentfs-send / agentfs-read (any POSIX C)
#
# On macOS or any non-Linux host, `make` builds only the helpers; the kernel
# module needs a Linux kbuild environment.

# -------- kernel-module half (Linux/kbuild only) --------

ifneq ($(KERNELRELEASE),)

# Invoked by kbuild from /lib/modules/<ver>/build
obj-m += agentfs.o

else

KDIR  ?= /lib/modules/$(shell uname -r)/build
PWD   := $(shell pwd)
UNAME := $(shell uname -s)

CC      ?= cc
# -std=c99 masks POSIX extensions; ask for POSIX 2008 explicitly so sigaction,
# O_CLOEXEC, etc. become visible.
CFLAGS  ?= -std=c99 -Wall -Wextra -Wpedantic -O2 -D_POSIX_C_SOURCE=200809L

HELPERS = agentfs-register agentfs-send agentfs-read

ifeq ($(UNAME),Linux)
all: module helpers
else
all: helpers
	@echo
	@echo "(skipping kernel module build — host is $(UNAME), not Linux)"
endif

module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

helpers: $(HELPERS)

agentfs-register: agentfs-register.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
agentfs-send: agentfs-send.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
agentfs-read: agentfs-read.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

install: module
	@echo "Run: sudo insmod agentfs.ko"
	@echo "     sudo mkdir -p /mnt/agentfs"
	@echo "     sudo mount -t agentfs none /mnt/agentfs"

uninstall:
	@echo "Run: sudo umount /mnt/agentfs && sudo rmmod agentfs"

clean:
	-$(MAKE) -C $(KDIR) M=$(PWD) clean 2>/dev/null
	rm -f $(HELPERS)

.PHONY: all module helpers install uninstall clean

endif
