# Canonical out-of-tree LKM Makefile.
#
# Pattern: kbuild expects the file to be invoked twice — once from the user
# (the "user phase", in the `else` branch) which calls the kernel's build
# tree, and once from the kernel's build tree itself (the "kbuild phase",
# in the `ifneq($(KERNELRELEASE),)` branch) which provides obj-m += ....

ifneq ($(KERNELRELEASE),)
# --- kbuild phase ---
obj-m := hello.o

else
# --- user phase ---
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	-$(MAKE) -C $(KDIR) M=$(PWD) clean
	-rm -f *.o *.ko *.mod *.mod.c .*.cmd Module.symvers modules.order
	-rm -rf .tmp_versions

.PHONY: all clean

endif
