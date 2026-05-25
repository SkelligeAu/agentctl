/* hello.c — canonical out-of-tree LKM.
 *
 * The whole point of this file is to be the smallest possible thing that
 * exercises the build pipeline. If `make hello` succeeds and `insmod
 * hello.ko` prints to dmesg, the kbuild + QEMU plumbing is working. */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

static int __init hello_init(void)
{
	pr_info("hello: loaded\n");
	return 0;
}

static void __exit hello_exit(void)
{
	pr_info("hello: unloaded\n");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("kdev environment");
MODULE_DESCRIPTION("Smallest possible out-of-tree LKM");
