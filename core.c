#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <asm/unistd.h>
#include <linux/highuid.h>
#include <linux/cacheflush.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>
#include <linux/tty.h>
#include <linux/unistd.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/list.h>
#include <linux/pid.h>
#include <linux/rculist.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/pid_namespace.h>
#include <linux/slab.h>
#include <linux/init_task.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>

#include "kkit.h"
#include "peekaboo.h"

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0))
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif

static int __init ovo_init(void) {
    cuteBabyPleaseDontCry();

    return 0;
}

static void __exit ovo_exit(void) {
    pr_info("[ovo] goodbye!\n");

}

module_init(ovo_init);
module_exit(ovo_exit);

MODULE_AUTHOR("fuqiuluo");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("https://github.com/fuqiuluo/ovo");
MODULE_VERSION("1.0.0");