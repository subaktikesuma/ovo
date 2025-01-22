#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <asm/unistd.h>
#include <linux/highuid.h>
#include <linux/cacheflush.h>
#include <asm/tlbflush.h>
#include <asm/tlbflush.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>

static int __init ovo_init(void) {

    return 0;
}

static void __exit ovo_exit(void) {

}

module_init(ovo_init);
module_exit(ovo_exit);

MODULE_AUTHOR("fuqiuluo");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("https://github.com/fuqiuluo/ovo");
MODULE_VERSION("1.0.0");