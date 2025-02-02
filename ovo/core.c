#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <asm/unistd.h>
#include <linux/highuid.h>
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
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/random.h>

#include "kkit.h"
#include "peekaboo.h"

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0))
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif

static char random_dev_name[12];
static dev_t dev;
static struct cdev cdev;
static struct class *device_class;

static ssize_t my_read(struct file *file, char __user *buf, size_t count, loff_t *ppos) {
    return 0;
}

static ssize_t my_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos) {
    return count;
}

static const struct file_operations my_fops = {
        .owner = THIS_MODULE,
        .read = my_read,
        .write = my_write,
};

static void generate_random_dev_name(void) {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    int i;
    u8 random_byte;

    for (i = 0; i < sizeof(random_dev_name) - 1; i++) {
        get_random_bytes(&random_byte, sizeof(random_byte));
        random_dev_name[i] = charset[random_byte % (sizeof(charset) - 1)];
    }
    random_dev_name[sizeof(random_dev_name) - 1] = '\0';
}

static void dev_random_names(void) {
    int i;
    for (i = 0; i < 5; i++) {
        generate_random_dev_name();
        pr_info("Random device name %d: %s\n", i, [ovo] );
    }
}

static int __init ovo_init(void) {
    cuteBabyPleaseDontCry();

    dev_random_names();
    ret = alloc_chrdev_region(&dev, 0, 1, random_dev_name);
    if (ret < 0) {
        return ret;
    }

    cdev_init(&cdev, &my_fops);
    cdev.owner = THIS_MODULE;

    ret = cdev_add(&cdev, dev, 1);
    if (ret < 0) {
        unregister_chrdev_region(dev, 1);
        return ret;
    }

    device_class = class_create(THIS_MODULE, random_dev_name);
    if (IS_ERR(device_class)) {
        cdev_del(&cdev);
        unregister_chrdev_region(dev, 1);
        return PTR_ERR(device_class);
    }

    if (IS_ERR(device_create(device_class, NULL, dev, NULL, random_dev_name))) {
        class_destroy(device_class);
        cdev_del(&cdev);
        unregister_chrdev_region(dev, 1);
        return PTR_ERR(device_class);
    }

    return 0;
}

static void __exit ovo_exit(void) {
    pr_info("[ovo] goodbye!\n");

    device_destroy(device_class, dev);
    class_destroy(device_class);
    cdev_del(&cdev);
    unregister_chrdev_region(dev, 1);
}

module_init(ovo_init);
module_exit(ovo_exit);

MODULE_AUTHOR("fuqiuluo");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("https://github.com/fuqiuluo/ovo");
MODULE_VERSION("1.0.0");