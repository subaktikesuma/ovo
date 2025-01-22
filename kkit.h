//
// Created by fuqiuluo on 25-1-22.
//

#ifndef OVO_KKIT_H
#define OVO_KKIT_H

#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/version.h>

unsigned long ovo_kallsyms_lookup_name(const char* symbol_name);

unsigned long * ovo_find_syscall_table(void);

int ovo_flip_open(const char *filename, int flags, umode_t mode, struct file **f);

int ovo_flip_close(struct file **f, fl_owner_t id);

bool is_file_exist(const char *filename);

int is_pid_alive(pid_t pid);

int mark_pid_root(pid_t pid);

#endif //OVO_KKIT_H
