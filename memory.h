//
// Created by fuqiuluo on 25-1-22.
//

#ifndef OVO_MEMORY_H
#define OVO_MEMORY_H

#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/version.h>

uintptr_t get_module_base(pid_t pid, char *name);

phys_addr_t vaddr_to_phy_addr(struct mm_struct *mm, uintptr_t va);

#endif //OVO_MEMORY_H
