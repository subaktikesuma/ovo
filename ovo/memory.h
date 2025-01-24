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

// 读写进程内存
// 依赖于current，只能在进程上下文中调用
// 使用ioremap_cache去映射物理地址，然后copy_to_user
int read_process_memory(pid_t pid, void __user* addr, void __user* dest, size_t size);
int write_process_memory(pid_t pid, void __user* addr, void __user* src, size_t size);

// 读写进程内存
// 不依赖于current，可以在任何上下文中调用
// 使用access_process_vm去读写进程内存
int access_process_vm_by_pid(pid_t from, void __user* from_addr, pid_t to, void __user* to_addr, size_t size);

#if BUILD_REMAP == 1
// 内存重映射
void* remap_process_memory(pid_t from, void __user* from_addr, pid_t to, size_t size);
int unmap_process_memory(pid_t from, void __user* from_addr, size_t size);
#endif

#endif //OVO_MEMORY_H
