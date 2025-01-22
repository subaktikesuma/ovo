//
// Created by fuqiuluo on 25-1-22.
//
#include "memory.h"

#include <linux/tty.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <asm/cpu.h>
#include <asm/page.h>
#include <asm/pgtable.h>


#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0))
#include <linux/mmap_lock.h>
#define MM_READ_LOCK(mm) mmap_read_lock(mm);
#define MM_READ_UNLOCK(mm) mmap_read_unlock(mm);
#else
#include <linux/rwsem.h>
#define MM_READ_LOCK(mm) down_read(&(mm)->mmap_sem);
#define MM_READ_UNLOCK(mm) up_read(&(mm)->mmap_sem);
#endif

uintptr_t get_module_base(pid_t pid, char *name) {
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
    struct vma_iterator vmi;
#endif
    char *buf = NULL;
    uintptr_t result;

    result = 0;

    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        return 0;
    }


    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) {
        return 0;
    }

    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) {
        return 0;
    }

    buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!buf) {
#ifdef CONFIG_MMU
        mmput_async(mm);
#else
        mmput(mm);
#endif
        return 0;
    }

    MM_READ_LOCK(mm)

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
    vma_iter_init(&vmi, mm, 0);
    for_each_vma(vmi, vma)
#else
        for (vma = mm->mmap; vma; vma = vma->vm_next)
#endif
    {
        char *path_nm;
        if (vma->vm_file) {
            path_nm = file_path(vma->vm_file, buf, PATH_MAX - 1);
            if (IS_ERR(path_nm)) {
                continue;
            }

            if (!strcmp(kbasename(path_nm), name)) {
                result = vma->vm_start;
                goto ret;
            }

        }
    }

    ret:
    MM_READ_UNLOCK(mm)

#ifdef CONFIG_MMU
    mmput_async(mm);
#else
    mmput(mm);
#endif
    kfree(buf);
    return result;
}

phys_addr_t vaddr_to_phy_addr(struct mm_struct *mm, uintptr_t va) {
    pgd_t * pgd;
#if __PAGETABLE_P4D_FOLDED == 1
    p4d_t *p4d;
#endif
    pmd_t *pmd;
    pte_t *pte;
    pud_t *pud;

    phys_addr_t page_addr;
    uintptr_t page_offset;

    pgd = pgd_offset(mm, va);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        return 0;
    }
#if __PAGETABLE_P4D_FOLDED == 1
    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
        return 0;
    }
    pud = pud_offset(p4d, va);
#else
    pud = pud_offset(pgd, va);
#endif
    if (pud_none(*pud) || pud_bad(*pud)) {
        return 0;
    }
    pmd = pmd_offset(pud, va);
    if (pmd_none(*pmd)) {
        return 0;
    }
    pte = pte_offset_kernel(pmd, va);
    if (pte_none(*pte)) {
        return 0;
    }
    if (!pte_present(*pte)) {
        return 0;
    }
    page_addr = (phys_addr_t) (pte_pfn(*pte) << PAGE_SHIFT);
    page_offset = va & (PAGE_SIZE - 1);

    return page_addr + page_offset;
}