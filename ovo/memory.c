//
// Created by fuqiuluo on 25-1-22.
//
#include "memory.h"

#include <linux/tty.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/memory.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <asm/page.h>
#include <linux/pgtable.h>
#include <linux/vmalloc.h>
#include <linux/mman.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0))
#include <linux/mmap_lock.h>
#define MM_READ_LOCK(mm) mmap_read_lock(mm);
#define MM_READ_UNLOCK(mm) mmap_read_unlock(mm);
#else
#include <linux/rwsem.h>
#define MM_READ_LOCK(mm) down_read(&(mm)->mmap_sem);
#define MM_READ_UNLOCK(mm) up_read(&(mm)->mmap_sem);
#endif

#include "mmuhack.h"
#include "kkit.h"

#ifdef CONFIG_CMA
//#warning CMA is enabled!
#endif

#if !defined(ARCH_HAS_VALID_PHYS_ADDR_RANGE) || defined(MODULE)
static inline int memk_valid_phys_addr_range(phys_addr_t addr, size_t size)
{
	return addr + size <= __pa(high_memory);
}
#define IS_VALID_PHYS_ADDR_RANGE(x,y) memk_valid_phys_addr_range(x,y)
#else
#define IS_VALID_PHYS_ADDR_RANGE(x,y) valid_phys_addr_range(x,y)
#endif

uintptr_t get_module_base(pid_t pid, char *name, int vm_flag) {
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
    struct vma_iterator vmi;
#endif
    uintptr_t result;
	struct dentry *dentry;
	size_t name_len;

    result = 0;

	name_len = strlen(name);
	if (name_len == 0) {
		pr_err("[ovo] module name is empty\n");
		return 0;
	}

    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
		pr_err("[ovo] failed to find pid_struct\n");
        return 0;
    }

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) {
		pr_err("[ovo] failed to get task from pid_struct\n");
        return 0;
    }

    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) {
		pr_err("[ovo] failed to get mm from task\n");
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
        if (vma->vm_file && (vma->vm_flags & vm_flag)) {
			dentry = vma->vm_file->f_path.dentry;
			if (!memcmp(dentry->d_name.name, name, min(name_len, dentry->d_name.len))) {
				result = vma->vm_start;
				goto ret;
			}
        }
    }

    ret:
    MM_READ_UNLOCK(mm)

    mmput(mm);
    return result;
}

phys_addr_t vaddr_to_phy_addr(struct mm_struct *mm, uintptr_t va) {
    pte_t *ptep;
    phys_addr_t page_addr;
    uintptr_t page_offset;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0) && defined(OVO_0X202501232139)
    spinlock_t *ptlp;
#endif

    if (!mm) return 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0) && defined(OVO_0X202501232139)
    follow_pte(mm, va, &pte, &ptlp); // not export!
#else
    ptep = page_from_virt_user(mm, va);
#endif

    if (!pte_present(*ptep)) {
        return 0;
    }

    // #define __pte_to_phys(pte)	(pte_val(pte) & PTE_ADDR_MASK)
    page_offset = va & (PAGE_SIZE - 1);
#if defined(__pte_to_phys)
    page_addr = (phys_addr_t) __pte_to_phys(*ptep);
#elif defined(pte_pfn)
    page_addr = (phys_addr_t) (pte_pfn(*pte) << PAGE_SHIFT);
#else
#error unsupported kernel version：__pte_to_phys or pte_pfn
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0) && defined(OVO_0X202501232139)
    pte_unmap_unlock(pte, ptlp);
#endif

    if (page_addr == 0) { // why?
        return 0;
    }

    return page_addr + page_offset;
}

static int pid_vaddr_to_phy(pid_t global_pid, void *addr, phys_addr_t* pa) {
	struct task_struct *task;
	struct mm_struct *mm;
	struct pid *pid_struct;

	pid_struct = find_get_pid(global_pid);
	if (!pid_struct) {
		pr_err("[ovo] failed to find pid_struct: %s\n", __func__);
		return -ESRCH;
	}

	task = get_pid_task(pid_struct, PIDTYPE_PID);
	put_pid(pid_struct);
	if(!task) {
		pr_err("[ovo] failed to get task from pid_struct: %s\n", __func__);
		return -ESRCH;
	}

	mm = get_task_mm(task);
	if (!mm) {
		pr_err("[ovo] failed to get mm from task: %s\n", __func__);
		return -ESRCH;
	}

	MM_READ_LOCK(mm)
	*pa = vaddr_to_phy_addr(mm, (uintptr_t)addr);
	MM_READ_UNLOCK(mm)
	mmput(mm);
	put_task_struct(task);

	if(*pa == 0) {
		return -EFAULT;
	}

	return 0;
}

int read_process_memory_ioremap(pid_t pid, void __user*addr, void __user*dest, size_t size) {
    phys_addr_t phy_addr;
    int ret;
    void* mapped;

	if (!access_ok(dest, size)) {
		pr_err("[ovo] access_ok failed: %s\n", __func__);
		return -EACCES;
	}

    ret = pid_vaddr_to_phy(pid, addr, &phy_addr);
	if (ret) {
		pr_err("[ovo] pid_vaddr_to_phy failed: %s\n", __func__);
		return ret;
	}

    if (pa && pfn_valid(__phys_to_pfn(pa)) && IS_VALID_PHYS_ADDR_RANGE(pa, size)){
        mapped = ioremap_cache(pa, size);
        if (mapped && !copy_to_user(dest, mapped, size)) {
            ret = 0;
        }
        if (mapped) {
            iounmap(mapped);
        }
    } else {
		ret = -EFAULT;
	}

    return ret;
}

int write_process_memory_ioremap(pid_t pid, void __user*addr, void __user*src, size_t size) {
    phys_addr_t pa;
    int ret;
    void* mapped;

	if (!access_ok(src, size)) {
		return -EACCES;
	}

	ret = pid_vaddr_to_phy(pid, addr, &pa);
	if (ret) {
		pr_err("[ovo] pid_vaddr_to_phy failed: %s\n", __func__);
		return ret;
	}

    if (pa && pfn_valid(__phys_to_pfn(pa)) && IS_VALID_PHYS_ADDR_RANGE(pa, size)){
        // why not use kmap_atomic?
        // '/proc/vmstat' -> nr_isolated_anon & nr_isolated_file
        // There is a quantity limit, it will panic when used up!
        mapped = ioremap_cache(pa, size);
		if (!mapped) {
			ret = -ENOMEM;
		} else if (copy_from_user(mapped, src, size)) {
			ret = -EACCES;
		} else {
			ret = 0;
		}
        if (mapped) {
            iounmap(mapped);
        }
    }

    return ret;
}

int access_process_vm_by_pid(pid_t from, void __user*from_addr, pid_t to, void __user*to_addr, size_t size) {
    struct task_struct *task;
    char __kernel *buf;
    int ret;

    rcu_read_lock();
    // find_vpid() does not take a reference to the pid, so we must hold RCU
    task = pid_task(find_vpid(from), PIDTYPE_PID);
    rcu_read_unlock();

    if (!task || !task->mm) return -ESRCH;

    buf = vmalloc(size);
    if (!buf) return -ENOMEM;

    ret = access_process_vm(task, (unsigned long) from_addr, buf, (int) size, 0);
    if (ret != size) {
        vfree(buf);
		put_task_struct(task);
        return -EIO;
    }
	put_task_struct(task);

	pid_struct = find_get_pid(to);
	if (!pid_struct) {
		pr_err("[ovo] failed to find pid_struct(to): %s\n", __func__);
		vfree(buf);
		return -ESRCH;
	}

	task = get_pid_task(pid_struct, PIDTYPE_PID);
	put_pid(pid_struct);
	if(!task) {
		pr_err("[ovo] failed to get task from pid_struct(to): %s\n", __func__);
		vfree(buf);
		return -ESRCH;
	}

    ret = access_process_vm(task, (unsigned long) to_addr, buf, (int) size, FOLL_WRITE);
    if (ret != size) {
        vfree(buf);
		put_task_struct(task);
        return -EIO;
    }

    vfree(buf);
	put_task_struct(task);
    return 0;
}

int read_process_memory(pid_t pid, void *addr, void *dest, size_t size) {
	phys_addr_t pa;
	int ret;
	void* mapped;

	if (!access_ok(dest, size)) {
		return -EACCES;
	}

	ret = pid_vaddr_to_phy(pid, addr, &pa);
	if (ret) {
		pr_err("[ovo] pid_vaddr_to_phy failed: %s\n", __func__);
		return ret;
	}

	if (pa && pfn_valid(__phys_to_pfn(pa)) && IS_VALID_PHYS_ADDR_RANGE(pa, size)){
		mapped = phys_to_virt(pa);
		if (!mapped) {
			ret = -ENOMEM;
		} else if (copy_to_user(dest, mapped, size)) {
			ret = -EACCES;
		} else {
			ret = 0;
		}
	}

	return ret;
}

int write_process_memory(pid_t pid, void *addr, void *src, size_t size) {
	phys_addr_t pa;
	int ret;
	void* mapped;

	if (!access_ok(src, size)) {
		return -EACCES;
	}

	ret = pid_vaddr_to_phy(pid, addr, &pa);
	if (ret) {
		pr_err("[ovo] pid_vaddr_to_phy failed: %s\n", __func__);
		return ret;
	}

	if (pa && pfn_valid(__phys_to_pfn(pa)) && IS_VALID_PHYS_ADDR_RANGE(pa, size)){
		mapped = phys_to_virt(pa);
		if (!mapped) {
			ret = -ENOMEM;
		} else if (copy_from_user(mapped, src, size)) {
			ret = -EACCES;
		} else {
			ret = 0;
		}
	}
	return ret;
}

#if BUILD_REMAP == 1
void* remap_process_memory(pid_t from, void *from_addr, pid_t to, size_t size) {
    static struct vm_area_struct *(*ovo_vm_area_alloc)(struct mm_struct *) = NULL;
    struct task_struct *from_task, *to_task;
    struct vm_area_struct *from_vma, *vma;
    pte_t* ptep;
    unsigned long pfn;
    void* unmapped_addr;
    unsigned long (*get_area)(struct file *, unsigned long,
                              unsigned long, unsigned long, unsigned long);
    struct mm_struct* mm;

    if (!capable(CAP_SYS_ADMIN))
        return NULL;

    size = PAGE_ALIGN(size);
    if (!from_addr || !size || size > TASK_SIZE)
        return NULL;

    if (ovo_vm_area_alloc == NULL) {
        ovo_vm_area_alloc = (struct vm_area_struct *(*)(struct mm_struct *))
                ovo_kallsyms_lookup_name("vm_area_alloc");
    }

    if(ovo_vm_area_alloc == NULL) {
        pr_err("[ovo] ovo_vm_area_alloc not found!");
        return NULL;
    }

    {
        rcu_read_lock();
        from_task = pid_task(find_vpid(from), PIDTYPE_PID);
        to_task = pid_task(find_vpid(to), PIDTYPE_PID);

        if (!from_task || !to_task || !from_task->mm || !to_task->mm)
            return NULL;

        get_task_struct(from_task);
        get_task_struct(to_task);
        rcu_read_unlock();
    }

    mm = get_task_mm(from_task);

    from_vma = find_vma(mm, (unsigned long)from_addr);
    if (!from_vma) {
        mmput(mm);
        put_task_struct(from_task);
        put_task_struct(to_task);
        return NULL;
    }

    ptep = page_from_virt_user(mm, (unsigned long) from_addr);
    pfn = pte_pfn(READ_ONCE(*ptep));

    { // release from_task's mm & from_task
        mmput(mm);
        put_task_struct(from_task);
        mm = NULL;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 10, 0)
#error "remap_process_memory: Not support Kernel 6.11.0"
#else
    mm = get_task_mm(to_task);
    get_area = mm->get_unmapped_area;
#endif

    unmapped_addr = (void*) get_area(NULL, 0, size, 0, 0);
    if (IS_ERR_VALUE(unmapped_addr)) {
        mmput(mm);
        put_task_struct(to_task);
        return NULL;
    }

    if ((unsigned long ) unmapped_addr > TASK_SIZE - size) {
        mmput(mm);
        put_task_struct(to_task);
        return NULL;
    }

    if (offset_in_page((unsigned long) unmapped_addr)) {
        mmput(mm);
        put_task_struct(to_task);
        return NULL;
    }

    vma = ovo_vm_area_alloc(mm);
    if (!vma) {
        mmput(mm);
        put_task_struct(to_task);
        return NULL;
    }

    vma->vm_start = (unsigned long) unmapped_addr;
    vma->vm_end = ((unsigned long) unmapped_addr) + size;
    *((unsigned long*) &vma->vm_flags) =
            calc_vm_prot_bits(PROT_READ | PROT_WRITE, 0);
    vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);

    if(remap_pfn_range(vma, (unsigned long)unmapped_addr, pfn, size, PAGE_SHARED)) {
        pr_err("[ovo] remap_pfn_range failed!");
        mmput(mm);
        put_task_struct(to_task);
        return NULL;
    }

    mmput(mm);
    put_task_struct(to_task);
    return unmapped_addr;
}

int unmap_process_memory(pid_t from, void *from_addr, size_t size) {
    struct task_struct *from_task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    pte_t* ptep;
    unsigned long pfn;

    rcu_read_lock();
    from_task = pid_task(find_vpid(from), PIDTYPE_PID);

    if (!from_task)
        return -ESRCH;

    get_task_struct(from_task);
    rcu_read_unlock();

    mm = get_task_mm(from_task);
    if (!mm)
        return -ESRCH;

    vma = find_vma(mm, (unsigned long)from_addr);
    if (!vma) {
        mmput(mm);
        put_task_struct(from_task);
        return -ESRCH;
    }

    ptep = page_from_virt_user(mm, (unsigned long) from_addr);
    pfn = pte_pfn(READ_ONCE(*ptep));

    if (remap_pfn_range(vma, (unsigned long)from_addr, 0, size, PAGE_SHARED)) {
        mmput(mm);
        put_task_struct(from_task);
        return -EIO;
    }

    mmput(mm);
    put_task_struct(from_task);
    return 0;
}
#endif
