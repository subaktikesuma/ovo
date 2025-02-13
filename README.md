# OvO
A kernel driver module designed to provide portable hacking operations!

Rootkit operation of some kernel modules is provided for the kernel of android-aarch64, this is a learning project of mine, and some mistakes may be corrected in the future.

## Inter-communication ~~(supports multiple users)~~
By implementing a custom network protocol family, user space communication can be achieved both synchronously and asynchronously without relying on character devices or netlinks:
- No filesystem operations required
- Low overhead implementation without using kprobes for system call interception
- Uses stable kernel interfaces for improved maintainability

## Features

### Module Base Address Acquisition (`memory.h->get_module_base`)
Provides an alternative method to get module base addresses without reading `/proc/self/maps`, which may be monitored by anti-cheat software.

### Process Memory Operations

#### Virtual to Physical Address Translation (`memory.h->vaddr_to_phy_addr`)
Converts virtual addresses (VA) to physical addresses (PA) by:
- Traversing page table hierarchy (PGD -> P4D -> PUD -> PMD -> PTE)
- Handling page table folding and huge pages
- Computing final physical address using page frame number and offset

#### Memory Read/Write Operations
Two implementations available:
- `memory.h->rw_process_memory`: Custom implementation using page table traversal and physical address mapping
- `memory.h->access_process_vm_by_pid`: Utilizes kernel's built-in `access_process_vm` function for direct process memory access

### Root Privilege Escalation (`kkit.h->mark_pid_root`) (Deprecated)
A stealthy approach to elevate process privileges by:
- Locating target process's `task_struct`
- Creating new credentials with root uid/gid (0)
- Directly modifying process credential pointer instead of using `commit_creds()`
- Avoiding root uid visibility in ps command output

### Fast Cross-Process Memory Remapping (`process_vaddr_to_pfn`, `remap_process_memory`)
An efficient approach for cross-process memory access by:
- Converting source process virtual address to physical page frame number (PFN)
- Directly remapping memory through page table manipulation
- Bypassing traditional system calls and memory copy operations
- Achieving 3ms per 100M operations vs 80ms/100k ops with traditional methods

Performance highlights:
- Direct page table access without syscalls
- 100M memory operations: ~3ms
- Traditional approach (ioremap): 80ms for 100k operations
- ~26,000x performance improvement over conventional methods

### Touch Event Simulation
Implements comprehensive touch event simulation through IOCTL interface with following capabilities:
- Touch event handling (`ovo_ioctl`):
    - Down events (`CMD_TOUCH_CLICK_DOWN`): Simulates finger press with pressure and position data
    - Up events (`CMD_TOUCH_CLICK_UP`): Handles touch release
    - Move events (`CMD_TOUCH_MOVE`): Processes continuous touch movement
- Event features:
    - Multi-touch support through slot management
    - Precise position control (X, Y coordinates)
    - Pressure simulation
    - Event pooling with overflow protection
- Implementation details:
    - Uses spinlock for thread-safe event handling
    - Implements proper error handling and user-space data validation
    - Efficient event caching through `input_event_cache`
    - Supports MT protocol for touch reporting

# CI Support
- [android-kernel-build-action](https://github.com/feicong/android-kernel-build-action/tree/main)