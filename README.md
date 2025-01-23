# OvO

本项目只为安卓在aarch64架构的内核服务。提供了一些内核模块的rootkit操作，可能违背KISS原则。 其他情况请移步到[KernelInlineHook](https://github.com/WeiJiLab/kernel-inline-hook-framework)。

> 本项目的部分操作可能导致设备无法正常使用，使用前请做好备份工作。

## 功能

### 获取目标进程对应模块基址

一些反作弊工具会监听`/proc/self/maps`，如果读取这里可能会被检测到，所以这里提供了一种获取模块基址的方法。

### 将某个进程提权到root

通过PID找到目标进程的`task_struct`结构，创建新的`credentials结构(cred)`，设置uid/gid为`0(root)`，直接修改进程的cred指针，而不是通过标准的`commit_creds`函数。 
其中使用了一个隐蔽的方式来提权，通过直接修改cred指针而不是`commit_creds()`，这样在ps命令下不会显示root uid。

### 虚拟内存地址转物理内存地址

用于将虚拟地址(VA)转换为物理地址(PA)。核心功能： 

- 遍历页表层次结构(PGD -> P4D -> PUD -> PMD -> PTE)
- 最终从PTE获取物理页帧号，加上页内偏移得到完整物理地址

> 考虑了页表折叠的情况(`__PAGETABLE_P4D_FOLDED`)

### 内存读写



- [x] 读取/写入目标进程内存
- [x] 将目标进程的内存映射到指定进程

