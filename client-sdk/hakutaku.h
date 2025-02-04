#ifndef HAKUTAKU_H
#define HAKUTAKU_H

#include <sys/uio.h>
#include <filesystem>
#include <dirent.h>
#include <string>
#include <vector>
#include <list>

#define VM_READ		0x00000001	/* currently active flags */
#define VM_WRITE	0x00000002
#define VM_EXEC		0x00000004
#define VM_SHARED	0x00000008

namespace hak {
	// Process State
	struct proc_stat {
		pid_t pid;
		std::string comm;
		char state;
		pid_t ppid;
	};

	// Get process list
	auto get_process_list() -> std::vector<proc_stat>;

	// Get pid list
	auto get_pid_list() -> std::vector<pid_t>;

	/**
	 * Read proc file
	 * @param package
	 * @return pid_t
	 */
	auto find_process(std::string_view package) -> pid_t;

	// get module base
	auto get_module_base(pid_t pid, std::string_view module) -> uintptr_t;

	enum DRIVER_FUNCTION_REQUEST: int {
		GET_PROCESS_PID = 0,
		IS_PROCESS_ALIVE_PID = 1,
		ATTACH_PROCESS = 2,
		GET_PROCESS_MODULE_BASE = 3,
		READ_PROCESS_MEMORY_IOREMAP = 4,
		WRITE_PROCESS_MEMORY_IOREMAP = 5,
		ACCESS_PROCESS_VM = 6,
		READ_PROCESS_MEMORY = 7,
		WRITE_PROCESS_MEMORY = 8,
		REMAP_MEMORY = 9,
	};

	class driver {
		public:
		driver();

		~driver();

		bool active();

		/**
		 * 获取进程PID
		 * @param package
		 * @return pid_t
		 */
		pid_t get_process_pid(std::string_view package);

		bool is_process_alive_pid(pid_t pid);

		/**
		 * 无需附加进程读写进程内存 (缺页不会终止)
		 * @param from
		 * @param from_addr
		 * @param to
		 * @param to_addr
		 * @param len
		 * @return 读取的数据长度
		 *
		 * @note ESRCH 无效的PID
		 * @note ENOMEM 内核内存不足
		 * @note EIO 无效的地址/读取失败
		 */
		int access_process_vm(pid_t from, uintptr_t from_addr, pid_t to, uintptr_t to_addr, size_t len);

		int attach_process_pid(pid_t pid);

		/**
		 * 获取进程模块基址
		 * @param module
		 * @param vm_flag  VM_READ, VM_WRITE, VM_EXEC, VM_SHARED
		 * @return
		 */
		uintptr_t get_process_module_base(std::string_view module, int vm_flag);

		/**
		 * 读写进程内存通过ioremap
		 * @param addr
		 * @param buffer
		 * @param size
		 * @return 读取的数据长度
		 *
		 * @note EFAULT 无效的目标地址/缺页
		 * @note ESRCH 目标进程死亡
		 * @note EACCES `buffer` 地址不合法
		 */
		size_t read_process_memory_ioremap(uintptr_t addr, void* buffer, size_t size);
		size_t write_process_memory_ioremap(uintptr_t addr, void* buffer, size_t size);

		size_t read_process_memory(uintptr_t addr, void* buffer, size_t size);
		size_t write_process_memory(uintptr_t addr, void* buffer, size_t size);

		/**
		 * 重新映射内存
		 * @param addr
		 * @param size
		 * @param buffer
		 * @return
		 *
		 * @warning 如果输入的地址对应的物理地址没有对齐会自动对齐以获取正确的pfn, 即向下对齐(丢弃低位)！
		 * @warning（请确保输入的地址是对齐的）
		 */
		int remap_memory(uintptr_t addr, size_t size, void** buffer);
		private:
		int sock;

		static auto find_driver_id() -> int;
	};
}

#endif //HAKUTAKU_H
