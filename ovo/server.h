//
// Created by fuqiuluo on 25-2-3.
//

#ifndef OVO_SERVER_H
#define OVO_SERVER_H

#include <linux/completion.h>
#include <linux/bpf.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <net/sock.h>

#define REQ_GET_PROCESS_PID 0
#define REQ_IS_PROCESS_PID_ALIVE 1
#define REQ_ATTACH_PROCESS	2
#define REQ_GET_PROCESS_MODULE_BASE	3
#define REQ_READ_PROCESS_MEMORY_IOREMAP	4
#define REQ_WRITE_PROCESS_MEMORY_IOREMAP 5
#define REQ_ACCESS_PROCESS_VM	6
#define REQ_READ_PROCESS_MEMORY	7
#define REQ_WRITE_PROCESS_MEMORY 8

struct req_access_process_vm {
	pid_t from;
	void __user* from_addr;
	pid_t to;
	void __user* to_addr;
	size_t size;
};

struct ovo_sock {
	pid_t pid;
};

int init_server(void);

void exit_server(void);

#endif //OVO_SERVER_H
