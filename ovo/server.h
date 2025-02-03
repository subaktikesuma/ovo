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

#define OPT_GET_PROCESS_PID 0
#define OPT_IS_PROCESS_PID_ALIVE 1
#define OPT_GET_PROCESS_MODULE_BASE	2

int init_server(void);

void exit_server(void);

#endif //OVO_SERVER_H
