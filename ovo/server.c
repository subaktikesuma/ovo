//
// Created by fuqiuluo on 25-2-3.
//
#include "server.h"
#include <linux/init.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/socket.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/rculist.h>
#include <linux/vmalloc.h>
#include <net/busy_poll.h>
#include "kkit.h"
#include "memory.h"

static int ovo_release(struct socket *sock) {
	struct sock *sk = sock->sk;

	if (sk) {
		sock_orphan(sk);
		sock_put(sk);
	}

	//pr_info("[ovo] OVO socket released!\n");
	return 0;
}

static __poll_t ovo_poll(struct file *file, struct socket *sock,
						 struct poll_table_struct *wait) {
	return 0;
}

static int ovo_setsockopt(struct socket *sock, int level, int optname,
						  sockptr_t optval, unsigned int optlen)
{
	switch (optname) {
		default:
			break;
	}

	return -ENOPROTOOPT;
}

__always_inline int ovo_get_process_pid(int len, char __user *process_name_user) {
	int err;
	char* process_name = kmalloc(len, GFP_KERNEL);
	if (!process_name) {
		return -ENOMEM;
	}

	if (copy_from_user(process_name, process_name_user, len)) {
		err = -EFAULT;
		goto out_proc_name;
	}

	pid_t pid = find_process_by_name(process_name);
	if (pid < 0) {
		err = -ESRCH;
		goto out_proc_name;
	}

	err = put_user((int) pid, (pid_t*) process_name_user);
	if (err)
		goto out_proc_name;

	out_proc_name:
	kfree(process_name);
	return err;
}

__always_inline int ovo_get_process_module_base(int len, pid_t pid, char __user *module_name_user, int flag) {
	int err;
	char* module_name;

	module_name = kmalloc(len, GFP_KERNEL);
	if (!module_name) {
		return -ENOMEM;
	}

	if (copy_from_user(module_name, module_name_user, len)) {
		err = -EFAULT;
		goto out_module_name;
	}

	uintptr_t base = get_module_base(pid, module_name, flag);
	if (base == 0) {
		err = -ENAVAIL;
		goto out_module_name;
	}

	err = put_user((uintptr_t) base, (uintptr_t*) module_name_user);
	if (err)
		goto out_module_name;

	out_module_name:
	kfree(module_name);
	return err;
}

/*
 * Don't worry about why the varname here is wrong,
 * in fact, this operation is similar to using ContentProvider to interact with Xposed module in Android,
 * and that thing is also wrong!
 */
static int ovo_getsockopt(struct socket *sock, int level, int optname,
						  char __user *optval, int __user *optlen)
{
	struct sock* sk;
	struct ovo_sock* os;
	int len, alive, ret;
	unsigned long pfn;

	sk = sock->sk;
	if (!sk)
		return -EINVAL;
	os = ((struct ovo_sock*)((char *) sock->sk + sizeof(struct sock)));

	switch (optname) {
		case REQ_GET_PROCESS_PID: {
			return ovo_get_process_pid(level, optval);
		}
		case REQ_IS_PROCESS_PID_ALIVE: {
			alive = is_pid_alive(level);
			if (put_user(alive, optlen)) {
				return -EFAULT;
			}
			return 0;
		}
		case REQ_ATTACH_PROCESS: {
			if(is_pid_alive(level) == 0) {
				return -ESRCH;
			}
			os->pid = level;
			pr_info("[ovo] attached process: %d\n", level);
			return 0;
		}
		case REQ_ACCESS_PROCESS_VM: {
			if (get_user(len, optlen))
				return -EFAULT;

			if (len < sizeof(struct req_access_process_vm))
				return -EINVAL;

			struct req_access_process_vm req;
			if (copy_from_user(&req, optval, sizeof(struct req_access_process_vm)))
				return -EFAULT;

			return access_process_vm_by_pid(req.from, req.from_addr, req.to, req.to_addr, req.size);
		}
		default:
			break;
	}

	// The following need to attach to a process!
	// u should check whether the attached process is legitimate
	if (os->pid <= 0 || is_pid_alive(os->pid) == 0) {
		return -ESRCH;
	}

	switch (optname) {
		case REQ_GET_PROCESS_MODULE_BASE: {
			if (get_user(len, optlen))
				return -EFAULT;

			if (len < 0)
				return -EINVAL;

			return ovo_get_process_module_base(len, os->pid, optval, level);
		}
		case REQ_READ_PROCESS_MEMORY_IOREMAP: {
			return read_process_memory_ioremap(os->pid, (void *) optval, (void *) optlen, level);
		}
		case REQ_WRITE_PROCESS_MEMORY_IOREMAP: {
			return write_process_memory_ioremap(os->pid, (void *) optval, (void *) optlen, level);
		}
		case REQ_READ_PROCESS_MEMORY: {
			return read_process_memory(os->pid, (void *) optval, (void *) optlen, level);
		}
		case REQ_WRITE_PROCESS_MEMORY: {
			return write_process_memory(os->pid, (void *) optval, (void *) optlen, level);
		}
		case REMAP_MEMORY: {
			if (atomic_cmpxchg(&os->remap_in_progress, 0, 1) != 0)
				return -EBUSY;

			ret = process_vaddr_to_pfn(os->pid, optval, &pfn, level);
			if (ret) {
				pr_err("[ovo] process_vaddr_to_pfn failed\n");
				return ret;
			}

			os->pfn = pfn;
			//os->pfn_prot = prot;
			return 0;
		}
		default:
			break;
	}

	return -EOPNOTSUPP;
}

int ovo_mmap(struct file *file, struct socket *sock,
				 struct vm_area_struct *vma) {
	int ret;
	struct ovo_sock *os;

	if (!sock->sk) {
		return -EINVAL;
	}
	os = (struct ovo_sock*)((char *) sock->sk + sizeof(struct sock));

	atomic_set(&os->remap_in_progress, 0);

	if (os->pid <= 0 || is_pid_alive(os->pid) == 0) {
		return -ESRCH;
	}

	if (!os->pfn) {
		return -EFAULT;
	}

	if (system_supports_mte()) {
		vm_flags_set(vma, VM_MTE);
	}
	vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);

	ret = remap_process_memory(vma, os->pfn, vma->vm_end - vma->vm_start);
	return ret;
}

static struct proto ovo_proto = {
	.name =		"OVO",
	.owner =	THIS_MODULE,
	.obj_size =	sizeof(struct sock) + sizeof(struct ovo_sock),
};

static struct proto_ops ovo_proto_ops = {
	.family		= PF_DECnet,
	.owner		= THIS_MODULE,
	.release	= ovo_release,
	.bind		= sock_no_bind,
	.connect	= sock_no_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= sock_no_accept,
	.getname	= sock_no_getname,
	.poll		= ovo_poll,
	.ioctl		= sock_no_ioctl,
	.listen		= sock_no_listen,
	.shutdown	= sock_no_shutdown,
	.setsockopt	= ovo_setsockopt,
	.getsockopt	= ovo_getsockopt,
	.sendmsg	= sock_no_sendmsg,
	.recvmsg	= sock_no_recvmsg,
	.mmap		= ovo_mmap
};

static int free_family = AF_DECnet;

static int ovo_create(struct net *net, struct socket *sock, int protocol,
					  int kern)
{
	uid_t caller_uid;
	struct sock *sk;
	struct ovo_sock *os;

	caller_uid = *((uid_t*) &current_cred()->uid);
	if (caller_uid != 0) {
		pr_warn("[ovo] Only root can create OVO socket!\n");
		return -EAFNOSUPPORT;
	}

	if (sock->type != SOCK_RAW) {
		//pr_warn("[ovo] a OVO socker must be SOCK_RAW!\n");
		return -ENOKEY;
	}

	sock->state = SS_UNCONNECTED;

	sk = sk_alloc(net, PF_INET, GFP_KERNEL, &ovo_proto, kern);
	if (!sk) {
		pr_warn("[ovo] sk_alloc failed!\n");
		return -ENOBUFS;
	}

	os = (struct ovo_sock*)((char *) sk + sizeof(struct sock));

	ovo_proto_ops.family = free_family;
	sock->ops = &ovo_proto_ops;
	sock_init_data(sock, sk);

	// Initialize the ovo_sock
	os->pid = 0;
	os->pfn = 0;
	atomic_set(&os->remap_in_progress, 0);

	//pr_info("[ovo] OVO socket created!\n");
	return 0;
}

static struct net_proto_family ovo_family_ops = {
	.family = PF_DECnet,
	.create = ovo_create,
	.owner	= THIS_MODULE,
};

static int register_free_family(void) {
	int family;
	int err;
	for(family = free_family; family < NPROTO; family++) {
		ovo_family_ops.family = family;
		err = sock_register(&ovo_family_ops);
		if (err)
			continue;
		else {
			free_family = family;
			pr_info("[ovo] Find free proto_family: %d\n", free_family);
			return 0;
		}
	}

	pr_err("[ovo] Can't find any free proto_family!\n");
	return err;
}

int init_server(void) {
	int err;

	err = proto_register(&ovo_proto, 1);
	if (err)
		goto out;

	err = register_free_family();
	if (err)
		goto out_proto;

	return 0;

	sock_unregister(free_family);
	out_proto:
	proto_unregister(&ovo_proto);
	out:
	return err;
}

void exit_server(void) {
	sock_unregister(free_family);
	proto_unregister(&ovo_proto);
}