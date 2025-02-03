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

inline int opt_get_process_pid(int len, char __user *process_name_user) {
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

static int ovo_getsockopt(struct socket *sock, int level, int optname,
						  char __user *optval, int __user *optlen)
{
	int len;

	if (get_user(len, optlen))
		return -EFAULT;

	if (len < 0)
		return -EINVAL;

	switch (optname) {
		case OPT_GET_PROCESS_PID: {
			return opt_get_process_pid(len, optval);
		}
		default:
			break;
	}

	return -EOPNOTSUPP;
}

static struct proto ovo_proto = {
	.name =		"OVO",
	.owner =	THIS_MODULE,
	.obj_size =	sizeof(struct sock),
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
	.mmap		= sock_no_mmap,
};

static int free_family = AF_DECnet;

static int ovo_create(struct net *net, struct socket *sock, int protocol,
					  int kern)
{
	uid_t caller_uid;
	struct sock *sk;

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

	ovo_proto_ops.family = free_family;
	sock->ops = &ovo_proto_ops;
	sock_init_data(sock, sk);

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