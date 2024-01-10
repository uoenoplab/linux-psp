#include <linux/net.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <net/inet_common.h>
#include <net/sock.h>
#include <net/udp.h>
#include "psp.h"

// structs needed to define protocol
static const struct proto psp_prot;
static const struct proto_ops psp_ops;
static const struct net_proto_family psp_family;

struct psp_sock {
	struct inet_sock isock;
	// add psp specific members 
};

static int psp_sock_create(struct net *net, struct socket *sock, int protocol, int kern){
	struct sock *sk;
	int rc;
	sk = sk_alloc(net, PF_PSP, GFP_KERNEL, &psp_prot, kern);
	if (!sk) {
		printk(KERN_ERR, "psp: sk_alloc failed\n");
		return -ENOMEM;
	}

	sock_init_data(sock, sk);
	sk->sk_protocol = protocol;

	sock->ops = &psp_ops;
	sock->state = SS_UNCONNECTED;

	// psp specific init.

	return 0;
}

static int psp_init(){
	int rc;
	rc = proto_register(&psp_prot, 1);
	return rc;
}

static int psp_cleanup(){
	proto_unregister(&psp_prot);
	return 0;
}

module_init(psp_init);
module_exit(psp_cleanup);

static const struct proto psp_prot = {
	.close = my_close,
	.connect = my_connect,
	.disconnect = my_disconnect,
	.accept = my_accept,
	.ioctl = my_ioctl,
	.init = my_init_sock,
	.shutdown = my_shutdown,
	.setsockopt = my_setsockopt,
	.getsockopt = my_getsockopt,
	.sendmsg = my_sendmsg,
	.recvmsg = my_recvmsg,
	.unhash = my_unhash,	// remove from hash tables
	.get_port = my_get_port, // get port 
	.sockets_allocated = &sockets_allocated,
	.memory_allocated = &memory_allocated,
	.memory_pressure = &memory_pressure,
	.orphan_count = &orphan_count,
	.sysctl_mem = sysctl_tcp_mem,
	.sysctl_wmem = sysctl_tcp_wmem,
	.sysctl_rmem = sysctl_tcp_rmem,
	.max_header = 0,
	.obj_size = sizeof(struct psp_sock),
	.owner = THIS_MODULE,
	.name = "PSP",
};

static const struct proto_ops psp_ops = {
	.family = PF_INET,
	.owner = THIS_MODULE,
	.release = inet_release,
	.bind = inet_bind,
	.connect = inet_stream_connect,
	.socketpair = sock_no_socketpair,
	.accept = inet_accept,
	.getname = inet_getname,
	.poll = datagram_poll,
	.ioctl = inet_ioctl,
	.listen = inet_listen,
	.shutdown = inet_shutdown,
	.setsockopt = sock_common_setsockopt,
	.getsockopt = sock_common_getsockopt,
	.sendmsg = inet_sendmsg,
	.recvmsg = sock_common_recvmsg,
};

static const struct net_proto_family psp_family = {
	.family = PF_INET,
	.create = psp_sock_create,
	.owner = THIS_MODULE,
};