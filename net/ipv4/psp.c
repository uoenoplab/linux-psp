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
	rc = sock_register(&psp_family);
	return rc;
}

static void psp_close(struct sock *sk, long timeout){
	// !TODO
}

static int psp_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len){
	// !TODO
}

static int psp_disconnect(struct sock *sk, int flags){
	// !TODO
}

static int psp_accept(struct sock *sk, struct socket *newsock, int flags){
	// !TODO
}

static int psp_ioctl(struct sock *sk, int cmd, unsigned long arg){
	// !TODO
}

static int psp_init_sock(struct sock *sk){
	// !TODO
}

static int psp_shutdown(struct sock *sk, int how){
	// !TODO
}

static int psp_setsockopt(struct sock *sk, int level, int optname, char __user *optval, unsigned int optlen){
	// !TODO
}

static int psp_getsockopt(struct sock *sk, int level, int optname, char __user *optval, int __user *optlen){
	// !TODO
}

static int psp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len){
	// !TODO
}

static int psp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int noblock, int flags, int *addr_len){
	// !TODO
}

static void psp_unhash(struct sock *sk){
	// !TODO
}

static int psp_get_port(struct sock *sk, unsigned short snum){
	// !TODO
}

static int psp_cleanup(){
	proto_unregister(&psp_prot);
	sock_unregister(PF_PSP);
	return 0;
}

module_init(psp_init);
module_exit(psp_cleanup);

static const struct proto psp_prot = {
	.close = psp_close,
	.connect = psp_connect,
	.disconnect = psp_disconnect,
	.accept = psp_accept,
	.ioctl = psp_ioctl,
	.init = psp_init_sock,
	.shutdown = psp_shutdown,
	.setsockopt = psp_setsockopt,
	.getsockopt = psp_getsockopt,
	.sendmsg = psp_sendmsg,
	.recvmsg = psp_recvmsg,
	.unhash = psp_unhash,	// remove from hash tables
	.get_port = psp_get_port, // get port 
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