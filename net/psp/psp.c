#include <linux/module.h>
#include <linux/net.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <net/sock.h>

#include <net/inet_common.h>


void module_init(){
    int rc;
    rc = proto_register(&psp_prot, 1);
    if (rc < 0){
        return 
    }
}


static struct proto_ops psp_proto_ops;
/* Protocol specific socket structure */
struct my_sock {
struct inet_sock isk;
/* Add the Protocol implementation specific data members per socket here from here on */
};





rc = sock_register(&my_net_proto, 1);



static int my_create_socket(struct socket *sock, int protocol)
{
struct sock *sk;
int rc;

sk = sk_alloc(PF_INET_NEW_TCP, GFP_KERNEL, &my_proto, 1);
if (!sk) {
printk("failed to allocate socket.\n");
return -ENOMEM;
}

sock_init_data(sock, sk);
sk->sk_protocol = 0x0;

sock->ops = &my_proto_ops;
sock->state = SS_UNCONNECTED;

/* Do the protocol specific socket object initialization */
return 0;
};


struct proto psp_prot = {
	.name			= "PSP",
	.owner			= THIS_MODULE,
	.close			= udp_lib_close,
	.pre_connect	= udp_pre_connect,
	.connect		= ip4_datagram_connect,
	.disconnect		= udp_disconnect,
	.ioctl			= udp_ioctl,
	.init			= udp_init_sock,
	.destroy		= udp_destroy_sock,
	.setsockopt		= udp_setsockopt,
	.getsockopt		= udp_getsockopt,
	.sendmsg		= udp_sendmsg,
	.recvmsg		= udp_recvmsg,
	.sendpage		= udp_sendpage,
	.release_cb		= ip4_datagram_release_cb,
	.hash			= udp_lib_hash,
	.unhash			= udp_lib_unhash,
	.rehash			= udp_v4_rehash,
	.get_port		= udp_v4_get_port,
	.memory_allocated	= &udp_memory_allocated,
	.sysctl_mem		= sysctl_udp_mem,
	.sysctl_wmem_offset	= offsetof(struct net, ipv4.sysctl_udp_wmem_min),
	.sysctl_rmem_offset	= offsetof(struct net, ipv4.sysctl_udp_rmem_min),
	.obj_size		= sizeof(struct udp_sock),
	.h.udp_table		= &udp_table,
	.diag_destroy		= udp_abort,
};
EXPORT_SYMBOL(psp_prot);

static struct proto_ops psp_proto_ops = {
    .family = PF_INET,
    .owner = THIS_MODULE,
    .release = inet_release,
    .bind = my_bind,
    .connect = inet_stream_connect,
    .socketpair = sock_no_socketpair,
    .accept = inet_accept,
    .getname = inet_getname,
    .poll = my_poll,
    .ioctl = inet_ioctl,
    .listen = my_inet_listen,
    .shutdown = inet_shutdown,
    .setsockopt = sock_common_setsockopt,
    .getsockopt = sock_common_getsockopt,
    .sendmsg = inet_sendmsg,
    .recvmsg = sock_common_recvmsg,
};

struct net_proto_family psp_net_proto = {
.family = AF_INET,
.create = my_create_socket,
.owner = THIS_MODULE,
};