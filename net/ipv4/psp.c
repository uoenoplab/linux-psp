#include <linux/module.h>

#include <net/tcp.h>
#include <net/inet_common.h>
#include <linux/highmem.h>
#include <linux/netdevice.h>
#include <linux/sched/signal.h>
#include <linux/inetdevice.h>
#include <linux/inet_diag.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <crypto/aead.h>
#include "psp.h"


#include <net/snmp.h>

MODULE_AUTHOR("Matthew Davidson");
MODULE_DESCRIPTION("PSP Protocol Support");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_ALIAS_TCP_ULP("PSP");

struct proto *prot;
struct proto_ops *proto_ops;

static int psp_sendpage_locked(struct sock *sk, struct page *page, int offset, size_t size, int flags){
	// return code
	int rc = 0;
	printk(KERN_INFO "PSP: sending page locked\n");
	return rc;
}

static ssize_t psp_splice_read(struct socket *sock, loff_t *ppos, struct pipe_inode_info *pipe, size_t len, unsigned int flags){
	// return code
	int rc = 0;
	printk(KERN_INFO "PSP: splice reading\n");
	return rc;
}

static int psp_setsockopt(struct sock *sk, int level, int optname, sockptr_t optval, unsigned int optlen){
	// return code
	int rc = 0;
	printk(KERN_INFO "PSP: setting socket option\n");
	return rc;
}

static int psp_getsockopt(struct sock *sk, int level, int optname, char __user *optval, int __user *optlen){
	// return code
	int rc = 0;
	printk(KERN_INFO "PSP: getting socket option\n");
	return rc;
}

static void psp_close(struct sock *sk, long timeout){
	printk(KERN_INFO "PSP: closing\n");
}

static int psp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size){
	// return code
	int rc = 0;
	struct psp_ctx *ctx;
	ctx = psp_get_ctx(sk);
	printk(KERN_INFO "PSP: sending message %s \n", ctx->udp_psp_hdr);
	printk(KERN_INFO "PSP: sending message\n");

	return rc;
}

static int psp_sendpage(struct sock *sk, struct page *page, int offset, size_t size, int flags){
	// return code
	int rc = 0;
	printk(KERN_INFO "PSP: sending page\n");
	return rc;
}

static int psp_recvmsg(struct sock *sk, struct msghdr *msg, size_t size, int noblock, int flags, int *addr_len){
	// return code
	int rc = 0;
	printk(KERN_INFO "PSP: receiving message\n");
	return rc;
}

static bool psp_sock_is_readable(struct sock *sk){
	// return code
	int rc = 0;
	printk(KERN_INFO "PSP: sock is readable\n");
	return rc;
}

static void psp_update(struct sock *sk, struct proto *p,
			 void (*write_space)(struct sock *sk)){
	printk(KERN_INFO "PSP: updating\n");

}

static int psp_get_info(const struct sock *sk, struct sk_buff *skb){
	// return code
	int rc = 0;
	printk(KERN_INFO "PSP: getting info\n");
	return rc;
}

static size_t psp_get_info_size(const struct sock *sk){
	// return code
	int rc = 0;
	printk(KERN_INFO "PSP: getting info size\n");
	return rc;
}

/* 
static void encrypt_data(){


}
*/

static const struct snmp_mib psp_mib_list[] = {
	SNMP_MIB_ITEM("PSPRXPkt", LINUX_MIB_PSPRXPKT),
	SNMP_MIB_ITEM("PSPRXBytes", LINUX_MIB_PSPRXBYTES),
	SNMP_MIB_ITEM("PSPRxAuthFail", LINUX_MIB_PSPRXAUTHFAIL),
	SNMP_MIB_ITEM("PSPRxErrPkt", LINUX_MIB_PSPRXERRPKT),
	SNMP_MIB_ITEM("PSPRxBadPkt", LINUX_MIB_PSPRXBADPKT),
	SNMP_MIB_ITEM("PSPTxPtks", LINUX_MIB_PSPTXPKT),
	SNMP_MIB_ITEM("PSPTxBytes", LINUX_MIB_PSPTXBYTES),
	SNMP_MIB_ITEM("PSPTxErrPkt", LINUX_MIB_PSPTXERRPKT),
	SNMP_MIB_SENTINEL
};

static int psp_init(struct sock *sk){
	// return code
	int rc = 0;


	// using ulp only works in an established state
	if (sk->sk_state != TCP_ESTABLISHED){
		return -ENOTCONN;
	}


	// replace proto methods with psp specific methods
	struct proto *prot = READ_ONCE(sk->sk_prot);
	struct proto_ops *proto_ops = READ_ONCE(sk->sk_socket->ops);

	proto_ops->sendpage_locked = psp_sendpage_locked;
	proto_ops->splice_read = psp_splice_read;
	
	prot->setsockopt = psp_setsockopt;
	prot->getsockopt = psp_getsockopt;
	prot->close = psp_close;
	prot->sendmsg = psp_sendmsg;
	prot->sendpage = psp_sendpage;
	prot->recvmsg = psp_recvmsg;
	prot->sock_is_readable = psp_sock_is_readable;

	WRITE_ONCE(sk->sk_prot, prot);
	WRITE_ONCE(sk->sk_socket->ops, proto_ops);

	// might need to create context

	// not supporting ipv6
	if (sk->sk_family == AF_INET6){
		rc = -EAFNOSUPPORT;
	}

	printk(KERN_INFO "PSP: initialised PSP protocol\n");

	return rc;
}

static int psp_stats_show(struct seq_file *seq, void *v){
	unsigned long buf[LINUX_MIB_PSPMAX];
	struct net *net = seq->private;
	int i;

	snmp_get_cpu_field_batch(buf, psp_mib_list, net->mib.psp_statistics);

	for (i = 0; psp_mib_list[i].name; i++){
		seq_printf(seq, "%s: %lu\n", psp_mib_list[i].name, buf[i]);
	}
	printk(KERN_INFO "PSP: showing stats\n");
	return 0;
}

int __net_init psp_proc_init(struct net *net){
	if(!proc_create_net_single("PSP_stat", 0444, net->proc_net, psp_stats_show, NULL)){
		return -ENOMEM;
	}
	printk(KERN_INFO "PSP: proc initialised\n");
	return 0;
}

static void __net_exit psp_proc_exit(struct net *net){
	remove_proc_entry("PSP_stat", net->proc_net);
}

static int __net_init psp_init_net(struct net *net){
	net->mib.psp_statistics = alloc_percpu(struct linux_psp_mib);
	if (!net->mib.psp_statistics){
		return -ENOMEM;
	}
	return 0;
}

static void __net_exit psp_exit_net(struct net *net){
	psp_proc_exit(net);
	free_percpu(net->mib.psp_statistics);
}

static struct pernet_operations psp_net_ops = {
	.init = psp_init_net,
	.exit = psp_exit_net,
};

static struct tcp_ulp_ops tcp_psp_ulp_ops = {
	.name = "PSP",
	.owner = THIS_MODULE,
	.init = psp_init,
	.update = psp_update,
	.get_info = psp_get_info,
	.get_info_size = psp_get_info_size,
};

static int __init psp_register(void){
	int err;
	err = register_pernet_subsys(&psp_net_ops);
	if (err){
		printk(KERN_INFO "PSP: Failed to register pernet subsystem\n");
		return err;
	}
	tcp_register_ulp(&tcp_psp_ulp_ops);
	printk(KERN_INFO "PSP: Registered PSP protocol\n");
	return 0;
}

static void __exit psp_unregister(void){
	tcp_unregister_ulp(&tcp_psp_ulp_ops);
	unregister_pernet_subsys(&psp_net_ops);
	printk(KERN_INFO "PSP: Unregistered PSP protocol\n");
}

module_init(psp_register);
module_exit(psp_unregister);

