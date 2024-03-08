#include <linux/module.h>

#include <net/tcp.h>
#include <uapi/linux/udp.h>
#include <net/inet_common.h>
#include <linux/scatterlist.h>
#include <linux/highmem.h>
#include <linux/netdevice.h>
#include <linux/sched/signal.h>
#include <linux/inetdevice.h>
#include <linux/inet_diag.h>
#include <net/strparser.h>
#include <linux/skmsg.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <crypto/aead.h>
#include <linux/ctype.h>
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

static void psp_queue(struct strparser *strp, struct sk_buff *skb){
	printk(KERN_INFO "PSP: psp-queue");
	struct psp_ctx *psp_ctx = psp_get_ctx(strp->sk);
	struct psp_crypto_ctx *ctx = psp_ctx->crypto_ctx_recv;
	ctx->recv_pkt = skb;
	strp_pause(strp);
}

static int psp_read_size(struct strparser *strp, struct sk_buff *skb){
	printk(KERN_INFO "PSP: psp_read_size");
	struct psp_ctx *psp_ctx = psp_get_ctx(strp->sk);
	struct psp_crypto_ctx *ctx = psp_ctx->crypto_ctx_recv;
	char header[32];
	struct strp_msg *rxm = strp_msg(skb);

	int ret = skb_copy_bits(skb, rxm->offset, header, 32);

	if (ret < 0){
		strp->sk->sk_err = -ret;
		sk_error_report(strp->sk);
		return ret;
	}

	size_t data_len = (size_t) header[3];
	
	return data_len + 32;

}

static int psp_setsockopt(struct sock *sk, int level, int optname, sockptr_t optval, unsigned int optlen){
	printk(KERN_INFO "PSP: psp_setsockopt");
	// return code
	int rc = 0;
	struct psp_ctx *ctx = psp_get_ctx(sk);
	struct psp_crypto_info *crypto_info;
	struct psp_crypto_ctx *crypto_ctx_send;
	struct psp_crypto_ctx *crypto_ctx_recv;
	struct crypto_aead **aead;
	struct crypto_tfm  *tfm;
	struct strp_callbacks cb;
	char *iv, *rec_seq, *key, *salt, *cipher_name;
	printk(KERN_INFO "PSP: setting socket option\n");

	if (level != SOL_PSP){
		return ctx->proto->setsockopt(sk, level, optname, optval, optlen);
	}

	if (!ctx){
		return -EINVAL;
	}

	lock_sock(sk);
	printk(KERN_INFO "locked sock");

	if (sockptr_is_null(optval) || optlen < sizeof(*crypto_info)){
		rc = -EINVAL;
		goto fail;
	}
	crypto_info = kzalloc(sizeof(*crypto_info), GFP_KERNEL);
	rc = copy_from_sockptr(crypto_info, optval, sizeof(*crypto_info));
	printk(KERN_INFO "copied something to %p from %p", &crypto_info, optval);
	printk(KERN_INFO "crypto_info: %s", crypto_info->iv);
	if (rc){
		rc = -EFAULT;
		goto fail;
	}

	rc = copy_from_sockptr_offset(crypto_info + 1, optval, sizeof(*crypto_info), optlen - sizeof(*crypto_info));

	if (rc){
		rc = -EFAULT;
		goto fail;
	}

	if (optname == PSP_TX){
		if (!ctx->crypto_ctx_send){
			crypto_ctx_send = kzalloc(sizeof(*crypto_ctx_send), GFP_KERNEL);
			if (!crypto_ctx_send){
				rc = -ENOMEM;
				goto fail;
			}
			ctx->crypto_ctx_send = crypto_ctx_send;
		} else {
			crypto_ctx_send = (struct psp_crypto_ctx *) ctx->crypto_ctx_send;
		}
	} else if (optname == PSP_RX){
		if (!ctx->crypto_ctx_recv){
			crypto_ctx_recv = kzalloc(sizeof(*crypto_ctx_recv), GFP_KERNEL);
			if (!crypto_ctx_recv){
				rc = -ENOMEM;
				goto fail;
			}
			ctx->crypto_ctx_recv = crypto_ctx_recv;
		} else {
			crypto_ctx_recv = (struct psp_crypto_ctx *) ctx->crypto_ctx_recv;
		}
	} else {
		rc = -EINVAL;
		goto fail;
	}

	if (optname == PSP_TX){
		crypto_init_wait(&crypto_ctx_send->async_wait);
		spin_lock_init(&crypto_ctx_send->compl_lock);
		aead = &crypto_ctx_send->aead;
		crypto_ctx_send->info = crypto_info;
		
	} else {
		crypto_init_wait(&crypto_ctx_recv->async_wait);
		spin_lock_init(&crypto_ctx_recv->compl_lock);
		aead = &crypto_ctx_recv->aead;
		crypto_ctx_recv->info = crypto_info;
	}


	//printk(KERN_INFO "psp: iv = %s \n", crypto_info->iv);
	
	if (!*aead){
		*aead = crypto_alloc_aead("gcm(aes)",0,0);
		if (IS_ERR(*aead)){
			rc = PTR_ERR(*aead);
			*aead = NULL;
			printk(KERN_ALERT "error allocating aead");
			goto fail;
		}
		if (optname == PSP_TX){
			crypto_ctx_send->aead = *aead;
		} else {
			crypto_ctx_recv->aead = *aead;
		}
	}

	rc = crypto_aead_setkey(*aead, crypto_info->key, 16);
	if (rc){
		goto free_aead;
	}

	rc = crypto_aead_setauthsize(*aead, 16);
	if (rc){
		goto free_aead;
	}

	//printk(KERN_INFO "psp: aead = %p", *aead);

	if(crypto_ctx_recv){
		tfm = crypto_aead_tfm(crypto_ctx_recv->aead);
		memset(&cb, 0, sizeof(cb));
		cb.rcv_msg = psp_queue;
		cb.parse_msg = psp_read_size;
		//strp_init(&crypto_ctx_recv->strp, sk, &cb);
	}
	release_sock(sk);
	printk(KERN_INFO "PSP: psp_setsockopt fini");
	return rc;

	fail:
		release_sock(sk);
		printk(KERN_INFO "PSP: psp_setsockopt fini");
		return rc;
	free_aead:
		crypto_free_aead(*aead);
		*aead = NULL;
		printk(KERN_INFO "PSP: psp_setsockopt fini");
		return rc;
}

static int psp_getsockopt(struct sock *sk, int level, int optname, char __user *optval, int __user *optlen){
	// return code
	int rc = 0;
	//if ()
	//switch (optname) {
	//	case 
	//}
	printk(KERN_INFO "PSP: getting socket option\n");
	return rc;
}

static void psp_close(struct sock *sk, long timeout){
	printk(KERN_INFO "PSP: closing\n");
}



static void print_psp_header(struct psp_hdr *hdr){
	printk(KERN_INFO "PSP: next_header - %d", hdr->next_header);
	printk(KERN_INFO "PSP: hdr_ext_len - %d", hdr->hdr_ext_len);
	printk(KERN_INFO "PSP: R - %d", hdr->R);
	printk(KERN_INFO "PSP: crypt_offset - %d", hdr->crypt_offset);
	printk(KERN_INFO "PSP: S - %d", hdr->S);
	printk(KERN_INFO "PSP: D - %d", hdr->D);
	printk(KERN_INFO "PSP: version - %d", hdr->version);
	printk(KERN_INFO "PSP: V - %d", hdr->V);
	printk(KERN_INFO "PSP: one - %d", hdr->one);
	printk(KERN_INFO "PSP: SPI - %s", hdr->SPI);
	printk(KERN_INFO "PSP: IV - %s", hdr->IV);
	printk(KERN_INFO "PSP: VC - %d", hdr->VC);
}

static void print_udp_header(struct udphdr *hdr){
	printk(KERN_INFO "PSP: source - %d", hdr->source);
	printk(KERN_INFO "PSP: dest - %d", hdr->dest);
	printk(KERN_INFO "PSP: len - %d", hdr->len);
	printk(KERN_INFO "PSP: check - %d", hdr->check);
}

static void print_psp_data(struct psp_data *data){
	print_psp_header(data->psp_hdr);
	print_udp_header(data->udp_hdr);
	printk(KERN_INFO "PSP: data - %p", *(data->data));
	printk(KERN_INFO "PSP: data_size - %d", data->data_size);
}

static struct psp_hdr* psp_make_header(struct psp_ctx *ctx){
	struct psp_hdr *hdr = kzalloc(sizeof(struct psp_hdr), GFP_KERNEL);
	hdr->next_header = (u8) ctx->sk->sk_protocol;
	hdr->hdr_ext_len = 0;
	hdr->R = 0;
	hdr->crypt_offset = 0;
	hdr->S = 0;
	hdr->D = 0;
	hdr->version = 0;
	hdr->V = 0;
	hdr->one = 1;
	memcpy(hdr->SPI, ctx->crypto_ctx_send->info->spi, 2);
	memcpy(hdr->IV, ctx->crypto_ctx_send->info->iv, 4);
	hdr->VC = 0;
	return hdr;
}

static struct udphdr* psp_make_udp_header(int size, int icv_size){
	struct udphdr *hdr = kzalloc(sizeof(struct udphdr), GFP_KERNEL);
	hdr->source = 0;
	hdr->dest = 1000;
	hdr->len = sizeof(struct psp_hdr) + sizeof(struct udphdr) + size + icv_size;
	hdr->check = 0;
	return hdr;
}


static int psp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size){
	printk(KERN_INFO "PSP: psp_sendmsg");
	// return code
	int rc = 0;
	// define structs we need
	struct psp_ctx *ctx;
	struct crypto_aead *tfm;
	struct aead_request *req;
	struct scatterlist sg = { 0 };
	u8 *buffer = NULL;
	u8 buffersize;
	struct udphdr *udp_header;
	struct psp_hdr *psp_header;
	struct iov_iter *msg_iter;
	char *icv;
	const int icv_size = 16;
	
	//return tcp_sendmsg(sk, msg, size);

	// declare wait for async crypto
	// TODO: check if this can be removed
	DECLARE_CRYPTO_WAIT(wait);
	// get context
	ctx = psp_get_ctx(sk);
	// allocate memory for headers/trailers
	udp_header = psp_make_udp_header(size, icv_size);
	psp_header = psp_make_header(ctx);
	//pr_info("psp hdr spi: %d", psp_header->next_header);

	//pr_info("PSP: set headers");

	tfm = ctx->crypto_ctx_send->aead;
	req = aead_request_alloc(tfm, GFP_KERNEL);
	if (!req){
		rc = -ENOMEM;	
	}

	buffersize = size + 16;
	buffer = kzalloc(buffersize, GFP_KERNEL);

	if (buffer == NULL){
		pr_err("PSP: failed kzalloc for msg");
		return -ENOMEM;
	}

	copy_from_iter(buffer, size, &msg->msg_iter);
	printk("buffer: %s", buffer);
	sg_init_one(&sg, buffer, buffersize);
	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG | 
				       CRYPTO_TFM_REQ_MAY_SLEEP, crypto_req_done, &wait);

	aead_request_set_crypt(req, &sg, &sg, buffersize - 16, ctx->crypto_ctx_send->info->iv);
	rc = crypto_wait_req(crypto_aead_encrypt(req), &wait);
	printk("buffer: %s", buffer);
	if (rc != 0){
		pr_err("PSP: error encrypting data for sendmsg()");
	}
	//pr_info("PSP: did encryption");

	size_t count = udp_header->len;
	char *finalmsg = kmalloc(count, GFP_KERNEL);
	struct kvec kvec = {};

	char udp_buf[sizeof(struct udphdr)];
	//printk("udp_header: %", cpy_buf);
	memcpy(&udp_buf, udp_header, sizeof(struct udphdr));
	memcpy(finalmsg, &udp_buf, sizeof(struct udphdr));
	
	char psp_buf[sizeof(struct psp_hdr)];
	memcpy(&psp_buf, psp_header, sizeof(struct psp_hdr));
	memcpy(finalmsg + sizeof(struct udphdr), &psp_buf, sizeof(struct psp_hdr));
	memcpy(finalmsg + sizeof(struct udphdr) + sizeof(struct psp_hdr), buffer, buffersize);
	printk("buffer:              %s", buffer);
	printk("constructed message: %x", finalmsg);

	//int i;
	//for (i = 0; i < count; i++){
	//	printk("%x", *(finalmsg+i));
	//}

	kvec.iov_base = buffer;
	kvec.iov_len = buffersize;
	iov_iter_kvec(&msg->msg_iter, WRITE, &kvec, 1, buffersize);

	//printk(KERN_INFO "PSP: sending message - %s\n", new->msg_iter.iov->iov_base);
	rc = tcp_sendmsg(sk, msg, count);
	//printk(KERN_INFO "PSP: sent tcp message %d", rc);
	if (req != NULL) {
		aead_request_free(req);
    	}
	kfree(buffer);
	//kfree(finalmsg);
	kfree(psp_header);
	kfree(udp_header);
	return rc;
}

static int psp_sendpage(struct sock *sk, struct page *page, int offset, size_t size, int flags){
	// return code
	int rc = 0;
	printk(KERN_INFO "PSP: sending page\n");
	return rc;
}

static struct psp_data *deserialise_header(struct msghdr *msg, size_t size){
	// allocate buffer and copy from msg
	u8 *buffer = NULL;
	buffer = kzalloc(size, GFP_KERNEL);
	copy_from_iter(buffer, size, &msg->msg_iter);

	// allocate structures for headers
	struct psp_hdr *psp_hdr = kzalloc(sizeof(struct psp_hdr), GFP_KERNEL);
	struct udphdr *udp_hdr = kzalloc(sizeof(struct udphdr), GFP_KERNEL);
	struct psp_data *psp_data = kzalloc(sizeof(struct psp_data), GFP_KERNEL);

	memcpy(udp_hdr, buffer, sizeof(struct udphdr));
	memcpy(psp_hdr, buffer + sizeof(struct udphdr), sizeof(struct psp_hdr));
	memcpy(psp_data->data, 
		buffer + sizeof(struct udphdr) + sizeof(struct psp_hdr), 
		size - sizeof(struct udphdr) - sizeof(struct psp_hdr));
	psp_data->psp_hdr = psp_hdr;
	psp_data->udp_hdr = udp_hdr;
	psp_data->data_size = size - sizeof(struct udphdr) - sizeof(struct psp_hdr);
	return psp_data;
}

static int psp_recvmsg(struct sock *sk, struct msghdr *msg, size_t size, int noblock, int flags, int *addr_len){
	
	int rc;

	struct msghdr recv_msg;
	struct kvec iov;
	u8 *buffer = NULL;
	buffer = kzalloc(size, GFP_KERNEL);
	if (buffer == NULL){
		printk(KERN_INFO "PSP: failed kzalloc for msg");
		return -ENOMEM;
	}

	iov.iov_base = buffer;
	iov.iov_len = size;
	iov_iter_kvec(&recv_msg.msg_iter, READ, &iov, 1, size);

	rc = tcp_recvmsg(sk, &recv_msg, size, noblock, flags, addr_len);
	
	if (rc > 0){
		printk("message size after recv: %d", rc);
		printk(KERN_INFO "Received data: %.*s\n", rc, buffer);
	}
	kfree(buffer);
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
	unsigned char *data;
	data = skb->data;
	printk(KERN_INFO "PSP: getting info\n");
	printk(KERN_INFO "PSP: data %s\n", *data);
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

struct psp_ctx *psp_ctx_create(struct sock *sk){
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct psp_ctx *ctx;
	ctx = kzalloc(sizeof(struct psp_ctx), GFP_ATOMIC);
	if (!ctx){
		return NULL;
	}
	rcu_assign_pointer(icsk->icsk_ulp_data, ctx);
	ctx->sk = sk;
	return ctx;
};

static int psp_init(struct sock *sk){
	// return code
	int rc = 0;
	struct psp_ctx *ctx;

	// replace proto methods with psp specific methods
	struct proto *prot = READ_ONCE(sk->sk_prot);
	struct proto *new_prot;
	struct proto_ops *proto_ops = READ_ONCE(sk->sk_socket->ops);
	struct proto_ops *ops;

	new_prot = kzalloc(sizeof(struct proto), GFP_KERNEL);
	ops = kzalloc(sizeof(struct proto_ops), GFP_KERNEL);

	memcpy(ops, proto_ops, sizeof(struct proto_ops));
	memcpy(new_prot, prot, sizeof(struct proto));
	// make context before setting new function pointers
	ctx = psp_ctx_create(sk);
	printk(KERN_INFO "PSP: returned from psp-ctx-create");
	ctx->proto = prot;
	printk(KERN_INFO "PSP: assigned prot");
	//ops->sendpage_locked = psp_sendpage_locked;
	//ops->splice_read = psp_splice_read;
	new_prot->setsockopt = psp_setsockopt;
	//new_prot->getsockopt = psp_getsockopt;
	//new_prot->close = psp_close;
	new_prot->sendmsg = psp_sendmsg;
	new_prot->recvmsg = psp_recvmsg;
	//new_prot->connect = tcp_v4_connect;

	printk(KERN_INFO "PSP: listen function pointer - %p", ops->listen);
	ops->listen = inet_listen;
	printk(KERN_INFO "PSP: listen function pointer - %p", ops->listen);
	printk(KERN_INFO "PSP: connect function pointer - %p", new_prot->connect);

	printk(KERN_INFO "PSP: reassigned function pointers");

	WRITE_ONCE(sk->sk_prot, new_prot);
	printk(KERN_INFO "PSP: wrote prot");
	WRITE_ONCE(sk->sk_socket->ops, ops);
	printk(KERN_INFO "PSP: wrote proto_ops");
	// might need to create context

	// not supporting ipv6
	if (sk->sk_family == AF_INET6){
		rc = -EAFNOSUPPORT;
	}

	printk(KERN_INFO "PSP: initialised PSP protocol\n");
	printk(KERN_INFO "PSP: return code %d\n", rc);
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

static void psp_clone(const struct request_sock *req, struct sock *newsk, const gfp_t priority)
{
	
	/* Copy any PSP-specific data from the original sock to the clone */
	// TODO: Add code to copy PSP-specific data
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
	//.update = psp_update,
	//.get_info = psp_get_info,
	//.get_info_size = psp_get_info_size,
	.clone = psp_clone,
};

static int __init psp_register(void){
	int err;
	err = register_pernet_subsys(&psp_net_ops);
	if (err){
		printk(KERN_INFO "PSP: Failed to register pernet subsystem\n");
		return err;
	}
	tcp_register_ulp(&tcp_psp_ulp_ops);
	printk(KERN_INFO "psp_register\n");
	return 0;
}

static void __exit psp_unregister(void){
	tcp_unregister_ulp(&tcp_psp_ulp_ops);
	unregister_pernet_subsys(&psp_net_ops);
	printk(KERN_INFO "psp_unregister\n");
}

module_init(psp_register);
module_exit(psp_unregister);

