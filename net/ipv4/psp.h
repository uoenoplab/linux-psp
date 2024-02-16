#include <linux/types.h>
#include <linux/socket.h>
#include <linux/crypto.h>
#include <linux/mutex.h>
#include <net/strparser.h>
#include <net/udp.h>


#define PSP_TX 1
#define PSP_RX 2

struct psp_crypto_info {
	unsigned char spi[4];
	unsigned char iv[8];
	unsigned char key[16];
	unsigned int crypt_offset;
	unsigned int lifetime;
};

struct psp_crypto_ctx {
	struct psp_crypto_info *info;
	struct crypto_aead *aead;
	struct crypto_wait async_wait;
	spinlock_t compl_lock;
	atomic_t pending;
	struct strparser strp;
	struct sk_buff *recv_pkt;
};

struct psp_ctx {
	struct psp_crypto_ctx *crypto_ctx_send;
	struct psp_crypto_ctx *crypto_ctx_recv;
	struct sock *sk;
	struct proto *proto;
	struct psp_data *psp_data;
};

struct psp_data {
	struct udphdr		*udp_hdr;
	struct psp_hdr		*psp_hdr;
	char 			*data;
	int			data_size;
};

struct psp_hdr {
	__u8		next_header;
	__u8		hdr_ext_len;
	__u8		R:2,	/* Reserved */
			crypt_offset:6;
	__u8		S:1,	/* Sample at Receiver */
			D:1,	/* Drop after Sampling */
			version:4,
			V:1,	/* Virtualisation Cookie Present bit */
			one:1;	/* always set to 1 */
	unsigned char	SPI[4];	/* Security Parameters Index */
	unsigned char	IV[8]; 	/* Initialisation Vector */
	__be64		VC;	/* Virtualisation Cookie (only present if V is set) */
};

static inline struct psp_ctx *psp_get_ctx(const struct sock *sk){
	struct inet_connection_sock *icsk = inet_csk(sk);
	return (struct psp_ctx *)icsk->icsk_ulp_data;
} 
