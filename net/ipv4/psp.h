#include <linux/types.h>

struct psp_ctx {
	struct udp_psp_hdr	*udp_psp_hdr;
	struct psp_hdr		*psp_hdr;
};

struct udp_psp_hdr {
	__be16		source;
	__be16		dest;
	__be16		len;
	__be16		check;
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
	__be32		SPI;	/* Security Parameters Index */
	__be64		IV; 	/* Initialisation Vector */
	__be64		VC;	/* Virtualisation Cookie (only present if V is set) */
};

struct psp_trailer {
	uint64_t	ICV[2];	/* Integrity Checksum Value */
};

static inline struct psp_ctx *psp_get_ctx(const struct sock *sk){
	struct inet_connection_sock *icsk = inet_csk(sk);
	return (struct psp_ctx *)icsk->icsk_ulp_data;
} 
