#include <linux/types.h>
#include <linux/skbuff.h>

// 25 seems like a good number
#define AF_PSP		25
#define PF_PSP		AF_PSP
#define PSP_PROTO_NAME			"PSP"
#define PSP_PROC_NET_FILENAME		"PSP_stats"
#define PSP_PROC_FULL_FILENAME		"/proc/net/" PSP_PROC_NET_FILENAME

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

