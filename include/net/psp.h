#include <linux/types.h>

#include <asm/byteorder.h>
#include <linux/types.h>

struct psphdr {
	__u8	next_header;
	__u8	header_ext_len;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	r:2,
		crypt_offset:6;
	__u8	s:1,
		d:1,
		version:4,
		v:1,
		one:1;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8	crypt_offset:6,
		r:2;
	__u8	one:1,
		v:1,
		version:4,
		d:1,
		s:1;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
	__be32 	spi;
	__be64	iv;
	__be64 	vc;
};

struct psptrailer {
	__be32  pad;
	__be32  pad1;
	__be32  pad2;
	__be32  pad3;
};

#define PSP_AES_TAG_SIZE 16